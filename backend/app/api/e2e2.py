"""Explicit whole-view E2E2 storage API; no server plaintext or signing keys."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import delete, select

from app import access, audit, e2e2, e2e2_rotation, machines
from app.api.machine import CurrentMachine
from app.api.machines_admin import _require_read, _require_reach
from app.deps import CurrentUser, MaintainerUser, OwnerUser, SessionDep, UnsealedBox, peer_ip
from app.models import (
    E2E2EnvironmentIdentity, E2E2Envelope, E2E2ProjectIdentity, E2E2ReaderGrant,
    E2E2Realm, E2E2View, E2E2AuthorityProjection, E2E2EpochReaderGrant,
    E2E2StagedReaderWrap, Environment, MachineIdentity, Project, Secret, User,
)

router = APIRouter(prefix="/e2e2", tags=["e2e2"])
machine_router = APIRouter(prefix="/v1/machine", tags=["machine-e2e2"])


def reject(reason: str, status=400):
    raise e2e2.Rejected(reason, status)


async def body(request: Request, maximum: int):
    raw, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > maximum:
            reject("ResponseTooLarge", 413)
        raw.append(chunk)
    return e2e2.load(b"".join(raw), maximum)


def scope(view: E2E2View) -> dict:
    return {"realm_id": view.realm_uuid, "project_id": view.project_uuid,
            "environment_id": view.environment_uuid, "view_id": view.id, "log_id": view.log_uuid}


def output(view: E2E2View) -> dict:
    return {"context": scope(view), "read_key_epoch": view.read_key_epoch,
            "publisher_policy_epoch": view.publisher_policy_epoch,
            "indexed_sequence": view.indexed_sequence, "indexed_hash": view.indexed_hash}


async def get_view(session, view_id: str, lock=False):
    if not e2e2.UUID.fullmatch(view_id):
        reject("SourceNotFound", 404)
    query = select(E2E2View).where(E2E2View.id == view_id)
    if lock:
        query = query.with_for_update(key_share=True).execution_options(populate_existing=True)
    view = await session.scalar(query)
    if view is None:
        reject("SourceNotFound", 404)
    return view


async def manage(session, user, view):
    for action in (access.READ, access.WRITE):
        if not await access.covers_whole(session, user, action, view.project_id, view.environment_id, []):
            reject("AccessDenied", 403)


async def whole_machine(session, machine, view):
    policies = await machines.effective_policies(session, machine)
    now = datetime.now(timezone.utc)
    if not all(machines.decide(policies, access.READ,
        access.Scope(project_id=view.project_id, environment_id=view.environment_id, path=path), now)
        for path in access.interesting_paths(policies, [])):
        reject("AccessDenied", 403)


async def reader_grant(session, machine, view):
    await whole_machine(session, machine, view)
    grant = await session.get(E2E2EpochReaderGrant, (view.id, machine.id, view.read_key_epoch, view.publisher_policy_epoch))
    if grant is None:
        grant = await session.get(E2E2ReaderGrant, (view.id, machine.id))
    if grant is None:
        reject("AccessDenied", 403)
    creator = await session.scalar(select(User).where(User.username == grant.created_by))
    if not machines.may_vouch(creator) or not await access.covers_whole(session, creator, access.READ, view.project_id, view.environment_id, []):
        reject("AccessDenied", 403)
    try:
        fingerprint = e2e2.node_fingerprint(machine.public_key)
    except e2e2.Rejected:
        reject("AwaitingProjectKey", 409)
    if fingerprint != grant.recipient_fingerprint or grant.read_key_epoch != view.read_key_epoch or grant.publisher_policy_epoch != view.publisher_policy_epoch:
        reject("AwaitingProjectKey", 409)
    return grant


async def snapshot(session, view, digest):
    if type(digest) is not str or not e2e2.HASH.fullmatch(digest):
        reject("CanonicalSnapshotUnavailable", 404)
    row = await session.get(E2E2Envelope, digest)
    if row is None or row.view_id != view.id:
        reject("CanonicalSnapshotUnavailable", 404)
    _, encoded, actual = e2e2.validate_envelope(row.canonical_envelope.encode(), scope(view), json.loads(view.publisher_keys), view.read_key_epoch, view.publisher_policy_epoch)
    if actual != digest:
        reject("CanonicalSnapshotUnavailable", 409)
    return row, encoded


def raw_response(raw):
    return Response(raw, media_type="application/json", headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


def witness_service(request: Request, view_id: str) -> None:
    if not e2e2.witness_fetch_allowed(view_id, request.headers.get("authorization", "")):
        reject("AuthRejected", 401)


WitnessService = Annotated[None, Depends(witness_service)]


async def reject_legacy(request: Request, user: CurrentUser, session: SessionDep):
    # Authenticate before inspecting a scoped source. Global lists remain usable.
    values = request.path_params
    env_id, project_id = values.get("env_id"), values.get("project_id")
    if env_id is None and project_id is None:
        return
    if env_id is None and request.method in ("GET", "HEAD") and "/e2e" not in request.url.path:
        return
    try:
        query = select(E2E2View)
        if env_id is not None:
            query = query.where(E2E2View.environment_id == int(env_id))
        else:
            query = query.where(E2E2View.project_id == int(project_id))
    except (ValueError, TypeError):
        return
    view = await session.scalar(query.limit(1))
    if view is not None:
        if not await access.visible_in(session, user, access.LIST, view.project_id, [view.environment_id]):
            reject("AccessDenied", 403)
        reject("UpgradeRequired", 409)


@router.post("/views", status_code=201)
async def register(request: Request, user: OwnerUser, session: SessionDep, _box: UnsealedBox):
    data = e2e2.exact(await body(request, 16384), {"project_id", "environment_id", "context", "publisher_keys", "read_key_epoch", "publisher_policy_epoch"})
    e2e2.require(type(data["project_id"]) is int and type(data["environment_id"]) is int, "InvalidShape")
    ctx = e2e2.context(e2e2.exact(data["context"], e2e2.SCOPE))
    e2e2.require(data["read_key_epoch"] == "1" and data["publisher_policy_epoch"] == "1", "UnsupportedEpoch")
    keys = e2e2.publisher_keys(data["publisher_keys"])
    project = await session.scalar(select(Project).where(Project.id == data["project_id"]).with_for_update(key_share=True))
    environment = await session.scalar(select(Environment).where(Environment.id == data["environment_id"]).with_for_update(key_share=True))
    if project is None or environment is None or environment.project_id != project.id:
        reject("SourceNotFound", 404)
    children = await session.scalar(select(Environment.id).where(Environment.parent_id == environment.id).limit(1))
    if project.e2e or environment.parent_id is not None or children is not None:
        reject("ExplicitMigrationRequired", 409)
    # No implicit migration: even deleted or pending legacy values require review.
    if await session.scalar(select(Secret.id).where(Secret.environment_id == environment.id).limit(1)):
        reject("ExplicitMigrationRequired", 409)
    realm = await session.get(E2E2Realm, 1)
    if realm is None:
        session.add(E2E2Realm(id=1, realm_uuid=ctx["realm_id"]))
    elif realm.realm_uuid != ctx["realm_id"]:
        reject("ContextMismatch", 409)
    for model, key, value, uuid_field in (
        (E2E2ProjectIdentity, project.id, ctx["project_id"], "project_uuid"),
        (E2E2EnvironmentIdentity, environment.id, ctx["environment_id"], "environment_uuid"),
    ):
        identity = await session.get(model, key)
        if identity is None:
            kwargs = {"project_id" if model is E2E2ProjectIdentity else "environment_id": key, uuid_field: value}
            session.add(model(**kwargs))
        elif getattr(identity, uuid_field) != value:
            reject("ContextMismatch", 409)
    if await session.get(E2E2View, ctx["view_id"]) is not None:
        reject("SourceConflict", 409)
    view = E2E2View(id=ctx["view_id"], realm_uuid=ctx["realm_id"], project_id=project.id,
        environment_id=environment.id, project_uuid=ctx["project_id"], environment_uuid=ctx["environment_id"],
        log_uuid=ctx["log_id"], publisher_keys=e2e2.canonical(keys).decode(), read_key_epoch="1",
        publisher_policy_epoch="1", indexed_sequence="0", indexed_hash=e2e2.ZERO, created_by=user.username)
    session.add(view)
    await audit.record(session, actor=user.username, action="e2e_enabled", target=view.id, detail="e2e2 whole-view registered", ip=peer_ip(request))
    await session.commit()
    return output(view)


@router.get("/views/{view_id}")
async def view_info(view_id: str, user: MaintainerUser, session: SessionDep):
    view = await get_view(session, view_id)
    await manage(session, user, view)
    return output(view)


@router.post("/views/{view_id}/envelopes", status_code=201)
async def stage(view_id: str, request: Request, user: MaintainerUser, session: SessionDep, _box: UnsealedBox):
    view = await get_view(session, view_id)
    await manage(session, user, view)
    data = await body(request, e2e2.MAX_ENVELOPE)
    header, encoded, digest = e2e2.validate_envelope(e2e2.canonical(data), scope(view), json.loads(view.publisher_keys), view.read_key_epoch, view.publisher_policy_epoch)
    existing = await session.get(E2E2Envelope, digest)
    if existing is not None:
        if existing.view_id != view.id or existing.canonical_envelope != encoded.decode():
            reject("SourceConflict", 409)
        return {"envelope_hash": digest, "state": "staged"}
    session.add(E2E2Envelope(envelope_hash=digest, view_id=view.id, sequence=header["sequence"], canonical_envelope=encoded.decode(), created_by=user.username))
    await audit.record(session, actor=user.username, action="secret_written", target=view.id, detail="e2e2 signed ciphertext staged", ip=peer_ip(request))
    await session.commit()
    return {"envelope_hash": digest, "state": "staged"}


@router.get("/views/{view_id}/envelopes/{envelope_hash}")
async def admin_snapshot(view_id: str, envelope_hash: str, user: MaintainerUser, session: SessionDep, _box: UnsealedBox):
    view = await get_view(session, view_id)
    await manage(session, user, view)
    _, encoded = await snapshot(session, view, envelope_hash)
    return raw_response(encoded)


@router.post("/views/{view_id}/index")
async def index(view_id: str, request: Request, user: MaintainerUser, session: SessionDep, _box: UnsealedBox):
    data = e2e2.exact(await body(request, 1024), {"envelope_hash"})
    view = await get_view(session, view_id, lock=True)
    await manage(session, user, view)
    row, _ = await snapshot(session, view, data["envelope_hash"])
    head = await e2e2.fresh_head(scope(view), view.indexed_sequence, view.indexed_hash)
    if head["envelope_hash"] != row.envelope_hash or head["sequence"] != row.sequence:
        reject("HeadChanged", 409)
    if head["read_key_epoch"] != view.read_key_epoch or head["publisher_policy_epoch"] != view.publisher_policy_epoch:
        reject("UnsupportedEpoch", 409)
    view.indexed_sequence, view.indexed_hash = head["sequence"], head["envelope_hash"]
    await audit.record(session, actor=user.username, action="secret_written", target=view.id, detail="e2e2 witness-committed snapshot indexed", ip=peer_ip(request))
    await session.commit()
    return {"envelope_hash": row.envelope_hash, "sequence": row.sequence, "state": "indexed"}


@router.post("/views/{view_id}/readers")
async def grant_reader(view_id: str, request: Request, user: OwnerUser, session: SessionDep, _box: UnsealedBox):
    data = e2e2.exact(await body(request, e2e2.MAX_WRAP + 1024), {"machine_id", "wrapper"})
    e2e2.require(type(data["machine_id"]) is int, "InvalidShape")
    view = await get_view(session, view_id, lock=True)
    environment = await session.get(Environment, view.environment_id)
    await _require_read(session, user, environment)
    await _require_reach(session, user, [data["machine_id"]])
    machine = await session.scalar(select(MachineIdentity).where(MachineIdentity.id == data["machine_id"]).with_for_update(key_share=True).execution_options(populate_existing=True))
    if machine is None:
        reject("SourceNotFound", 404)
    await whole_machine(session, machine, view)
    fingerprint = e2e2.node_fingerprint(machine.public_key)
    wrapper = e2e2.validate_wrapper(e2e2.canonical(data["wrapper"]), scope(view), fingerprint, json.loads(view.publisher_keys), view.read_key_epoch, view.publisher_policy_epoch)
    grant = await session.get(E2E2ReaderGrant, (view.id, machine.id))
    if grant is None:
        grant = E2E2ReaderGrant(view_id=view.id, machine_id=machine.id)
        session.add(grant)
    grant.recipient_fingerprint, grant.canonical_wrapper = fingerprint, wrapper.decode()
    grant.read_key_epoch, grant.publisher_policy_epoch, grant.created_by = view.read_key_epoch, view.publisher_policy_epoch, user.username
    epoch_grant = await session.get(E2E2EpochReaderGrant, (view.id, machine.id, view.read_key_epoch, view.publisher_policy_epoch))
    if epoch_grant is None:
        epoch_grant = E2E2EpochReaderGrant(view_id=view.id, machine_id=machine.id, read_key_epoch=view.read_key_epoch, publisher_policy_epoch=view.publisher_policy_epoch)
        session.add(epoch_grant)
    epoch_grant.recipient_fingerprint, epoch_grant.canonical_wrapper, epoch_grant.created_by = fingerprint, wrapper.decode(), user.username
    await audit.record(session, actor=user.username, action="e2e_machine_wrapped", target=view.id, detail="e2e2 full-view reader grant", ip=peer_ip(request))
    await session.commit()
    return {"machine_id": machine.id, "view_id": view.id, "has_wrap": True}


@router.delete("/views/{view_id}/readers/{machine_id}", status_code=204)
async def revoke_reader(view_id: str, machine_id: int, request: Request, user: OwnerUser, session: SessionDep):
    view = await get_view(session, view_id, lock=True)
    grant = await session.get(E2E2ReaderGrant, (view.id, machine_id))
    epochs = await session.execute(delete(E2E2EpochReaderGrant).where(E2E2EpochReaderGrant.view_id == view.id, E2E2EpochReaderGrant.machine_id == machine_id))
    candidates = await session.execute(delete(E2E2StagedReaderWrap).where(E2E2StagedReaderWrap.view_id == view.id, E2E2StagedReaderWrap.machine_id == machine_id))
    if grant is not None:
        await session.delete(grant)
    if grant is not None or epochs.rowcount or candidates.rowcount:
        await audit.record(session, actor=user.username, action="policy_deleted", target=view.id, detail="e2e2 view reader revoked; previously disclosed keys require rotation", ip=peer_ip(request))
    await session.commit()
    return Response(status_code=204)


@router.post("/views/{view_id}/rotation-stage", status_code=201)
async def stage_rotation(view_id: str, request: Request, user: OwnerUser, session: SessionDep, _box: UnsealedBox):
    view = await get_view(session, view_id, lock=True)
    await manage(session, user, view)
    data = e2e2.exact(await body(request, e2e2.MAX_ENVELOPE), {"envelope", "readers"})
    e2e2.require(type(data["readers"]) is list and len(data["readers"]) <= 32, "InvalidShape")
    header, encoded, digest = e2e2.staged_envelope(e2e2.canonical(data["envelope"]), scope(view))
    e2e2.require(e2e2.counter(header["read_key_epoch"]) >= e2e2.counter(view.read_key_epoch) and e2e2.counter(header["publisher_policy_epoch"]) >= e2e2.counter(view.publisher_policy_epoch), "AuthorityDowngrade", 409)
    existing = await session.get(E2E2Envelope, digest)
    if existing is not None:
        e2e2.require(existing.view_id == view.id and existing.canonical_envelope == encoded.decode(), "SourceConflict", 409)
    else:
        session.add(E2E2Envelope(envelope_hash=digest, view_id=view.id, sequence=header["sequence"], canonical_envelope=encoded.decode(), created_by=user.username))
    environment = await session.get(Environment, view.environment_id)
    await _require_read(session, user, environment)
    seen = set()
    for candidate in data["readers"]:
        e2e2.exact(candidate, {"machine_id", "wrapper"})
        machine_id = candidate["machine_id"]
        e2e2.require(type(machine_id) is int and machine_id > 0 and machine_id not in seen, "InvalidShape")
        seen.add(machine_id)
        await _require_reach(session, user, [machine_id])
        machine = await session.scalar(select(MachineIdentity).where(MachineIdentity.id == machine_id).with_for_update(key_share=True).execution_options(populate_existing=True))
        if machine is None:
            reject("SourceNotFound", 404)
        await whole_machine(session, machine, view)
        fingerprint = e2e2.node_fingerprint(machine.public_key)
        wrapper = e2e2.staged_wrapper(e2e2.canonical(candidate["wrapper"]), scope(view), fingerprint)
        context = candidate["wrapper"]["body"]["context"]
        e2e2.require(context["read_key_epoch"] == header["read_key_epoch"] and context["publisher_policy_epoch"] == header["publisher_policy_epoch"], "UnsupportedEpoch")
        identity = (view.id, machine.id, context["read_key_epoch"], context["publisher_policy_epoch"])
        staged = await session.get(E2E2StagedReaderWrap, identity)
        if staged is None:
            staged = E2E2StagedReaderWrap(view_id=view.id, machine_id=machine.id, read_key_epoch=identity[2], publisher_policy_epoch=identity[3])
            session.add(staged)
        staged.recipient_fingerprint, staged.canonical_wrapper, staged.created_by = fingerprint, wrapper.decode(), user.username
    await audit.record(session, actor=user.username, action="secret_written", target=view.id, detail="e2e2 untrusted opaque rotation candidates staged", ip=peer_ip(request))
    await session.commit()
    return {"view_id": view.id, "envelope_hash": digest, "state": "rotation-staged", "reader_candidates": len(seen)}


@router.post("/views/{view_id}/rotation-project")
async def project_rotation(view_id: str, request: Request, user: OwnerUser, session: SessionDep, _box: UnsealedBox):
    e2e2.exact(await body(request, 1024), set())
    view = await get_view(session, view_id, lock=True)
    await manage(session, user, view)
    projection = await session.get(E2E2AuthorityProjection, view.id)
    state = await e2e2_rotation.fresh_authority(scope(view), projection)
    authority, current, snapshot_meta = state["authority"], state["cursor"], state["snapshot"]
    e2e2.require(e2e2.counter(authority["read_key_epoch"]) >= e2e2.counter(view.read_key_epoch) and e2e2.counter(authority["publisher_policy_epoch"]) >= e2e2.counter(view.publisher_policy_epoch), "AuthorityDowngrade", 409)
    sequence, previous_sequence = e2e2.counter(snapshot_meta["sequence"]), e2e2.counter(view.indexed_sequence, True)
    e2e2.require(sequence >= previous_sequence and (sequence != previous_sequence or snapshot_meta["envelope_hash"] == view.indexed_hash), "AuthorityDowngrade", 409)
    if projection is not None:
        new_journal, old_journal = e2e2.counter(current["journal_sequence"], True), e2e2.counter(projection.journal_sequence, True)
        e2e2.require(new_journal >= old_journal and (new_journal != old_journal or current["record_hash"] == projection.record_hash), "AuthorityDowngrade", 409)
        revision, old_revision = e2e2.counter(authority["revision"]), e2e2.counter(projection.authority_revision)
        e2e2.require(revision >= old_revision and (revision != old_revision or state["authority_digest"] == projection.authority_digest), "AuthorityFork", 409)
        e2e2.require(e2e2.counter(authority["witness_epoch"]) >= e2e2.counter(projection.witness_epoch), "AuthorityDowngrade", 409)
    row = await session.get(E2E2Envelope, snapshot_meta["envelope_hash"])
    if row is None or row.view_id != view.id:
        reject("CanonicalSnapshotUnavailable", 409)
    keys = {key["key_id"]: key["public_key"] for key in authority["publisher_keys"]}
    header, _, actual = e2e2.validate_envelope(row.canonical_envelope.encode(), scope(view), keys, authority["read_key_epoch"], authority["publisher_policy_epoch"])
    e2e2.require(actual == snapshot_meta["envelope_hash"] and header["sequence"] == snapshot_meta["sequence"], "CanonicalSnapshotUnavailable", 409)
    candidates = list(await session.scalars(select(E2E2StagedReaderWrap).where(E2E2StagedReaderWrap.view_id == view.id, E2E2StagedReaderWrap.read_key_epoch == authority["read_key_epoch"], E2E2StagedReaderWrap.publisher_policy_epoch == authority["publisher_policy_epoch"]).limit(257)))
    e2e2.require(len(candidates) <= 256, "TooManyReaderCandidates", 409)
    for candidate in candidates:
        await _require_reach(session, user, [candidate.machine_id])
        machine = await session.scalar(select(MachineIdentity).where(MachineIdentity.id == candidate.machine_id).with_for_update(key_share=True).execution_options(populate_existing=True))
        if machine is None:
            reject("SourceNotFound", 404)
        await whole_machine(session, machine, view)
        creator = await session.scalar(select(User).where(User.username == candidate.created_by))
        if not machines.may_vouch(creator) or not await access.covers_whole(session, creator, access.READ, view.project_id, view.environment_id, []):
            reject("AccessDenied", 403)
        fingerprint = e2e2.node_fingerprint(machine.public_key)
        e2e2.require(fingerprint == candidate.recipient_fingerprint, "AwaitingProjectKey", 409)
        wrapper = e2e2.validate_wrapper(candidate.canonical_wrapper.encode(), scope(view), fingerprint, keys, authority["read_key_epoch"], authority["publisher_policy_epoch"])
        identity = (view.id, machine.id, authority["read_key_epoch"], authority["publisher_policy_epoch"])
        grant = await session.get(E2E2EpochReaderGrant, identity)
        if grant is None:
            grant = E2E2EpochReaderGrant(view_id=view.id, machine_id=machine.id, read_key_epoch=identity[2], publisher_policy_epoch=identity[3])
            session.add(grant)
        grant.recipient_fingerprint, grant.canonical_wrapper, grant.created_by = fingerprint, wrapper.decode(), candidate.created_by
        await session.delete(candidate)
    if projection is None:
        projection = E2E2AuthorityProjection(view_id=view.id)
        session.add(projection)
    projection.genesis_hash, projection.journal_sequence, projection.record_hash = state["genesis_hash"], current["journal_sequence"], current["record_hash"]
    projection.witness_epoch, projection.authority_revision, projection.authority_digest = authority["witness_epoch"], authority["revision"], state["authority_digest"]
    view.publisher_keys = e2e2.canonical(keys).decode()
    view.read_key_epoch, view.publisher_policy_epoch = authority["read_key_epoch"], authority["publisher_policy_epoch"]
    view.indexed_sequence, view.indexed_hash = snapshot_meta["sequence"], snapshot_meta["envelope_hash"]
    await audit.record(session, actor=user.username, action="secret_written", target=view.id, detail="e2e2 fresh independently pinned witness authority projected", ip=peer_ip(request))
    await session.commit()
    return {"view_id": view.id, "sequence": view.indexed_sequence, "envelope_hash": view.indexed_hash, "journal_sequence": projection.journal_sequence, "state": "projected", "readers_promoted": len(candidates)}


@router.get("/witness/views/{view_id}/envelopes/{envelope_hash}")
async def witness_snapshot(view_id: str, envelope_hash: str, session: SessionDep, _witness: WitnessService):
    view = await get_view(session, view_id)
    _, encoded = await snapshot(session, view, envelope_hash)
    return raw_response(encoded)


@machine_router.get("/capabilities")
async def capabilities(_machine: CurrentMachine, session: SessionDep):
    views = list(await session.scalars(select(E2E2View).limit(64)))
    supported = bool(views) and (e2e2.configured() or any(e2e2_rotation.configured(scope(view)) for view in views))
    return {"protocols": ["plain", "e2e1"] + (["e2e2"] if supported else []), "e2e2_profile": "WholeView-WitnessCurrent-v1" if supported else ""}


@machine_router.get("/e2e2/views/{view_id}/envelopes/{envelope_hash}")
async def machine_snapshot(view_id: str, envelope_hash: str, machine: CurrentMachine, session: SessionDep, _box: UnsealedBox):
    view = await get_view(session, view_id)
    await reader_grant(session, machine, view)
    _, encoded = await snapshot(session, view, envelope_hash)
    return raw_response(encoded)


@machine_router.get("/e2e2/views/{view_id}/reader-wrap")
async def machine_wrapper(view_id: str, envelope_hash: str, machine: CurrentMachine, session: SessionDep, _box: UnsealedBox):
    view = await get_view(session, view_id)
    grant = await reader_grant(session, machine, view)
    await snapshot(session, view, envelope_hash)
    wrapper = e2e2.validate_wrapper(grant.canonical_wrapper.encode(), scope(view), grant.recipient_fingerprint, json.loads(view.publisher_keys), view.read_key_epoch, view.publisher_policy_epoch)
    return raw_response(wrapper)
