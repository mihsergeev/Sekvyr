"""Сборка и подпись агента.

Агент обновляет себя сам, и это ровно тот случай, когда "скачал и запустил"
означает выполнение чужого кода от root на всех нодах сразу. Поэтому новую
версию подписывают ключом, которого на панели нет: панель раздает бинарь и
описание, а решает, ставить ли его, сама нода - по подписи.

Ключ живет у того, кто выпускает версии (в менеджере паролей, не в
репозитории). Публичная половина лежит в `agent/pubkey.txt`, попадает в бинарь
при сборке и приезжает на ноды вместе с ним.

    python ops/agent_release.py --keygen        # один раз: создать пару ключей
    SEKVYR_AGENT_KEY=... python ops/agent_release.py --sign

Сборка идет в том же образе golang, что и в Dockerfile, с теми же флагами:
`-trimpath` и фиксированная версия дают одинаковый бинарь при одинаковом
исходнике, поэтому хеш из описания сходится с тем, что окажется в образе.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

def _russian() -> bool:
    """Язык вывода: SEKVYR_LANG (ru или en), иначе русская локаль, иначе
    английский."""
    choice = os.environ.get("SEKVYR_LANG", "").strip().lower()
    if choice in ("ru", "en"):
        return choice == "ru"
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(name, "")
        if value:
            return value.lower().startswith("ru")
    return False


RU = _russian()


def t(ru: str, en: str) -> str:
    return ru if RU else en


DESCRIPTION_EN = """Build and sign the Sekvyr agent.

The agent updates itself, so a new release is signed with a key the panel does
not have: the panel serves the binary and its description, and the node decides
by the signature whether to install it. The private key stays with whoever
releases versions; the public half lives in agent/pubkey.txt and is built into
the binary.

    python ops/agent_release.py --keygen        # once: create a key pair
    SEKVYR_AGENT_KEY=... python ops/agent_release.py --sign

The build runs in the same golang image as the Dockerfile, with the same
flags, so the hash in the description matches what ends up in the image.
"""

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent"
MANIFEST = AGENT / "manifest.json"
PUBKEY = AGENT / "pubkey.txt"
GO_IMAGE = "golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c"
ARCHES = ("amd64", "arm64")


def version() -> str:
    """Версия агента. Своя, а не панели: правка интерфейса не меняет бинарь, и
    подписывать его заново из-за этого незачем."""
    return (AGENT / "VERSION").read_text(encoding="utf-8").strip()


def signed_text(ver: str, digests: dict[str, str]) -> bytes:
    """Что именно подписывается.

    Версия и хеши, ничего больше: подпись должна ломаться от подмены бинаря и
    от подсовывания старой версии под видом новой.
    """
    lines = ["sekvyr-agent", f"version {ver}"]
    lines += [f"{arch} {digests[arch]}" for arch in sorted(digests)]
    return ("\n".join(lines) + "\n").encode()


def keygen() -> int:
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    PUBKEY.write_text(base64.b64encode(raw_public).decode() + "\n", encoding="utf-8", newline="\n")
    print(t("публичный ключ записан в", "public key written to"), PUBKEY.relative_to(ROOT))
    print()
    print(
        t(
            "ЗАКРЫТЫЙ КЛЮЧ: сохраните его в менеджере паролей и больше нигде не держите:",
            "PRIVATE KEY: keep it in a password manager and nowhere else:",
        )
    )
    print(base64.b64encode(raw_private).decode())
    print()
    print(t("Дальше: SEKVYR_AGENT_KEY=<ключ> python ops/agent_release.py --sign",
            "Next: SEKVYR_AGENT_KEY=<key> python ops/agent_release.py --sign"))
    return 0


def build(ver: str) -> dict[str, dict[str, object]]:
    out = AGENT / "build"
    out.mkdir(exist_ok=True)
    script = " && ".join(
        f"CGO_ENABLED=0 GOOS=linux GOARCH={arch} go build -trimpath "
        f'-ldflags "-s -w -buildid= -X main.Version={ver} -X main.PublicKey=$PUBKEY" '
        f"-o /out/sekvyr-linux-{arch} ."
        for arch in ARCHES
    )
    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{AGENT}:/src",
            "-v", f"{out}:/out",
            "-e", f"PUBKEY={PUBKEY.read_text(encoding='utf-8').strip()}",
            "-w", "/src",
            GO_IMAGE,
            "sh", "-c", script,
        ],
        check=True,
    )
    files: dict[str, dict[str, object]] = {}
    for arch in ARCHES:
        blob = (out / f"sekvyr-linux-{arch}").read_bytes()
        files[arch] = {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
    return files


def digests_from(args: list[str]) -> dict[str, dict[str, object]]:
    """Хеши, посчитанные где-то еще: `--digest amd64=abc... --digest arm64=...`.

    Сборка и подпись - разные машины: собирать можно где угодно, а закрытый ключ
    должен оставаться там, где его держат. Хеши для этого и нужны - их можно
    передать по любому каналу, они не тайна. Размер можно дописать через
    двоеточие (`amd64=abc...:7340032`); без него поля size в описании не будет
    вовсе, а не будет стоять ноль, как будто бинарь пустой.
    """
    out: dict[str, dict[str, object]] = {}
    for item in args:
        arch, _, rest = item.partition("=")
        digest, _, size = rest.partition(":")
        # Get-FileHash в PowerShell печатает хеш заглавными, а агент сверяет
        # строчные: такой хеш подписывался, и обновление отклонялось на всех
        # нодах. Приводим к одному виду и не пропускаем не-hex.
        digest = digest.strip().lower()
        size = size.strip()
        if (
            arch not in ARCHES
            or len(digest) != 64
            or set(digest) - set("0123456789abcdef")
            or (size and not size.isdigit())
        ):
            raise SystemExit(t(f"не разобрал --digest {item}", f"cannot parse --digest {item}"))
        out[arch] = {"sha256": digest}
        if size:
            out[arch]["size"] = int(size)
    return out


def sign(given: dict[str, dict[str, object]] | None = None) -> int:
    raw = os.environ.get("SEKVYR_AGENT_KEY", "").strip()
    if not raw:
        raise SystemExit(
            t(
                "нет SEKVYR_AGENT_KEY — закрытый ключ берётся из окружения",
                "no SEKVYR_AGENT_KEY: the private key is taken from the environment",
            )
        )
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
    public = base64.b64encode(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()
    if PUBKEY.exists() and PUBKEY.read_text(encoding="utf-8").strip() != public:
        raise SystemExit(
            t(
                "ключ не тот: публичная половина не совпадает с agent/pubkey.txt",
                "wrong key: its public half does not match agent/pubkey.txt",
            )
        )
    PUBKEY.write_text(public + "\n", encoding="utf-8", newline="\n")

    ver = version()
    files = given or build(ver)
    digests = {arch: str(files[arch]["sha256"]) for arch in files}
    signature = base64.b64encode(private.sign(signed_text(ver, digests))).decode()
    MANIFEST.write_text(
        json.dumps(
            {
                "version": ver,
                "files": files,
                "signature": signature,
                "signed_at": datetime.now(timezone.utc).isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(t(f"подписана версия {ver}", f"signed version {ver}"))
    for arch, meta in files.items():
        print(f"  {arch}: {meta['sha256']}")
    print(t("описание:", "description:"), MANIFEST.relative_to(ROOT))
    return 0


def verify() -> int:
    """Сходится ли подпись с публичным ключом. Этим же занимается самопроверка."""
    if not MANIFEST.exists():
        raise SystemExit(
            t("нет agent/manifest.json — выпустите версию: --sign", "no agent/manifest.json: release a version with --sign")
        )
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    public = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(PUBKEY.read_text(encoding="utf-8").strip())
    )
    digests = {arch: meta["sha256"] for arch, meta in data["files"].items()}
    public.verify(base64.b64decode(data["signature"]), signed_text(data["version"], digests))
    print(t(f"подпись версии {data['version']} сходится", f"the signature of version {data['version']} checks out"))
    return 0


def compare(directory: str) -> int:
    """Совпадает ли собранный агент с подписанными хешами.

    Панель отдает бинарь, только если его хеш сошелся с manifest.json, а иначе
    отвечает 500. CI собирает агента так же, как образ панели, и сверяет здесь,
    чтобы такую сборку нельзя было выпустить.
    """
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data["version"] != version():
        print(
            t(
                f"manifest.json подписан для {data['version']}, а agent/VERSION - {version()}",
                f"manifest.json is signed for {data['version']}, but agent/VERSION is {version()}",
            )
        )
        return 1
    bad = 0
    for arch, meta in sorted(data["files"].items()):
        got = hashlib.sha256((Path(directory) / f"sekvyr-linux-{arch}").read_bytes()).hexdigest()
        same = got == meta["sha256"]
        bad += not same
        verdict = t("сходится", "matches") if same else t("НЕ сходится", "DOES NOT match")
        print(f"{arch}: {verdict} {got}")
    if bad:
        print(
            t(
                "Сборка агента не совпала с подписью: панель ответит 500 вместо агента.",
                "The agent build does not match the signature: the panel would answer 500 instead of the agent.",
            )
        )
        print(t("Соберите и подпишите заново: python ops/agent_release.py --sign",
                "Build and sign again: python ops/agent_release.py --sign"))
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__ if RU else DESCRIPTION_EN,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--keygen", action="store_true", help=t("создать пару ключей", "create a key pair"))
    parser.add_argument("--sign", action="store_true", help=t("собрать и подписать", "build and sign"))
    parser.add_argument("--verify", action="store_true", help=t("проверить подпись", "check the signature"))
    parser.add_argument(
        "--build", action="store_true", help=t("только собрать и показать хеши", "only build and show the hashes")
    )
    parser.add_argument(
        "--digest",
        action="append",
        default=[],
        metavar="arch=sha256[:size]",
        help=t("подписать чужую сборку по её хешам, без docker", "sign a build made elsewhere by its hashes, without docker"),
    )
    parser.add_argument(
        "--compare",
        metavar="DIR",
        help=t(
            "сверить собранные sekvyr-linux-* из каталога с manifest.json",
            "compare the sekvyr-linux-* builds in a directory with manifest.json",
        ),
    )
    args = parser.parse_args()
    if args.compare:
        return compare(args.compare)
    if args.keygen:
        return keygen()
    if args.build:
        ver = version()
        for arch, meta in build(ver).items():
            print(f"{arch}={meta['sha256']}")
        return 0
    if args.sign:
        return sign(digests_from(args.digest) if args.digest else None)
    if args.verify:
        return verify()
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
