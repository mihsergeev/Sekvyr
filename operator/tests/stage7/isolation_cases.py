"""Live source and namespace authorization checks; no packet-isolation claim."""

from app_modes import OwnedNamespace, require
from fixture import canonical, write_private


def run(cases, e2e):
    c, p = cases.c, cases.installation
    require(e2e.c is c and e2e.installed and p.namespace != c.app.namespace, "Two explicit namespace installations required")
    proof_path = c.private / "stage7-isolation-complete.json"
    require(not proof_path.exists(), "Isolation checks cannot silently replay an existing proof")
    # The real file token belongs to the unchanged legacy-agent Pod. Backend
    # mapping is namespace/SA names with offline JWT expiry, not pinned SA UID.
    agent_session = cases.agent_provider.exchange(cases.token()["token"])
    cases.agent_provider.read(agent_session, {"GENERATION": cases.agent_selected["generation"], "DEMO_VALUE": cases.agent_selected["demo"]})
    main = cases.provider.routing()
    require(cases.agent_provider.assert_denied_source(agent_session, main["project"], main["environment"]).get("http") == 403,
        "Cross-project denial was not observed")
    own = cases.agent_provider.routing()
    require(cases.agent_provider.assert_denied_source(agent_session, own["project"], "denied").get("http") == 403,
        "Denied-environment authorization was not observed")
    apps = OwnedNamespace(c.cluster, c.app.namespace)
    apps.reload_pins()
    require(("ServiceAccount", p.sa) not in apps.pins, "Wrong-namespace test account has prior creation history")
    apps.create_service_account(p.sa)  # Same SA name, other owned namespace, no RoleBinding.
    wrong_namespace = c.cluster.kube("create", "token", p.sa, "-n", c.app.namespace, "--audience=sekvyr", "--duration=10m").stdout.strip()
    code, _ = c.panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": wrong_namespace}, expected=(401,))
    require(code == 401, "Panel accepted same account name from the wrong namespace")
    wrong_audience = c.cluster.kube("create", "token", p.sa, "-n", p.namespace, "--audience=stage7-invalid-audience", "--duration=10m").stdout.strip()
    code, _ = c.panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": wrong_audience}, expected=(401,))
    require(code == 401, "Panel accepted the wrong projected-token audience")
    rbac = c.app.rbac_cases()
    probes = [(p.namespace, p.sa, p.namespace, "secret/" + p.state_name, True),
        (p.namespace, p.sa, c.app.namespace, "secret/" + c.app.state_name, False),
        (c.app.namespace, "sekvyr-operator", p.namespace, "secret/" + p.state_name, False),
        (p.namespace, p.sa, p.namespace, "sekvyrstores.secrets.sekvyr.ru", False)]
    for actor_ns, sa, namespace, resource, expected in probes:
        verb = "patch" if resource.startswith("sekvyrstores.") else "get"
        actor = "system:serviceaccount:" + actor_ns + ":" + sa
        response = c.cluster.kube("auth", "can-i", verb, resource, "-n", namespace, "--as", actor, check=False)
        require(response.returncode in (0, 1) and response.stdout.strip() in ("yes", "no")
            and (response.stdout.strip() == "yes") == expected, "Namespace authorization exceeded the exact expected permission")
    result = {"production": False, "allowedSourceAuthenticatedWithActualPodFileJWT": True,
        "crossProjectAndDeniedEnvironmentHTTP": 403, "sameAccountNameOtherNamespaceHTTP": 401, "wrongAudienceHTTP": 401,
        "liveRBACTestedOperations": rbac["operatorRBACTestedOperations"] + len(probes),
        "crossNamespaceBootstrapSecretReadsDenied": True, "operatorStoreSpecPatchDenied": True,
        "panelMachineAuthorizationUIDBound": False, "packetIsolationClaimed": False}
    write_private(proof_path, canonical(result))
    return result
