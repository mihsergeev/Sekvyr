"""Bounded custom-slots mTLS client; deliberately not an S3 proxy or signer."""

import re
import ssl
import base64
import os
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class JournalClient:
    def __init__(self, origin, ca_file, certificate=None, private_key=None):
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("Fixed HTTPS journal origin required")
        self.origin = origin.rstrip("/")
        context = ssl.create_default_context(cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if certificate or private_key:
            if not certificate or not private_key:
                raise ValueError("Complete mTLS identity required")
            context.load_cert_chain(str(certificate), str(private_key))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def __repr__(self):
        return "<trial journal mTLS client [redacted]>"

    def request(self, method, path, raw=None, headers=None, expected=(200,), maximum=16 << 20):
        # Test-only paths still cannot redirect credentials to another authority.
        if not path.startswith("/") or path.startswith("//") or "#" in path or "\r" in path or "\n" in path:
            raise ValueError("Invalid same-origin path")
        request = urllib.request.Request(self.origin + path, data=raw, method=method, headers=headers or {})
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, ssl.SSLError, OSError):
            raise RuntimeError("Journal TLS or transport rejected request") from None
        with response:
            body = response.read(maximum + 1)
            if len(body) > maximum:
                raise RuntimeError("Journal response bounds exceeded")
            if response.status not in expected:
                raise RuntimeError("Unexpected journal HTTP status " + str(response.status))
            # Never print the headers or body; signed proof bytes and private
            # fixture details are consumed by the caller and safe assertions.
            return response.status, body, dict(response.headers)

    @staticmethod
    def path(log_id, sequence=None):
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", log_id):
            raise ValueError("Invalid fixed trial log ID")
        prefix = "/v1/storage/logs/" + log_id
        if sequence is None:
            return prefix + "/journal"
        if not re.fullmatch(r"0|[1-9][0-9]{0,19}", sequence) or int(sequence) > 18446744073709551615:
            raise ValueError("Invalid canonical slot counter")
        return prefix + "/slots/" + sequence

    def journal(self, log_id):
        nonce = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        return nonce, self.request("GET", self.path(log_id),
            headers={"X-Sekvyr-Journal-Nonce": nonce}, maximum=64 << 20)

    def append(self, log_id, sequence, raw, expected=(201, 200)):
        return self.request("PUT", self.path(log_id, sequence), raw,
            {"Content-Type": "application/json", "If-None-Match": "*"}, expected)


def rejected_runtime_routes(client, log_id):
    """Call this only against the approved disposable registered test log.

    These checks deliberately omit authorization to create a record. Successful
    gateway handling would be a failure, never silently accepted as conformance.
    """
    path = JournalClient.path(log_id, "0")
    for method, suffix, headers in (
        ("DELETE", "", {}),
        ("PUT", "", {"Content-Type": "application/json"}),
        ("PUT", "", {"X-Amz-Copy-Source": "/unregistered/object", "If-None-Match": "*"}),
        ("POST", "?uploads", {}),
        ("DELETE", "?versionId=unregistered", {}),
    ):
        client.request(method, path + suffix, b"{}" if method != "DELETE" else None, headers,
            expected=(400, 403, 404, 405, 409, 412), maximum=16 << 10)
    return {"unsafeRuntimeOperationsRejected": 5}
