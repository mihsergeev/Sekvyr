import copy
import unittest

from cluster import verify_webhook_service_pin


class WebhookEndpointPins(unittest.TestCase):
    def setUp(self):
        self.service = {"namespace": "owned-apps", "name": "legacy-release-fencer", "port": 9443, "path": "/admit"}
        self.pins = [{"kind": "Service", "namespace": "owned-apps", "name": "legacy-release-fencer", "uid": "creator-service"}]
        self.current = {"kind": "Service", "metadata": {"namespace": "owned-apps", "name": "legacy-release-fencer", "uid": "creator-service"}}

    def test_existing_reviewed_service_name_is_not_a_hardcoded_release_alias(self):
        verify_webhook_service_pin(self.service, self.service, self.pins, self.current)

    def test_replacement_uid_is_rejected(self):
        self.current["metadata"]["uid"] = "replacement"
        with self.assertRaises(ValueError):
            verify_webhook_service_pin(self.service, self.service, self.pins, self.current)

    def test_missing_or_duplicate_creation_identity_is_rejected(self):
        for pins in ([], self.pins * 2):
            with self.assertRaises(ValueError):
                verify_webhook_service_pin(self.service, self.service, pins, self.current)

    def test_wrong_namespace_is_rejected(self):
        self.current["metadata"]["namespace"] = "foreign"
        with self.assertRaises(ValueError):
            verify_webhook_service_pin(self.service, self.service, self.pins, self.current)

    def test_deleting_service_is_rejected(self):
        self.current["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(ValueError):
            verify_webhook_service_pin(self.service, self.service, self.pins, self.current)

    def test_switch_to_another_owned_service_is_rejected(self):
        other = copy.deepcopy(self.service)
        other["name"] = "another-owned-service"
        current = copy.deepcopy(self.current)
        current["metadata"]["name"] = other["name"]
        pins = [dict(self.pins[0], name=other["name"])]
        with self.assertRaises(ValueError):
            verify_webhook_service_pin(self.service, other, pins, current)

    def test_service_path_or_port_cannot_change(self):
        for field, value in (("path", "/other"), ("port", 443)):
            other = dict(self.service, **{field: value})
            with self.assertRaises(ValueError):
                verify_webhook_service_pin(self.service, other, self.pins, self.current)


if __name__ == "__main__":
    unittest.main()
