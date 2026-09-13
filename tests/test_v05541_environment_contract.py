from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts import env_validate

ROOT = Path(__file__).resolve().parents[1]


def _example_values() -> dict[str, str]:
    return dict(env_validate.parse_env_file(ROOT / ".env.example").values)


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n", encoding="utf-8")


class EnvironmentContractTests(unittest.TestCase):
    def test_repository_contract_is_complete_and_static_validation_passes(self):
        errors, warnings, report = env_validate.validate_contract(ROOT / ".env.example", None)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(report["schema"], "zen_environment_contract_v1")
        self.assertEqual(report["example_variables"], report["compose_variables"])
        self.assertFalse(report["local_env_checked"])

    def test_example_and_compose_have_exact_same_user_variable_names(self):
        example = set(env_validate.parse_env_file(ROOT / ".env.example").values)
        compose = set(env_validate.compose_refs())
        self.assertEqual(example, compose)
        self.assertGreaterEqual(len(example), 60)

    def test_all_source_environment_references_are_contract_or_explicit_internal(self):
        example = set(env_validate.parse_env_file(ROOT / ".env.example").values)
        refs = env_validate.source_env_refs()
        unknown = refs - example - env_validate.INTERNAL_ENV_VARS - set(env_validate.DEPRECATED_ENV_VARS)
        self.assertEqual(unknown, set())
        self.assertEqual(env_validate.INTERNAL_ENV_VARS - refs, set())

    def test_source_scanner_finds_wrapped_and_direct_environment_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(
                "import os\n"
                "A = os.getenv('ZEN_SAMPLE_ONE')\n"
                "B = _env_bool('ZEN_SAMPLE_TWO', False)\n"
                "C = os.environ['ZEN_SAMPLE_THREE']\n"
                "D = source.get('ZEN_SAMPLE_FOUR')\n",
                encoding="utf-8",
            )
            self.assertEqual(
                env_validate.source_env_refs([sample]),
                {"ZEN_SAMPLE_ONE", "ZEN_SAMPLE_TWO", "ZEN_SAMPLE_THREE", "ZEN_SAMPLE_FOUR"},
            )

    def test_duplicate_environment_names_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("A=1\nA=2\n", encoding="utf-8")
            parsed = env_validate.parse_env_file(path)
            self.assertEqual(parsed.duplicates, ("A",))

    def test_local_environment_matches_contract_without_printing_values(self):
        values = _example_values()
        # Required values are intentionally dummy local values for contract testing.
        for name, ref in env_validate.compose_refs().items():
            if ref.required and not values.get(name):
                values[name] = f"configured-{name.lower()}"
        values["SESSION_SECRET"] = "SUPER-SECRET-DO-NOT-PRINT"
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / ".env"
            _write_env(local, values)
            errors, warnings, report = env_validate.validate_contract(ROOT / ".env.example", local)
            self.assertEqual(errors, [])
            self.assertEqual(warnings, [])
            self.assertTrue(report["local_env_checked"])
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                rc = env_validate.main(["--env-file", str(local), "--quiet"])
            self.assertEqual(rc, 0)
            self.assertNotIn("SUPER-SECRET-DO-NOT-PRINT", stream.getvalue())

    def test_undocumented_local_variable_fails_by_name_only(self):
        values = _example_values()
        for name, ref in env_validate.compose_refs().items():
            if ref.required and not values.get(name):
                values[name] = "configured"
        values["ZEN_UNDOCUMENTED_TEST"] = "TOPSECRETVALUE"
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / ".env"
            _write_env(local, values)
            errors, _, _ = env_validate.validate_contract(ROOT / ".env.example", local)
            joined = "\n".join(errors)
            self.assertIn("ZEN_UNDOCUMENTED_TEST", joined)
            self.assertNotIn("TOPSECRETVALUE", joined)

    def test_smtp_enabled_requires_host_from_and_to(self):
        values = _example_values()
        for name, ref in env_validate.compose_refs().items():
            if ref.required and not values.get(name):
                values[name] = "configured"
        values["ZEN_SMTP_ENABLED"] = "1"
        values["ZEN_SMTP_HOST"] = ""
        values["ZEN_SMTP_FROM"] = ""
        values["ZEN_SMTP_TO"] = ""
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / ".env"
            _write_env(local, values)
            errors, _, _ = env_validate.validate_contract(ROOT / ".env.example", local)
            text = "\n".join(errors)
            self.assertIn("ZEN_SMTP_HOST", text)
            self.assertIn("ZEN_SMTP_FROM", text)
            self.assertIn("ZEN_SMTP_TO", text)

    def test_smtp_ssl_and_starttls_are_mutually_exclusive(self):
        values = _example_values()
        for name, ref in env_validate.compose_refs().items():
            if ref.required and not values.get(name):
                values[name] = "configured"
        values.update(
            {
                "ZEN_SMTP_ENABLED": "1",
                "ZEN_SMTP_HOST": "smtp.example.test",
                "ZEN_SMTP_FROM": "zen@example.test",
                "ZEN_SMTP_TO": "parent@example.test",
                "ZEN_SMTP_SSL": "1",
                "ZEN_SMTP_STARTTLS": "1",
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / ".env"
            _write_env(local, values)
            errors, _, _ = env_validate.validate_contract(ROOT / ".env.example", local)
            self.assertTrue(any("may not both be enabled" in item for item in errors))

    def test_http_webhook_simulation_requires_signing_secret(self):
        values = _example_values()
        for name, ref in env_validate.compose_refs().items():
            if ref.required and not values.get(name):
                values[name] = "configured"
        values["ZEN_WEBHOOK_ALLOW_HTTP"] = "1"
        values["ZEN_WEBHOOK_SIGNING_SECRET"] = ""
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / ".env"
            _write_env(local, values)
            errors, _, _ = env_validate.validate_contract(ROOT / ".env.example", local)
            self.assertTrue(any("ZEN_WEBHOOK_SIGNING_SECRET" in item for item in errors))

    def test_remote_access_requires_security_posture(self):
        values = _example_values()
        for name, ref in env_validate.compose_refs().items():
            if ref.required and not values.get(name):
                values[name] = "configured"
        values.update(
            {
                "ZEN_REMOTE_ACCESS_ENABLED": "1",
                "ZEN_PUBLIC_HOST": "",
                "ZEN_ALLOWED_HOSTS": "",
                "CLOUDFLARE_TUNNEL_TOKEN_FILE": "",
                "ZEN_SECURE_COOKIES": "0",
                "ZEN_CLOUDFLARE_ACCESS_PROTECTED": "0",
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / ".env"
            _write_env(local, values)
            errors, _, _ = env_validate.validate_contract(ROOT / ".env.example", local)
            text = "\n".join(errors)
            self.assertIn("ZEN_PUBLIC_HOST", text)
            self.assertIn("ZEN_SECURE_COOKIES=1", text)
            self.assertIn("ZEN_CLOUDFLARE_ACCESS_PROTECTED=1", text)

    def test_secret_examples_are_placeholders_or_blank(self):
        example = env_validate.parse_env_file(ROOT / ".env.example")
        unsafe = [
            name
            for name in env_validate.SECRET_VARS
            if name in example.values and not env_validate._secret_example_safe(example.values[name])
        ]
        self.assertEqual(unsafe, [])


if __name__ == "__main__":
    unittest.main()
