"""Automated tests for the interactive Quick-Start & onboarding wizard (setup.sh)."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPT = PROJECT_ROOT / "setup.sh"


def _base_env(**overrides: str) -> dict[str, str]:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["PFSENSEMON_SKIP_DOCKER_CHECK"] = "1"
    env["PFSENSEMON_ENV_ONLY"] = "1"
    env.update(overrides)
    return env


def test_setup_sh_syntax_and_macos_bash32_compatibility() -> None:
    """Verify setup.sh is executable, passes bash -n, and avoids Bash 4+ only constructs."""
    assert SETUP_SCRIPT.exists(), "setup.sh must exist in project root"
    assert os.access(SETUP_SCRIPT, os.X_OK), "setup.sh must have executable permissions (+x)"

    res = subprocess.run(
        ["/bin/bash", "-n", str(SETUP_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"bash -n failed: {res.stderr}"

    content = SETUP_SCRIPT.read_text(encoding="utf-8")
    # Ensure no Bash 4+ associative arrays or case-modification expansions that break macOS /bin/bash 3.2
    assert "declare -A" not in content
    assert "readarray" not in content
    assert "mapfile" not in content
    assert not re.search(r"\$\{[a-zA-Z0-9_]+\^\^\}", content), "Avoid ${var^^} for macOS Bash 3.2 compatibility"


def test_setup_sh_help_and_version() -> None:
    """Verify --help and --version flags return 0 and expected output."""
    help_res = subprocess.run(
        ["/bin/bash", str(SETUP_SCRIPT), "--help"],
        capture_output=True,
        text=True,
        env=_base_env(),
        check=False,
    )
    assert help_res.returncode == 0
    assert "--check" in help_res.stdout
    assert "--test-only" in help_res.stdout
    assert "--non-interactive" in help_res.stdout

    ver_res = subprocess.run(
        ["/bin/bash", str(SETUP_SCRIPT), "--version"],
        capture_output=True,
        text=True,
        env=_base_env(),
        check=False,
    )
    assert ver_res.returncode == 0
    assert "setup.sh version" in ver_res.stdout


def test_setup_sh_non_interactive_generates_0600_env_and_backup(tmp_path: Path) -> None:
    """Verify --non-interactive writes .env with 0600 permissions and creates .env.bak on re-run."""
    env_file = tmp_path / ".env"

    res1 = subprocess.run(
        ["/bin/bash", str(SETUP_SCRIPT), "--non-interactive", "--env-file", str(env_file)],
        capture_output=True,
        text=True,
        env=_base_env(
            LLM_PROVIDER="openai",
            LLM_BASE_URL="http://host.docker.internal:1234/v1",
            LLM_MODEL="google/gemma-4-12b",
            TELEGRAM_BOT_TOKEN="123456789:AAF_dummy_test_token_value",
            TELEGRAM_CHAT_ID="123456789",
        ),
        check=False,
    )
    assert res1.returncode == 0, f"setup.sh failed: {res1.stderr}\n{res1.stdout}"
    assert env_file.exists()

    mode = stat.S_IMODE(env_file.stat().st_mode)
    assert mode == 0o600, f"Expected 0600 permissions on .env, got {oct(mode)}"

    text1 = env_file.read_text(encoding="utf-8")
    assert "LLM_PROVIDER=openai" in text1
    assert "LLM_MODEL=google/gemma-4-12b" in text1
    assert "TELEGRAM_CHAT_ID=123456789" in text1

    # Re-run with a different model and verify .env.bak is created with 0600 permissions
    res2 = subprocess.run(
        ["/bin/bash", str(SETUP_SCRIPT), "--non-interactive", "--env-file", str(env_file)],
        capture_output=True,
        text=True,
        env=_base_env(
            LLM_PROVIDER="ollama",
            LLM_MODEL="qwen2.5:14b",
        ),
        check=False,
    )
    assert res2.returncode == 0
    bak_file = tmp_path / ".env.bak"
    assert bak_file.exists(), "Expected .env.bak to be created when .env already exists"
    assert stat.S_IMODE(bak_file.stat().st_mode) == 0o600
    assert "LLM_MODEL=google/gemma-4-12b" in bak_file.read_text(encoding="utf-8")
    assert "LLM_MODEL=qwen2.5:14b" in env_file.read_text(encoding="utf-8")


def test_setup_sh_check_mode_validates_env(tmp_path: Path) -> None:
    """Verify --check succeeds on valid .env and fails on missing or invalid .env."""
    missing_env = tmp_path / "missing.env"
    res_missing = subprocess.run(
        ["/bin/bash", str(SETUP_SCRIPT), "--check", "--env-file", str(missing_env)],
        capture_output=True,
        text=True,
        env=_base_env(),
        check=False,
    )
    assert res_missing.returncode != 0

    valid_env = tmp_path / ".env"
    valid_env.write_text(
        "LLM_PROVIDER=ollama\n"
        "LLM_MODEL=qwen2.5:14b\n"
        "TELEGRAM_BOT_TOKEN=123456789:AAF_dummy_test_token_value\n"
        "TELEGRAM_CHAT_ID=123456789\n",
        encoding="utf-8",
    )
    res_valid = subprocess.run(
        ["/bin/bash", str(SETUP_SCRIPT), "--check", "--env-file", str(valid_env)],
        capture_output=True,
        text=True,
        env=_base_env(),
        check=False,
    )
    assert res_valid.returncode == 0, f"Expected --check to pass: {res_valid.stderr}"

    invalid_env = tmp_path / "invalid.env"
    invalid_env.write_text("LLM_PROVIDER=unsupported_vendor\n", encoding="utf-8")
    res_invalid = subprocess.run(
        ["/bin/bash", str(SETUP_SCRIPT), "--check", "--env-file", str(invalid_env)],
        capture_output=True,
        text=True,
        env=_base_env(),
        check=False,
    )
    assert res_invalid.returncode != 0


def test_setup_sh_interactive_lm_studio_model_autodiscovery(tmp_path: Path) -> None:
    """Verify interactive wizard probes localhost:/v1/models and writes host.docker.internal into .env."""

    class _MockModelsHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/v1/models":
                payload = {
                    "object": "list",
                    "data": [
                        {"id": "google/gemma-4-12b"},
                        {"id": "qwen/qwen3.5-9b"},
                    ],
                }
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = HTTPServer(("127.0.0.1", 0), _MockModelsHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        env_file = tmp_path / ".env"
        # Interactive answers:
        # 1 -> Choose LM Studio
        # <port> -> Custom LM Studio port on host
        # 2 -> Select 2nd discovered model (qwen/qwen3.5-9b)
        # English -> Report language
        # Y -> Enable GeoIP
        # 1234567890:AAF-replace-with-your-botfather-token -> Keep placeholder token (skips external network call)
        # 123456789 -> Telegram Chat ID
        # N -> Skip advanced settings
        user_inputs = "\n".join(
            [
                "1",
                str(port),
                "2",
                "English",
                "Y",
                "1234567890:AAF-replace-with-your-botfather-token",
                "123456789",
                "N",
                "",
            ]
        )

        res = subprocess.run(
            ["/bin/bash", str(SETUP_SCRIPT), "--env-file", str(env_file)],
            input=user_inputs,
            capture_output=True,
            text=True,
            env=_base_env(),
            check=False,
        )
        assert res.returncode == 0, f"Interactive wizard failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        assert env_file.exists()

        env_content = env_file.read_text(encoding="utf-8")
        assert "LLM_PROVIDER=openai" in env_content
        assert f"LLM_BASE_URL=http://host.docker.internal:{port}/v1" in env_content
        assert "LLM_MODEL=qwen/qwen3.5-9b" in env_content
        assert "LLM_TIMEOUT_SECONDS=240" in env_content
        assert "AI_REPORT_LANGUAGE=English" in env_content
        assert "ENABLE_GEOIP=true" in env_content
    finally:
        server.shutdown()
        server.server_close()
