from pathlib import Path


def _write_stealth_config(home: Path):
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(
        """
security:
  output_filter:
    enabled: true
    redact_paths: true
    redact_model_provider: true
    block_internal_disclosure: true
""".strip(),
        encoding="utf-8",
    )


def test_control_audience_preserves_operational_details(tmp_path, monkeypatch):
    home = tmp_path / "profiles" / "stealth"
    _write_stealth_config(home)
    monkeypatch.setenv("HERMES_HOME", str(home))

    from tools.stealth_io_policy import filter_output

    text = (
        "path=/home/nvidia/.hermes/profiles/stealth/config.yaml\n"
        "route=RedPill z-ai/glm-5.1\n"
        "policy=stealth_io_policy"
    )
    out, meta = filter_output(text, audience="control")

    assert meta["enabled"] is True
    assert meta["audience"] == "control"
    assert "/home/nvidia/.hermes/profiles/stealth/config.yaml" in out
    assert "RedPill" in out
    assert "z-ai/glm-5.1" in out
    assert "stealth_io_policy" in out
    assert "STEALTH_REDACTED" not in out


def test_control_audience_still_redacts_raw_secrets(tmp_path, monkeypatch):
    home = tmp_path / "profiles" / "stealth"
    _write_stealth_config(home)
    monkeypatch.setenv("HERMES_HOME", str(home))

    from tools.stealth_io_policy import filter_output

    secret = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890"
    out, meta = filter_output(secret, audience="control")

    assert meta["audience"] == "control"
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in out
    assert "OPENAI_API_KEY=" in out


def test_external_audience_redacts_operational_details(tmp_path, monkeypatch):
    home = tmp_path / "profiles" / "stealth"
    _write_stealth_config(home)
    monkeypatch.setenv("HERMES_HOME", str(home))

    from tools.stealth_io_policy import filter_output

    text = (
        "path=/home/nvidia/.hermes/profiles/stealth/config.yaml\n"
        "route=RedPill z-ai/glm-5.1\n"
        "policy=stealth_io_policy"
    )
    out, meta = filter_output(text, audience="external")

    assert meta["enabled"] is True
    assert meta["audience"] == "external"
    assert "[STEALTH_REDACTED_PATH]" in out
    assert "[STEALTH_REDACTED_ROUTE]" in out
    assert "/home/nvidia/.hermes/profiles/stealth/config.yaml" not in out
    assert "RedPill" not in out
    assert "z-ai/glm-5.1" not in out
