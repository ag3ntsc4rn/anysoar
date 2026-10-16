import json
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters
from mcp.client import ClientRequestContext
from mcp.types import ElicitRequestParams, ElicitResult

from anysoar.interface import ActionTier, Capability
from anysoar.mcp.cli import load_policy, main, state_dir
from anysoar.policy import Decision


def write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


class TestPolicyFile:
    def test_partial_tiers_keep_defaults(self, tmp_path: Path) -> None:
        policy = load_policy(
            write(
                tmp_path / "policy.toml",
                """
                [tiers]
                read = "require_approval"

                [capabilities]
                add_note = "allow"

                [playbooks]
                pb-notify-reporter = "allow"
                """.replace("                ", ""),
            )
        )
        assert policy.tiers[ActionTier.READ] is Decision.REQUIRE_APPROVAL
        assert policy.tiers[ActionTier.DESTRUCTIVE] is Decision.DENY
        assert policy.capabilities == {Capability.ADD_NOTE: Decision.ALLOW}
        assert policy.playbooks == {"pb-notify-reporter": Decision.ALLOW}

    def test_unknown_section(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown policy sections: tier"):
            load_policy(write(tmp_path / "p.toml", '[tier]\nread = "allow"\n'))

    def test_invalid_policy_exits(self, tmp_path: Path) -> None:
        bad = write(tmp_path / "p.toml", '[capabilities]\nrun_playbook = "allow"\n')
        with pytest.raises(SystemExit, match=r"(?s)invalid policy .*per playbook"):
            main(["--policy", str(bad)])


def test_state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert state_dir() == tmp_path / "anysoar"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert state_dir() == Path.home() / ".local" / "state" / "anysoar"


async def approve(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult:
    return ElicitResult(action="accept", content={"approve": True, "reason": ""})


async def test_stdio_end_to_end(tmp_path: Path) -> None:
    audit, stop = tmp_path / "audit.jsonl", tmp_path / "STOP"
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "anysoar.mcp", "--audit-log", str(audit), "--kill-switch", str(stop)],
    )
    async with Client(server, elicitation_callback=approve) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"describe_soar", "close_case", "run_playbook"} <= names

        result = await client.call_tool("add_note", {"case_uid": "case-0002", "comment": "hi"})
        assert not result.is_error

        stop.write_text("demo stop\n")
        result = await client.call_tool("get_alert", {"alert_uid": "alert-0001"})
        assert result.is_error

    kinds = [json.loads(line)["kind"] for line in audit.read_text().splitlines()]
    assert kinds == ["requested", "approval", "completed", "requested", "denied"]


def test_shuffle_driver_needs_its_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHUFFLE_URL", raising=False)
    monkeypatch.delenv("SHUFFLE_API_KEY", raising=False)
    with pytest.raises(SystemExit, match=r"cannot start the shuffle driver: .*SHUFFLE_URL"):
        main(["--driver", "shuffle"])
