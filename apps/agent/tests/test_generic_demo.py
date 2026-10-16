from anysoar.drivers.mock import MockDriver
from anysoar.interface import Capability
from anysoar.mcp import ElicitationApprover, create_server
from anysoar.policy import Decision, GuardedDriver, Policy
from anysoar_agent.cli import run_triage
from anysoar_agent.model import AssistantTurn
from anysoar_agent.triage import generic_demo_model


async def approve_all(question: str) -> tuple[bool, str]:
    return True, "ok"


def tool_calls(transcript: object) -> list[str]:
    return [
        call.name
        for entry in transcript  # type: ignore[attr-defined]
        if isinstance(entry, AssistantTurn)
        for call in entry.tool_calls
    ]


async def test_enriches_indicators_before_noting() -> None:
    mock = MockDriver()
    server = await create_server(GuardedDriver(mock, approver=ElicitationApprover()))
    result = await run_triage("case-0001", generic_demo_model("case-0001"), server, approve_all)

    assert result.stop == "end"
    calls = tool_calls(result.transcript)
    assert calls[:2] == ["describe_soar", "get_case"]
    assert 1 <= calls.count("enrich_indicator") <= 3
    assert calls[-1] == "add_note"
    note = (await mock.get_case("case-0001")).notes[-1].comment
    assert note.startswith("Triage (anysoar demo agent): reviewed 'Credential phishing")
    # URLs and IPs first, then the sender, whom the mock knows as a phishing source.
    reputations = note.split("Indicator reputations: ")[1]
    assert reputations.startswith("https://login.example.net/owa/verify")
    assert "it-support@example.net malicious (1 report)" in reputations


async def test_looks_up_senders_but_not_recipients() -> None:
    mock = MockDriver()
    server = await create_server(GuardedDriver(mock, approver=ElicitationApprover()))
    result = await run_triage("case-0002", generic_demo_model("case-0002"), server, approve_all)
    looked_up = [
        call.arguments["value"]
        for entry in result.transcript
        if isinstance(entry, AssistantTurn)
        for call in entry.tool_calls
        if call.name == "enrich_indicator"
    ]
    assert "billing@example.org" in looked_up  # email.from
    assert "accounts@example.com" not in looked_up  # email.to


async def test_skips_enrichment_the_policy_denies() -> None:
    mock = MockDriver()
    policy = Policy(capabilities={Capability.ENRICH_INDICATOR: Decision.DENY})
    server = await create_server(GuardedDriver(mock, policy=policy, approver=ElicitationApprover()))
    result = await run_triage("case-0002", generic_demo_model("case-0002"), server, approve_all)

    assert result.stop == "end"
    assert tool_calls(result.transcript) == ["describe_soar", "get_case", "add_note"]
    note = (await mock.get_case("case-0002")).notes[-1].comment
    assert "reputations" not in note


async def test_unreadable_case_ends_without_writing() -> None:
    server = await create_server(GuardedDriver(MockDriver(), approver=ElicitationApprover()))
    result = await run_triage("case-9999", generic_demo_model("case-9999"), server, approve_all)
    assert result.stop == "end"
    assert result.text == "Could not read case-9999."
    assert "add_note" not in tool_calls(result.transcript)
