import json

import pytest

from anysoar.drivers.thehive import TheHiveDriver
from anysoar.drivers.thehive.enrichment import data_types, reputation
from anysoar.interface import Capability
from anysoar.models import Observable, ObservableTypeId, ReputationScoreId

from .fake_thehive import API_KEY, BASE_URL, FakeTheHive

IP = ObservableTypeId.IP_ADDRESS


@pytest.fixture
def thehive() -> FakeTheHive:
    return FakeTheHive()


@pytest.fixture
def soar(thehive: FakeTheHive) -> TheHiveDriver:
    return TheHiveDriver(BASE_URL, API_KEY, poll_interval=0, transport=thehive.transport())


def ip(value: str) -> Observable:
    return Observable(type_id=IP, value=value, name="src_endpoint.ip")


class TestEnrichment:
    async def test_runs_every_analyzer_for_the_type(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        result = await soar.enrich_indicator(ip("198.51.100.23"))
        assert (result.observable.type_id, result.observable.value) == (IP, "198.51.100.23")
        assert result.observable.name == "src_endpoint.ip"
        by_analyzer = {e.provider: e for e in result.enrichments}
        assert set(by_analyzer) == {"DShield_lookup_1_0", "Abuse_Finder_3_0"}

        dshield = by_analyzer["DShield_lookup_1_0"]
        assert (dshield.name, dshield.value) == ("src_endpoint.ip", "198.51.100.23")
        assert dshield.type == "cortex-analyzer"
        assert dshield.data == {"ip": "198.51.100.23", "reputation": "malicious"}
        assert dshield.short_desc == "DShield Score: 0 (malicious)"
        assert dshield.created_time is not None

    async def test_failed_analyzer_says_why(self, soar: TheHiveDriver) -> None:
        result = await soar.enrich_indicator(ip("198.51.100.23"))
        (failed,) = [e for e in result.enrichments if e.provider == "Abuse_Finder_3_0"]
        assert failed.short_desc == (
            "failed: ipwhois.exceptions.IPDefinedError: IPv4 address 198.51.100.23 is already "
            "defined as TEST-NET-3 via RFC 5737."
        )
        assert isinstance(failed.data, dict)
        assert str(failed.data["error"]).startswith("Traceback")

    async def test_reputation_is_the_worst_taxonomy(self, soar: TheHiveDriver) -> None:
        result = await soar.enrich_indicator(ip("198.51.100.23"))
        rep = result.observable.reputation
        assert rep is not None
        assert (rep.score_id, rep.base_score, rep.provider) == (
            ReputationScoreId.MALICIOUS,
            100.0,
            "Cortex",
        )

    async def test_runs_on_the_newest_matching_observable(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        # The phishing alert's address is also on a newer alert.
        other = thehive.alert(
            "Same sender again",
            minutes=60,
            observables=(("ip", "198.51.100.23"),),
        )
        newest = thehive.observables[other][0]
        await soar.enrich_indicator(ip("198.51.100.23"))
        assert {j["artifactId"] for j in thehive.jobs.values()} == {newest["_id"]}
        assert "DShield_lookup_1_0" in newest["reports"]

    async def test_only_analyzers_for_the_type(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        mail = Observable(type_id=ObservableTypeId.EMAIL_ADDRESS, value="it-support@example.net")
        result = await soar.enrich_indicator(mail)
        assert [e.provider for e in result.enrichments] == ["Abuse_Finder_3_0"]
        assert result.observable.reputation is None  # it failed, so nothing to go on
        assert result.enrichments[0].name == "mail"  # the indicator has no name; its type

    async def test_unknown_indicator_has_no_enrichments(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        result = await soar.enrich_indicator(ip("192.0.2.1"))
        assert result.enrichments == []
        assert result.observable.reputation is None
        assert thehive.jobs == {}

    async def test_types_thehive_cannot_store_are_not_looked_up(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        port = Observable(type_id=ObservableTypeId.PORT, value="443")
        requests = len(thehive.requests)
        assert (await soar.enrich_indicator(port)).enrichments == []
        assert len(thehive.requests) == requests

    async def test_unfinished_analyzers_are_reported(self, thehive: FakeTheHive) -> None:
        thehive.stalled.add("DShield_lookup_1_0")
        soar = TheHiveDriver(
            BASE_URL, API_KEY, enrich_timeout=0, poll_interval=0, transport=thehive.transport()
        )
        result = await soar.enrich_indicator(ip("198.51.100.23"))
        (stalled,) = [e for e in result.enrichments if e.provider == "DShield_lookup_1_0"]
        assert stalled.short_desc == "did not finish in time"
        assert stalled.data == {"status": "InProgress"}

    async def test_job_request(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        await soar.enrich_indicator(ip("198.51.100.23"))
        posts = [r for r in thehive.requests if r.method == "POST" and r.url.path.endswith("/job")]
        sent = json.loads(posts[0].content)
        assert sent["cortexId"] == "Cortex"
        assert sent["artifactId"] == thehive.observables[thehive.phishing][2]["_id"]


class TestAnalyzerDiscovery:
    async def test_offered_with_analyzers(self, soar: TheHiveDriver) -> None:
        assert Capability.ENRICH_INDICATOR in (await soar.describe()).capabilities

    async def test_not_offered_without_cortex(self, thehive: FakeTheHive) -> None:
        thehive.cortex = False
        soar = TheHiveDriver(BASE_URL, API_KEY, transport=thehive.transport())
        info = await soar.describe()
        assert Capability.ENRICH_INDICATOR not in info.capabilities
        assert Capability.GET_CASE in info.capabilities


class TestMapping:
    @pytest.mark.parametrize(
        ("indicator", "expected"),
        [
            (Observable(type_id=IP), ["ip"]),
            (Observable(type_id=ObservableTypeId.HOSTNAME), ["domain", "fqdn", "hostname"]),
            (
                Observable(type_id=ObservableTypeId.HOSTNAME, type="fqdn"),
                ["fqdn", "domain", "hostname"],
            ),
            (Observable(type_id=ObservableTypeId.PORT), []),
        ],
    )
    def test_data_types(self, indicator: Observable, expected: list[str]) -> None:
        assert data_types(indicator) == expected

    @pytest.mark.parametrize(
        ("levels", "score"),
        [
            (["info"], None),
            (["safe", "info"], ReputationScoreId.SAFE),
            (["safe", "suspicious"], ReputationScoreId.SUSPICIOUS_RISKY),
            (["suspicious", "malicious", "safe"], ReputationScoreId.MALICIOUS),
        ],
    )
    def test_reputation(self, levels: list[str], score: ReputationScoreId | None) -> None:
        found = reputation([{"level": level} for level in levels])
        assert (found.score_id if found else None) == score
