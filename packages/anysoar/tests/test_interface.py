import inspect

import pytest
from pydantic import ValidationError

from anysoar.errors import CapabilityNotSupportedError, NotFoundError
from anysoar.interface import (
    CAPABILITY_TIERS,
    ActionTier,
    AlertQuery,
    Capability,
    Driver,
    DriverInfo,
    Page,
    Playbook,
    PlaybookRun,
    PlaybookRunStatus,
)
from anysoar.models import (
    ActivityId,
    DetectionFinding,
    FindingInfo,
    Metadata,
    Product,
    SeverityId,
)


def make_alert(uid: str) -> DetectionFinding:
    return DetectionFinding(
        activity_id=ActivityId.CREATE,
        severity_id=SeverityId.LOW,
        time=1_760_540_400_000,
        metadata=Metadata(product=Product(name="Test SOAR")),
        finding_info=FindingInfo(uid=uid),
    )


class AlertsOnlyDriver(Driver):
    name = "alerts-only"

    def __init__(self) -> None:
        self.closed = 0
        self.alerts = {"a-1": make_alert("a-1")}

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        try:
            return self.alerts[alert_uid]
        except KeyError:
            raise NotFoundError("alert", alert_uid) from None

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        return Page(items=list(self.alerts.values()))

    async def aclose(self) -> None:
        self.closed += 1


class TestCapabilities:
    def test_every_capability_has_a_driver_method_and_a_tier(self) -> None:
        for capability in Capability:
            method = getattr(Driver, capability.value)
            assert inspect.iscoroutinefunction(method), capability
            assert capability in CAPABILITY_TIERS

    def test_every_overridable_operation_is_a_capability(self) -> None:
        lifecycle = {"describe", "aclose"}
        operations = {
            name
            for name, member in vars(Driver).items()
            if inspect.iscoroutinefunction(member) and not name.startswith("_")
        }
        assert operations - lifecycle == {c.value for c in Capability}

    def test_tiers(self) -> None:
        writes = {c for c, t in CAPABILITY_TIERS.items() if t is ActionTier.WRITE}
        assert writes == {Capability.ADD_NOTE, Capability.RUN_PLAYBOOK, Capability.CLOSE_CASE}
        assert Capability.ENRICH_INDICATOR.tier is ActionTier.READ

    def test_tier_mapping_is_read_only(self) -> None:
        with pytest.raises(TypeError):
            CAPABILITY_TIERS[Capability.CLOSE_CASE] = ActionTier.READ  # type: ignore[index]


class TestDriver:
    def test_capabilities_are_the_overridden_methods(self) -> None:
        assert AlertsOnlyDriver.implemented_capabilities() == {
            Capability.GET_ALERT,
            Capability.LIST_ALERTS,
        }

    async def test_describe_defaults_to_implemented_capabilities(self) -> None:
        info = await AlertsOnlyDriver().describe()
        assert info == DriverInfo(
            name="alerts-only",
            capabilities=frozenset({Capability.GET_ALERT, Capability.LIST_ALERTS}),
        )

    async def test_unimplemented_operation_raises(self) -> None:
        with pytest.raises(CapabilityNotSupportedError) as exc_info:
            await AlertsOnlyDriver().get_case("c-1")
        assert exc_info.value.capability is Capability.GET_CASE
        assert exc_info.value.driver == "alerts-only"
        assert str(exc_info.value) == "get_case is not supported by driver 'alerts-only'"

    async def test_implemented_operations(self) -> None:
        driver = AlertsOnlyDriver()
        assert (await driver.get_alert("a-1")).finding_info.uid == "a-1"
        assert [a.finding_info.uid for a in (await driver.list_alerts()).items] == ["a-1"]
        with pytest.raises(NotFoundError, match="alert 'missing' not found"):
            await driver.get_alert("missing")

    async def test_async_context_manager_closes(self) -> None:
        async with AlertsOnlyDriver() as driver:
            pass
        assert driver.closed == 1

    def test_driver_must_have_a_name(self) -> None:
        class Nameless(Driver):
            pass

        with pytest.raises(TypeError, match="must define a class attribute 'name'"):
            Nameless()

    def test_intermediate_base_without_name_is_allowed(self) -> None:
        class HttpDriverBase(Driver):
            pass

        class Concrete(HttpDriverBase):
            name = "concrete"

        assert Concrete().name == "concrete"


class TestModels:
    def test_alert_query_defaults_and_bounds(self) -> None:
        assert AlertQuery().limit == 50
        with pytest.raises(ValidationError):
            AlertQuery(limit=0)
        with pytest.raises(ValidationError):
            AlertQuery(limt=10)  # type: ignore[call-arg]

    def test_playbook_tier_defaults_to_write_and_cannot_be_read(self) -> None:
        assert Playbook(uid="p-1", name="Block sender").tier is ActionTier.WRITE
        with pytest.raises(ValidationError, match="cannot be lower than write"):
            Playbook(uid="p-1", name="Block sender", tier=ActionTier.READ)

    def test_playbook_run_status(self) -> None:
        run = PlaybookRun(uid="r-1", playbook_uid="p-1", status=PlaybookRunStatus.RUNNING)
        assert not run.status.is_finished
        assert PlaybookRunStatus.FAILED.is_finished

    def test_page_validates_item_type(self) -> None:
        with pytest.raises(ValidationError):
            Page[DetectionFinding](items=[{"not": "an alert"}])  # type: ignore[list-item]

    def test_models_are_immutable(self) -> None:
        info = DriverInfo(name="x", capabilities=frozenset())
        with pytest.raises(ValidationError):
            info.name = "y"  # type: ignore[misc]
