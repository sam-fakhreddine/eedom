"""Contract tests for AnalyzerRegistryPort, DecisionStorePort, EvidenceStorePort, PackageIndexPort.
# tested-by: tests/unit/test_ports.py

RED phase for issue #159 — these tests import symbols that do not exist yet.
All imports come from eedom.core.ports which does not yet exist.
Every test is expected to fail with ImportError until the production code is added.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# AnalyzerRegistryPort
# ---------------------------------------------------------------------------


class TestAnalyzerRegistryPortIsProtocol:
    def test_analyzer_registry_port_is_a_protocol(self) -> None:
        import typing

        from eedom.core.ports import AnalyzerRegistryPort

        assert hasattr(AnalyzerRegistryPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(AnalyzerRegistryPort, "__mro__", [])
        )

    def test_analyzer_registry_port_is_runtime_checkable(self) -> None:
        import pytest

        from eedom.core.ports import AnalyzerRegistryPort

        try:
            isinstance(object(), AnalyzerRegistryPort)
        except TypeError as exc:
            pytest.fail(
                f"AnalyzerRegistryPort is not @runtime_checkable — isinstance() raised: {exc}"
            )

    def test_analyzer_registry_port_has_run_all_method(self) -> None:
        from eedom.core.ports import AnalyzerRegistryPort

        assert hasattr(
            AnalyzerRegistryPort, "run_all"
        ), "AnalyzerRegistryPort must declare a 'run_all' method"


class TestFakeAnalyzerRegistrySatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from eedom.core.ports import AnalyzerRegistryPort

        class FakeRegistry:
            def run_all(self, files: list, repo_path: Path, **kwargs) -> list:
                return []

        assert isinstance(FakeRegistry(), AnalyzerRegistryPort)

    def test_fake_returns_list_of_plugin_results(self) -> None:
        from eedom.core.ports import AnalyzerRegistryPort

        class FakeRegistry:
            def run_all(self, files: list, repo_path: Path, **kwargs) -> list:
                return []

        registry = FakeRegistry()
        assert isinstance(registry, AnalyzerRegistryPort)
        result = registry.run_all(files=["/repo/foo.py"], repo_path=Path("/repo"))
        assert isinstance(result, list)

    def test_object_without_run_all_does_not_satisfy_protocol(self) -> None:
        from eedom.core.ports import AnalyzerRegistryPort

        class NotARegistry:
            def execute_all(self) -> list:
                return []

        assert not isinstance(NotARegistry(), AnalyzerRegistryPort)


# ---------------------------------------------------------------------------
# DecisionStorePort
# ---------------------------------------------------------------------------


class TestDecisionStorePortIsProtocol:
    def test_decision_store_port_is_a_protocol(self) -> None:
        import typing

        from eedom.core.ports import DecisionStorePort

        assert hasattr(DecisionStorePort, "__protocol_attrs__") or (
            typing.Protocol in getattr(DecisionStorePort, "__mro__", [])
        )

    def test_decision_store_port_is_runtime_checkable(self) -> None:
        import pytest

        from eedom.core.ports import DecisionStorePort

        try:
            isinstance(object(), DecisionStorePort)
        except TypeError as exc:
            pytest.fail(f"DecisionStorePort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_decision_store_port_has_save_decision_method(self) -> None:
        from eedom.core.ports import DecisionStorePort

        assert hasattr(
            DecisionStorePort, "save_decision"
        ), "DecisionStorePort must declare a 'save_decision' method"


class TestFakeDecisionStoreSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from eedom.core.ports import DecisionStorePort

        class FakeStore:
            def save_decision(self, decision) -> None:
                pass

        assert isinstance(FakeStore(), DecisionStorePort)

    def test_fake_save_decision_accepts_any(self) -> None:
        from eedom.core.ports import DecisionStorePort

        saved: list = []

        class CapturingStore:
            def save_decision(self, decision) -> None:
                saved.append(decision)

        store = CapturingStore()
        assert isinstance(store, DecisionStorePort)
        store.save_decision({"id": "abc", "verdict": "approve"})
        assert len(saved) == 1
        assert saved[0]["verdict"] == "approve"

    def test_object_without_save_decision_does_not_satisfy_protocol(self) -> None:
        from eedom.core.ports import DecisionStorePort

        class NotAStore:
            def persist(self, data) -> None:
                pass

        assert not isinstance(NotAStore(), DecisionStorePort)


# ---------------------------------------------------------------------------
# EvidenceStorePort
# ---------------------------------------------------------------------------


class TestEvidenceStorePortIsProtocol:
    def test_evidence_store_port_is_a_protocol(self) -> None:
        import typing

        from eedom.core.ports import EvidenceStorePort

        assert hasattr(EvidenceStorePort, "__protocol_attrs__") or (
            typing.Protocol in getattr(EvidenceStorePort, "__mro__", [])
        )

    def test_evidence_store_port_is_runtime_checkable(self) -> None:
        import pytest

        from eedom.core.ports import EvidenceStorePort

        try:
            isinstance(object(), EvidenceStorePort)
        except TypeError as exc:
            pytest.fail(f"EvidenceStorePort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_evidence_store_port_has_write_artifact_method(self) -> None:
        from eedom.core.ports import EvidenceStorePort

        assert hasattr(
            EvidenceStorePort, "write_artifact"
        ), "EvidenceStorePort must declare a 'write_artifact' method"


class TestFakeEvidenceStoreSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from eedom.core.ports import EvidenceStorePort

        class FakeEvidence:
            def write_artifact(self, path: str, content: bytes) -> str:
                return f"/evidence/{path}"

        assert isinstance(FakeEvidence(), EvidenceStorePort)

    def test_fake_write_artifact_returns_artifact_ref_string(self) -> None:
        from eedom.core.ports import EvidenceStorePort

        class FakeEvidence:
            def write_artifact(self, path: str, content: bytes) -> str:
                return f"/evidence/{path}"

        store = FakeEvidence()
        assert isinstance(store, EvidenceStorePort)
        ref = store.write_artifact("sbom.xml", b"<sbom/>")
        assert isinstance(ref, str)
        assert "sbom.xml" in ref

    def test_object_without_write_artifact_does_not_satisfy_protocol(self) -> None:
        from eedom.core.ports import EvidenceStorePort

        class NotAnEvidenceStore:
            def store(self, key: str, name: str, content: bytes) -> str:
                return ""

        assert not isinstance(NotAnEvidenceStore(), EvidenceStorePort)


# ---------------------------------------------------------------------------
# PackageIndexPort
# ---------------------------------------------------------------------------


class TestPackageIndexPortIsProtocol:
    def test_package_index_port_is_a_protocol(self) -> None:
        import typing

        from eedom.core.ports import PackageIndexPort

        assert hasattr(PackageIndexPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(PackageIndexPort, "__mro__", [])
        )

    def test_package_index_port_is_runtime_checkable(self) -> None:
        import pytest

        from eedom.core.ports import PackageIndexPort

        try:
            isinstance(object(), PackageIndexPort)
        except TypeError as exc:
            pytest.fail(f"PackageIndexPort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_package_index_port_has_get_package_info_method(self) -> None:
        from eedom.core.ports import PackageIndexPort

        assert hasattr(
            PackageIndexPort, "get_package_info"
        ), "PackageIndexPort must declare a 'get_package_info' method"


class TestFakePackageIndexSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from eedom.core.ports import PackageIndexPort

        class FakeIndex:
            def get_package_info(self, name: str, ecosystem: str) -> dict:
                return {"name": name, "ecosystem": ecosystem, "latest_version": "1.0.0"}

        assert isinstance(FakeIndex(), PackageIndexPort)

    def test_fake_get_package_info_returns_dict(self) -> None:
        from eedom.core.ports import PackageIndexPort

        class FakeIndex:
            def get_package_info(self, name: str, ecosystem: str) -> dict:
                return {"name": name, "ecosystem": ecosystem, "latest_version": "2.3.4"}

        index = FakeIndex()
        assert isinstance(index, PackageIndexPort)
        info = index.get_package_info("requests", "pypi")
        assert isinstance(info, dict)
        assert info["name"] == "requests"
        assert info["ecosystem"] == "pypi"

    def test_fake_get_package_info_accepts_name_and_ecosystem(self) -> None:
        from eedom.core.ports import PackageIndexPort

        calls: list[tuple[str, str]] = []

        class RecordingIndex:
            def get_package_info(self, name: str, ecosystem: str) -> dict:
                calls.append((name, ecosystem))
                return {}

        index = RecordingIndex()
        assert isinstance(index, PackageIndexPort)
        index.get_package_info("lodash", "npm")
        assert calls == [("lodash", "npm")]

    def test_object_without_get_package_info_does_not_satisfy_protocol(self) -> None:
        from eedom.core.ports import PackageIndexPort

        class NotAnIndex:
            def fetch(self, name: str) -> dict:
                return {}

        assert not isinstance(NotAnIndex(), PackageIndexPort)
