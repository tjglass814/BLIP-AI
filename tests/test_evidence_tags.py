import pytest

from blip_core.deterministic.evidence_tags import EVIDENCE_TAGS, confidence_weight_for
from blip_core.deterministic.mitre import TAG_TECHNIQUE_MAP


def test_every_evidence_tag_has_a_mitre_mapping():
    assert set(EVIDENCE_TAGS.keys()) == set(TAG_TECHNIQUE_MAP.keys())


@pytest.mark.parametrize(
    "tag,expected_weight",
    [
        ("network_reconnaissance", 0.20),
        ("ssh_brute_force", 0.25),
        ("privilege_escalation_confirmed", 0.35),
        ("port_scan", 0.15),
        ("persistence_ssh_key", 0.25),
    ],
)
def test_ported_weights_match_investigation_engine(tag, expected_weight):
    assert confidence_weight_for(tag) == expected_weight


def test_unknown_tag_raises():
    with pytest.raises(KeyError):
        confidence_weight_for("not_a_real_tag")


def test_every_tag_declares_at_least_one_allowed_source():
    for tag, spec in EVIDENCE_TAGS.items():
        assert len(spec["allowed_sources"]) >= 1, f"{tag} has no allowed sources"
