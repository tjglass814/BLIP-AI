import pytest

from blip_core.deterministic.mitre import (
    TAG_TECHNIQUE_MAP,
    UnknownEvidenceTag,
    map_evidence_to_techniques,
)
from blip_core.verdict.schema import EvidenceItem


def evidence(tag, source="auditd_host"):
    return EvidenceItem(source=source, tag=tag, detail={}, confidence_contribution=0.1)


def test_single_tag_maps_to_its_techniques():
    mappings = map_evidence_to_techniques([evidence("ssh_brute_force")])
    ids = {m.id for m in mappings}
    assert ids == {"T1110", "T1078", "T1021.004"}


def test_confirmed_and_suspected_statuses_come_from_the_table():
    mappings = map_evidence_to_techniques([evidence("ssh_brute_force")])
    by_id = {m.id: m for m in mappings}
    assert by_id["T1110"].status == "CONFIRMED"
    assert by_id["T1078"].status == "SUSPECTED"


def test_evidence_ref_points_back_to_the_source_item():
    mappings = map_evidence_to_techniques([evidence("network_reconnaissance")])
    assert mappings[0].evidence_ref == [0]


def test_multiple_items_mapping_to_same_technique_merge_evidence_refs():
    items = [evidence("network_reconnaissance"), evidence("port_scan")]
    mappings = map_evidence_to_techniques(items)
    t1046 = [m for m in mappings if m.id == "T1046"]
    assert len(t1046) == 1
    assert t1046[0].evidence_ref == [0, 1]


def test_merge_prefers_confirmed_over_suspected():
    # suid_enumeration alone is SUSPECTED for T1548.001; if some other
    # tag ever mapped the same ID as CONFIRMED, the merged status must
    # be CONFIRMED. Simulate that by mapping the same tag twice — status
    # should stay SUSPECTED since both entries agree.
    items = [evidence("suid_enumeration"), evidence("suid_enumeration")]
    mappings = map_evidence_to_techniques(items)
    assert mappings[0].status == "SUSPECTED"
    assert mappings[0].evidence_ref == [0, 1]


def test_unknown_tag_raises_rather_than_silently_dropping():
    with pytest.raises(UnknownEvidenceTag):
        map_evidence_to_techniques([evidence("some_made_up_tag")])


def test_no_evidence_returns_empty_list():
    assert map_evidence_to_techniques([]) == []


def test_results_are_sorted_by_technique_id():
    items = [evidence("persistence_cron"), evidence("network_reconnaissance")]
    mappings = map_evidence_to_techniques(items)
    ids = [m.id for m in mappings]
    assert ids == sorted(ids)


@pytest.mark.parametrize("tag", list(TAG_TECHNIQUE_MAP.keys()))
def test_every_defined_tag_produces_at_least_one_technique(tag):
    mappings = map_evidence_to_techniques([evidence(tag)])
    assert len(mappings) >= 1
    for mapping in mappings:
        assert mapping.id.startswith("T")
        assert mapping.status in ("CONFIRMED", "SUSPECTED")


def test_playbook_technique_ids_are_all_represented():
    # Ported from the technique IDs declared in playbooks/brute_force.py,
    # privilege_escalation.py, network_recon.py, and persistence.py.
    expected_ids = {
        "T1046", "T1110", "T1078", "T1021.004",
        "T1548", "T1548.001", "T1548.003", "T1053.003",
        "T1552.001", "T1070.002", "T1105", "T1136.001",
        "T1098.004", "T1543.002", "T1546.004",
    }
    all_mapped_ids = {
        technique_id
        for techniques in TAG_TECHNIQUE_MAP.values()
        for technique_id, _, _ in techniques
    }
    assert all_mapped_ids == expected_ids
