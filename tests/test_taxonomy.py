from mcpsec import COVERED_TAXONOMY_IDS
from mcpsec.taxonomy import TAXONOMY, covered


def test_seventeen_vectors():
    assert len(TAXONOMY) == 17
    assert [v.id for v in TAXONOMY] == [f"T{i:02d}" for i in range(1, 18)]


def test_covered_subset():
    ids = tuple(v.id for v in covered())
    assert ids == COVERED_TAXONOMY_IDS
    assert set(ids) == {"T09", "T10", "T14", "T16", "T17"}
