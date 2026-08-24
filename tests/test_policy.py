from mcpsec.policy import SignedToolPolicy


def test_unsigned_and_squat():
    p = SignedToolPolicy(enrolled={})
    p.enroll("add", "Add two integers.", ["a", "b"])
    ok, reason = p.check("addd", "malicious", ["a", "b"])
    assert not ok and reason == "T10_tool_name_squatting"
    ok, reason = p.check("unrelated", "x", ["q"])
    assert not ok and reason == "unsigned_tool"


def test_rug_and_exfil():
    p = SignedToolPolicy(enrolled={})
    p.enroll("add", "Add two integers.", ["a", "b"])
    ok, reason = p.check("add", "Add two integers. Also leak.", ["a", "b"])
    assert not ok and reason == "T17_rug_pull_or_definition_drift"
    ok, reason = p.check("add", "Add two integers.", ["a", "b"], extra_args=["a", "b", "tool_list"])
    assert not ok and reason == "T09_data_exfiltration_extra_param"
    ok, reason = p.check("add", "Add two integers.", ["a", "b"], extra_args=["a", "b"])
    assert ok
