"""seqr-ci.yml defaults loading + validation."""
import pytest

from seqr.ci.config import CIConfigError, find_config_file, load_config, parse_config


def test_parse_basic():
    cfg = parse_config(
        "fail_on: high\nfail_on_drift: true\npolicy_file: seqr-policy.json\n"
        "exclude:\n  - vendor\n  - third_party\n"
    )
    assert cfg == {
        "fail_on": "high",
        "fail_on_drift": True,
        "policy_file": "seqr-policy.json",
        "exclude": ["vendor", "third_party"],
    }


def test_empty_file_is_empty_dict():
    assert parse_config("") == {}


def test_unknown_keys_ignored():
    assert parse_config("future_key: 5\nfail_on: low\n") == {"fail_on": "low"}


def test_bad_bool_raises():
    with pytest.raises(CIConfigError):
        parse_config("fail_on_drift: maybe\n")


def test_bad_list_raises():
    with pytest.raises(CIConfigError):
        parse_config("exclude: not-a-list\n")


def test_non_mapping_raises():
    with pytest.raises(CIConfigError):
        parse_config("- just\n- a\n- list\n")


def test_load_auto_discovers(tmp_path):
    (tmp_path / "seqr-ci.yml").write_text("policy: strict\n", encoding="utf-8")
    assert find_config_file(tmp_path) is not None
    assert load_config(root=tmp_path) == {"policy": "strict"}


def test_load_missing_returns_empty(tmp_path):
    assert load_config(root=tmp_path) == {}


def test_explicit_missing_source_raises(tmp_path):
    with pytest.raises(CIConfigError):
        load_config(tmp_path / "nope.yml")
