"""POST /api/v1/remediation/plan — budget-constrained remediation planner (offline solvers)."""

import pytest


def _auth(user):
    return {"Authorization": f"Bearer {user['access_token']}"}


@pytest.mark.asyncio
async def test_requires_auth(client):
    r = await client.post("/api/v1/remediation/plan", json={"use_opt": False})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_sample_plan_offline(client, registered_user):
    r = await client.post("/api/v1/remediation/plan", headers=_auth(registered_user),
                          json={"budget": 40, "use_opt": False, "curve": [20, 40, 80]})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["source"] == "sample:acme-risk-v2"
    g, e = d["plans"]["greedy"], d["plans"]["exhaustive"]
    assert g["feasible"] and e["feasible"]
    assert e["residual"] <= g["residual"]                 # certified optimum never worse
    assert "opt" not in d["plans"] and not d["errors"]
    removed = [c["removed_pct"] for c in d["curve"]]
    assert removed == sorted(removed) and len(removed) == 3   # more budget never removes less
    assert d["findings"][0]["score"] >= d["findings"][-1]["score"]
    assert any("HNDL" in n for n in d["notes"])


@pytest.mark.asyncio
async def test_uploaded_report(client, registered_user):
    report = {"findings": [
        {"rel_path": "api/kex.py", "line_number": 3, "algorithm": "DH", "algorithm_family": "DH",
         "score": 90, "role": "key_exchange", "exposure": "internet", "effort_hours": 10, "tier": "IMMEDIATE"},
        {"rel_path": "core/sig.java", "line_number": 9, "algorithm": "RSA", "algorithm_family": "RSA",
         "score": 30, "role": "signature", "exposure": "internal", "effort_hours": 20, "tier": "PLANNED"},
    ]}
    r = await client.post("/api/v1/remediation/plan", headers=_auth(registered_user),
                          json={"report": report, "budget": 10, "use_opt": False, "curve": []})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["source"] == "uploaded"
    assert d["plans"]["exhaustive"]["effort"] <= 10
    assert d["baseline_risk"] == 120


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"report": {"findings": []}},
    {"report": {"nope": 1}},
    {"report": {"findings": [{"rel_path": "x"}]}},
    {"budget": 0},
])
async def test_rejects_bad_input(client, registered_user, body):
    body = {"use_opt": False, **body}
    r = await client.post("/api/v1/remediation/plan", headers=_auth(registered_user), json=body)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_unknown_qcloud_device_rejected(client, registered_user):
    r = await client.post("/api/v1/remediation/plan", headers=_auth(registered_user),
                          json={"use_opt": False, "use_qaoa": True, "qaoa_device": "IBM-Eagle"})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_opt_platform_refusal_is_reported_not_fatal(client, registered_user, monkeypatch):
    from app.migration import remediation as rem

    def refuse(*a, **k):
        raise RuntimeError("Failed to create opt job: your organization does not have access to 'HUBO Solver'")
    monkeypatch.setattr(rem, "plan_opt", refuse)
    r = await client.post("/api/v1/remediation/plan", headers=_auth(registered_user),
                          json={"use_opt": False, "opt_platform": True, "curve": []})
    assert r.status_code == 200, r.text
    d = r.json()
    assert "HUBO Solver" in d["errors"]["opt_platform"]
    assert d["plans"]["exhaustive"]["feasible"]                 # local results still served


@pytest.mark.asyncio
async def test_qaoa_options_reach_the_solver(client, registered_user, monkeypatch):
    from app.migration import remediation as rem
    seen = {}

    def fake(findings, actions, budget, focus, **kw):
        seen.update(kw, focus=focus)
        return {"cloud": {"status": "failed", "error": "subscription required", "job_ids": []}}
    monkeypatch.setattr(rem, "plan_alternatives_qaoa", fake)
    r = await client.post("/api/v1/remediation/plan", headers=_auth(registered_user), json={
        "use_opt": False, "use_qaoa": True, "qaoa_device": "QpiAI-QSV-Simulator",
        "qaoa_warm_start": True, "curve": []})
    assert r.status_code == 200, r.text
    assert seen["device"] == "QpiAI-QSV-Simulator"
    assert seen["warm_start_plan"] and set(seen["warm_start_plan"]) <= set(seen["focus"])
    assert r.json()["qaoa"]["cloud"]["status"] == "failed"
