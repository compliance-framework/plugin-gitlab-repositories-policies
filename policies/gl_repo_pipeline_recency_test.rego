package compliance_framework.pipeline_recency_test

import data.compliance_framework.pipeline_recency as policy

test_no_pipeline_run_violation if {
    inp := {}
    v := count(policy.violation) with input as inp
    v == 1
}

test_recent_pipeline_ok if {
    # ran 1 day ago
    recent_ts := time.format(time.now_ns() - (24 * 60 * 60 * 1000 * 1000 * 1000))
    inp := {"last_pipeline_run": {"updated_at": recent_ts, "status": "success"}}
    v := count(policy.violation) with input as inp
    v == 0
}

test_pipeline_just_within_limit_ok if {
    # ran exactly max_age_days ago (not strictly greater, so no violation)
    max_ns := policy.max_age_days * 24 * 60 * 60 * 1000 * 1000 * 1000
    boundary_ts := time.format(time.now_ns() - max_ns)
    inp := {"last_pipeline_run": {"updated_at": boundary_ts, "status": "success"}}
    v := count(policy.violation) with input as inp
    v == 0
}

test_old_pipeline_violation if {
    # ran 200 days ago
    old_ts := time.format(time.now_ns() - (200 * 24 * 60 * 60 * 1000 * 1000 * 1000))
    inp := {"last_pipeline_run": {"updated_at": old_ts, "status": "success"}}
    v := count(policy.violation) with input as inp
    v == 1
}

test_old_pipeline_violation_id if {
    old_ts := time.format(time.now_ns() - (200 * 24 * 60 * 60 * 1000 * 1000 * 1000))
    inp := {"last_pipeline_run": {"updated_at": old_ts, "status": "failed"}}
    policy.violation[v] with input as inp
    v.id == "pipeline_run_too_old"
}

test_no_pipeline_violation_id if {
    inp := {}
    policy.violation[v] with input as inp
    v.id == "no_pipeline_run"
}
