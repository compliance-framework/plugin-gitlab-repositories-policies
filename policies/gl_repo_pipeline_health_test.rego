package compliance_framework.pipeline_health_test

import data.compliance_framework.pipeline_health as policy

test_no_runs_ok if {
    inp := {"pipeline_runs": []}
    v := count(policy.violation) with input as inp
    v == 0
}

test_all_success_ok if {
    inp := {"pipeline_runs": [
        {"status": "success"},
        {"status": "success"},
        {"status": "success"}
    ]}
    v := count(policy.violation) with input as inp
    v == 0
}

test_exactly_50_percent_failure_violation if {
    # 5 failed out of 10 = exactly 50% -- at the threshold, so violation
    inp := {"pipeline_runs": [
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"}
    ]}
    v := count(policy.violation) with input as inp
    v == 1
}

test_below_50_percent_failure_ok if {
    # 4 failed out of 10 = 40% — below threshold, no violation
    inp := {"pipeline_runs": [
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"}
    ]}
    v := count(policy.violation) with input as inp
    v == 0
}

test_above_50_percent_failure_violation if {
    # 6 failed out of 10 = 60% — violation
    inp := {"pipeline_runs": [
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "success"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"}
    ]}
    v := count(policy.violation) with input as inp
    v == 1
}

test_canceled_and_skipped_not_counted_as_failures if {
    # canceled/skipped pipelines should not count as failures
    inp := {"pipeline_runs": [
        {"status": "success"},
        {"status": "canceled"},
        {"status": "skipped"},
        {"status": "canceled"},
        {"status": "skipped"}
    ]}
    v := count(policy.violation) with input as inp
    v == 0
}

test_violation_id if {
    inp := {"pipeline_runs": [
        {"status": "failed"},
        {"status": "failed"},
        {"status": "failed"},
        {"status": "success"}
    ]}
    policy.violation[v] with input as inp
    v.id == "excessive_pipeline_failures"
}

test_description_includes_counts if {
    inp := {"pipeline_runs": [
        {"status": "failed"},
        {"status": "failed"},
        {"status": "success"}
    ]}
    desc := policy.description with input as inp
    contains(desc, "[2/3 pipelines failed]")
}

test_description_defaults_to_zero_counts_when_pipeline_runs_missing if {
    desc := policy.description with input as {}
    contains(desc, "[0/0 pipelines failed]")
}

test_description_defaults_to_zero_counts_when_pipeline_runs_null if {
    desc := policy.description with input as {"pipeline_runs": null}
    contains(desc, "[0/0 pipelines failed]")
}
