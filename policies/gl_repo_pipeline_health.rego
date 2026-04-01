package compliance_framework.pipeline_health

# Maximum allowed failure rate for pipeline runs (0.5 = 50%).
max_failure_rate := 0.5

pipeline_runs := [] if {
    object.get(input, "pipeline_runs", null) == null
}

pipeline_runs := runs if {
    runs := object.get(input, "pipeline_runs", null)
    runs != null
}

total := count(pipeline_runs)
failed := count([x |
    x := pipeline_runs[_]
    x.status == "failed"
])

risk_templates := [{
  "name": "Repository has excessive pipeline failure rate",
  "title": "High CI/CD Pipeline Failure Rate Indicates Systemic Build or Test Instability",
  "statement": "A pipeline failure rate exceeding the allowed threshold indicates that automated quality gates are not reliably passing. This suggests either that defective code is frequently being introduced, that the CI/CD pipeline itself is misconfigured, or that required checks are being bypassed. Persistent failures erode trust in automated controls and increase the likelihood of defective or vulnerable changes reaching production.",
  "violation_ids": ["excessive_pipeline_failures"],
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-358",
      "title": "Improperly Implemented Security Check for Standard",
      "url": "https://cwe.mitre.org/data/definitions/358.html"
    }
  ],
  "remediation": {
    "title": "Investigate and resolve persistent pipeline failures",
    "description": "Review recent failed pipeline runs to identify root causes (flaky tests, build infrastructure issues, defective code) and restore the pipeline to a consistently healthy state.",
    "tasks": [
      { "title": "Review recent failed pipeline runs to identify patterns and root causes" },
      { "title": "Fix or quarantine flaky tests that contribute disproportionately to failures" },
      { "title": "Resolve any build infrastructure issues (runner availability, dependency fetching)" },
      { "title": "Ensure that merge requests cannot bypass required pipeline checks when pipelines are failing" },
      { "title": "Set up alerting for pipeline failure rate exceeding the defined threshold" }
    ]
  }
}]

violation[{"id": "excessive_pipeline_failures", "remarks": sprintf("Pipeline failure rate is too high: %d/%d pipelines failed (max allowed: <%.0f%%)", [failed, total, max_failure_rate * 100])}] if {
    total > 0
    failed / total >= max_failure_rate
}

title := "Repository has an acceptable pipeline failure rate"
description := sprintf("All repositories must have a pipeline failure rate below %.0f%%. [%d/%d pipelines failed]", [max_failure_rate * 100, failed, total])
remarks := sprintf("Pipeline failure rate is evaluated over the configured lookback window. Failures are counted when pipeline status is 'failed'. Max allowed failure rate: %.0f%%.", [max_failure_rate * 100])
