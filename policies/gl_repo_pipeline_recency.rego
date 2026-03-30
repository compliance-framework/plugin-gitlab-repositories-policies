package compliance_framework.pipeline_recency

# Maximum allowed age of the last pipeline run (in days).
max_age_days := 90

last := input.last_pipeline_run

risk_templates := [
  {
    "name": "Repository has no pipeline runs",
    "title": "Absence of CI/CD Pipeline Execution Indicates Unverified Changes",
    "statement": "A repository with no recorded pipeline runs suggests that automated quality gates have never executed or are not configured. Without CI/CD verification, code changes may reach production without automated testing, security scanning, or compliance checks.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["no_pipeline_run"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Configure and run CI/CD pipelines for the repository",
      "description": "Introduce a CI/CD pipeline configuration (e.g., .gitlab-ci.yml) so that automated checks run on every commit or merge request.",
      "tasks": [
        { "title": "Add a .gitlab-ci.yml pipeline definition to the repository" },
        { "title": "Define at minimum a build and test stage" },
        { "title": "Ensure the pipeline runs on merge requests to the default branch" }
      ]
    }
  },
  {
    "name": "Last pipeline run is too old",
    "title": "Stale CI/CD Pipeline Indicates Accumulated Unverified Changes",
    "statement": "A last pipeline run older than the permitted threshold suggests that automated quality gates have not executed recently. This means recent code changes may not have been verified by automated tests, security scans, or compliance checks, increasing the risk of defective or vulnerable code reaching production undetected.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["pipeline_run_too_old"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Restore active CI/CD pipeline execution",
      "description": "Investigate why the pipeline has not run recently and restore regular automated execution.",
      "tasks": [
        { "title": "Check GitLab CI/CD settings and ensure pipelines are not disabled" },
        { "title": "Verify that recent commits are triggering pipeline runs" },
        { "title": "Review scheduled pipelines and confirm they are active" },
        { "title": "Set up alerting for pipelines that have not run within the allowed window" }
      ]
    }
  }
]

violation[{"id": "pipeline_run_too_old", "remarks": sprintf("Last pipeline run is too old (older than %d days)", [max_age_days])}] if {
    pipeline_present
    pipeline_too_old
}

violation[{"id": "no_pipeline_run", "remarks": "No pipeline runs found for this repository."}] if {
    not pipeline_present
}

pipeline_present if {
    last != null
}

pipeline_too_old if {
    ts := last.updated_at
    ts != null

    run_ns := time.parse_rfc3339_ns(ts)
    now_ns := time.now_ns()

    age_ns := now_ns - run_ns
    max_ns := max_age_days * 24 * 60 * 60 * 1000000000

    age_ns > max_ns
}

title := "Repository has a recent pipeline run"
description := sprintf("All repositories must have a CI/CD pipeline run within the last %d days. Expected shape: input.last_pipeline_run.updated_at as an RFC3339 timestamp.", [max_age_days])
