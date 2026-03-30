# Policies for use with the GitLab Repositories plugin

OPA/Rego policies designed to evaluate compliance data collected by [`plugin-gitlab-repositories`](../plugin-gitlab-repositories). Each policy receives a `SaturatedProject` as `input` and emits `violation` entries when the project does not meet the policy's requirements.

## Prerequisites

- [OPA CLI](https://www.openpolicyagent.org/docs/latest/cli/) installed
- Data collected by `plugin-gitlab-repositories` — the plugin must be configured and running to supply the `input` document evaluated by these policies

## Available Policies

| Policy | Package | Description |
|--------|---------|-------------|
| `gl_repo_pipeline_recency` | `compliance_framework.pipeline_recency` | Last pipeline run must be within the last 90 days |
| `gl_repo_pipeline_health` | `compliance_framework.pipeline_health` | Pipeline failure rate must be below 50% within the lookback window |

---

## Input Shape

Policies consume a `SaturatedProject` document produced by `plugin-gitlab-repositories`. The fields relevant to pipeline policies are:

```json
{
  "last_pipeline_run": {
    "id": 12345,
    "iid": 10,
    "project_id": 42,
    "status": "success",
    "source": "push",
    "ref": "main",
    "sha": "abc123def456",
    "web_url": "https://gitlab.example.com/mygroup/myrepo/-/pipelines/12345",
    "created_at": "2024-10-01T12:00:00Z",
    "updated_at": "2024-10-01T12:05:00Z"
  },
  "pipeline_runs": [
    {
      "id": 12345,
      "status": "success",
      "ref": "main",
      "updated_at": "2024-10-01T12:05:00Z"
    },
    {
      "id": 12344,
      "status": "failed",
      "ref": "feature/my-branch",
      "updated_at": "2024-09-30T09:30:00Z"
    }
  ]
}
```

**Key distinctions:**

- `last_pipeline_run` — the single most recent pipeline ever run on the project, regardless of the configured lookback window. Used by `gl_repo_pipeline_recency` to determine CI/CD staleness.
- `pipeline_runs` — all pipeline runs within the `pipeline_lookback_days` window (default: 90 days) configured on the plugin. Used by `gl_repo_pipeline_health` to calculate the failure rate.

Pipeline `status` values emitted by GitLab: `created`, `waiting_for_resource`, `preparing`, `pending`, `running`, `success`, `failed`, `canceled`, `skipped`, `manual`, `scheduled`. Only `failed` is counted as a failure in health calculations.

---

## Policy Details

### `gl_repo_pipeline_recency`

Checks that CI/CD has run recently by inspecting `input.last_pipeline_run.updated_at`.

**Violations:**

| Violation ID | Trigger |
|---|---|
| `no_pipeline_run` | `input.last_pipeline_run` is `null` — no pipeline has ever run |
| `pipeline_run_too_old` | The last pipeline ran more than `max_age_days` (default: 90) days ago |

**Example — passing input:**

```json
{
  "last_pipeline_run": {
    "status": "success",
    "updated_at": "2024-12-01T10:00:00Z"
  }
}
```

**Example — failing input (no pipelines):**

```json
{
  "last_pipeline_run": null
}
```

---

### `gl_repo_pipeline_health`

Evaluates the ratio of `failed` pipelines within the lookback window (`input.pipeline_runs`). A failure rate of 50% or above triggers a violation.

**Violations:**

| Violation ID | Trigger |
|---|---|
| `excessive_pipeline_failures` | `failed / total >= 0.5` (50% or more of runs failed) |

No violation is raised when `pipeline_runs` is empty (no runs in the window).

**Example — passing input (2/10 failed = 20%):**

```json
{
  "pipeline_runs": [
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "failed" },
    { "status": "failed" }
  ]
}
```

**Example — failing input (5/10 failed = 50%):**

```json
{
  "pipeline_runs": [
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "success" },
    { "status": "failed" },
    { "status": "failed" },
    { "status": "failed" },
    { "status": "failed" },
    { "status": "failed" }
  ]
}
```

---

## Testing

```shell
make test
# or directly:
opa test policies
```

## Bundling

Policies are packaged into a bundle for distribution via an OCI registry.

```shell
make build
```

The bundle is written to `dist/bundle.tar.gz`.

## Writing Policies

Policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/). The minimum required shape is:

```rego
package compliance_framework.my_policy

violation[{"id": "my_violation_id", "remarks": "Human-readable explanation"}] if {
    # condition that must be true for a violation to be raised
    input.some_field != expected_value
}

title := "Short human-readable title"
description := "Longer description of what this policy checks and why."
```

Optionally include `risk_templates` to attach structured risk metadata (likelihood, impact, threat references, remediation tasks) to each violation ID.
