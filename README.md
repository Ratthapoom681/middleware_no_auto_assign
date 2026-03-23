# Wazuh to DefectDojo Middleware

This project is a FastAPI middleware that receives Wazuh alerts, applies routing and finding logic, and creates or skips findings in DefectDojo.

The README is written as a reset-proof handoff. If context is lost, this file should be enough to understand how the service works, where the important logic lives, and how to operate it safely.

## What This Service Does

At a high level, the middleware:

1. Accepts Wazuh alerts on `/webhook`
2. Places them into a durable SQLite-backed queue
3. Processes them in the background
4. Routes them to a team / owner group
5. Builds a DefectDojo finding payload
6. Applies dedup, endpoint, reviewer, and grouping logic
7. Creates a new finding or skips creation if a duplicate already exists

## Current Architecture

Main runtime files:

- `app/main.py`
  Main FastAPI app, webhook entrypoint, runtime flow, reviewer assignment, finding payload creation
- `app/defectdojo_client.py`
  DefectDojo API client, context creation, dedup, endpoint reuse/attachment, admin inventory loading
- `app/config.py`
  Runtime config models and environment variables
- `app/alert_queue.py`
  Durable queue worker, retries, queue snapshot API support
- `app/finding_groups.py`
  Rolling-window finding grouping logic based on unique source IP counts
- `app/wazuh_parser.py`
  Dedup key generation, severity mapping helpers, markdown description, CVE/CWE extraction
- `app/admin_ui.py`
  Admin page routes and admin JSON API

Frontend admin files:

- `app/admin_assets/admin.html`
- `app/admin_assets/admin_destination.html`
- `app/admin_assets/admin_routing.html`
- `app/admin_assets/admin_teams.html`
- `app/admin_assets/admin_findings.html`
- `app/admin_assets/admin_create.html`
- `app/admin_assets/admin_users.html`

## How Alerts Flow

### 1. Intake

- Wazuh sends JSON to `POST /webhook`
- The request is accepted immediately
- The raw payload is written into the alert queue database
- A background worker processes queued jobs

Why this matters:

- DefectDojo latency should not block webhook intake
- If the app restarts, in-flight queued jobs are recovered
- Failed jobs retry with backoff instead of silently disappearing

### 2. Parsing

- `WazuhAlert` is the main payload model
- Missing or malformed payloads are treated as permanent failures and not retried forever

### 3. Routing

Routing uses `config.yaml`:

- `routing_rules`
- `default_owner_group`
- `teams`

Matching is based on Wazuh rule groups and decoder/program tokens, not DefectDojo tags.

### 4. DefectDojo Context

For each alert, the middleware ensures these objects exist:

- Product Type
- Product
- Engagement
- Test

The service reuses existing DefectDojo objects when possible instead of creating duplicates.

### 5. Finding Creation Logic

The middleware builds:

- title
- description
- impact
- mitigation
- severity
- numerical severity
- tags
- reviewer info when applicable
- endpoint association when possible
- CWE from alert or NVD lookup

## Queue Behavior

Queue implementation:

- storage: SQLite
- file path: same DB path used by the app, controlled by `ASSIGNMENT_DB_PATH`
- worker: in-process background thread
- retries: exponential backoff
- failed jobs: retained as failed records instead of retried forever

Environment variables:

- `ALERT_QUEUE_POLL_SECONDS`
- `ALERT_QUEUE_MAX_ATTEMPTS`
- `ALERT_QUEUE_RETRY_BASE_SECONDS`
- `ALERT_QUEUE_RETRY_MAX_SECONDS`

Admin visibility:

- `GET /admin/api/queue`
- Admin home shows pending, ready, processing, failed, and recent failed queue items

## Dedup Behavior

Current default dedup in `config.yaml` is tuned for:

- same title
- same `src_ip`
- same `dst_ip`
- create new finding when either IP changes

Current default values:

```yaml
dedup_settings:
  enabled: true
  use_unique_id: false
  use_title_test_fallback: true
  require_same_endpoint: false
  require_same_cwe: false
  require_network_match: true
  network_match_mode: "all"
  network_match_fields: ["src_ip", "dst_ip"]
  ignore_mitigated: true
  action_on_match: "skip"
```

Important note:

- `use_unique_id` is intentionally `false` in the current default policy
- if enabled, the generated dedup key can match earlier than the title/IP logic and make dedup broader than expected

Dedup is runtime configurable from the admin page.

## Endpoint Behavior

Endpoint selection priority:

1. `data.dstip`
2. `data.dst_ip`
3. `data.hostname`
4. `data.host`
5. `location`
6. `agent.ip`
7. `agent.name`
8. `manager.name`

Filtering rules:

- ignores empty values
- ignores placeholders like `unknown`, `n/a`, `none`
- ignores file paths such as `/var/log/...`

DefectDojo endpoint behavior:

- reuse existing endpoint by `product + host`
- create a new endpoint only when no matching endpoint exists
- attach endpoint to the finding via `endpoint_status`
- fallback to patching the finding if needed

## Reviewer Assignment

Reviewer assignment is enabled only when:

- the finding ends up with `under_review = true`

Behavior:

- team users are taken from `teams.<group>.users`
- fallback user can be used
- the middleware checks for active DefectDojo users
- round-robin assignment is remembered per dedup key

If no active reviewer is available:

- the finding is still created
- a warning is logged
- the note explains that no reviewer could be assigned

## Finding Defaults And Status Rules

### Finding Defaults

Applied to every new finding before rule overrides:

- `active`
- `verified`
- `false_positive`
- `out_of_scope`
- `risk_accepted`
- `under_review`

### Finding Status Rules

Used to override finding behavior in real time.

Supported conditions:

- severity min
- severity max
- Wazuh rule groups

Supported actions:

- `set_active`
- `set_verified`
- `set_false_positive`
- `set_out_of_scope`
- `set_risk_accepted`
- `set_under_review`

These rules are managed from `/admin/findings`.

## Finding Group Rules

The middleware can group bursts of related findings using a rolling time window.

This is middleware-side logic that uses DefectDojo finding groups through `vuln_id_from_tool`.

Current grouping behavior:

- tracks recent alerts in SQLite
- counts distinct source IPs in a rolling window
- when the threshold is crossed, assigns a stable group key
- patches recent matching findings so they share the same group key
- ensures the DefectDojo test uses `group_by = vuln_id_from_tool`

Supported rule fields:

- `name`
- `enabled`
- `match_rule_groups`
- `severity_values`
- `unique_src_ip_threshold`
- `window_minutes`
- `require_same_title`
- `require_same_dst_ip`

Example use case:

- severity is `Low`
- same title
- same destination IP
- more than `N` unique source IPs in `60` minutes

Then those findings will be grouped together in DefectDojo.

Important limitations:

- grouping requires `srcip` in the alert data
- if `require_same_dst_ip` is enabled, grouping also requires `dstip`
- grouping does not replace dedup; they are separate layers

## CVE / CWE Behavior

The middleware:

- uses CWE directly from the alert when present
- otherwise extracts a CVE
- queries NVD for a related CWE
- adds the CWE to the finding payload when found

Environment variables:

- `NVD_API_KEY`
- `NVD_TIMEOUT_SECONDS`

## Admin UI

Admin pages:

- `/admin`
  Dashboard, queue health, application errors
- `/admin/destination`
  DefectDojo destination path and inventory
- `/admin/routing`
  routing rules, default owner, tag rules
- `/admin/teams`
  local teams plus live DefectDojo group/user inventory
- `/admin/findings`
  dedup, finding defaults, status rules, finding group rules
- `/admin/create`
  guided DefectDojo object creation
- `/admin/users`
  DefectDojo user creation

Admin APIs:

- `GET /admin/api/config`
- `POST /admin/api/config`
- `GET /admin/api/dojo-options`
- `POST /admin/api/dojo/{object_type}`
- `GET /admin/api/logs`
- `GET /admin/api/queue`

## Runtime Config vs Rebuild Required

### Runtime configurable after the feature already exists in the code

These are saved through the admin UI / admin API and reloaded without rebuilding:

- destination path config in `config.yaml`
- routing rules
- teams
- tag rules
- finding defaults
- finding status rules
- dedup settings
- finding group rules

### Requires rebuild / restart

These do not hot-reload automatically:

- Python code changes
- HTML / CSS / JS asset changes
- Dockerfile / Compose changes
- environment variable changes in `.env`

## Deployment

### Local / VM startup

1. Copy `.env.example` to `.env`
2. Set DefectDojo URL and API key
3. Start the app

```bash
docker compose up -d --build
```

### Full rebuild for code or admin asset changes

Use this on the VM when Python, HTML, CSS, or JS changed:

```bash
docker compose down
docker compose build --no-cache
docker compose up -d --force-recreate
```

### Ports

- app listens on `8000`
- admin UI is served from the same app

Main URL:

- `http://<host>:8000/admin`

## Docker Notes

Current Compose behavior:

- `./data` is mounted into the container as `/data`
- `./config.yaml` is mounted as `/app/config.yaml`
- app source files are baked into the image

This means:

- config changes can survive rebuilds through `config.yaml`
- source / frontend changes do not show up until the image is rebuilt

## Environment Variables

Current `.env.example` values:

- `DEFECTDOJO_URL`
- `DEFECTDOJO_API_KEY`
- `LOG_LEVEL`
- `ASSIGNMENT_DB_PATH`
- `NVD_API_KEY`
- `NVD_TIMEOUT_SECONDS`
- `DEFECTDOJO_TIMEOUT_SECONDS`
- `ALERT_QUEUE_POLL_SECONDS`
- `ALERT_QUEUE_MAX_ATTEMPTS`
- `ALERT_QUEUE_RETRY_BASE_SECONDS`
- `ALERT_QUEUE_RETRY_MAX_SECONDS`

## Files Worth Reading First After A Context Reset

If context is gone, read these in order:

1. `README.md`
2. `config.yaml`
3. `app/main.py`
4. `app/defectdojo_client.py`
5. `app/alert_queue.py`
6. `app/finding_groups.py`
7. `app/admin_ui.py`
8. `app/admin_assets/admin_findings.js`

## Known Operational Gotchas

- If the admin UI looks unchanged after editing HTML/CSS/JS, the container was not rebuilt or the browser cached old assets.
- If findings seem to ignore new status/default rules, check whether dedup skipped creation.
- If alerts stop appearing, verify the Wazuh / OSSEC integration script is still executable and still points to the correct webhook URL.
- If endpoint association seems missing, inspect logs for endpoint attach failures after finding creation.
- If queue backlog grows, check DefectDojo latency and queue failures from `/admin`.
- If finding grouping does not trigger, confirm the alert includes `srcip` and, when required, `dstip`.

## DefectDojo API Reference

Local API reference file:

- `DefectDojoApiDoc.json`

This repo should prefer the local DefectDojo spec before guessing payload fields or endpoint behavior.

Important areas already used by the middleware:

- `findings`
- `tests`
- `endpoints`
- `endpoint_status`
- `users`
- `product_types`
- `products`
- `engagements`
- `dojo_groups`
- `dojo_group_members`

## Quick Summary

If you only remember five things, remember these:

1. Webhook intake is queued first, not processed inline
2. Admin config changes are live, but code/UI changes need rebuild
3. Dedup and finding grouping are separate features
4. Endpoint reuse is by `product + host`
5. The admin UI on `/admin/findings` is the main place for dedup, defaults, status rules, and grouping rules
