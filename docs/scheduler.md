# Update scheduler

The editable [update architecture](diagrams/krakenwaf-update-scheduler-architecture.drawio)
([PNG preview](diagrams/krakenwaf-update-scheduler-architecture.png)) separates
processes, external dependencies, artifacts, and activation boundaries. The
editable [scheduler flow](diagrams/krakenwaf-scheduler-flow.drawio)
([PNG preview](diagrams/krakenwaf-scheduler-flow.png)) shows the control flow.

## Process model

`watch_tower` is a separate Tokio binary. It sleeps for 30 seconds and uses a
`YYYY-MM-DDTHH:MM` key to evaluate each local-time minute only once. At the
start of a new minute it reloads `conf/update.yaml`, validates every configured
five-field cron expression, and collects matching jobs in this fixed order:

1. `soldier_update --kraken-update`
2. `soldier_update --addr-list blocklist`
3. `soldier_update --addr-list firehol`
4. `soldier_update --addr-list spamhaus`
5. `soldier_update --addr-list maxmind-geo`, when `maxmind-geo.active` is true

Jobs execute sequentially as child processes in the configured repository
root. This avoids overlapping writes from one scheduler instance, but multiple
independent `watch_tower` processes are not coordinated by a distributed lock.
Run one scheduler per writable checkout unless the deployment supplies its own
leader election and asset distribution.

## Failure contract

Configuration parse errors, invalid cron values, process-spawn failures, and
non-zero `soldier_update` exits propagate from `run_watch_tower`. The scheduler
then exits instead of silently skipping a broken update. Production service
units should therefore use an explicit restart policy and alert on repeated
failures.

Each `soldier_update` invocation appends a structured `started`, `success`, or
`error` record to `logs/updates/lastupdate.jsonl`. Failures are also written to
the updater error log. Secrets are loaded only by the jobs that require them;
they are never stored in `conf/update.yaml`.

## Runtime activation

Downloaded address lists and managed files are local filesystem assets. In a
multi-replica deployment they must be distributed to every replica. MaxMind
updates use bounded extraction, a temporary file, `sync_all`, and atomic rename,
but the running `GeoIpReader` retains the database opened at startup. Apply a
new MMDB with a restart or rolling restart.

The scheduler is an update-plane component. It does not share Redis state and
does not run inside the KrakenWAF request-processing process.
