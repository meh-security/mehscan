# Self-host a Turso sync server

Use Turso Database’s `tursodb --sync-server` to share selected Mehscan review
publications over HTTPS without a Turso Cloud account. Mehscan keeps its local
review memory and journal on each installation. Security engineers and managed
scanners can pull publications as advisory review context, then stage and push
their own retained reviews from their local replicas. [Mehscan memory sync](review-worker.md#share-retained-context-with-turso-sync)

Turso documents this server for development and testing. Use it as a small,
private deployment for mutually trusted collaborators. One host can serve
multiple repositories. [Turso local sync server](https://docs.turso.tech/sync/local-sync-server)

## Multiple repositories and access

An audience is the group of people and automation trusted with a set of review
publications. Provision one Turso process, database directory, and loopback
port per repository and audience. Give each instance its own systemd unit and
service account so its state directory stays private. One reverse proxy can
serve all instances with separate HTTPS hostnames and bearer secrets.
For example, a host could use these bindings.

| Repository key | Audience | State directory under `/var/lib` | Server listener | HTTPS hostname |
| --- | --- | --- | --- | --- |
| `github.com/repositories/123` | Engineering | `mehscan-sync-payments-eng` | `127.0.0.1:8080` | `payments-eng.sync.example.com` |
| `github.com/repositories/456` | Engineering | `mehscan-sync-inventory-eng` | `127.0.0.1:8081` | `inventory-eng.sync.example.com` |
| `github.com/repositories/123` | Incident response | `mehscan-sync-payments-ir` | `127.0.0.1:8082` | `payments-ir.sync.example.com` |

The host operator maintains the access list explicitly. GitHub repository
membership grants no automatic access to native sync. A client uses the
same explicit repository key as its review inventory and a distinct local
replica path for each upstream. The key lets Mehscan detect a repository
mismatch and bind the replica to its URL. The proxy checks the bearer secret
for the selected hostname. Separate endpoints enforce the audience boundary
even where two audiences use the same repository key. `--publisher-label` is
supplied by the client. When the same client reviews a repository for multiple
audiences, use separate `MEHSCAN_STATE_HOME` directories to keep their local
review history apart. [Mehscan replica and repository checks](https://github.com/meh-security/mehscan/blob/v0.17.0/crates/cli/src/review_memory/upstream.rs)

Duplicate the Caddy site block with the hostname and port for each instance.
Use a different secret and environment variable in each block. Give authorized
engineers and managed jobs the matching secret as `MEHSCAN_TURSO_AUTH_TOKEN`.
Everyone who holds that secret can read and modify the publications at that
endpoint. Removing a member requires rotating the shared secret and distributing
it to the remaining members. Check that a valid secret for one hostname gets
HTTP 401 on the other hostnames. [Caddy site addresses](https://caddyserver.com/docs/caddyfile/concepts#addresses)

Host administrators and local accounts with shell access can reach the
unauthenticated loopback listeners.
Use a separate host or network isolation for audiences that require protection
from each other’s local users. Revocation controls future access. Downloaded
replicas remain on clients. For read-only viewers, per-user grants, or GitHub
Actions OIDC, Mehscan’s existing enrolled review-sharing service uses Turso
Cloud. [Server implementation](https://github.com/tursodatabase/turso/blob/v0.8.4/cli/sync_server.rs),
[Enrolled review sharing](review-sharing.md)

## Install and start Turso

The version pair verified for this guide is **Mehscan 0.17.0** (Rust Turso SDK
0.8.3) and **`tursodb` 0.8.4** on Linux x86-64. Install Mehscan on the clients
and the Turso Database CLI on the server. Choose the matching archive and SHA-256
file for the server architecture from the Turso release. [Mehscan installation](installation.md),
[Pinned SDK](https://github.com/meh-security/mehscan/blob/v0.17.0/crates/cli/Cargo.toml),
[Turso Database 0.8.4 release](https://github.com/tursodatabase/turso/releases/tag/v0.8.4)

```sh
# Linux x86-64. Use a clean download directory.
release=https://github.com/tursodatabase/turso/releases/download/v0.8.4
archive=turso_cli-x86_64-unknown-linux-gnu.tar.xz
curl -fLO "$release/$archive" -O "$release/$archive.sha256" &&
  sha256sum -c "$archive.sha256" &&
  tar -xf "$archive" &&
  sudo install -m 0755 "${archive%.tar.xz}/tursodb" /usr/local/bin/tursodb
/usr/local/bin/tursodb --version
```

For a foreground trial on the same machine, run the server from a private data
directory outside the checkout. Leave it running in a separate terminal. The
server creates `upstream.turso` on first use.

```sh
umask 077
mkdir -p "$HOME/.local/state/mehscan-sync-server"
tursodb "$HOME/.local/state/mehscan-sync-server/upstream.turso" --sync-server 127.0.0.1:8080
```

For a persistent Linux host, create a service account once and save the unit
below as `/etc/systemd/system/mehscan-sync.service`. `systemd` creates and owns
the private state directory on behalf of the service user. Start with a fresh
upstream file and use a local disk for the database and its sidecar files.
[systemd execution settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin mehscan-sync
```

```ini
[Unit]
Description=Turso sync server for Mehscan review memory

[Service]
User=mehscan-sync
Group=mehscan-sync
StateDirectory=mehscan-sync
StateDirectoryMode=0700
WorkingDirectory=/var/lib/mehscan-sync
ExecStart=/usr/local/bin/tursodb /var/lib/mehscan-sync/upstream.turso --sync-server 127.0.0.1:8080
Restart=on-failure
RestartSec=2s
KillSignal=SIGINT
TimeoutStopSec=45s
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mehscan-sync.service
sudo journalctl -u mehscan-sync.service -n 50 --no-pager
```

## Configure HTTPS

Keep Turso bound to `127.0.0.1` and use an HTTPS reverse proxy for client access.
Keep the proxy on a private network or behind an access allowlist. Use a hostname
and TLS certificate trusted by the clients. For an internal hostname, configure the
proxy with a certificate from your organization’s CA and trust that CA on the
clients. Add this site block to `/etc/caddy/Caddyfile` and replace
`sync.example.com` with your hostname. The proxy checks a shared bearer secret
and forwards the two sync protocol routes.
Keep the secret in the proxy service’s environment and give it only to this
database’s authorized clients. [Install Caddy](https://caddyserver.com/docs/install),
[Caddy TLS settings](https://caddyserver.com/docs/caddyfile/directives/tls),
[Caddy request matchers](https://caddyserver.com/docs/caddyfile/matchers),
[Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)

```caddyfile
sync.example.com {
	@sync {
		method POST
		path /v2/pipeline /pull-updates
		expression `{env.MEHSCAN_SYNC_BEARER_TOKEN} != "" && {http.request.header.Authorization} == "Bearer " + {env.MEHSCAN_SYNC_BEARER_TOKEN}`
	}
	handle @sync {
		reverse_proxy 127.0.0.1:8080 {
			header_up -Authorization
		}
	}
	handle {
		respond "Unauthorized" 401
	}
}
```

Generate a secret with `openssl rand -hex 32` and save it as
`MEHSCAN_SYNC_BEARER_TOKEN=<secret>` in `/etc/caddy/mehscan-sync.env` (owner
`root`, mode `0600`). Use `sudo systemctl edit caddy.service` to add the
following drop-in.

```ini
[Service]
EnvironmentFile=/etc/caddy/mehscan-sync.env
```

Validate the Caddyfile and restart Caddy to load the environment file. Deliver
the same secret through the client’s secret manager as `MEHSCAN_TURSO_AUTH_TOKEN`
and use `https://sync.example.com` as the remote. Before initializing, verify
that the request below returns HTTP 401. Use the two-replica check below to
verify authorized sync. To rotate the secret, update the environment file,
restart Caddy, and update the client secret.

```sh
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile &&
  sudo systemctl restart caddy.service
curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://sync.example.com/v2/pipeline
```

## Initialize and verify a publication

To use a saved project key and upstream from a staged source folder, see
[staged source preparation](standalone-source.md#pull-configured-shared-context).

On each client, use the same explicit repository key supplied when creating
the inventory. Use a new replica path outside the source directory for each
installation, separate from any existing local review-memory database. Each
replica binds to the exact remote URL and repository key. Set the HTTPS URL and
use the following shell function to pull and publish. [Mehscan URL and replica validation](https://github.com/meh-security/mehscan/blob/v0.17.0/crates/cli/src/review_memory/upstream.rs)

```sh
ROOT=/path/to/source
KEY=team:example-repo
REMOTE=https://sync.example.com
REPLICA_DIR="$HOME/.local/state/mehscan-sync/example-repo"
install -d -m 0700 "$REPLICA_DIR"
REPLICA="$REPLICA_DIR/replica.turso"

sync_memory() {
  operation=$1
  shift
  mehscan memory sync "$operation" --source-root "$ROOT" --repository-key "$KEY" \
    --remote "$REMOTE" --replica "$REPLICA" "$@"
}
```

One maintainer runs `sync_memory init`. The fresh upstream returns
`initialized: true` and `created: true`. Repeating the command returns
`created: false`. Each writer and reader runs `sync_memory pull` and checks
`initialized: true` before using its replica.

Publish from an existing retained review. Use the `memory.batch` value in the
close receipt, the effective inventory used at close, and the same stream.
Include `--store /path/to/local-memory.turso` if the review used a custom store.
Staging can run offline after the initial pull. If a push fails, retry from
the same replica so Mehscan can reconcile the existing publication.

```sh
INVENTORY=/path/to/effective/inventory
STREAM=main
BATCH=retained-batch-id

sync_memory stage --inventory "$INVENTORY" --stream "$STREAM" \
  --batch "$BATCH" --publisher-label team-maintainer
sync_memory push
```

On the engineer’s installation, pull and query with the matching source
snapshot, effective inventory, and stream. Check that `publications` includes
the ID returned by `stage`.

```sh
sync_memory pull
sync_memory context --inventory "$INVENTORY" --stream "$STREAM"
sync_memory status
```

On that same installation, close and retain an independent review. Set `BATCH`
and `INVENTORY` from the engineer’s review and repeat `stage` and `push` with
the engineer’s configured HTTPS credential. Pull on the first installation and
verify that `publications` includes the engineer’s publication ID.

## Publish a shared resolution

An engineer or a configured AI reviewer can publish a final decision using
the same HTTPS credential. The operator runs `memory sync init` once with
the updated client to enable resolutions on an existing upstream. An upgrade
returns `upgraded: true` and preserves existing publications. Each writer
pulls before staging a resolution.

1. Pull and read `memory sync context`. For the finding under
   `review_state.findings`, inspect the current assessments, evidence, and
   pending checks. `needs_review` means a check still needs an answer.
   `disputed` means there are opposing final verdicts.
2. Review the current source and retain the native decision from the review
   close, as in the publication workflow above. Use `mehscan memory assessments`
   with the same source, inventory, and stream to find the retained batch and
   its `decision_id`. Copy the parent IDs from the finding's `current` entries.
   Save the resolution file outside the source directory. A file for an engineer
   uses the following fields.

   ```json
   {
     "decision_id": "<native-decision-id>",
     "parents": ["<current-head-id>", "<another-current-head-id>"],
     "reviewer_kind": "engineer",
     "rationale": "Explain what the cited source showed and how it answered the prior checks."
   }
   ```

   For an AI reviewer, use `"reviewer_kind": "ai"` and include
   `"reviewer_contract"` with the configured reviewer contract identifier.
   This identifier and the publisher label are recorded attribution.
3. Stage the resolution with the retained batch and push it.

   ```sh
   sync_memory stage --inventory "$INVENTORY" --stream "$STREAM" \
     --batch "$BATCH" --publisher-label "$REVIEWER" --resolution "$RESOLUTION"
   sync_memory push
   ```

   Staging checks the parents against a fresh upstream copy. If the parent set
   changed, pull and review the new heads before confirming. While offline,
   keep the finished review and resolution file locally. Keep the file and
   original batch for retries or recovery after a restore.
4. Pull on the next scanner or engineer installation. The finding shows the
   current verdict and the publication holding the rationale, evidence, and
   dependencies. Use `review_state.findings` for the current state and
   `publications` for history. The legacy `conflicting_verdicts` field
   summarizes published verdicts across that history. A new conflicting
   verdict can reopen the finding. Compare against a fresh replica when
   confirming recovery.

[Staged source preparation](standalone-source.md#pull-configured-shared-context)
shows how to read the shared decision before planning a later scan.

## Back up and recover

- Keep one server process per upstream database. Back up the **entire server
  data directory** after stopping the service cleanly, then restart it. Store
  the backup with the same access protections as the live data. This server’s
  page sync uses WAL frame numbers as revisions. Preserve the WAL and any other
  sidecar files and keep server-side checkpointing disabled. `memory sync
  checkpoint` compacts a **client replica**. Monitor free disk space on the
  server. [Turso server source](https://github.com/tursodatabase/turso/blob/v0.8.4/cli/sync_server.rs),
  [Replica checkpointing](https://docs.turso.tech/sync/checkpoint)
- Restore a complete copy of the server directory with the service stopped and
  restore its owner and permissions. Test the restored database with a fresh
  replica before admitting new writes. If the restore rolls back the server’s
  history, have clients pull into new replica paths. Preserve the old replicas
  and local stores until any missing publications have been identified and
  restaged from retained local batches.
- Pin the CLI version on the host. Before upgrading, test against a copy of
  the upstream directory with both an existing replica copy and a new replica.
  Keep the test isolated from live clients and use the URL that the existing
  replica is bound to. Verify that both replicas read the same publications
  after a push and a restart.

For example, to take a stopped backup of the systemd instance on the host,
run the following commands. Check that `tar` succeeds before using the archive
for recovery.

```sh
sudo install -d -m 0700 /var/backups/mehscan-sync
sudo systemctl stop mehscan-sync.service &&
  sudo tar -czf "/var/backups/mehscan-sync/$(date -u +%Y%m%dT%H%M%SZ).tar.gz" \
    -C /var/lib/mehscan-sync .
sudo systemctl start mehscan-sync.service
```

## Run the sync acceptance test

Run the test from the Mehscan repository with a supported Rust toolchain.

```sh
MEHSCAN_TURSO_SYNC_SERVER=/usr/local/bin/tursodb \
  cargo test --locked -p mehscan-cli --test review_state_cli \
  native_sync_preserves_offline_conflicts_on_a_clean_third_replica -- --ignored
```
