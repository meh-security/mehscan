# Enrolled review sharing

The sharing service lets authorized checkouts read shared review history and
publish from an approved GitHub Actions workflow. Each enrollment links a
stable GitHub repository ID and one sharing audience to a dedicated Turso Cloud
database. Publication is advisory. Local review and its journal remain
available when sharing fails.

| Role | Access |
| --- | --- |
| Viewer | Link a checkout and read all shared records within the enrolled audience. |
| Contributor | Read, add attributed facts, and revise or withdraw their own facts. |
| Manager | Contribute evidence and manage the audience's grants and workflow policy. |
| Scanner | Read and publish retained reviews from the approved Actions workflow and stream. |

## Enroll a repository

Install the service dependencies and run the service behind an HTTPS reverse
proxy. The service listens on loopback. Keep its registry and credentials on the
service host.

In the [Turso dashboard](https://app.turso.tech/), select the organization that
owns the database and open **Settings → API Tokens → Create Token**. Choose the
database's group and grant `read` and `db:mint-token` when the form offers
individual scopes. Those scopes cover database lookup and read-token issuance.
The [Turso CLI](https://docs.turso.tech/cli/auth/api-tokens/mint) can also mint a
token with these exact scopes. Store the Platform API token as
`MEHSCAN_TURSO_PLATFORM_TOKEN` in the sharing service's environment.

Use a separate, database-scoped SQL write token for each enrollment. Pass its
environment variable name to `--writer-env`. The example uses
`MEHSCAN_TURSO_WRITE_TOKEN_TEAM`. The Actions Scanner authenticates to the
sharing service with GitHub OIDC and receives short-lived read credentials.

```sh
python -m pip install -r scripts/review-host-requirements.txt
python scripts/review_host.py --registry /var/lib/mehscan/registry.sqlite enroll \
  --repository-id REPOSITORY_ID --audience team --organization ORG --database DATABASE \
  --writer-env MEHSCAN_TURSO_WRITE_TOKEN_TEAM --manager MANAGER_NAME
python scripts/review_host.py --registry /var/lib/mehscan/registry.sqlite issue --name MANAGER_NAME
python scripts/review_host.py --registry /var/lib/mehscan/registry.sqlite serve \
  --oidc-audience YOUR_SERVICE_AUDIENCE
```

Create a dedicated database for each audience before enrolling it. Enrollment
pins the Turso database ID. The service issues database-scoped, read-only
credentials for 15 minutes. Each list or get command requests a fresh credential.
Revoking a grant or application token stops new credentials and submissions.
Previously issued database credentials remain valid until they expire or Turso
invalidates them. [Turso database tokens](https://docs.turso.tech/api-reference/databases/create-token)

`issue` returns the application token once. Set `MEHSCAN_SHARE_TOKEN` on the
authorized client. A Manager can grant Viewer, Contributor, or Manager access
with a JSON document containing `name` and `role`. A null `role` removes the
grant. Use `review_host.py revoke --name NAME` to revoke all application tokens
for an identity. The operator can disable the whole enrollment with
`review_host.py disable --repository-id REPOSITORY_ID --audience team`.

## Link and read

Keep the link file and review state outside the checkout. The link file stores
the service and enrollment coordinates. Credentials come from the current
process environment or the approved Actions job.

```sh
python scripts/review_share.py link --host https://reviews.example.com \
  --repository-id REPOSITORY_ID --audience team --source-root CHECKOUT --output LINK.json
python scripts/review_share.py list --link LINK.json
python scripts/review_share.py get --link LINK.json --id EVENT_ID
python scripts/review_share.py grant --link LINK.json --input GRANT.json
```

Pass `--after` with the returned `next` cursor to read subsequent events.
The audience covers the database, including published history across streams.
Use separate enrollments for groups that need different read access.

To contribute a fact, submit a document with `key`, a retry-safe `operation`
identifier, `parent_revision`, and `fact`. The fact uses the local fields
`statement`, `origin`, `scope`, `evidence`, `source_sha256`, `observed_at`,
and `expires_at`. The service assigns the authenticated author. Set the parent
to null for the first revision. To revise or withdraw it, use a new operation
identifier and the current event ID as the parent. Set `fact` to null for
withdrawal.

```sh
python scripts/review_share.py fact --link LINK.json --input FACT.json
```

## Use shared facts in a review

Build the inventory with the linked repository key, then sync the latest facts
before starting the review. Use repository-relative paths in shared fact
scopes and source hashes.

```sh
mehscan investigate review-inventory CHECKOUT \
  --repository-key github.com/repositories/REPOSITORY_ID --output INVENTORY
python scripts/review_share.py sync --link LINK.json --scanner MEHSCAN \
  --source-root CHECKOUT --inventory INVENTORY
```

Use the returned `state_home` as `MEHSCAN_STATE_HOME` for the entire review
and the returned `state_store` as the native journal. Other local review commands
use those same paths. A separate control directory for each checkout gives it
its own progress and cache. The native controller also checks that a journal
and a retained batch stay within their sharing audience.

`memory prepare` and `state work` automatically include applicable cached fact
revisions. The controller checks scope, source hashes, and expiration against
the current checkout. A correction or withdrawal reopens affected work and
invalidates responses still using the previous revision. Unchanged work stays
eligible for reuse under the normal native checks. Sync before each linked
review to pick up changes. An offline review can use its last successful local
cache, with the last synced event ID available from `memory shared-facts`.

The sync cursor advances with each committed page of facts. Repeated syncs
download only newer revisions. A restored upstream database that lacks the
local checkpoint requires reconciliation. Shared review publications are
available as advisory history through `list` and `get`.

## Publish a protected branch review

As Manager, approve a workflow with `review_share.py workflow --link LINK.json
--input WORKFLOW.json`. For example, use the following policy.

```json
{
  "workflow_ref": "OWNER/REPO/.github/workflows/review.yml@refs/heads/main",
  "ref": "refs/heads/main",
  "environment": "Review",
  "stream": "main",
  "events": ["push", "schedule", "workflow_dispatch"]
}
```

Configure protection rules on that GitHub environment and grant the job
`id-token: write`. The service verifies the workload's issuer, custom audience,
repository ID, workflow, environment, ref, run identity, and source SHA. A null
workflow document revokes the workload grant. This flow publishes reviews of
approved branch runs, with the checkout pinned to the job's own SHA.
[GitHub Actions OIDC claims](https://docs.github.com/en/actions/reference/security/oidc)

Use `github.com/repositories/REPOSITORY_ID` as the inventory repository key.
Sync shared facts, set the returned state home, and run the usual local review
in the approved stream. Close it with its effective
inventory, and take `memory.batch` from the retention receipt. Use the same
source root, effective inventory, stream, and local database to publish.
In the Actions job, link with `--oidc-audience YOUR_SERVICE_AUDIENCE` and use the
job identity. Keep the application token out of that job.

```sh
python scripts/review_share.py publish --link LINK.json --scanner MEHSCAN \
  --source-root CHECKOUT --inventory INVENTORY --stream main --batch BATCH_ID
```

Publish with the same `MEHSCAN_STATE_HOME`. Add `--store` if the review used a
specific local database. Retry with the
same retained batch and Actions run identity to recover the original receipt.
The publication carries assessment summaries, pending questions, source
references, and dependency fingerprints. Provider transcripts, raw source
archives, and run-control artifacts stay local. Read shared events as advisory
history. A local verdict still needs a source-bound review.

## Review pull requests from enrolled Actions

Install the [hosted review example](examples/mehscan-hosted-review.yml) on the
protected default branch. Enroll its workflow once as a Manager. Include
`pull_request_target` and `workflow_dispatch` in the workflow policy's `events`
and use the workflow path and `Review` environment from the example. Set the
repository variables `MEHSCAN_COMMIT` to a reviewed Mehscan commit,
`MEHSCAN_SHARE_HOST` to the service origin, `MEHSCAN_SHARE_AUDIENCE` to the
enrolled audience, and `MEHSCAN_OIDC_AUDIENCE` to the service's OIDC audience.
Configure the `MEHSCAN_CODEX_AUTH_JSON` secret on the protected environment.
GitHub may require enabling `pull_request_target` through its Actions event
policy. For private repositories, give the sharing service a repository-scoped
`MEHSCAN_GITHUB_READ_TOKEN` with read access to pull requests and contents.
[GitHub privileged PR workflow guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)

The protected workflow reviews ready same-repository PRs on open, reopen,
transition out of draft, and new pushes. It skips drafts and forks. The runner
builds the pinned Mehscan tool and reads target source from a separate checkout.
Keep provider configuration and executable workflow steps on trusted revisions.
Run the workflow manually from the same branch to review a PR on demand. Select
**Review the full PR diff comprehensively** to use Comprehensive for the
current diff. Runs sync applicable facts and publish retained work. A duplicate
automatic run can reuse a finished publication of the same snapshot. An explicit
re-review starts fresh. On a compatible subsequent push, the default Value
review prioritizes files changed since the previous reviewed head and keeps the
rest of the native review queue accounted for. Shared results remain advisory
history, with verdict admission performed by the current review.
If fact sync fails after the run binds to a PR, the run keeps its local review
artifacts in Actions and reports that shared facts were unavailable.

For a custom protected dispatch job, use the job's OIDC identity to bind the
run to a PR. The service resolves the current head and base through GitHub.
Check out the returned `head_sha` with Git history available and prepare the
inventory for those exact endpoints. Use `--path-prefix` for a nested scan root.

```sh
python scripts/review_share.py pr-target --link LINK.json --pull-request 75
mehscan investigate review-inventory CHECKOUT \
  --repository-key github.com/repositories/REPOSITORY_ID \
  --source-repository-key github.com/repositories/REPOSITORY_ID \
  --changed-from BASE_SHA --target HEAD_SHA --diff-mode files --merge-base --output INVENTORY
```

Sync the shared facts, review in the returned stream, and close the native
attempt with its effective inventory. Publish the retained batch using the
same run attempt and checkout.

```sh
python scripts/review_share.py publish --link LINK.json --scanner MEHSCAN \
  --source-root CHECKOUT --inventory INVENTORY --stream pr:75 --batch BATCH_ID --pull-request 75
```

A completed review stays attached to its pinned comparison. If the PR changes
or closes during the review, the publication is historical. A retry of an
already accepted batch returns its original receipt while the run's grant
remains active. The Actions summary reports freshness at publication. Use
`pr-current` for a fresh lookup and `get` to read the returned publication.

```sh
python scripts/review_share.py pr-current --link LINK.json --pull-request 75
```
