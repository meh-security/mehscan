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
service host. Set `MEHSCAN_TURSO_PLATFORM_TOKEN` for database lookup and
read-token issuance. Use a separate, database-scoped write token for each
enrollment. In this example, its environment variable is
`MEHSCAN_TURSO_WRITE_TOKEN_TEAM`.

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
Run the usual local review in the approved stream, close it with its effective
inventory, and take `memory.batch` from the retention receipt. Use the same
source root, effective inventory, stream, and local database to publish.
In the Actions job, link with `--oidc-audience YOUR_SERVICE_AUDIENCE` and use the
job identity. Keep the application token out of that job.

```sh
python scripts/review_share.py publish --link LINK.json --scanner MEHSCAN \
  --source-root CHECKOUT --inventory INVENTORY --stream main --batch BATCH_ID
```

Add `--store` if the review used a specific local database. Retry with the
same retained batch and Actions run identity to recover the original receipt.
The publication carries assessment summaries, pending questions, source
references, and dependency fingerprints. Provider transcripts, raw source
archives, and run-control artifacts stay local. Read shared events as advisory
history. A local verdict still needs a source-bound review.
