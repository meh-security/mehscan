# GitHub acceptance setup

Create one dedicated public test repository now. A GitHub App is not required
for the current advisory Action or an Actions-based SARIF ingestion test.
The hosted conversational agent/publisher is later work. Use synthetic fixtures
in this repository; all security findings are deliberate test cases.

## Repository setup

1. Open [New repository](https://github.com/new). Choose the intended owner, for
   example `meh-security`, and name it `mehscan-integration-test` if available.
   Choose Public, initialize a README and use `main` as the default branch.
2. In Settings → Actions → General, allow GitHub Actions and the pinned actions
   used by the caller workflow. Keep the default token read-only. Approve outside
   contributor workflow runs when GitHub requests approval; do not grant fork
   workflows write tokens or secrets for this test.
3. Use GitHub-hosted Ubuntu runners initially. No persistent state store, model
   credentials, PAT or self-hosted runner is required for native artifact tests.
4. After a reviewed V11 commit is published to `meh-security/mehscan`, add the
   repository Actions variable `MEHSCAN_V11_COMMIT` containing its full 40-character
   SHA. The currently released 0.8.0 and the local uncommitted implementation are
   not valid substitutes. A reviewed branch commit is sufficient; no release tag
   is needed. Wait for its CI/review before enabling the caller.
5. Copy [mehscan-advisory.yml](examples/mehscan-advisory.yml) into the test repo as
   `.github/workflows/mehscan-advisory.yml`, on `main`, with the variable configured.
   It builds only the pinned trusted tool, checks out target source separately and
   uploads advisory artifacts. Its permissions are `contents: read` and
   `pull-requests: read`. Do not make the job a required merge check.
6. Add tiny source fixtures to `main`, then open test PRs that modify them. A second
   account or another contributor should fork the test repo and open a PR for the
   external-contributor acceptance case. Same-repository branches do not test the
   external fork approval/permission boundary.

Public repositories support code scanning on GitHub.com. Private/internal
repositories need the applicable GitHub Code Security entitlement enabled, so a
public synthetic repository keeps the first ingestion test simple.
[GitHub SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

## Native Action acceptance

After the native lane passes, copy [the BYOK caller](examples/mehscan-byok-advisory.yml)
into the same synthetic test repository. It is an example, not an enabled workflow
in this checkout. Keep the same reviewed `MEHSCAN_V11_COMMIT` pin.

Add repository Actions secret `MEHSCAN_CODEX_AUTH_JSON`: the explicit authentication
JSON supported by the chosen company Codex client. Do not put it in repository
files, workflow inputs, artifacts or chat. The example uses the tested Linux x64
client version `0.162.0-alpha.17.2`, Terra 6.1/medium and Value by default. Repository
variables `MEHSCAN_CODEX_VERSION` and `MEHSCAN_REVIEW_MODEL` can select an approved
compatible client/model; unsupported authentication/model access fails without
substitution. Actual company API-key use still needs hosted acceptance.

The trusted setup helper downloads the pinned OpenAI npm client package without
Node/npm, verifies the package's published SHA-512 integrity and writes a private
auth/config root under runner temp. It does not create the adapter's session store;
the adapter owns that initialization. Companies can replace this installation
step with their approved client provisioner and the same explicit config contract.
The setup helper is for this Linux x64 example; the reviewer adapter itself remains
portable. The example installs the bundled adapter's pinned Python validation
requirements before credential setup and selects stable/addressed input. Setup
is not a model scan or a provider-containment boundary.

Before credential setup, `github_action.py model-lane` reads authoritative GitHub
metadata through the same resolver used by Action preparation. Automatic forks,
drafts, closed PRs and metadata-only edits do not receive the auth setup step.
Manual fork model scans require `workflow_dispatch` plus `allow_fork_review: true`.
Same-repository and explicit release comparisons use the selected model lane.
The Action rechecks current metadata and source binding during actual execution;
the preliminary lane result is not a review receipt or authority to publish.

Record configured client/model/auth lane, exact endpoints, native completion and
downloaded JSON/SARIF/usage/manifest. Upload only the Action's artifact-directory;
never upload runner temp or the private setup directory. The caller retains only
read permissions and does not publish SARIF, comments or required checks.

Record workflow URL, PR/base/head SHAs, run/snapshot identifiers, status and
downloaded artifacts for each case. Check artifact contracts, not just green jobs.
Native-only preparation is not completed AI review.

| Case | Expected observation |
| --- | --- |
| Introduce URL-to-innerHTML or request-to-eval code in a PR | Inventory scopes the exact current head against its pinned merge base and includes the changed file. Native questions are leads, not confirmed issues. |
| Push an unrelated second file to that PR | Both earlier and later PR changes remain in total PR scope. |
| Ready → draft → ready; close → reopen | Supported lifecycle routing and explicit advisory/skipped statuses; no inherited AI completion. |
| Force-push or retarget the base branch | A fresh pinned contract; original artifacts retain their original endpoints. |
| Push only to the base branch | Manually dispatch the workflow with the PR number. Confirm it reads the current base tip. The current example has no automatic base watcher. |
| Delete a guard, rename a file or change unsupported text | Change records and gaps remain visible; zero native questions never imply safety. |
| Quickly push again or cancel a run | No completed current-review claim from cancellation; downloaded old artifacts remain historical. Hard cancellation can prevent artifact upload. |
| Open an external fork PR | Actual fork checkout/approval behavior and separate base/source namespaces; no model secrets or target build scripts. |
| Merge conflict | Automatic PR workflow can be unavailable; manual PR dispatch may prepare head-only source evidence, without claiming prospective merge coverage. |
| Manual base/target release refs, including divergent history | Direct pinned endpoint comparison, separate from PR merge-base semantics. |

The default caller is native-only; the opt-in caller runs AI and exports advisory
artifacts. Neither publishes comments, custom checks or SARIF to code scanning.
Artifact acceptance can proceed independently of those capabilities.

## SARIF ingestion acceptance, after artifacts work

A separate test-only upload workflow is still to be implemented. Start with
same-repository branches and manual trusted runs, keeping the exact analyzed
commit/ref and source checkout bound to each SARIF upload. Use the official
`github/codeql-action/upload-sarif`, pinned to a reviewed commit. It does not
require installing a GitHub App or running CodeQL analysis.

The upload job needs `security-events: write` and `contents: read`; GitHub also
documents `actions: read` for private repositories. Scope these permissions to
the upload job. Fork upload behavior needs its own observed acceptance; do not
solve a denied write by executing PR code with a privileged event.
[Upload permissions and workflow](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

Use deterministic fixture decisions for transport/fingerprint tests, clearly
labeled synthetic. Test these independently from model correctness:

- Repeated same-snapshot upload and inserting unrelated lines above an operation:
  inspect actual GitHub alert continuity and duplicate behavior.
- Two operations on the same line, and multiple represented source paths to one
  sink: inspect alert separation, primary/related locations and code flows.
- Root versus Changed categories and empty/partial uploads: observe GitHub's
  actual replacement/closure behavior. Custom advisory properties do not prevent
  GitHub from changing its alert state; this is not a production upload policy.
- Dismiss a test alert as a false positive, then modify/reintroduce the source:
  inspect external dismissal behavior separately from native all-verdict history.
  GHAS dismissal must never import a native safe verdict automatically.

Capture alert/analysis IDs and API/UI results, including ingestion completion,
not just the upload request's success. Compare GitHub line hints with native
occurrence/subject keys without assuming GitHub consumes every custom fingerprint.
Keep this synthetic test lane separate from production security analyses.

## GitHub App, when the service exists

An App becomes useful for a continuously running service that receives base-push
and PR events, publishes under a bot identity and supports authorized comment
follow-ups across installed repositories. An Actions-based implementation can
also cover parts of that behavior; registering an App alone does not implement it.
Do not create an active webhook registration before a receiver is available.

Once the receiver and publisher are ready:

1. Open account/organization Settings → Developer settings → GitHub Apps → New
   GitHub App. Name the test registration uniquely, such as `mehscan-test-OWNER`.
   Use the test repository URL as its homepage if there is no service homepage.
2. Set the receiver's actual HTTPS webhook URL, enable SSL verification and
   configure a generated webhook secret in the service secret store and App UI.
   The receiver must verify signatures and persist delivery IDs for deduplication.
3. Start with Contents read and Pull requests read. Add Pull requests write for
   review publication; Checks write for custom checks; Issues read for
   `issue_comment` follow-ups; Code scanning alerts write only if the service
   itself uploads SARIF. Metadata read is implicit. Add no workflow/content write
   permission merely to scan source. Endpoint requirements determine final scopes.
4. Subscribe to `pull_request`, `push`, and, once comment authorization exists,
   `issue_comment`. Installation lifecycle events maintain access state. Add
   review-comment/check rerun/merge-group events only when their handlers exist.
5. Restrict installation to the owning account initially, and install only on the
   test repository. Generate a private key and keep it in the service secret store.
   Use short-lived installation tokens; user OAuth authorization is unnecessary
   for this initial repository bot.
6. Record App ID and installation ID as service configuration. Keep the private
   key and webhook secret out of repository files, artifacts and chat. The App
   publisher holds write credentials separately from the source/model worker.

Registration and permissions:
[Registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app),
[Choosing permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app),
[Installing on selected repositories](https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party).

For now, the user's only external setup is the public test repository and access
to a fork contributor. Tool publication, fixture/upload harness preparation and
hosted acceptance remain explicit next steps; no App credentials are needed yet.
