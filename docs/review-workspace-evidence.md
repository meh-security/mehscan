# Shared deciding evidence (experimental)

The opt-in bridge `prepare-evidence` command supplies source and local dependency
observations before a reviewer asks for them. It does not answer a security
question, establish caller applicability, or transfer a verdict. It is not wired
into ordinary review scheduling.

Run work planning first, then prepare evidence, then create a fresh review
session. Use the same native binding arguments as bridge `init`:

```text
python scripts/review_workspace_bridge.py prepare-evidence <native binding arguments> --evidence-request request.json --operation-key deciding-evidence-1
```

`request.json` has this shape; replace the sample path, hash and work ID with
actual source-bound values:

```json
{
  "version": "mehscanDecidingEvidence/experimental-v1",
  "targets": [{
    "work_id": "selected-work-id",
    "question": "Does assigning the body owner constrain the path-selected update?",
    "windows": [{
      "path": "lib/guard.ts",
      "start_line": 10,
      "end_line": 20,
      "file_sha256": "full-file-sha256"
    }],
    "packages": ["example-package"]
  }]
}
```

Each target needs a deciding question and at least one source window or package.
The controller chooses exact targets; there is no semantic retrieval, automatic
helper/caller matching or model grouping pass. Native AST/source receipts can
identify a helper window; a filename or shared category alone is not sufficient
to establish its relevance. Existing propositions/notebooks remain the path for
source-backed interpretations with conditions and exclusions.

Source is captured once in SQLite, against the supplied whole-file hash, and
delivered to each selected work context. Package observations are also stored
once by content identity, with separate question/consumer references. Source
text still reaches each independent reviewer context: database deduplication is
not a claim of avoided model input or conversation replay.

For each named package, inspect only root `package.json`, `package-lock.json`,
`npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, and
`node_modules/<package>/package.json`. Record declarations, an installed manifest
version if present, and explicit present/hash or missing receipts for those
paths. A declaration is not a resolved version. An installed manifest is not
proof of deployment. Lockfile contents are not interpreted. Workspace, nested,
PnP/global resolution, entrypoints and runtime behavior are not established.
No package installation, application execution, network retrieval or evaluator
dependency source is used.

Revalidate metadata and captured source when rendering a context or replaying
preparation. A previously missing file becoming present invalidates the receipt.
Symlinks and supported Windows junction detection reject linked metadata paths.
Reads use existing bounded source-file limits; hashes require local I/O on view
construction. Metadata hash I/O is not reported as model input or captured source
bytes. Only selected observations enter a work context. Bounds are 16 targets,
8 windows and 4 packages per target, 8 receipts per work, existing source budgets,
and 128 KiB maximum prepared context. Preparation is one atomic transaction;
late failure rolls back earlier captures. Identical operation retries reuse
receipts; changed requests fail. Model interpretation updates cannot invoke it.

Splits inherit supplied evidence and its unresolved questions, without gaining
any applicability judgment. Adding evidence changes the context and requires a
new explicit session; it cannot silently mutate an existing session. Planning
cannot replace work after deciding evidence is prepared.

## Stop or dig deeper

After a local metadata receipt, do not repeat the same path search expecting new
information. Dig deeper when a specific alternative can establish the remaining
contract: a resolved lock entry, an authorized dependency source location, or a
version-pinned reference whose relationship to deployment is explicitly limited.
This release of the experimental controller does not automatically resolve those
alternatives or suppress reviewer requests. It supplies the facts for the
reviewer's next decision.

Missing checked metadata alone cannot justify a safe verdict or a global
unavailability statement. If no concrete alternative is available within scope,
retain the exact unresolved check-to-effect relationship as `needs_review`.
Shared guard source also cannot establish how every caller uses the mutated
field. Keep that question separate from what the helper does.

The [offline check](experiments/review-workspace-evidence-results.md) validates
delivery, provenance, freshness and rollback. Live savings and security quality
remain untested for this new path.
