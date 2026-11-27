# Review experiments

## Work formation

This checkout-only diagnostic compares deterministic work grouping with a bounded provider proposal for the same claims. Run these commands from the repository root.

```sh
python research/review_work_formation_experiment.py prepare --spec CASES.json --scanner PATH_TO_MEHSCAN --config CODEX_CONFIG.json --output FROZEN_DIR
python research/review_work_formation_experiment.py run --output FROZEN_DIR --config CODEX_CONFIG.json --private PRIVATE_DIR
```

`prepare` takes a `mehscanWorkFormationCases/experimental-v1` specification containing application source roots, inventories, permitted lookup files and operation spans with review IDs. It uses the native scanner, records the input and runtime hashes, and makes zero model calls. Choose a new output directory outside the source tree. `run` uses the frozen inputs, a new private directory outside the source tree, and up to three provider calls. Its proposal is diagnostic. A freeze prepared under the former `scripts/` path belongs to that checkout. Keep that checkout to run it, or prepare a new freeze here.

Run the six deterministic experiment checks from the checkout.

```sh
python -m unittest discover -s research -p test_work_formation_experiment.py
```

The existing `python scripts/test-review-suites.py --tier research --output results.json` command includes these checks. Use `--list` for the complete inventory and classifications. Product and smoke executions discover only the worker test directory.

## Routing and hybrid comparison

From the checkout, create a routing proposal for a prepared inventory and bundle manifest. To validate the saved proposal against the same source, replace `--output` with `--check`.

```sh
python research/review_routing.py --source-root SOURCE --inventory INVENTORY --manifest MANIFEST.json --output ROUTES
```

The hybrid comparison consumes `ROUTES/routing.json`. Supply the same planner plan and selections if the proposal used them. The study design enables both batch and hybrid mode.

```sh
python research/review_hybrid.py prepare --routing ROUTES/routing.json --routing-inventory INVENTORY/inventory.json --routing-manifest MANIFEST.json --design DESIGN.json --output STUDY --private PRIVATE_DIR --scanner PATH_TO_MEHSCAN --provider-config CONFIG.json --provider-executable PATH_TO_CODEX
python STUDY/package/research/review_hybrid.py check --root STUDY
python STUDY/package/research/review_hybrid.py run --root STUDY
```

Preparation and checking make zero model calls. Running the comparison uses the study's provider allowance. For an older frozen study, use its original bundled driver under `package/scripts/` so its runtime hashes match.

## Workspace pilot and comparison tests

The eleven `review_workspace*.py` drivers and their workspace, evidence, bridge, routing, audit, and comparison tests live together here. Run the pilot from the repository root with `python research/review_workspace_pilot.py --help`. Frozen pilot packages keep their bundled drivers under `package/scripts/`. The installed worker and provider adapter own the supported review and provider protocols. Run them with the other checkout experiments using `python scripts/test-review-suites.py --tier research --output results.json`. Set `MEHSCAN_TEST_SCANNER` to a built Mehscan CLI for the native integration cases.
