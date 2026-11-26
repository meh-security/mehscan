# Work-formation experiment

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
