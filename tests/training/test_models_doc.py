"""docs/MODELS.md carries the feature table generated from feature_contract.toml."""

import importlib.util
import os

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "contract_table.py")


def test_models_doc_feature_table_matches_the_contract():
    spec = importlib.util.spec_from_file_location("contract_table", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with open(mod.DOC) as fh:
        doc = fh.read()
    assert mod.replaced(doc) == doc, "regenerate: uv run python scripts/contract_table.py --write"
