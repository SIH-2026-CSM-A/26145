"""Every figure the dashboard's model card quotes appears verbatim in docs/MODELS.md."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_model_card_facts_are_quoted_from_models_md():
    doc = (ROOT / "docs" / "MODELS.md").read_text()
    card = json.loads((ROOT / "dashboard" / "src" / "modelCard.json").read_text())
    for item in card["items"]:
        assert item["facts"], item["label"]
        for fact in item["facts"]:
            assert fact in doc, f"{item['label']}: {fact!r} is not in MODELS.md"
            assert fact.lower() in item["text"].lower(), f"{item['label']}: the card text must show {fact!r}"
