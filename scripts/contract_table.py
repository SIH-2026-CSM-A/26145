"""Print the engineered-feature table for docs/MODELS.md from feature_contract.toml.

    uv run python scripts/contract_table.py            # print
    uv run python scripts/contract_table.py --write    # replace the table in docs/MODELS.md

tests/training/test_models_doc.py fails if the table in MODELS.md drifts from the contract.
"""

import os
import sys

from sih26145.contract import load_contract

DOC = os.path.join(os.path.dirname(__file__), "..", "docs", "MODELS.md")
START, END = "<!-- contract-table:start -->", "<!-- contract-table:end -->"


def table() -> str:
    c = load_contract()
    used = {name: [k for k, v in c.consumers.items() if name in v.reads] for name in c.features}
    lines = [f"Contract version {c.version}: {len(c.features)} features. `ML` = read by the models "
             f"(`ml_flow_models`, {len(c.consumer('ml_flow_models').reads)} features).", "",
             "| Feature | ML | State | Tier | Approx. | Sources | Read by | Definition and caveats |",
             "|---|---|---|---|---|---|---|---|"]
    for f in c.features.values():
        readers = ", ".join(r for r in used[f.name] if r != "ml_flow_models") or "—"
        ml = "yes" if "ml_flow_models" in used[f.name] else ""
        reason = f.reason.replace("|", "\\|")
        lines.append(f"| `{f.name}` | {ml} | {f.state} | {f.tier} | {f.approx} | {', '.join(f.sources) or '—'} "
                     f"| {readers} | {reason} |")
    return "\n".join(lines)


def replaced(doc: str) -> str:
    a, b = doc.index(START) + len(START), doc.index(END)
    return doc[:a] + "\n" + table() + "\n" + doc[b:]


if __name__ == "__main__":
    if "--write" in sys.argv:
        with open(DOC) as fh:
            doc = fh.read()
        with open(DOC, "w") as fh:
            fh.write(replaced(doc))
    else:
        print(table())
