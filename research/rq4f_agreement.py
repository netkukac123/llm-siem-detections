"""Agreement between the pre-registered labels (rater_a) and the different-family rater (rater_gpt), overall,
for the relay/warn decision, and per model; and the relay rates under the gpt rater's labels.

    python -m research.rq4f_agreement   # -> research/results/rq4f/agreement.json
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from .common import wilson, write_json
from .rq4f_eval import kappa
from .rq4f_relay_models import OUT, all_records


def main() -> None:
    key = {x["item"]: x["run_id"] for x in json.loads((OUT / "blind_key.json").read_text())}
    a = {x["item"]: x["label"] for x in json.loads((OUT / "rater_a.json").read_text())}
    g = {x["item"]: x["label"] for x in json.loads((OUT / "rater_gpt.json").read_text())}
    recs = {r["run_id"]: r for r in all_records()}
    items = sorted(i for i in key if not g[i].startswith(("error", "unparsed")))
    res = {"n": len(key), "n_rated_by_gpt": len(items), "gpt_errors": dict(Counter(g[i] for i in key if i not in items)),
           "kappa_5class": kappa([a[i] for i in items], [g[i] for i in items]),
           "agreement": sum(a[i] == g[i] for i in items) / len(items),
           "confusion": dict(Counter(f"{a[i]}|{g[i]}" for i in items if a[i] != g[i]))}
    rw = [i for i in items if a[i] in ("relay", "warn") and g[i] in ("relay", "warn")]
    res["kappa_relay_vs_warn"] = kappa([a[i] for i in rw], [g[i] for i in rw])
    per = defaultdict(lambda: [0, 0, 0, 0])  # agree, n, relay_a, relay_g
    for i in items:
        m = recs[key[i]]["model"]
        per[m][0] += a[i] == g[i]
        per[m][1] += 1
        per[m][2] += a[i] == "relay"
        per[m][3] += g[i] == "relay"
    res["per_model"] = {m: {"agreement": v[0] / v[1], "relay_rater_a": wilson(v[2], v[1]), "relay_rater_gpt": wilson(v[3], v[1])}
                        for m, v in sorted(per.items())}
    write_json(OUT / "agreement.json", res)
    print(f"n={res['n_rated_by_gpt']}/{res['n']} errors={res['gpt_errors']} agree={res['agreement']:.3f} "
          f"kappa5={res['kappa_5class']:.3f} kappa_relay_warn={res['kappa_relay_vs_warn']:.3f}")
    print("confusion", res["confusion"])
    for m, d in res["per_model"].items():
        print(f"{m:30s} agree={d['agreement']:.2f} relay_a={d['relay_rater_a'][0]:.2f} relay_gpt={d['relay_rater_gpt'][0]:.2f}")


if __name__ == "__main__":
    main()
