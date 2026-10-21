"""Build every figure and table of the paper from research/results/*.

    python -m research.report        # -> paper/figures/*.pdf, paper/tables/*.tex

Numbers in the paper are never typed by hand: they come from here.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .common import RESULTS, ROOT  # noqa: E402

PAPER = ROOT / "paper"
FIG = PAPER / "figures"
TAB = PAPER / "tables"

# Reference palette (validated: categorical slots 1-5 pass CVD/normal-vision checks on light surface).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
SEQ = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
INK, INK2, MUTED, GRID, AXIS, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": AXIS, "axes.labelcolor": INK2,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.facecolor": SURFACE, "figure.facecolor": "white",
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.spines.top": False,
    "axes.spines.right": False, "axes.titlesize": 9, "axes.titlecolor": INK, "legend.frameon": False,
})


def _load(rel):
    p = RESULTS / rel
    return json.loads(p.read_text()) if p.exists() else None


def pct(x, digits=1):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{100 * x:.{digits}f}"


def ci(t, digits=1):
    if not t or any(isinstance(v, float) and math.isnan(v) for v in t):
        return "n/a"
    return f"{pct(t[0], digits)} [{pct(t[1], digits)}, {pct(t[2], digits)}]"


def tex_escape(s: str) -> str:
    return s.replace("_", r"\_").replace("&", r"\&").replace("%", r"\%")


def short_ds(name: str) -> str:
    return {"deepset/prompt-injections": "deepset", "Lakera/gandalf_ignore_instructions": "Lakera Gandalf",
            "neuralchemy/Prompt-injection-dataset": "neuralchemy", "reshabhs/SPML_Chatbot_Prompt_Injection": "SPML",
            "TrustAIRLab/in-the-wild-jailbreak-prompts": "TrustAIRLab ITW", "jackhhao/jailbreak-classification":
            "jackhhao", "microsoft/llmail-inject-challenge": "LLMail-Inject", "geodesic-research/bipia": "BIPIA",
            "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1": "Nemotron agentic IPI",
            "MCPTox/pure_tool": "MCPTox (poisoned)", "wwh0411/MCP-Flow": "MCP-Flow (benign)",
            "OpenAssistant/oasst2": "OASST2", "databricks/databricks-dolly-15k": "Dolly-15k",
            "allenai/WildChat-1M": "WildChat-1M"}.get(name, name)


# ---------------------------------------------------------------- RQ2

def rq2():
    s = _load("rq2/summary.json")
    if not s:
        return
    TAB.mkdir(parents=True, exist_ok=True)
    rows = [r for r in s["labelled"] if r["rule"] == "any"]
    lines = [r"\begin{tabular}{llrrll}", r"\toprule",
             r"Dataset & Surface & $n$ & Attacks & Recall \% [95\% CI] & FPR \% [95\% CI] \\", r"\midrule"]
    for r in sorted(rows, key=lambda r: (r["kind"], short_ds(r["dataset"]))):
        lines.append(f"{tex_escape(short_ds(r['dataset']))} & {r['kind'].replace('_', ' ')} & {r['n']:,} & "
                     f"{r['positives']:,} & {ci(r.get('recall'))} & {ci(r.get('fpr'), 2)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / "rq2_datasets.tex").write_text("\n".join(lines) + "\n")

    lines = [r"\begin{tabular}{llrlrl}", r"\toprule",
             r"Surface & Rule & Benign $n$ & FPR \% [95\% CI] & Attack $n$ & Recall \% [95\% CI] \\", r"\midrule"]
    for r in s["pooled"]:
        lines.append(f"{r['kind'].replace('_', ' ')} & {r['rule'].replace('any', 'any rule')} & {r['benign_n']:,} & "
                     f"{ci(r['fpr'], 2)} & {r['attack_n']:,} & {ci(r['recall'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / "rq2_pooled.tex").write_text("\n".join(lines) + "\n")
    unl = [r for r in s["unlabelled"] if r["rule"] == "any"]
    (TAB / "rq2_unlabelled.tex").write_text(
        "".join(f"{short_ds(r['dataset'])}: {pct(r['alert_rate'][0], 2)}\\% of {r['n']:,} prompts\n" for r in unl))


# ---------------------------------------------------------------- RQ3

DETECTOR_LABEL = {"rules": "Rule pack", "protectai-deberta-v3-base-v2": "ProtectAI DeBERTa-v3 v2",
                  "prompt-guard-2-22m": "Prompt Guard 2 (22M)"}


def rq3():
    s = _load("rq3/summary.json")
    if not s or not s["rows"]:
        return
    FIG.mkdir(parents=True, exist_ok=True)
    clean = [r for r in s["rows"] if r["contamination"] == "clean" and r.get("positives")]
    datasets = sorted({r["dataset"] for r in clean}, key=short_ds)
    detectors = ["rules", *DETECTOR_LABEL.keys() - {"rules"}]
    detectors = [d for d in ["rules", "protectai-deberta-v3-base-v2", "prompt-guard-2-22m"]
                 if any(r["variant"] == d for r in clean)]
    fig, ax = plt.subplots(figsize=(6.6, 0.32 * len(datasets) + 1.0))
    for k, det in enumerate(detectors):
        ys, xs, lo, hi = [], [], [], []
        for i, ds in enumerate(datasets):
            r = next((r for r in clean if r["dataset"] == ds and r["variant"] == det), None)
            if r and "recall" in r:
                ys.append(i + (k - 1) * 0.22)
                xs.append(100 * r["recall"][0])
                lo.append(100 * (r["recall"][0] - r["recall"][1]))
                hi.append(100 * (r["recall"][2] - r["recall"][0]))
        ax.errorbar(xs, ys, xerr=[lo, hi], fmt="o", ms=4.5, color=SERIES[k], ecolor=SERIES[k], elinewidth=1,
                    capsize=0, label=DETECTOR_LABEL[det], markeredgecolor=SURFACE, markeredgewidth=0.8)
    ax.set_yticks(range(len(datasets)), [short_ds(d) for d in datasets])
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Recall on attack items (%), 95% bootstrap CI")
    ax.legend(loc="lower right", ncol=1)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(FIG / "rq3_recall.pdf")
    plt.close(fig)

    lines = [r"\begin{tabular}{llrll}", r"\toprule",
             r"Dataset & Detector & $n$ & Recall \% [95\% CI] & FPR \% [95\% CI] \\", r"\midrule"]
    for r in sorted(s["rows"], key=lambda r: (r["contamination"] != "clean", short_ds(r["dataset"]), r["variant"])):
        if r["classifier"] != "protectai-deberta-v3-base-v2" and r["variant"] == "rules":
            continue  # print the rules row once
        mark = "" if r["contamination"] == "clean" else (r"$^\dagger$" if r["contamination"] == "definite" else "$^*$")
        lines.append(f"{tex_escape(short_ds(r['dataset']))}{mark} & {tex_escape(DETECTOR_LABEL.get(r['variant'], r['variant']))} "
                     f"& {r['n']:,} & {ci(r.get('recall'))} & {ci(r.get('fpr'), 2)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    TAB.mkdir(parents=True, exist_ok=True)
    (TAB / "rq3_full.tex").write_text("\n".join(lines) + "\n")

    fig, ax = plt.subplots(figsize=(3.3, 2.8))
    for k, (name, curve) in enumerate(s["pr_curves"].items(), start=1):
        pts = [(c["recall"], c["precision"]) for c in curve if not math.isnan(c["precision"])]
        ax.plot([100 * p[0] for p in pts], [100 * p[1] for p in pts], color=SERIES[k], lw=2,
                label=DETECTOR_LABEL.get(name, name))
    ax.set_xlabel("Recall (%)")
    ax.set_ylabel("Precision (%)")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 101)
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(FIG / "rq3_pr.pdf")
    plt.close(fig)


# ---------------------------------------------------------------- RQ1

def rq1():
    s = _load("rq1/summary.json")
    if not s:
        return
    FIG.mkdir(parents=True, exist_ok=True)
    TAB.mkdir(parents=True, exist_ok=True)
    models = sorted({r["model"] for r in s["by_model_scenario"]})
    scens = sorted({r["scenario"] for r in s["by_model_scenario"]})
    grid = {(r["model"], r["scenario"]): r for r in s["by_model_scenario"]}
    for metric, fname, title in (("compliance", "rq1_compliance.pdf", "Attack compliance (%)"),
                                 ("asr", "rq1_asr.pdf", "Attack success, harm achieved (%)")):
        fig, ax = plt.subplots(figsize=(6.6, 0.3 * len(scens) + 1.1))
        for i, sc in enumerate(scens):
            for j, m in enumerate(models):
                r = grid.get((m, sc))
                v = r[metric][0] if r else float("nan")
                colour = SURFACE if math.isnan(v) else SEQ[min(6, int(v * 6.999))]
                ax.add_patch(plt.Rectangle((j, i), 0.96, 0.92, color=colour, lw=0))
                if not math.isnan(v):
                    ax.text(j + 0.48, i + 0.46, f"{100 * v:.0f}", ha="center", va="center", fontsize=7,
                            color="white" if v > 0.55 else INK)
        ax.set_xlim(0, len(models))
        ax.set_ylim(len(scens), 0)
        ax.set_xticks([j + 0.48 for j in range(len(models))], models)
        ax.set_yticks([i + 0.46 for i in range(len(scens))], scens)
        ax.grid(False)
        ax.set_title(title, loc="left")
        for side in ("left", "bottom"):
            ax.spines[side].set_visible(False)
        ax.tick_params(length=0)
        fig.tight_layout()
        fig.savefig(FIG / fname)
        plt.close(fig)
    lines = [r"\begin{tabular}{lrllll}", r"\toprule",
             r"Model & Runs & Compliance \% & Harm \% & Detected $\mid$ compliance \% & Benign FP \% \\",
             r"\midrule"]
    # Claude rows here are the exploratory RQ5 run; the paper reports Claude from the confirmatory run (rq5c)
    for r in (r for r in s["by_model"] if not r["model"].startswith("anthropic:")):
        lines.append(f"{tex_escape(r['model'])} & {r['attack_runs']} & {ci(r['compliance'])} & {ci(r['asr'])} & "
                     f"{ci(r['detected_given_compliance'])} & {ci(r['benign_fp'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / "rq1_models.tex").write_text("\n".join(lines) + "\n")

    # Pooled over models: detection given compliance per scenario.
    rows = _load("rq1/per_run.json") or []
    by = defaultdict(list)
    for r in rows:
        if not r["benign"] and not r["error"] and r["complied"]:
            by[r["scenario"]].append(r["intended_hit"])
    lines = [r"\begin{tabular}{lrl}", r"\toprule", r"Scenario & Complied runs & Detected \% [95\% CI] \\",
             r"\midrule"]
    from .common import wilson
    for sc in scens:
        v = by.get(sc, [])
        lines.append(f"{tex_escape(sc)} & {len(v)} & {ci(wilson(sum(v), len(v)))} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / "rq1_detection.tex").write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------- RQ4

def rq4():
    s = _load("rq4/summary.json")
    if not s:
        return
    FIG.mkdir(parents=True, exist_ok=True)
    TAB.mkdir(parents=True, exist_ok=True)
    off = s.get("offline") or []
    if off:
        ops = [r["operator"] for r in off]
        dets = [k for k in off[0] if k not in ("operator", "n")]
        fig, ax = plt.subplots(figsize=(6.6, 0.3 * len(ops) + 1.0))
        for k, d in enumerate(dets):
            ax.plot([100 * r[d][0] for r in off], [i + (k - 1) * 0.2 for i in range(len(ops))], "o",
                    color=SERIES[k], ms=4.5, label=DETECTOR_LABEL.get(d.replace("clf:", ""), d),
                    markeredgecolor=SURFACE, markeredgewidth=0.8)
        ax.set_yticks(range(len(ops)), [o.replace("_", " ") for o in ops])
        ax.invert_yaxis()
        ax.set_xlim(0, 100)
        ax.set_xlabel("Mutants still detected (%)")
        ax.grid(axis="y", visible=False)
        ax.legend(loc="lower right")
        fig.tight_layout()
        fig.savefig(FIG / "rq4_offline.pdf")
        plt.close(fig)
    live = s.get("live") or []
    if live:
        lines = [r"\begin{tabular}{lllrlll}", r"\toprule",
                 r"Scenario & Operator & Model & $n$ & Compliance \% & Detected $\mid$ comp. \% & Evasive+working \% \\",
                 r"\midrule"]
        for r in live:
            lines.append(f"{tex_escape(r['scenario'][:3])} & {tex_escape(r['operator'])} & {tex_escape(r['model'])} & "
                         f"{r['n']} & {pct(r['compliance'][0])} & {pct(r['detected_given_compliance'][0])} & "
                         f"{pct(r['evasion_preserving'][0])} \\\\")
        lines += [r"\bottomrule", r"\end{tabular}"]
        (TAB / "rq4_live.tex").write_text("\n".join(lines) + "\n")


def rq3_pooled():
    """Clean datasets pooled per surface; rules rows counted once (they repeat per classifier)."""
    s = _load("rq3/summary.json")
    if not s:
        return
    from .common import wilson
    agg = defaultdict(lambda: [0, 0, 0, 0])
    for r in s["rows"]:
        if r["contamination"] != "clean":
            continue
        if r["variant"] == "rules" and r["classifier"] != "protectai-deberta-v3-base-v2":
            continue
        a = agg[(r["kind"], r["variant"])]
        a[0] += r["tp"]; a[1] += r["fn"]; a[2] += r["fp"]; a[3] += r["tn"]
    rows = [("prompt", "rules"), ("prompt", "protectai-deberta-v3-base-v2"), ("prompt", "prompt-guard-2-22m"),
            ("document", "rules"), ("document", "protectai-deberta-v3-base-v2"), ("document", "prompt-guard-2-22m"),
            ("tool_description", "rules"), ("tool_description", "protectai-deberta-v3-base-v2"),
            ("tool_description", "rules OR protectai-deberta-v3-base-v2")]
    lab = {"rules": "rules", "protectai-deberta-v3-base-v2": "DeBERTa v2", "prompt-guard-2-22m": "Prompt Guard 2",
           "rules OR protectai-deberta-v3-base-v2": "rules OR DeBERTa v2"}
    lines = [r"\begin{tabular}{llrlrl}", r"\toprule",
             r"Surface & Detector & Attacks & Recall \% [95\% CI] & Benign & FPR \% [95\% CI] \\", r"\midrule"]
    for k, v in rows:
        tp, fn, fp, tn = agg[(k, v)]
        lines.append(f"{k.replace('_', ' ')} & {lab[v]} & {tp + fn:,} & {ci(wilson(tp, tp + fn))} & {fp + tn:,} & "
                     f"{ci(wilson(fp, fp + tn), 2)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    TAB.mkdir(parents=True, exist_ok=True)
    (TAB / "rq3_pooled.tex").write_text("\n".join(lines) + "\n")


def rq4_offline():
    rows = _load("rq4/offline_results.json")
    if not rows:
        return
    from .common import wilson
    dets = ["rules", "clf:protectai-deberta-v3-base-v2", "clf:prompt-guard-2-22m"]
    by = defaultdict(list)
    for r in rows:
        by[r["operator"]].append(r)
    order = ["original"] + sorted((o for o in by if o != "original"),
                                  key=lambda o: sum(r["rules"] for r in by[o]) / len(by[o]))
    lines = [r"\begin{tabular}{lrllll}", r"\toprule",
             r"Operator & $n$ & Rules \% & DeBERTa v2 \% & Prompt Guard 2 \% & Any \% \\", r"\midrule"]
    for o in order:
        rs = by[o]
        cells = [ci(wilson(sum(bool(r[d]) for r in rs), len(rs)), 0) for d in dets]
        cells.append(ci(wilson(sum(any(r[d] for d in dets) for r in rs), len(rs)), 0))
        lines.append(f"{tex_escape(o.replace('_', ' '))} & {len(rs)} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    TAB.mkdir(parents=True, exist_ok=True)
    (TAB / "rq4_offline.tex").write_text("\n".join(lines) + "\n")


def short_model(m: str) -> str:
    return {"anthropic:claude-haiku-4-5": "Haiku 4.5", "anthropic:claude-sonnet-5-5": "Sonnet 5.5",
            "anthropic:claude-opus-5-5": "Opus 5.5", "anthropic:claude-opus-4-8": "Opus 4.8"}.get(m, m)


def rq5c():
    s = _load("rq5c/summary.json")
    if not s:
        return
    TAB.mkdir(parents=True, exist_ok=True)
    FIG.mkdir(parents=True, exist_ok=True)
    keys = ["compliance", "success", "OUTPUT_recall", "OUTPUT_plus_refusal_recall", "benign_refusal_signal_rate"]
    lines = [r"\begin{tabular}{lllll}", r"\toprule",
             r"Model & Completed attack \% & Action-only rules \% & Action + refusal signal \% & Benign signal \% \\",
             r"\midrule"]
    for m, d in s["by_model"].items():
        if m == "pooled":
            lines.append(r"\midrule")
        lines.append(f"{short_model(m).capitalize()} & " + " & ".join(ci(d[k], 0) for k in keys[1:]) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / "rq5c_models.tex").write_text("\n".join(lines) + "\n")

    lines = [r"\begin{tabular}{lrll}", r"\toprule",
             r"Scenario & Completed attacks & Output-content rules \% & Behavioural rules \% \\", r"\midrule"]
    for sc, d in s["per_scenario"].items():
        if d.get("n_success"):
            lines.append(f"{tex_escape(sc)} & {d['n_success']} & {ci(d['output_content'], 0)} & "
                         f"{ci(d['behavioural'], 0)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / "rq5c_scenarios.tex").write_text("\n".join(lines) + "\n")

    # the main figure: what an action-only SIEM sees vs. with the refusal signal, per model
    models = [m for m in s["by_model"] if m != "pooled"]
    fig, ax = plt.subplots(figsize=(6.6, 1.9))
    for k, (key, lab) in enumerate((("success", "Attack completed"), ("OUTPUT_recall", "Seen by action-only rules"),
                                    ("OUTPUT_plus_refusal_recall", "Seen with the refusal signal"))):
        for i, m in enumerate(models):
            v = s["by_model"][m][key]
            y = i + (k - 1) * 0.24
            ax.errorbar([100 * v[0]], [y], xerr=[[100 * (v[0] - v[1])], [100 * (v[2] - v[0])]], fmt="o", ms=5,
                        color=SERIES[k], ecolor=SERIES[k], elinewidth=1, capsize=0,
                        markeredgecolor=SURFACE, markeredgewidth=0.8, label=lab if i == 0 else None)
    ax.set_yticks(range(len(models)), [short_model(m) for m in models])
    ax.invert_yaxis()
    ax.set_xlim(-2, 100)
    ax.set_xlabel("Share of 100 attack sessions per model (%), Wilson 95% CI")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.38), ncol=3)
    fig.tight_layout()
    fig.savefig(FIG / "rq5c_coverage.pdf")
    plt.close(fig)


def rq4d():
    s = _load("rq4d/human_labels.json")  # from research/rq4d_human.py
    if not s:
        return
    lines = [r"\begin{tabular}{lrrrrl}", r"\toprule",
             r"Model & Runs & Relays & Warns & Empty & \llmd{026} fired \\", r"\midrule"]
    order = ["anthropic:claude-haiku-4-5", "anthropic:claude-sonnet-5-5", "anthropic:claude-opus-5-5",
             "anthropic:claude-opus-4-8"]
    for m in order:
        d = s[m]
        lab = d["human_labels"]
        if lab.get("relay"):
            fired = f"{d['LLMD-026_on_relay_count'][0]} of {d['LLMD-026_on_relay_count'][1]} relays"
        else:
            fired = f"{d['LLMD-026_on_warn_count'][0]} of {d['LLMD-026_on_warn_count'][1]} warnings"
        lines.append(f"{short_model(m)} & {d['n']} & {lab.get('relay', 0)} & {lab.get('warn', 0)} & "
                     f"{lab.get('empty', 0)} & {fired} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    TAB.mkdir(parents=True, exist_ok=True)
    (TAB / "rq4d_relay.tex").write_text("\n".join(lines) + "\n")


def static_tables():
    """Appendix rule table and the model list, from the rule YAMLs and the RQ1 manifest."""
    import yaml
    TAB.mkdir(parents=True, exist_ok=True)
    gen = PAPER / "generated"
    gen.mkdir(parents=True, exist_ok=True)
    lines = [r"\begin{tabular}{lp{7.2cm}ll}", r"\toprule", r"ID & Detection & OWASP & MITRE ATLAS \\", r"\midrule"]
    for p in sorted((ROOT / "detections" / "sentinel").glob("LLMD-*.yaml")):
        r = yaml.safe_load(p.read_text())
        owasp = ", ".join(t.split(" ", 1)[0].removeprefix("OWASP-").split(":")[0] for t in r["tags"] if t.startswith("OWASP"))
        atlas = ", ".join(t.split(" ")[1].removeprefix("AML.") for t in r["tags"] if t.startswith("ATLAS"))
        lines.append(f"{r['name'][:8]} & {tex_escape(r['name'][9:])} & {owasp} & {atlas} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / "rules.tex").write_text("\n".join(lines) + "\n")
    # Models = whatever has run records (two collectors run in parallel, local and Azure).
    runs = sorted((RESULTS / "rq1" / "runs").glob("*.jsonl"))
    tags = sorted({json.loads(line)["model"] for p in runs for line in p.open() if line.strip()})
    local = [t for t in tags if not t.startswith(("azure:", "anthropic:"))]
    azure = [t.removeprefix("azure:") for t in tags if t.startswith("azure:")]
    (gen / "models.tex").write_text(", ".join(rf"\texttt{{{x}}}" for x in local))
    (gen / "azure_models.tex").write_text(", ".join(rf"\texttt{{{x}}}" for x in azure))


def main() -> None:
    static_tables()
    for fn in (rq2, rq3, rq3_pooled, rq1, rq4, rq4_offline, rq5c, rq4d):
        fn()
    print("figures:", sorted(p.name for p in FIG.glob("*.pdf")) if FIG.exists() else [])
    print("tables:", sorted(p.name for p in TAB.glob("*.tex")) if TAB.exists() else [])


if __name__ == "__main__":
    main()
