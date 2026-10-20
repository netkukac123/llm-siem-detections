# Evidence standard for this study

Rules the study follows so that every claim can be checked, not taken on trust.

1. **Novelty is claimed only after a prior-art search.** The search, its sources (opened and
   verified) and the verdict per idea are recorded in `docs/research/prior-art.md`. Anything that
   exists already is called a reproduction or an extension and the prior work is cited.
2. **Hypotheses are pre-registered.** Before an experiment on a new technique runs, its hypotheses,
   design, metrics, sample size and decision criteria are committed to `docs/research/`. The git
   commit timestamp precedes the first run; deviations are listed in the paper.
3. **Measurements, not anecdotes.** Every number comes from scripts in `research/` over raw
   per-run records kept in `research/results/`, with Wilson or bootstrap 95% intervals. Success is
   judged by unit-tested oracles on side effects, independent of the detection rules.
4. **Negative and null results are reported** with the same prominence as positive ones.
5. **Reproducible by one command per experiment**, with model tags, seeds and software versions
   in run manifests.
6. **Scope.** Attacks are run only against the project's own demo agent and models the author
   controls or rents (local Ollama, the author's Azure deployment). No third-party product or
   service is attacked.
