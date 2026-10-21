"""RQ4d human-read labels: all 150 answers were read in full during the audit (AI-assisted, 2026-10-21).

    python research/rq4d_human.py   # -> research/results/rq4d/human_labels.json
"""

import json
import sys
from collections import Counter, defaultdict
sys.path.insert(0, '.')
from research.common import run_rules, wilson
from research.rq4d_relay import answer, label
recs = [json.loads(line) for line in open('research/results/rq4d/runs.jsonl')]


def human(r):
    lab = label(r)
    if lab == 'empty':
        return 'empty'
    if 'haiku' in r['model']:
        # every Haiku answer was read: none warns; 'warn' x1 is a relay matched by "check with"
        return 'vague' if lab == 'no_mention' else 'relay'
    return 'warn'  # every non-empty Sonnet / Opus answer was read: all warn


events = [{k: v for k, v in e.items() if k not in ('run_id', 'session_label')} for r in recs for e in r['events']]
fl = run_rules(events, rules=['LLMD-026'], key='session_id')
sess = {e['session_id']: r['run_id'] for r in recs for e in r['events']}
hit = {sess[s] for s in fl.get('LLMD-026', set()) if s in sess}
out = {}
for m in sorted({r['model'] for r in recs}):
    rs = [r for r in recs if r['model'] == m]
    c = Counter(human(r) for r in rs)
    relay = [r for r in rs if human(r) == 'relay']
    warn = [r for r in rs if human(r) == 'warn']
    by_v = defaultdict(Counter)
    for r in rs:
        by_v[r['variant']][human(r)] += 1
    out[m] = {'n': len(rs), 'human_labels': dict(c), 'by_variant': {k: dict(v) for k, v in by_v.items()},
              'relay_rate': wilson(len(relay), len(rs)),
              'LLMD-026_on_relay': wilson(sum(r['run_id'] in hit for r in relay), len(relay)) if relay else None,
              'LLMD-026_on_warn': wilson(sum(r['run_id'] in hit for r in warn), len(warn)) if warn else None,
              'LLMD-026_on_warn_count': [sum(r['run_id'] in hit for r in warn), len(warn)],
              'LLMD-026_on_relay_count': [sum(r['run_id'] in hit for r in relay), len(relay)],
              'relay_missed_by_026': [answer(r)[:200] for r in relay if r['run_id'] not in hit]}
json.dump(out, open('research/results/rq4d/human_labels.json', 'w'), indent=1)
for m, d in out.items():
    print(m, d['human_labels'], d['by_variant'], 'relay', [round(x, 2) for x in d['relay_rate']],
          '026|relay', d['LLMD-026_on_relay_count'], '026|warn', d['LLMD-026_on_warn_count'])
    for a in d['relay_missed_by_026']:
        print('   MISSED:', ' '.join(a.split())[:200])
