#!/usr/bin/env python3
"""Runs Symbol Hunter over the corpus and compares with corpus_expected.json."""
import json, subprocess, sys, os
CORPUS = sys.argv[1] if len(sys.argv) > 1 else '/opt/work/corpus'
EXP = os.path.join(os.path.dirname(CORPUS.rstrip('/')), os.path.basename(CORPUS.rstrip('/')) + '_expected.json')
if not os.path.exists(EXP): EXP = os.path.join(os.path.dirname(CORPUS.rstrip('/')), 'corpus_expected.json')
OUTJ = '/tmp/corpus_result.json'
r = subprocess.run(['/home/claude/symhunt/build/dev.sh', 'Scan', CORPUS, OUTJ, sys.argv[2] if len(sys.argv) > 2 else '2'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3600)
print(r.stdout.decode().strip().splitlines()[-1] if r.stdout else 'no output')
res = {i['path'].replace('\\', '/'): i for i in json.load(open(OUTJ))['items']}
exp = json.load(open(EXP))
rank = {'None': 0, 'Weak': 1, 'Medium': 2, 'Strong': 3}
ok = bad = 0
for e in exp:
    it = res.get(e['path'])
    errs = []
    if it is None: errs.append('not in results')
    else:
        kinds = {h['kind'] for h in it['hits']}
        best = max([rank[h['strength']] for h in it['hits']] or [0])
        if e.get('partof'):
            if it['status'] != 'PartOfSet': errs.append('should be part of a set, status=' + it['status'])
        else:
            for k in e['must']:
                if k not in kinds: errs.append('missing ' + k)
            if not e['must'] and best > rank[e['max']]: errs.append('unexpected ' + ', '.join(f"{h['kind']}({h['strength']}) at {h['where']}" for h in it['hits'] if rank[h['strength']] > rank[e['max']])[:300])
            if 'volumes' in e and len(it['volumes']) != e['volumes']: errs.append(f"volumes {len(it['volumes'])} != {e['volumes']}")
            for pk in e.get('problems', []):
                if not any(p['kind'] == pk for p in it['problems']): errs.append('expected a ' + pk + ' problem, got: ' + '; '.join(p['kind'] + ': ' + p['message'] for p in it['problems'])[:200])
            hard = [p for p in it['problems'] if p['kind'] not in ('warning',)]
            if hard and not e.get('partial_ok'): errs.append('problems: ' + '; '.join(p['kind'] + ': ' + p['where'] + ': ' + p['message'] for p in hard)[:300])
    if errs: bad += 1; print('FAIL', e['path'], '->', ' | '.join(errs))
    else: ok += 1
extra = [p for p in res if p not in {e['path'] for e in exp}]
for p in extra: print('NOTE unexpected item', p)
print(f'\n{ok}/{ok + bad} corpus items as expected')
