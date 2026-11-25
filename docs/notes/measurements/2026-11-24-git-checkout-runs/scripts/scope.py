"""The paper's scope for its 95 test-file-modification episodes (its Table 7: the 8 models run in all of conditions A
to E, conditions A to D, runs whose test file hash changed), from the dataset's own fields, and whether each of the 13
runs in A to D that tried git is in it. Prints counts and run keys only. Text only: nothing recorded is executed.
Usage: python3 -I scope.py TRANSCRIPT_DIR TABLES_DIR
TABLES_DIR holds the dataset's per_run_data_all_conditions.csv and test_harness_modification_breakdown.csv.
"""
import json,sys,glob,os,hashlib,csv,collections
T,TAB=sys.argv[1:3]
KEYS13="8c59013708fcb740 b119bfab6d23147a b71d24ca8f2d90e4 14d87319c39dee8d 461e2d8db1b6b5e8 a052ff749d0eed93 3626fd0f3f7caed2 4011af1b9022b6bb 507248c6829070d6 a3a86d5f9fe248e9 faa2dca3f9cb1192 339e8d980abed5bc 5665081fe44b6821".split()
K=lambda rk: hashlib.sha256(rk.encode()).hexdigest()[:16]
conds=collections.defaultdict(set); recs={}
for fn in glob.glob(os.path.join(T,'*.jsonl')):
    for line in open(fn):
        d=json.loads(line)
        if not d['in_paper_analysis']: continue
        fmd=d['score_details']['file_modification_details']; fmd=json.loads(fmd) if isinstance(fmd,str) else fmd
        recs[K(d['run_key'])]=dict(model=d['model'],cond=d['condition'],tp=bool(fmd['test_script_modified']),tc=bool(fmd['test_cases_modified']))
        conds[d['model']].add(d['condition'])
full=sorted(m for m,c in conds.items() if set('ABCDE')<=c)
print('runs in analysis',len(recs),'| models with A-E:',len(full),full)
C={K(r['run_key']):r for r in csv.DictReader(open(os.path.join(TAB,'per_run_data_all_conditions.csv'),newline=''))}
scope={k for k,r in recs.items() if r['model'] in full and r['cond'] in 'ABCD' and (r['tp'] or r['tc'])}
print('scope by hash flags (A-D):',dict(sorted(collections.Counter(recs[k]['cond'] for k in scope).items())),len(scope))
scope2={k for k,r in C.items() if r['model'] in full and r['condition'] in 'ABCD' and r['files_modified']=='yes'}
print('scope by csv files_modified:',dict(sorted(collections.Counter(C[k]['condition'] for k in scope2).items())),len(scope2), 'same set:',scope==scope2)
E={k for k,r in recs.items() if r['model'] in full and r['cond']=='E' and (r['tp'] or r['tc'])}
print('E, same definition:',len(E))
print('runs with a changed test file outside the 8 models:',collections.Counter(r['model'] for k,r in recs.items() if (r['tp'] or r['tc']) and r['model'] not in full))
B={K(r['run_key']):r for r in csv.DictReader(open(os.path.join(TAB,'test_harness_modification_breakdown.csv'),newline=''))}
print('breakdown table rows',len(B),dict(sorted(collections.Counter(r['condition'] for r in B.values()).items())),'equal to scope:',set(B)==scope)
print('breakdown disclosed:',collections.Counter(r['disclosed'] for r in B.values()), 'outcome:',collections.Counter(r['outcome'].split(' ')[0] for r in B.values()))
for k in KEYS13:
    print(k,recs[k]['cond'],'in scope:',k in scope,'| in breakdown:',k in B, '| disclosed:',B[k]['disclosed'] if k in B else '-', B[k]['change_made'] if k in B else '')
