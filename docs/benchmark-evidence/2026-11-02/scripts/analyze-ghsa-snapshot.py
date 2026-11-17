import tarfile,json,collections
p='/tmp/vigie-benchmark-20261102/ghsa-snapshot.tar.gz';counts=collections.Counter();ex=[]
with tarfile.open(p,'r|gz') as t:
 for m in t:
  if not m.isfile() or not m.name.endswith('.json') or '/advisories/' not in m.name: continue
  try:a=json.load(t.extractfile(m))
  except Exception:counts['parse_errors']+=1;continue
  kind='reviewed' if '/github-reviewed/' in m.name else 'unreviewed' if '/unreviewed/' in m.name else 'other'
  counts[kind]+=1
  if a.get('withdrawn'):counts[kind+'_withdrawn']+=1;ex.append(a['id'])
  if a.get('affected'):counts[kind+'_affected']+=1
  if a.get('database_specific',{}).get('github_reviewed'):counts[kind+'_flag_reviewed']+=1
print(dict(counts),'withdrawn_examples',ex[:4])
