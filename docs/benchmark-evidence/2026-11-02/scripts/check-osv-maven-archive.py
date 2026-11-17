import json,zipfile,collections,hashlib
p='/tmp/vigie-benchmark-20261102/'
a=json.load(open(p+'output/dubbo-snyk-adjudication-sanitized.json')); index=collections.defaultdict(list); bad=[]
with zipfile.ZipFile(p+'osv-maven-all.zip') as z:
 for fn in z.namelist():
  if not fn.endswith('.json'): continue
  try: d=json.loads(z.read(fn))
  except (ValueError,UnicodeDecodeError): bad.append(fn);continue
  for ident in [d.get('id')]+d.get('aliases',[]):
   if ident: index[ident].append(d)
if bad: raise RuntimeError('malformed '+str(bad[:5]))
for case in a['cases']:
 docs={d['id']:d for ident in [case['snykId']]+case['cves'] for d in index.get(ident,[])}
 target=[];other=[]
 for doc in docs.values():
  aff=[q for q in doc.get('affected',[]) if q.get('package',{}).get('ecosystem')=='Maven' and q['package'].get('name')==case['package']]
  row={'id':doc['id'],'aliases':doc.get('aliases',[]),'packages':sorted({x.get('package',{}).get('name') for x in doc.get('affected',[]) if x.get('package',{}).get('ecosystem')=='Maven' and x.get('package',{}).get('name')}),'targetAffected':aff}
  (target if aff else other).append(row)
 case['archiveTargetDocs']=target; case['archiveOtherDocs']=other
 case['category']=('OSV Maven target but version not returned: source disagreement' if target else 'OSV Maven other target: unconfirmed coordinate' if other else 'No matching identity in OSV Maven archive: indeterminate')
a['osvMavenArchive']={'url':'https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip','retrievedAt':'2026-11-02','sha256':hashlib.sha256(open(p+'osv-maven-all.zip','rb').read()).hexdigest(),'files':7224,'malformed':len(bad)}
a['counts']=dict(collections.Counter(x['category'] for x in a['cases']))
json.dump(a,open(p+'output/dubbo-snyk-adjudication-sanitized.json','w'),indent=2)
print(a['counts']);print('6481',json.dumps([x for x in a['cases'] if 'CVE-2023-6481' in x['cves']],indent=2)[:1200])
