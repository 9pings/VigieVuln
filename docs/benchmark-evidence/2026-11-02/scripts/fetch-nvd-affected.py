import json,pathlib,urllib.request,hashlib
root=pathlib.Path(__file__).resolve().parent.parent
out=pathlib.Path('/tmp/vv-nvd-fields');out.mkdir(exist_ok=True)
cases=[]
for project,f in [('dubbo','dubbo-snyk-consolidated.json'),('petclinic','petclinic-snyk-primary-evidence.json')]:
 report=json.load(open('/tmp/vigie-benchmark-20261102/output/'+project+'-vv-bindings-online.json'))
 found={(m['dep']['coord'],m['dep']['version'],i) for m in report['cve'] if not m.get('suppressed') and not m.get('cpeFiltered') for i in [m['id']]+m.get('aliases',[])}
 raw=json.load(open('/tmp/vigie-benchmark-20261102/output/'+('dubbo-snyk-online.json' if project=='dubbo' else 'petclinic-snyk.json')))
 snapshots=raw if isinstance(raw,list) else [raw]
 unique=set()
 for snapshot in snapshots:
  for c in snapshot.get('vulnerabilities',[]):
   pkg=c['name'];ids=[c['id']]+c.get('identifiers',{}).get('CVE',[])+c.get('identifiers',{}).get('GHSA',[])
   k=(pkg,c['version'],c['id'])
   if k in unique or any((pkg,c['version'],i) in found for i in ids):continue
   if project=='dubbo' and pkg.startswith('org.apache.dubbo:'):continue
   unique.add(k);cases.append({'project':project,'package':pkg,'version':c['version'],'ids':ids})

ids=sorted({i for c in cases for i in c['ids'] if i.startswith('CVE-')}|{'CVE-2026-13006'})
(out/'cases.json').write_text(json.dumps(cases,indent=2))
for start in range(0,len(ids),100):
 url='https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds='+','.join(ids[start:start+100])
 raw=urllib.request.urlopen(url,timeout=60).read();j=json.loads(raw)
 for v in j['vulnerabilities']:(out/(v['cve']['id']+'.json')).write_text(json.dumps(v['cve'],indent=2))
 print('Downloaded',start,len(j['vulnerabilities']),flush=True)
print('cases',len(cases),'ids',len(ids),'records',len(list(out.glob('CVE-*.json'))))
fields={}
for f in out.glob('CVE-*.json'):
 j=json.load(open(f))
 for group in j.get('affected',[]):
  for a in group.get('affectedData',[]):
   for k in a:fields[k]=fields.get(k,0)+1
print('affected keys',fields)
