import json,os,re
D='/tmp/vigie-benchmark-20261102/output'
files={'vv-after':'dubbo-vigie-after-offline.json','vv-online':'dubbo-vigie-online.json','vv-offline':'dubbo-vigie-offline-warm.json','vv-cold':'dubbo-vigie-offline-cold.json','osv':'dubbo-osv-online.json','grype':'dubbo-grype-online.json','trivy':'dubbo-trivy-online.json','osv-offline':'dubbo-osv-offline.json','trivy-offline':'dubbo-trivy-offline.json','grype-offline':'dubbo-grype-offline.json'}
raw={k:json.load(open(os.path.join(D,v))) for k,v in files.items() if os.path.isfile(os.path.join(D,v))}
parents={}
def root(a):
 a=str(a).upper(); parents.setdefault(a,a)
 while parents[a]!=a: parents[a]=parents[parents[a]];a=parents[a]
 return a
def union(ids):
 ids=[str(i).upper() for i in ids if isinstance(i,str) and re.match(r'^(CVE-|GHSA-|SNYK-|OSV-)',i,re.I)]
 if ids:
  r=root(ids[0])
  for i in ids[1:]:parents[root(i)]=r
for name,j in raw.items():
 if name.startswith('vv'):
  for x in j.get('cve',[]):union([x.get('id')]+(x.get('aliases') or []))
 elif name.startswith('osv'):
  for s in j.get('results',[]):
   for p in s.get('packages',[]):
    for x in p.get('vulnerabilities',[]):union([x.get('id')]+(x.get('aliases') or []))
 elif name.startswith('grype'):
  for x in j.get('matches',[]):union([x.get('vulnerability',{}).get('id')]+[v.get('id') for v in x.get('relatedVulnerabilities',[])])
 elif name.startswith('trivy'):
  for r in j.get('Results',[]):
   for x in r.get('Vulnerabilities') or []:union([x.get('VulnerabilityID')]+(x.get('VendorIDs') or []))
groups={}
for i in parents:groups.setdefault(root(i),[]).append(i)
def canon(i):
 if not isinstance(i,str):return None
 arr=groups.get(root(i),[i.upper()]);return sorted(arr,key=lambda x:(not x.startswith('CVE-'),not x.startswith('GHSA-'),x))[0]
def tup(name,version,id):
 if not name or not version or not id:return None
 name=str(name).lower()
 if name.startswith('org.apache.dubbo:'):return None
 return (name,str(version),canon(id))
def collect(name,j):
 out=set()
 def add(*args):
  x=tup(*args)
  if x and x[-1]:out.add(x)
 if name.startswith('vv'):
  for x in j.get('cve',[]):
   d=x.get('dep') or {}
   if d.get('ecosystem') in ['maven','gradle'] and not x.get('suppressed') and not x.get('cpeFiltered'):add(d.get('coord'),d.get('version'),x.get('id'))
 elif name.startswith('osv'):
  for r in j.get('results',[]):
   for p in r.get('packages',[]):
    q=p.get('package') or {}
    if q.get('ecosystem')=='Maven':
     for v in p.get('vulnerabilities',[]):add(q.get('name'),q.get('version'),v.get('id'))
 elif name.startswith('grype'):
  for x in j.get('matches',[]):
   a=x.get('artifact',{});m=a.get('metadata') or {};g=m.get('pomGroupID');art=m.get('pomArtifactID') or a.get('name')
   if g:add(g+':'+art,a.get('version'),x.get('vulnerability',{}).get('id'))
 elif name.startswith('trivy'):
  for r in j.get('Results',[]):
   for x in r.get('Vulnerabilities') or []:add(x.get('PkgName'),x.get('InstalledVersion'),x.get('VulnerabilityID'))
 return out
sets={n:collect(n,j) for n,j in raw.items()}
for k,v in sets.items():print(k,len(v))
for n in ['osv','trivy','grype']:
 if n in sets:
  a,b=sets['vv-online'],sets[n]; print(n, 'common',len(a&b),'vv_only',len(a-b),'other_only',len(b-a));json.dump({'common':len(a&b),'vv_only':sorted(a-b),'other_only':sorted(b-a)},open(os.path.join(D,'dubbo-diff-'+n+'.json'),'w'),indent=2)
if 'vv-online' in sets and 'vv-offline' in sets:print('warm offline',len(sets['vv-online']-sets['vv-offline']),len(sets['vv-offline']-sets['vv-online']))
