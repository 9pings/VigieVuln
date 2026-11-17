import json,urllib.request,urllib.error,concurrent.futures
j=json.load(open('cli/docs/benchmark-evidence/2026-11-02/dubbo-snyk-other-coordinates.json'));v=json.load(open('/tmp/vigie-benchmark-20261102/output/dubbo-vigie-default-sources.json'))['cve'];rows=[x for x in j['cases'] if x['verdict'].startswith('affected') and not any(z.get('id') in x['cves'] for z in v)]
def f(x):
 id=x['cves'][0];url='https://api.github.com/advisories?cve_id='+id+'&per_page=100'
 try:
  with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'vigievuln-research','Accept':'application/vnd.github+json'}),timeout=20) as r:
   data=json.load(r);out=[]
   for a in data:
    for q in a.get('vulnerabilities',[]):
     if q.get('package',{}).get('name')==x['package'] and q.get('package',{}).get('ecosystem')=='maven':out.append({'ghsa':a['ghsa_id'],'vulnerable_version_range':q.get('vulnerable_version_range')})
   return id,{'status':r.status,'package':x['package'],'version':x['version'],'matching':out,'advisoryCount':len(data),'remaining':r.headers.get('X-RateLimit-Remaining')}
 except urllib.error.HTTPError as e:return id,{'status':e.code,'package':x['package'],'version':x['version']}
 except Exception as e:return id,{'status':'error','error':type(e).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool: results=dict(pool.map(f,rows))
json.dump(results,open('/tmp/vigie-benchmark-20261102/ghsa-14.json','w'),indent=2)
for id,x in results.items():print(id,x['status'],'matches',len(x.get('matching',[])),'GHSA',x.get('advisoryCount'))
