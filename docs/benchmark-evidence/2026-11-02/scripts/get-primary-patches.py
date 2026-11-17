import json,re,urllib.request,urllib.error,concurrent.futures
src='cli/docs/benchmark-evidence/2026-11-02/dubbo-snyk-adjudication.json'; a=json.load(open(src));rows=[x for x in a['cases'] if x['category'].startswith('OSV Maven other')]
urls=set()
for x in rows:
 for u in x['snykSourceReferences']:
  if re.match(r'^https://github.com/[^/]+/[^/]+/commit/[a-f0-9]{40}$',u):urls.add(u)
def fetch(u):
 try:
  with urllib.request.urlopen(urllib.request.Request(u+'.patch',headers={'User-Agent':'vigievuln-benchmark'}),timeout=25) as r:
   b=r.read(3000000);s=b.decode('utf8','replace');return u,{'status':r.status,'truncated':len(b)==3000000,'files':re.findall(r'^diff --git a/(.*?) b/',s,re.M)}
 except urllib.error.HTTPError as e:return u,{'status':e.code}
 except Exception as e:return u,{'status':'error','error':type(e).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool: results=dict(pool.map(fetch,urls))
json.dump(results,open('/tmp/vigie-benchmark-20261102/primary-patches.json','w'),indent=2)
from collections import Counter
print(len(urls),Counter(str(x['status']) for x in results.values()))
