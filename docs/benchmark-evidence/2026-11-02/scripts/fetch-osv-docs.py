import json, urllib.request, urllib.error, concurrent.futures
base='/tmp/vigie-benchmark-20261102/'
r=json.load(open(base+'snyk-osv-batch-response.json'))
c=json.load(open(base+'output/dubbo-snyk-comparison.json'))
ids={v['id'] for item in r['results'] for v in item.get('vulns',[])}
ids.update(z for row in c['snykOnlyFindings'] for z in row['ids'] if z.startswith('CVE-'))
def get(id):
 try:
  with urllib.request.urlopen('https://api.osv.dev/v1/vulns/'+id,timeout=30) as response: return (id,{'status':response.status,'body':json.load(response)})
 except urllib.error.HTTPError as e: return (id,{'status':e.code})
 except Exception as e: return (id,{'status':'error','error':type(e).__name__})
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool: docs=dict(pool.map(get,sorted(ids)))
json.dump(docs,open(base+'snyk-osv-docs.json','w'))
from collections import Counter
print('ids',len(ids),'statuses',dict(Counter(str(v['status']) for v in docs.values())))
