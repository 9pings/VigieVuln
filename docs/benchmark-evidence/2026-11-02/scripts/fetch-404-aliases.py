import json,re,urllib.request,urllib.error,concurrent.futures
p='/tmp/vigie-benchmark-20261102/output/dubbo-snyk-adjudication-sanitized.json';d=json.load(open(p));ids=set()
for c in d['cases']:
 for r in c['cveLookups']:
  s=r.get('rechecked404',{}).get('body',{}).get('message','');ids.update(re.findall(r'\b(?:GHSA-[a-z0-9-]+|BIT-[a-z0-9-]+)\b',s,re.I))
def get(i):
 try:
  with urllib.request.urlopen('https://api.osv.dev/v1/vulns/'+i,timeout=30) as r: return i,{'status':r.status,'body':json.load(r)}
 except urllib.error.HTTPError as e:return i,{'status':e.code}
 except Exception as e:return i,{'status':'error','error':type(e).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool: docs=dict(pool.map(get,ids))
for c in d['cases']:
 for r in c['cveLookups']:
  s=r.get('rechecked404',{}).get('body',{}).get('message','');aliases=re.findall(r'\b(?:GHSA-[a-z0-9-]+|BIT-[a-z0-9-]+)\b',s,re.I);r['reportedAliases']=[]
  for ident in aliases:
   o=docs[ident]; x={'id':ident,'url':'https://api.osv.dev/v1/vulns/'+ident,'status':o['status']}
   if o['status']==200:
    b=o['body'];x.update({'aliases':b.get('aliases',[]),'affected':b.get('affected',[])})
   r['reportedAliases'].append(x)
json.dump(d,open(p,'w'),indent=2)
print('alias lookups',len(ids),'statuses', {str(z):sum(v['status']==z for v in docs.values()) for z in set(v['status'] for v in docs.values())})
