import json,re,urllib.request,urllib.error,concurrent.futures
p='cli/docs/benchmark-evidence/2026-11-02/dubbo-snyk-other-coordinates.json';d=json.load(open(p));ids={i for r in d['cases'] for i in r['cves']}
def get(i):
 _,year,num=i.split('-');url='https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'+year+'/'+str(int(num)//1000)+'xxx/'+i+'.json'
 try:
  with urllib.request.urlopen(url,timeout=20) as r:
   a=json.load(r); c=a.get('containers',{}).get('cna',{}); return i,{'status':200,'url':url,'assigner':a.get('cveMetadata',{}).get('assignerShortName'),'descriptions':c.get('descriptions',[]),'affected':c.get('affected',[]),'references':c.get('references',[])}
 except urllib.error.HTTPError as e:return i,{'status':e.code,'url':url}
 except Exception as e:return i,{'status':'error','error':str(e),'url':url}
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:res=dict(pool.map(get,ids))
json.dump(res,open('/tmp/vigie-benchmark-20261102/cna-other.json','w'),indent=2)
from collections import Counter
print('CNA',len(ids),Counter(str(x['status']) for x in res.values()))
