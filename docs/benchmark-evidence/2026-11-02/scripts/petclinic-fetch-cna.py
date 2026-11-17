import json,urllib.request,concurrent.futures,os,time
p='/tmp/vigie-benchmark-20261102/'
x=json.load(open(p+'output/petclinic-snyk-diff-final.json'))['snykOnly'];ids=sorted({i for c in x for i in c['ids'] if i.startswith('CVE-')})
os.makedirs(p+'petclinic-cna',exist_ok=True)
def get(i):
 year,num=i.split('-')[1:];url=f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{num[:-3]}xxx/{i}.json'
 try:
  with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'vigievuln-benchmark'}),timeout=30) as res: raw=res.read();status=res.status
  data=json.loads(raw);open(p+'petclinic-cna/'+i+'.json','w').write(json.dumps(data));return (i,status)
 except Exception as e:return (i,str(e))
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:r=list(ex.map(get,ids))
json.dump(dict(r),open(p+'petclinic-cna-status.json','w'),indent=2);print('ids',len(ids),'ok',sum(s==200 for _,s in r),'errors',[(i,s) for i,s in r if s!=200])
