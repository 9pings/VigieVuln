import hashlib,json,re,urllib.request,urllib.error,concurrent.futures,zipfile,io
p='cli/docs/benchmark-evidence/2026-11-02/dubbo-snyk-adjudication.json'; a=json.load(open(p));rows=[x for x in a['cases'] if x['category'].startswith('OSV Maven other')]; patches=json.load(open('/tmp/vigie-benchmark-20261102/primary-patches.json')); sources={}
def download(u):
 try:
  with urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'vigievuln-benchmark'}),timeout=30) as r:return {'status':r.status,'body':r.read(6000000)}
 except urllib.error.HTTPError as e:return {'status':e.code}
 except Exception as e:return {'status':'error','error':type(e).__name__}
coords=set((x['package'],x['version']) for x in rows)
def source(item):
 coord,ver=item; group,name=coord.split(':');url='https://repo.maven.apache.org/maven2/'+group.replace('.','/')+'/'+name+'/'+ver+'/'+name+'-'+ver+'-sources.jar'; result=download(url);result['url']=url
 return item,result
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:sources=dict(pool.map(source,coords))
urls=set(u for x in rows for u in x['snykSourceReferences'] if u in patches)
def patch(u):return u,download(u+'.patch')
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:patchesraw=dict(pool.map(patch,urls))
for row in rows:
 source=sources[(row['package'],row['version'])];row['sourceJar']={'url':source['url'],'status':source['status']};row['patchEvidence']=[]
 if source['status']!=200: continue
 try: jar=zipfile.ZipFile(io.BytesIO(source['body']))
 except Exception as e:row['sourceJar']['error']=type(e).__name__;continue
 names=set(jar.namelist())
 for u in row['snykSourceReferences']:
  if u not in patchesraw:continue
  pa=patchesraw[u]
  if pa['status']!=200:row['patchEvidence'].append({'url':u,'status':pa['status']});continue
  text=pa['body'].decode('utf8','replace');files=[]
  for block in re.split(r'(?=^diff --git )',text,flags=re.M):
   m=re.search(r'^diff --git a/(.*?) b/',block,re.M)
   if not m:continue
   path=m.group(1); match=re.search(r'(?:^|/)(?:src/main/(?:java|resources)|java)/(.*)$',path)
   if not match or match.group(1) not in names:continue
   inner=match.group(1); src=jar.read(inner).decode('utf8','replace'); removed=[l[1:].strip() for l in block.splitlines() if l.startswith('-') and not l.startswith('---') and len(l[1:].strip())>=20]; shared=[line for line in removed if line in src]
   files.append({'upstreamPath':path,'sourceJarPath':inner,'removedLinesPresent':len(shared),'removedLinesChecked':len(removed)})
  if files:row['patchEvidence'].append({'url':u,'status':200,'files':files})
 row['sourceJar']['sha256']=hashlib.sha256(source['body']).hexdigest();row['sourceJar']['javaEntries']=sum(n.endswith('.java') for n in names)
from collections import Counter
print('source jars',len(sources),Counter(str(v['status']) for v in sources.values()));print('rows with source file in fix',sum(bool(r['patchEvidence']) for r in rows));print('rows with removed lines',sum(any(f['removedLinesPresent'] for e in r['patchEvidence'] for f in e.get('files',[])) for r in rows))
json.dump(rows,open('/tmp/vigie-benchmark-20261102/other-coordinate-evidence.json','w'),indent=2)
