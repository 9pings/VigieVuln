import hashlib,json,re,urllib.request,urllib.error,concurrent.futures,zipfile,io,collections
root='/tmp/vigie-benchmark-20261102/'
rows=json.load(open(root+'output/petclinic-snyk-cna-evidence.json'))['cases']
def download(u):
 try:
  with urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'vigievuln-benchmark'}),timeout=25) as r:
   body=r.read(12000001)
   if len(body)>12000000:return {'status':'oversized'}
   return {'status':r.status,'body':body}
 except urllib.error.HTTPError as e:return {'status':e.code}
 except Exception as e:return {'status':'error','error':type(e).__name__}
coords=set((x['name'],x['version']) for x in rows)
def source(item):
 coord,ver=item
 if ':' not in coord:return item,{'status':'invalid'}
 group,name=coord.split(':',1);url='https://maven-central.storage-download.googleapis.com/maven2/'+group.replace('.','/')+'/'+name+'/'+ver+'/'+name+'-'+ver+'-sources.jar';r=download(url);r['url']=url;return item,r
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:sources=dict(pool.map(source,coords))
urls=set(u for row in rows for u in row['refs'] if re.fullmatch(r'https://github\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]{7,40}',u))
def patch(u):return u,download(u+'.patch')
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:patches=dict(pool.map(patch,urls))
for row in rows:
 s=sources[(row['name'],row['version'])];row['sourceJar']={'url':s.get('url'),'status':s['status']};row['patchEvidence']=[]
 if s['status']!=200:continue
 try:jar=zipfile.ZipFile(io.BytesIO(s['body']))
 except Exception as e:row['sourceJar']['error']=type(e).__name__;continue
 names=set(jar.namelist());row['sourceJar']['sha256']=hashlib.sha256(s['body']).hexdigest()
 for u in row['refs']:
  if u not in patches:continue
  r=patches[u]
  if r['status']!=200:row['patchEvidence'].append({'url':u,'status':r['status']});continue
  text=r['body'].decode('utf8','replace');files=[]
  for block in re.split(r'(?=^diff --git )',text,flags=re.M):
   m=re.search(r'^diff --git a/(.*?) b/',block,re.M)
   if not m:continue
   path=m.group(1);match=re.search(r'(?:^|/)(?:src/main/(?:java|resources)|java)/(.*)$',path)
   if not match or match.group(1) not in names:continue
   inner=match.group(1);src=jar.read(inner).decode('utf8','replace');removed=[l[1:].strip() for l in block.splitlines() if l.startswith('-') and not l.startswith('---') and len(l[1:].strip())>=20]
   files.append({'upstreamPath':path,'sourceJarPath':inner,'removedLinesPresent':sum(line in src for line in removed),'removedLinesChecked':len(removed)})
  if files:row['patchEvidence'].append({'url':u,'status':200,'files':files})
json.dump({'date':'2026-11-02','scope':'Individual Snyk gaps; source paths and patch overlap are evidence only, not verdicts','cases':rows},open(root+'output/petclinic-snyk-primary-evidence.json','w'),indent=2)
print('source jars',len(sources),dict(collections.Counter(str(v['status']) for v in sources.values())),'patches',len(patches),dict(collections.Counter(str(v['status']) for v in patches.values())),'cases',len(rows),'files overlap',sum(bool(r['patchEvidence']) for r in rows))
