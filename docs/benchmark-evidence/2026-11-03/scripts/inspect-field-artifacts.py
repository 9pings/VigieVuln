import json,pathlib,urllib.request,concurrent.futures,hashlib,zipfile,re,io,collections
root=pathlib.Path('/mnt/wsl/WipDrive/_libs/VigieVuln/cli');out=pathlib.Path('/tmp/vv-field-debug');cases=json.load(open(root/'docs/benchmark-evidence/2026-11-02/nvd-affected-audit.json'))['rows']
rows=[];coords=set()
for c in cases:
 for record in c['records']:
  entries=[a for g in record.get('affected',[]) for a in g.get('affectedData',[]) if set(a)&{'repo','programFiles','programRoutines','modules','packageURL'}]
  if entries:rows.append({k:c[k] for k in ['project','package','version']}|{'id':record['id'],'entries':entries});coords.add((c['package'],c['version']))
coords.update([('org.eclipse.jetty:jetty-http','9.4.11.v20180605'),('com.fasterxml.jackson.dataformat:jackson-dataformat-cbor','2.6.7'),('com.fasterxml.jackson.dataformat:jackson-dataformat-cbor','2.11.4'),('com.fasterxml.jackson.core:jackson-databind','2.11.0'),('com.fasterxml.jackson.core:jackson-core','2.15.0')])
def fetch(pair):
 coord,version=pair;g,a=coord.split(':');url='https://maven-central.storage-download.googleapis.com/maven2/'+g.replace('.','/')+'/'+a+'/'+version+'/'+a+'-'+version+'-sources.jar';dest=out/(coord.replace(':','_')+'-'+version+'.jar')
 try:
  if not dest.exists():
   raw=urllib.request.urlopen(url,timeout=40).read(16000001)
   if len(raw)>16000000:raise ValueError('size')
   dest.write_bytes(raw)
  data=dest.read_bytes();jar=zipfile.ZipFile(io.BytesIO(data));names=jar.namelist();java={n:jar.read(n).decode('utf8','replace') for n in names if n.endswith('.java') and jar.getinfo(n).file_size<4000000}
  return pair,{'url':url,'sha256':hashlib.sha256(data).hexdigest(),'java':java,'javaFiles':len(java)}
 except Exception as e:return pair,{'url':url,'error':str(e)}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:sources=dict(pool.map(fetch,coords))
for row in rows:
 source=sources[(row['package'],row['version'])];row['source']={k:v for k,v in source.items() if k!='java'};java=source.get('java',{})
 for a in row['entries']:
  a['fileEvidence']=[]
  for f in a.get('programFiles',[]):
   p=f.split('src/main/java/')[-1];matches=[n for n in java if n==p or ('/' not in p and n.rsplit('/',1)[-1]==p)]
   a['fileEvidence'].append({'requested':f,'matches':matches})
  a['routineEvidence']=[]
  for routine in a.get('programRoutines',[]):
   name=routine['name'];bits=name.split('.');method=bits[-1];cls='/'.join(bits[:-1])+'.java';matches=[n for n,s in java.items() if (n==cls or ('/' not in cls and n.rsplit('/',1)[-1]==cls)) and re.search(r'\b'+re.escape(method)+r'\s*\(',s)]
   a['routineEvidence'].append({'requested':name,'matches':matches})
 # These class paths are explicitly named by the upstream advisories / patch.
 row['relatedClasses']=[n for n in java if n.rsplit('/',1)[-1] in ['HardenedObjectInputStream.java','HttpURI.java','DefaultBaseTypeLimitingValidator.java','NonBlockingUtf8JsonParserBase.java','TypeDeserializerBase.java','CBORParser.java']]
result={'date':'2026-11-03','method':'Maven Central exact coordinate/version source JARs, hashed; class/method presence is identity evidence only, never sufficient proof of vulnerability or version applicability. No source code is executed.','observations':len(rows),'distinctAdvisories':len({r['id'] for r in rows}),'sourceArtifacts':len(sources),'downloadFailures':sum('error' in s for s in sources.values()),'rows':rows,'controls':[{'package':p,'version':v,**{k:x for k,x in s.items() if k!='java'},'relatedClasses':[n for n in s.get('java',{}) if n.rsplit('/',1)[-1] in ['HttpURI.java','DefaultBaseTypeLimitingValidator.java','NonBlockingUtf8JsonParserBase.java','CBORParser.java']]} for (p,v),s in sources.items()]}
(out/'source-audit.json').write_text(json.dumps(result,indent=2));print({k:v for k,v in result.items() if k not in ['rows','controls']})
