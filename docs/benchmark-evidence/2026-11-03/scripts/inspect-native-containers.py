import pathlib,json,urllib.request,concurrent.futures,collections,hashlib
root=pathlib.Path('/mnt/wsl/WipDrive/_libs/VigieVuln/cli');out=pathlib.Path('/tmp/vv-field-debug/native');out.mkdir(exist_ok=True)
audit=json.load(open(root/'docs/benchmark-evidence/2026-11-02/nvd-affected-audit.json'));ids=sorted({c['id'] for r in audit['rows'] for c in r['records']})
def get(id):
 year,num=id.split('-')[1:];url=f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{int(num)//1000}xxx/{id}.json';f=out/(id+'.json')
 try:
  if not f.exists():f.write_bytes(urllib.request.urlopen(url,timeout=35).read(4000000))
  j=json.load(open(f));containers=[j.get('containers',{}).get('cna',{})]+j.get('containers',{}).get('adp',[])
  return {'id':id,'url':url,'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'state':j.get('cveMetadata',{}).get('state'),'fields':[sorted(c) for c in containers],'extraApplicability':[{'provider':c.get('providerMetadata'),'cpeApplicability':c['cpeApplicability']} for c in containers if c.get('cpeApplicability')],'affectedKeys':sorted({k for c in containers for a in c.get('affected',[]) for k in a})}
 except Exception as e:return {'id':id,'url':url,'error':str(e)}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:rows=list(pool.map(get,ids))
result={'date':'2026-11-03','records':rows,'containerFields':dict(collections.Counter(k for r in rows for c in r.get('fields',[]) for k in c)),'affectedFields':dict(collections.Counter(k for r in rows for k in r.get('affectedKeys',[])))}
(out.parent/'native-fields.json').write_text(json.dumps(result,indent=2));print('records',len(rows),'errors',[r for r in rows if 'error' in r]);print('container fields',result['containerFields']);print('extra applicability',[r['id'] for r in rows if r.get('extraApplicability')]);print('affected fields',result['affectedFields'])
