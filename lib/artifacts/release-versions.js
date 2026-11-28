'use strict';

const {distroCatalogues,readResource} = require('./release-catalogues');
const {debian,apk} = require('../system-inventory/versions');

// Keys identify catalogued products, or source packages in Debian and its Ubuntu derivative.
// Numeric Anitya IDs distinguish upstream projects with identical names.
const cycles = {
  apache:'apache-http-server',php:'php',python:'python',node:'nodejs',ruby:'ruby',nginx:'nginx',
  mariadb:'mariadb',postgresql:'postgresql',dotnet:'dotnet',go:'go',perl:'perl',redis:'redis',
  mysql:'mysql',mongo:'mongodb',elasticsearch:'elasticsearch',opensearch:'opensearch',deno:'deno',
  bun:'bun',electron:'electron',powershell:'powershell',erlang:'erlang',julia:'julia',
};
const productIds = {bash:166,dash:394,gawk:868};
const sourceCycles = {apache2:'apache-http-server',mariadb:'mariadb',nginx:'nginx',perl:'perl'};
const debSources = {
  ...productIds,pam:12244,acl:16,lz4:1865,shadow:4802,rsync:4217,gnupg2:1214,glibc:5401,dpkg:8127,
  sqlite3:4877,elfutils:5679,'libdbi-perl':2811,'util-linux':8179,libtirpc:1740,libbpf:141355,
  tar:4939,libzstd:12083,coreutils:343,krb5:13287,gnutls28:1221,systemd:5440,popt:3689,
  openssl:2566,'xz-utils':5277,pcre2:5832,libxml2:1783,zlib:5303,icu:379847,curl:381,
};

async function upstreamRelease(repo,opts,slug,id) {
  if (slug) {
    if (opts.eol===false) return null;
    const entry=await readResource(repo,opts,'eol','product',{product:slug},r=>r.json());
    const legacy=!entry && opts.offline ? repo.get('auxiliary','eol-cache.json')?.value : null;
    const records=entry?.value || legacy?.entries?.[slug];
    if (!Array.isArray(records))return null;
    const now=Date.now();
    const stable=records.filter(c=>typeof c.latest==='string' && /^\d+(?:\.\d+)+(?:p\d+)?$/.test(c.latest) &&
      (!c.releaseDate || Date.parse(c.releaseDate)<=now) && (!c.latestReleaseDate || Date.parse(c.latestReleaseDate)<=now));
    stable.sort((a,b)=>b.latest.localeCompare(a.latest,'en',{numeric:true}));
    return stable.length ? {version:stable[0].latest,source:'endoflife.date',url:'https://endoflife.date/'+slug,
      asOf:entry?.fetchedAt || legacy?.fetchedAt?.[slug] || legacy?.meta?.fetchedAt} : null;
  }
  if (!id) return null;
  const entry=await readResource(repo,opts,'package-releases','upstream',{project:id},async r=>{
    const {stable_versions}=await r.json();
    return Array.isArray(stable_versions) && typeof stable_versions[0]==='string' ? stable_versions[0] : null;
  });
  return entry ? {version:entry.value,source:'Anitya',url:'https://release-monitoring.org/project/'+id+'/',asOf:entry.fetchedAt} : null;
}

async function attachReleaseVersions(artifact,components,opts={}) {
  if (opts.allLibs===false || !components.length)return;
  const repo=opts.cacheRepository || require('../cache/repository').createCacheRepository(opts.cacheDir || require('../cache/directory').getCacheDir());
  const distro=artifact.distribution;
  const packages=artifact.components.filter(c=>c.ecosystem==='system');
  const nativeArches=new Set(packages.map(c=>c.architecture).filter(a=>a && !['all','noarch'].includes(a)));
  const platform=artifact.metadata?.platform?.architecture;
  const defaultArch=nativeArches.size===1 ? [...nativeArches][0] : platform;
  const owners=new Map();
  const ownerKey=c=>JSON.stringify([c.manager,c.name,c.version]);
  for(const c of packages){
    const key=ownerKey(c);
    if (!owners.has(key))owners.set(key,[]);
    owners.get(key).push(c);
  }
  const indexes=new Map(),upstreams=new Map(),byCoord=new Map();
  for(const c of components) {
    const refs={};
    const product=c.imageProduct?.id;
    let pkg=c.ecosystem==='system' ? c : null;
    if(!pkg && c.osPackageOwners?.length===1 && c.ecosystem==='binary') {
      const owner=c.osPackageOwners[0];
      const candidates=(owners.get(ownerKey(owner)) || []).filter(p=>!owner.architecture || p.architecture===owner.architecture);
      if(candidates.length===1)pkg=candidates[0];
    }
    const isDeb=['ubuntu','debian'].includes(distro?.id) && ['dpkg','deb'].includes(pkg?.manager);
    if(isDeb || (distro?.id==='alpine' && pkg?.manager==='apk')) {
      const arch=['all','noarch'].includes(pkg.architecture) ? defaultArch : pkg.architecture;
      if(arch) {
        if(!indexes.has(arch))indexes.set(arch,await distroCatalogues(repo,opts,distro,arch));
        const key=[pkg.name,pkg.sourceName || pkg.name,pkg.architecture].join('/');
        const compare=isDeb ? debian : apk;
        for (const index of indexes.get(arch)){
          const v=index.packages[key];
          if(v && (!refs.distribution || compare(v,refs.distribution.version)>0))
            refs.distribution={version:v,source:[distro.id,index.source,arch].join(' · '),url:index.url,asOf:index.asOf};
        }
      }
    }
    const source=pkg?.sourceName || pkg?.name;
    const sourceSlug=isDeb && Object.hasOwn(sourceCycles,source) && sourceCycles[source];
    const slug=Object.hasOwn(cycles,product) ? cycles[product] :
      c.ecosystem==='go' && c.name==='stdlib' ? 'go' : sourceSlug;
    const id=Object.hasOwn(productIds,product) ? productIds[product] : isDeb && Object.hasOwn(debSources,source) ? debSources[source] : null;
    if(slug || id) {
      const key=slug||id;
      if(!upstreams.has(key))upstreams.set(key,await upstreamRelease(repo,opts,slug,id));
      if(upstreams.get(key))refs.upstream={...upstreams.get(key),...(!product && pkg ? {sourcePackage:source} : {})};
    }
    if(Object.keys(refs).length){c.releaseVersions=refs;byCoord.set(c.coordKey,refs);}
  }
  for(const e of artifact.productInventory?.entries || []) {
    const refs=byCoord.get(e.componentKey);
    if(refs)e.releaseVersions=refs;
  }
}
module.exports={attachReleaseVersions};
