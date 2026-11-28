'use strict';

// Requests contain only public archive coordinates or a curated upstream project ID.
const archives = {
  debian:'https://deb.debian.org/debian', 'debian-security':'https://deb.debian.org/debian-security',
  'debian-archive':'https://archive.debian.org/debian', 'debian-archive-security':'https://archive.debian.org/debian-security',
  ubuntu:'https://archive.ubuntu.com/ubuntu', 'ubuntu-security':'https://security.ubuntu.com/ubuntu',
  'ubuntu-ports':'https://ports.ubuntu.com/ubuntu-ports', 'ubuntu-archive':'https://old-releases.ubuntu.com/ubuntu',
};
const suite = /^[a-z]{2,24}(?:-updates|-security|\/updates)?$/;
const index = /^(?:main|contrib|non-free(?:-firmware)?|restricted|universe|multiverse)\/binary-(?:amd64|i386|arm64|armhf|armel|ppc64el|s390x|riscv64|mips64el|mipsel)\/Packages\.(?:gz|xz)$/;
const alpine = /^v\d{1,2}\.\d{1,2}$/;
const apkArch = /^(?:x86|x86_64|armhf|armv7|aarch64|ppc64le|s390x|riscv64|loongarch64)$/;
function build(type,p={}) {
  if(type==='upstream' && Number.isSafeInteger(p.project) && p.project>0 && p.project<=1000000)
    return {url:'https://release-monitoring.org/api/v2/versions/?project_id='+p.project};
  if(type==='apk' && alpine.test(p.series) && apkArch.test(p.arch) && ['main','community'].includes(p.section))
    return {url:`https://dl-cdn.alpinelinux.org/alpine/${p.series}/${p.section}/${p.arch}/APKINDEX.tar.gz`};
  if(Object.hasOwn(archives,p.archive) && suite.test(p.suite)) {
    const root=archives[p.archive]+'/dists/'+p.suite+'/';
    if(type==='release')return {url:root+'Release'};
    if(type==='index' && index.test(p.file))return {url:root+p.file};
  }
  throw Error('Invalid release catalogue coordinates');
}
module.exports={id:'package-releases',ttlMs:4*3600000,build,archives,suite,index,alpine,apkArch};
