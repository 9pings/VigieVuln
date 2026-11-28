'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {dockerfileReferences,yamlReferences,discoverImageReferences,referenceWarnings,resolveVariables}=require('../lib/images/references');
test('Dockerfile parses arguments, continuation, stage aliases and unresolved values',()=>{
 const text=['ARG BASE=alpine','ARG ARCH','FROM --platform=linux/$ARCH ${BASE}:3.20 AS build','RUN echo hi','FROM build AS copied','FROM \\', '  ${FINAL:-debian}:stable AS release'].join('\n');
 const refs=dockerfileReferences(text);assert.equal(refs.length,2);assert.equal(refs[0].reference,'alpine:3.20');assert.deepEqual(refs[0].unresolved,['ARCH']);assert.equal(refs[0].line,3);assert.equal(refs[1].reference,'debian:stable');assert.equal(refs[1].line,6);assert.equal(refs[1].finalStage,true);
 assert.deepEqual(resolveVariables('${MISSING}:$X',{}).unresolved,['MISSING','X']);
});
test('YAML image discovery handles multidoc and structured values',()=>{
 const items=yamlReferences('services:\n  app:\n    image: "repo/app:${TAG}"\n---\nspec:\n  containers:\n    - image: redis:7\n  image: {name: ignored}\n');
 assert.equal(items.length,2);assert.deepEqual(items[0].unresolved,['TAG']);assert.equal(items[1].reference,'redis:7');assert.equal(items[0].role,'deployment');
});
test('directory discovery returns explicit warnings, excludes dependencies and accepts adapters',t=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'image-refs-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));
 fs.writeFileSync(path.join(d,'Dockerfile'),'FROM alpine:3\n');fs.writeFileSync(path.join(d,'broken.yaml'),'foo: [\n');fs.mkdirSync(path.join(d,'node_modules'));fs.writeFileSync(path.join(d,'node_modules','Dockerfile'),'FROM hidden\n');
 const result=discoverImageReferences(d);assert.equal(result.references.length,1);assert.equal(result.references[0].contentVerified,false);assert.equal(result.warnings[0].reason,'image-reference-parse-error');
 const warnings=referenceWarnings(result.references);assert.equal(warnings[0].reason,'image-content-unverified');assert.match(warnings[0].message,/final built image/);
 const extra={id:'custom',accepts:n=>n==='custom.txt',extract:()=>[{declared:'x',reference:'x',unresolved:[],role:'deployment'}]};fs.writeFileSync(path.join(d,'custom.txt'),'x');assert.equal(discoverImageReferences(d,{extractors:[extra]}).references.length,1);
 assert.throws(()=>discoverImageReferences(d,{extractors:[extra,extra]}),/duplicate/);
});
test('Dockerfile heredoc bodies never become fake image references',()=>{
 const text=['FROM alpine:3 AS build','RUN <<EOF','FROM fake:latest','EOF',"COPY <<-'DATA' /tmp/file",'FROM also-fake', '\tDATA','FROM debian:12'].join('\n');
 const refs=dockerfileReferences(text);assert.deepEqual(refs.map(r=>r.reference),['alpine:3','debian:12']);assert.throws(()=>dockerfileReferences('FROM alpine\nRUN <<EOF\nFROM hidden'),/unterminated/);
});
test('declarations bind only exact image or index digests, preserving stage context',()=>{
 const {bindImageDefinitions}=require('../lib/images/references'),digest='sha256:'+'a'.repeat(64),index='sha256:'+'b'.repeat(64);
 const refs=[{id:'base',path:'Dockerfile',line:2,declared:`repo/app@${digest}`,reference:`repo/app@${digest}`,role:'base',stage:0,finalStage:false,unresolved:[]},
 {id:'index',path:'compose.yml',location:'0.services.app.image',declared:`repo/app@${index}`,reference:`repo/app@${index}`,role:'deployment',unresolved:[]},
 {id:'tag',path:'Dockerfile',line:4,declared:'repo/app:latest',reference:'repo/app:latest',role:'base',unresolved:[]},
 {id:'unresolved',path:'x.yml',declared:`${'$'}REG@${digest}`,reference:`${'$'}REG@${digest}`,role:'deployment',unresolved:['REG']}];
 const targets=[{id:'image',metadata:{digest,registryEvidence:{digest:index}}}];const result=bindImageDefinitions(targets,refs);
 assert.deepEqual(targets[0].metadata.definitions.map(d=>d.binding),['manifest-digest','index-digest']);assert.equal(targets[0].metadata.definitions[0].finalStage,false);
 assert.deepEqual(result.map(r=>r.boundArtifactIds),[['image'],['image'],[],[]]);
});

test('Compose local builds and their consumers are never registry acquisitions',()=>{
 const text='services:\n  build:\n    build: ./app\n    image: example-app:local\n  consumer:\n    image: example-app:local\n  nginx:\n    image: nginx:1.24\n  remote:\n    image: registry.example.test/team/app:2\n';
 const refs=yamlReferences(text,{filePath:'compose.yml'});assert.deepEqual(refs.map(x=>x.classification),['local-build','local-build','registry','registry']);assert.deepEqual(refs.map(x=>x.scanEligible),[false,false,true,true]);assert.equal(refs[0].blockReason,'local-build');
});

test('GitLab explicit variables and CI service images resolve without guessing dependency proxy variables',()=>{
 const text='variables:\n  BASE: alpine\n  TAG: "3.20"\n  COMPLETE: "${BASE}:${TAG}"\nimage: "$COMPLETE"\nbuild:\n  variables:\n    TAG: "3.19"\n  image:\n    name: "$BASE:$TAG"\n  services:\n    - name: postgres:16\n    - redis:7\ntest:\n  image: "$CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX/alpine:3"\n';
 const refs=yamlReferences(text,{filePath:'.gitlab-ci.yml'});assert.deepEqual(refs.map(x=>x.reference),['alpine:3.20','alpine:3.19','postgres:16','redis:7','$CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX/alpine:3']);assert.ok(refs.every(x=>x.role==='ci'));assert.deepEqual(refs.map(x=>x.scanEligible),[true,true,true,true,false]);assert.deepEqual(refs[4].unresolved,['CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX']);
});

test('explicit variable overrides and invalid references remain distinguishable',()=>{
 const refs=yamlReferences('services:\n  x:\n    image: "${IMAGE}:${TAG}"\n  y:\n    image: "invalid image!"\n',{filePath:'compose.yml',variables:{IMAGE:'alpine',TAG:'3.20'}});
 assert.equal(refs[0].reference,'alpine:3.20');assert.equal(refs[0].classification,'registry');assert.equal(refs[1].classification,'non-scannable');assert.equal(refs[1].blockReason,'invalid-reference');
 const stages=dockerfileReferences('FROM alpine AS build\nFROM build AS final\n');assert.equal(stages.length,1);assert.equal(stages[0].classification,'registry');
});

test('repeated declarations remain separate and CI context is derived from file path',t=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'image-ci-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));fs.mkdirSync(path.join(d,'.github','workflows'),{recursive:true});fs.writeFileSync(path.join(d,'.github','workflows','build.yml'),'jobs:\n  first:\n    container:\n      image: alpine:3\n  second:\n    container:\n      image: alpine:3\n');
 const refs=discoverImageReferences(d).references;assert.equal(refs.length,2);assert.notEqual(refs[0].id,refs[1].id);assert.ok(refs.every(r=>r.role==='ci'&&r.classification==='registry'));
});

test('Compose and Dockerfile platforms are resolved and malformed platforms are not scanned',()=>{
 const compose=yamlReferences('services:\n  arm:\n    image: nginx\n    platform: linux/arm64\n  missing:\n    image: alpine\n    platform: linux/${TARGET_ARCH}\n  bad:\n    image: debian\n    platform: linux\n  wrongtype:\n    image: redis\n    platform: 42\n',{filePath:'compose.yml'});
 assert.equal(compose[0].platform,'linux/arm64');assert.equal(compose[0].classification,'registry');assert.deepEqual(compose[1].unresolved,['TARGET_ARCH']);assert.equal(compose[1].classification,'unresolved');assert.equal(compose[2].blockReason,'invalid-platform');assert.equal(compose[3].blockReason,'invalid-platform');
 const explicit=yamlReferences('services:\n  x:\n    image: nginx\n    platform: linux/${TARGET_ARCH}\n',{variables:{TARGET_ARCH:'arm64'}});assert.equal(explicit[0].platform,'linux/arm64');assert.equal(explicit[0].scanEligible,true);
 const docker=dockerfileReferences('FROM --platform=linux/arm64 nginx\nFROM --platform=broken alpine\nFROM --platform=linux/$ARCH debian');assert.equal(docker[0].platform,'linux/arm64');assert.equal(docker[1].blockReason,'invalid-platform');assert.equal(docker[2].classification,'unresolved');
});

test('unpinned image warnings cover all mutable tags and retain locations without treating a resolved digest as a pin',()=>{
 const {unpinnedImageWarnings}=require('../lib/images/references'),digest='sha256:'+'a'.repeat(64);
 const refs=dockerfileReferences(`FROM nginx:stable-alpine AS base\nFROM nginx:1.30.7 AS numeric\nFROM nginx AS implicit\nFROM nginx@${digest} AS pinned\nFROM nginx:stable-alpine@${digest}\n`)
  .map(r=>({...r,path:'Dockerfile',contentVerified:true,boundArtifactIds:['image'],digest}));
 refs.push(...yamlReferences('services:\n  app:\n    image: local:latest\n    build: .\n  unknown:\n    image: ${IMAGE}\n  registry:\n    image: localhost:5000/team/app:2\n',{filePath:'compose.yml'}).map(r=>({...r,path:'compose.yml'})));
 const warnings=unpinnedImageWarnings(refs);assert.equal(warnings.length,1);const w=warnings[0];assert.equal(w.type,'image-unpinned');assert.equal(w.severity,'warning');assert.equal(w.affectsCompleteness,false);
 assert.deepEqual(w.items.map(i=>i.reference),['nginx:stable-alpine','nginx:1.30.7','nginx','localhost:5000/team/app:2']);assert.equal(w.items[1].line,2);assert.deepEqual(w.items[1].manifestPaths,['Dockerfile']);
 assert.equal(unpinnedImageWarnings([...refs,...refs])[0].count,4);
 assert.deepEqual(unpinnedImageWarnings([{reference:'nginx@sha256:bad'}]),[]);
});
test('one ARG line declares several names, quoted values and names without defaults',()=>{
 const text=['ARG NODE=20 DEBIAN=bookworm','ARG TAG="3.20 ignored" ARCH REG=\'docker.io\' FLAVOR=sl"im"','FROM ${REG}/library/node:${NODE}-${DEBIAN}-$FLAVOR','FROM --platform=linux/$ARCH busybox'].join('\n');
 const refs=dockerfileReferences(text);
 assert.equal(refs[0].reference,'docker.io/library/node:20-bookworm-slim');assert.deepEqual(refs[0].unresolved,[]);
 assert.equal(refs[1].reference,'busybox');assert.deepEqual(refs[1].unresolved,['ARCH']);
 assert.equal(dockerfileReferences('ARG A=1 A=2\nFROM x:$A',{variables:{}})[0].reference,'x:1');
 assert.equal(dockerfileReferences('ARG V="a b"\nFROM x:$V')[0].reference,'x:a b');
 assert.equal(dockerfileReferences('ARG NODE=20 DEBIAN=bookworm\nFROM node:$NODE',{variables:{NODE:'22'}})[0].reference,'node:22');
});
