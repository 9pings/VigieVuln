const {test}=require('node:test');
const assert=require('node:assert/strict');
const {buildProjectDescriptor}=require('../lib/project-descriptor');

test('project descriptor keeps directness per version and strips paths',()=>{
 const resolved=new Map([['npm:demo',{ecosystem:'npm',name:'demo',versions:['1.0.0','2.0.0'],
  versionRelations:{'1.0.0':['direct'],'2.0.0':['transitive']},scope:'prod',manifestPaths:['/private/path']}],
  ['npm:unknown',{ecosystem:'npm',name:'unknown',version:'3.0.0',scope:'prod'}]]);
 const out=buildProjectDescriptor(resolved);
 assert.equal(out.schema,'fad-deps/2');
 assert.deepEqual(out.deps.map(x=>[x.name,x.version,x.relation]),[['demo','1.0.0','direct'],['demo','2.0.0','transitive'],['unknown','3.0.0','unknown']]);
 assert.ok(!JSON.stringify(out).includes('/private/path'));
});
