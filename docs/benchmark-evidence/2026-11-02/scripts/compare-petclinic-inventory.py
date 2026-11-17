import json,re
p='/tmp/vigie-benchmark-20261102/'
a=json.load(open(p+'output/petclinic-inventory.json'))
vv={(x.get('groupId'),x.get('artifactId'),str(v)) for x in a if x.get('ecosystem')=='maven' and x.get('scope')!='parent' for v in (x.get('versions') or [x.get('version')]) if v}
tree=set()
for line in open(p+'petclinic-full-tree.log'):
 m=re.search(r'(?:\+-|\\-) ([^:\s]+):([^:\s]+):([^:\s]+):([^:\s]+)(?::([^:\s]+))?:(compile|runtime|provided|test|system)',line)
 if m:
  g,a,t,v,c,scope=m.groups();tree.add((g,a,c if c else v))
print('maven',len(tree),'vv',len(vv),'maven only',len(tree-vv),'vv only',len(vv-tree))
print('maven-only',sorted(tree-vv));print('vv-only',sorted(vv-tree))
