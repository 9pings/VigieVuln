'use strict';
const sign = n => n < 0 ? -1 : n > 0 ? 1 : 0;
function number(a,b) {a=(a||'0').replace(/^0+/,'')||'0';b=(b||'0').replace(/^0+/,'')||'0';return sign(a.length-b.length)||sign(a.localeCompare(b,'en'));}
function debPart(a,b) {
 let i=0,j=0;
 const ord=c=>!c ? 0 : c==='~' ? -1 : /[A-Za-z]/.test(c) ? c.charCodeAt(0) : c.charCodeAt(0)+256;
 while(i<a.length || j<b.length) {
  while((i<a.length&&!/\d/.test(a[i])) || (j<b.length&&!/\d/.test(b[j]))) {
   const x=i<a.length&&!/\d/.test(a[i])?a[i]:'';const y=j<b.length&&!/\d/.test(b[j])?b[j]:'';
   const c=sign(ord(x)-ord(y));if(c)return c;if(x)i++;if(y)j++;
  }
  const x=(a.slice(i).match(/^\d+/)||[''])[0],y=(b.slice(j).match(/^\d+/)||[''])[0];
  const c=number(x,y);if(c)return c;i+=x.length;j+=y.length;
 }
 return 0;
}
function splitDeb(v){const m=String(v).match(/^(?:(\d+):)?([A-Za-z0-9.+:~\-]+?)(?:-([A-Za-z0-9+.~]+))?$/);return m&&[m[1]||'0',m[2],m[3]||'0'];}
function debian(a,b) {a=splitDeb(a);b=splitDeb(b);return a&&b ? number(a[0],b[0])||debPart(a[1],b[1])||debPart(a[2],b[2]) : null;}
function rpmPart(a,b) {
 let i=0,j=0;
 while(i<a.length || j<b.length) {
  while(i<a.length && !/[A-Za-z0-9~^]/.test(a[i]))i++;
  while(j<b.length && !/[A-Za-z0-9~^]/.test(b[j]))j++;
  if(a[i]==='~'||b[j]==='~'){if(a[i]!=='~')return 1;if(b[j]!=='~')return -1;i++;j++;continue;}
  if(a[i]==='^'||b[j]==='^'){if(i>=a.length)return -1;if(j>=b.length)return 1;if(a[i]!=='^')return 1;if(b[j]!=='^')return -1;i++;j++;continue;}
  if(i>=a.length || j>=b.length)break;
  const dig=/\d/.test(a[i]), x=(a.slice(i).match(dig?/^\d+/:/^[A-Za-z]+/)||[''])[0],y=(b.slice(j).match(dig?/^\d+/:/^[A-Za-z]+/)||[''])[0];
  if(!y)return dig?1:-1;
  const c=dig?number(x,y):sign(x<y?-1:x>y?1:0);if(c)return c;i+=x.length;j+=y.length;
 }
 return sign((i<a.length?1:0)-(j<b.length?1:0));
}
function rpm(a,b) {
 const parse=v=>String(v).match(/^(?:(\d+):)?([A-Za-z0-9._+~^]+)(?:-([A-Za-z0-9._+~^]+))?$/);
 a=parse(a);b=parse(b);return a&&b ? number(a[1],b[1])||rpmPart(a[2],b[2])||rpmPart(a[3]||'',b[3]||'') : null;
}
function apk(a,b) {
 const parse=v=>{
  const m=String(v).match(/^(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$/);
  if(!m)return null;
  const tokens=m[1].split('.').map((value,i)=>({type:i?1:0,value}));
  if(m[2])tokens.push({type:2,value:m[2]});
  for(const sm of m[3].matchAll(/_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)/g)){tokens.push({type:3,value:sm[1]});if(sm[2])tokens.push({type:4,value:sm[2]});}
  if(m[4]!==undefined)tokens.push({type:6,value:m[4]});
  tokens.push({type:7,value:''});return tokens;
 };
 a=parse(a);b=parse(b);if(!a||!b)return null;
 const rank={alpha:-4,beta:-3,pre:-2,rc:-1,cvs:1,svn:2,git:3,hg:4,p:5};let i=0;
 while(a[i].type===b[i].type && a[i].type!==7){const x=a[i],y=b[i];let c;
  if(x.type===3)c=sign(rank[x.value]-rank[y.value]);
  else if(x.type===2 || (x.type===1 && (x.value[0]==='0'||y.value[0]==='0')))c=sign(x.value<y.value?-1:x.value>y.value?1:0);
  else c=number(x.value,y.value);
  if(c)return c;i++;
 }
 const x=a[i],y=b[i];if(x.type===y.type)return 0;
 if(x.type===3 && rank[x.value]<0)return -1;if(y.type===3 && rank[y.value]<0)return 1;
 return x.type>y.type?-1:1;
}
module.exports={debian,rpm,apk};
