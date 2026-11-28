'use strict';
module.exports = {id:'mit-kerberos',ttlMs:24*3600000,build(type,params={}) {
 if (type !== 'announcement' || !/^\d{4}q[1-4]$/.test(params.quarter) || !/^\d{6}$/.test(params.message))
  throw Error('Invalid MIT Kerberos announcement');
 return {url:`https://mailman.mit.edu/pipermail/kerberos-announce/${params.quarter}/${params.message}.html`};
}};
