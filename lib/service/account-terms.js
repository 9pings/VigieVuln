'use strict';

async function requireTerms({account, terms, ask, interactive = !!(process.stdin.isTTY && process.stderr.isTTY), warn = console.error}) {
  if (!terms) throw new Error('unable to verify current terms; please retry or contact support');
  if (terms.accepted) return;
  warn(`Vigie Vuln terms of service (version ${terms.version}): ${terms.url}`);
  if (!interactive) throw new Error('terms acceptance required: run vigievuln login in an interactive terminal, then retry');
  const answer = await ask('Accept these terms? Type yes to accept: ');
  if (typeof answer !== 'string' || answer.trim().toLowerCase() !== 'yes')
    throw new Error('terms not accepted; run vigievuln login to review them');
  await account.acceptTerms(terms.version);
}
module.exports = { requireTerms };
