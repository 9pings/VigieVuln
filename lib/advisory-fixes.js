'use strict';

// A shared alias does not prove that two advisories describe identical affected
// ranges. Without all native ranges at this reporting boundary, require agreement
// between evaluated targets rather than guessing a maximum/minimum version.
function mergeAdvisoryFixes(left, right) {
  const candidates = [...new Set([...(left._fixCandidates || []), ...(right._fixCandidates || []), left.fixVersion, right.fixVersion].filter(value => typeof value === 'string' && value))];
  const unknown = left.fixEvaluation === 'unknown' || right.fixEvaluation === 'unknown';
  const conflict = left.fixConflict || right.fixConflict ||
    (candidates.length > 1 ? 'inconsistent-advisory-targets' : candidates.length && unknown ? 'unverified-advisory' : null);
  if (conflict) return { fixVersion: null, branchFix: undefined, fixEvaluation: 'unknown', fixConflict: conflict, _fixCandidates: candidates };
  const fixVersion = candidates[0] || null;
  const result = { fixVersion, _fixCandidates: candidates };
  if (unknown) result.fixEvaluation = 'unknown';
  else if (left.fixEvaluation === 'verified' || right.fixEvaluation === 'verified') result.fixEvaluation = 'verified';
  if (left.branchFix || right.branchFix) result.branchFix = require('./maven-version').stricterBranchFix(left.branchFix, right.branchFix);
  return result;
}

module.exports = { mergeAdvisoryFixes };
