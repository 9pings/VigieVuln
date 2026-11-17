'use strict';

// Informational observations describe the chosen scan context, not failed work.
// Keep them available for provenance without counting them as alerts or gaps.
const isInformational = diagnostic => diagnostic?.severity === 'info' || (!diagnostic?.severity &&
 (diagnostic?.informational === true || diagnostic?.reason === 'image-content-unverified'));
function partitionDiagnostics(diagnostics = []) {
 const warnings = [], notices = [];
 for (const diagnostic of diagnostics) (isInformational(diagnostic) ? notices : warnings).push(diagnostic);
 return {warnings, notices};
}
module.exports = {isInformational, partitionDiagnostics};
