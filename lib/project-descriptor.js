"use strict";

const {cleanVersion} = require("./deps-descriptor");
const SAFE_COORD = /^[A-Za-z0-9@._+\/-]+$/;
/** Build a path-free descriptor. Unknown relations stay unknown, never direct. */
function buildProjectDescriptor(resolved, {generator="vigievuln"} = {}) {
  const deps = [];
  for (const dep of resolved.values()) {
    if (!dep || typeof dep.ecosystem !== "string" || !SAFE_COORD.test(dep.ecosystem) ||
        typeof dep.name !== "string" || !SAFE_COORD.test(dep.name) || dep.name.includes("..") ||
        (dep.namespace && (!SAFE_COORD.test(dep.namespace) || dep.namespace.includes("..")))) continue;
    const versions = [...new Set((Array.isArray(dep.versions) && dep.versions.length ? dep.versions : [dep.version]).map(cleanVersion).filter(Boolean))];
    for (const version of versions.length ? versions : [null]) {
      let relation = dep.versionRelations?.[version] || "unknown";
      if (Array.isArray(relation)) relation = relation.includes("direct") ? "direct"
        : relation.length && relation.every(r => r === "transitive") ? "transitive" : "unknown";
      if (!["direct","transitive","unknown"].includes(relation)) relation = "unknown";
      // Managed pins and embedded binaries cannot be direct declarations.
      if (dep.managedOnly || ["embedded","binary"].includes(dep.provenance)) relation = "unknown";
      const ecosystemType = typeof dep.ecosystemType === "string" && /^[A-Za-z0-9._-]+$/.test(dep.ecosystemType) ? dep.ecosystemType : dep.ecosystem;
      const scope = typeof dep.scope === "string" && /^[A-Za-z0-9._-]+$/.test(dep.scope) ? dep.scope : "prod";
      deps.push({ecosystem:dep.ecosystem,ecosystemType,
        namespace:dep.namespace || "",name:dep.name,version,versions:version ? [version] : [],
        scope,isDev:!!dep.isDev,relation});
    }
  }
  deps.sort((a,b)=>`${a.ecosystem}\0${a.namespace}\0${a.name}\0${a.version || ""}`.localeCompare(`${b.ecosystem}\0${b.namespace}\0${b.name}\0${b.version || ""}`));
  return {schema:"fad-deps/2",generator,deps};
}
module.exports={buildProjectDescriptor};
