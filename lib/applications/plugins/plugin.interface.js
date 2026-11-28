/** Contract for trusted, bundled application analysis plugins. */
const API_VERSION = 1;
const HOOKS = ["discover", "collect", "assess", "remediation"];
const QUALITIES = new Set(["experimental", "qualified"]);

function assertPluginShape(plugin) {
	if (!plugin || typeof plugin !== "object") throw new Error("application plugin must be an object");
	if (!/^[a-z][a-z0-9-]*$/.test(plugin.id || "")) throw new Error("application plugin requires a valid id");
	if (plugin.apiVersion !== API_VERSION) throw new Error(`application plugin ${plugin.id}: unsupported apiVersion`);
	if (typeof plugin.version !== "string" || !plugin.version || typeof plugin.label !== "string" || !plugin.label) throw new Error(`application plugin ${plugin.id}: version and label required`);
	for (const key of ["supportedLayouts", "requiredCodecs", "providerIds"]) {
		if (!Array.isArray(plugin[key])) throw new Error(`application plugin ${plugin.id}: ${key} must be an array`);
	}
	if (!plugin.capabilities || typeof plugin.capabilities !== "object" || !QUALITIES.has(plugin.capabilities.inventory)) throw new Error(`application plugin ${plugin.id}: inventory capability must have a qualification`);
	for (const quality of Object.values(plugin.capabilities)) if (!QUALITIES.has(quality)) throw new Error(`application plugin ${plugin.id}: invalid capability qualification`);
	for (const hook of HOOKS) if (typeof plugin[hook] !== "function") throw new Error(`application plugin ${plugin.id}: missing ${hook} hook`);
	return true;
}

module.exports = { API_VERSION, assertPluginShape };
