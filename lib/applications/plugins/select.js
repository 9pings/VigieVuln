const { assertPluginShape } = require("./plugin.interface");

function selectPlugins(plugins, selection = "auto") {
	const available = new Map();
	for (const plugin of plugins) {
		assertPluginShape(plugin);
		if (available.has(plugin.id)) throw new Error(`duplicate application plugin: ${plugin.id}`);
		available.set(plugin.id, plugin);
	}
	if (selection === "none") return [];
	// A present CMS/framework must be activated: `auto` inventories every recognized
	// layout — the detection markers are conjunctive positive evidence, so activation
	// cannot turn an unrelated PHP package into an application. `all` stays as an
	// explicit synonym.
	if (selection === "auto" || selection === "all") return plugins.filter(p => p.capabilities?.inventory).slice();
	const requested = [...new Set(String(selection).split(",").map(s => s.trim()).filter(Boolean))];
	if (!requested.length) throw new Error("empty application plugin selection");
	return requested.map(id => {
		const plugin = available.get(id);
		if (!plugin) throw new Error(`unknown application plugin: ${id}`);
		return plugin;
	});
}

module.exports = { selectPlugins };
