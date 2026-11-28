/**
 * lib/codecs/recipes.js — recettes de fix par écosystème pour le report.
 *
 * Extrait de lib/reports/cve-report.js (ECO_RECIPE + snippet helpers). Clés = id de codec
 * (== ecosystemType). Chaque recette : { label, pinSection, pinIntro(cnt),
 * snippet(items), directSection }. `items` = [{ groupId, artifactId, fixVersion }].
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { makeT } = require("../reports/i18n");
// Default translator: English, which still INTERPOLATES {n}. An identity function would
// leave the placeholder in the text, so `pinIntro(3)` must not fall back to `x => x`.
const EN = makeT("en");
// The English count decides the form; each form is its own catalogue key.
const pl = (t, n, one, many) => t(n > 1 ? many : one, { n });

function esc(s) {
	if (s == null) return "";
	return String(s)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

function dependencyManagementSnippet(items) {
	const inner = items.map(it => `        <dependency>
            <groupId>${esc(it.groupId)}</groupId>
            <artifactId>${esc(it.artifactId)}</artifactId>
            <version>${esc(it.fixVersion)}</version>
        </dependency>`).join("\n");
	return `<dependencyManagement>
    <dependencies>
${inner}
    </dependencies>
</dependencyManagement>`;
}

function npmOverridesSnippet(items) {
	const lines = items.map(it => `    "${esc(it.artifactId)}": "${esc(it.fixVersion)}"`).join(",\n");
	return `{
  "overrides": {
${lines}
  }
}`;
}

function yarnResolutionsSnippet(items) {
	const lines = items.map(it => `    "${esc(it.artifactId)}": "${esc(it.fixVersion)}"`).join(",\n");
	return `{
  "resolutions": {
${lines}
  }
}`;
}

const maven = {
	label: "Maven",
	noFix: "Add an &lt;exclusion&gt; in the declaring POM",
	pinSection: "A. Pin vulnerable transitives in <dependencyManagement>",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Paste into the root POM to immediately neutralise {n} transitive vulnerability:",
		"Paste into the root POM to immediately neutralise {n} transitive vulnerabilities:"),
	snippet: dependencyManagementSnippet,
	directSection: "B. Or update the direct dependencies pulling them in",
};

function gradleConstraintsSnippet(items) {
	const inner = items.map(it => `        implementation("${esc(it.groupId)}:${esc(it.artifactId)}:${esc(it.fixVersion)}")`).join("\n");
	return `dependencies {
    constraints {
${inner}
    }
}`;
}

const gradle = {
	label: "Gradle",
	noFix: "Add an exclude in the dependency",
	pinSection: "A. Pin vulnerable transitives via a constraints { } block",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Add to the (sub)project <code>build.gradle(.kts)</code> dependencies block to force {n} transitive to a fixed version:",
		"Add to the (sub)project <code>build.gradle(.kts)</code> dependencies block to force {n} transitives to a fixed version:"),
	snippet: gradleConstraintsSnippet,
	directSection: "B. Or bump the direct dependency (or its version in <code>gradle/libs.versions.toml</code>)",
};

const npm = {
	label: "npm",
	noFix: "Add an npm override",
	pinSection: "A. Pin vulnerable transitives via npm overrides",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Add to the root <code>package.json</code> and run <code>npm install</code> to force {n} transitive to a fixed version:",
		"Add to the root <code>package.json</code> and run <code>npm install</code> to force {n} transitives to a fixed version:"),
	snippet: npmOverridesSnippet,
	directSection: "B. Or update the direct dependencies (and run npm install)",
};

const yarn = {
	label: "Yarn",
	noFix: "Add a yarn resolution",
	pinSection: "A. Pin vulnerable transitives via yarn resolutions",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Add to the root <code>package.json</code> and run <code>yarn install</code> to force {n} transitive to a fixed version:",
		"Add to the root <code>package.json</code> and run <code>yarn install</code> to force {n} transitives to a fixed version:"),
	snippet: yarnResolutionsSnippet,
	directSection: "B. Or update the direct dependencies (and run yarn install)",
};

function composerRequireSnippet(items) {
	return items.map(it => `composer require ${it.groupId ? it.groupId + "/" : ""}${it.artifactId}:^${esc(it.fixVersion)}`).join("\n");
}

const composer = {
	label: "Composer",
	noFix: "Replace or remove the package",
	pinSection: "A. Update the abandoned / vulnerable packages",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Run for the {n} affected package, then commit the updated <code>composer.lock</code>:",
		"Run for the {n} affected packages, then commit the updated <code>composer.lock</code>:"),
	snippet: composerRequireSnippet,
	directSection: "B. Or bump them in composer.json and run composer update",
};

function pipInstallSnippet(items) {
	return items.map(it => `pip install '${esc(it.artifactId)}>=${esc(it.fixVersion)}'`).join("\n");
}

const pypi = {
	label: "PyPI",
	noFix: "Upgrade or replace the package",
	pinSection: "A. Upgrade the affected packages",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Upgrade the {n} affected package, then re-lock (poetry lock / pip-compile):",
		"Upgrade the {n} affected packages, then re-lock (poetry lock / pip-compile):"),
	snippet: pipInstallSnippet,
	directSection: "B. Or bump them in pyproject.toml / requirements.txt and re-lock",
};

function dotnetAddSnippet(items) {
	return items.map(it => `dotnet add package ${esc(it.artifactId)} --version ${esc(it.fixVersion)}`).join("\n");
}

const nuget = {
	label: "NuGet",
	noFix: "Upgrade or replace the package",
	pinSection: "A. Update the affected packages",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Run for the {n} affected package (or bump <code>Directory.Packages.props</code> under Central Package Management):",
		"Run for the {n} affected packages (or bump <code>Directory.Packages.props</code> under Central Package Management):"),
	snippet: dotnetAddSnippet,
	directSection: "B. Then restore and commit packages.lock.json",
};

function goGetSnippet(items) {
	return items.map(it => `go get ${esc(it.artifactId)}@v${esc(it.fixVersion)}`).join("\n");
}

const go = {
	label: "Go",
	noFix: "Upgrade or replace the module",
	pinSection: "A. Upgrade the affected modules",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Run for the {n} affected module, then commit go.mod / go.sum (go mod tidy):",
		"Run for the {n} affected modules, then commit go.mod / go.sum (go mod tidy):"),
	snippet: goGetSnippet,
	directSection: "B. Or bump them in go.mod and run go mod tidy",
};

function bundleUpdateSnippet(items) {
	return items.map(it => `bundle update ${esc(it.artifactId)} --conservative   # to >= ${esc(it.fixVersion)}`).join("\n");
}

const ruby = {
	label: "Ruby",
	noFix: "Upgrade or replace the gem",
	pinSection: "A. Update the affected gems",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Run for the {n} affected gem, then commit Gemfile.lock:",
		"Run for the {n} affected gems, then commit Gemfile.lock:"),
	snippet: bundleUpdateSnippet,
	directSection: "B. Or pin them in the Gemfile and run bundle update",
};

const binary = {
	label: "Binaries",
	noFix: "Replace or remove the vendored binary",
	pinSection: "A. Replace or remove the vendored binary",
	pinIntro: (cnt, t = EN) => pl(t, cnt,
		"Replace {n} committed binary with a managed dependency, or verify its provenance/checksum:",
		"Replace {n} committed binaries with a managed dependency, or verify their provenance/checksum:"),
	snippet: (items) => ((items || []).map(it => `# ${it.artifactId || "binary"}: replace with a managed dependency, or record its origin and verify its checksum`).join("\n")) || "# verify the provenance/checksum of each vendored binary, or replace it with a managed dependency",
	directSection: "B. Prefer declaring these through a package manager (Maven/npm/NuGet/…)",
};

module.exports = { maven, gradle, npm, yarn, composer, pypi, nuget, go, ruby, binary, dependencyManagementSnippet, gradleConstraintsSnippet, npmOverridesSnippet, yarnResolutionsSnippet, composerRequireSnippet, pipInstallSnippet, dotnetAddSnippet, goGetSnippet, bundleUpdateSnippet };
