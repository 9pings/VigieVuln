/**
 * Access tokens. Three roles, no accounts (docs/SPEC-fad-service.md §9):
 *   anonymous — no token: public pages and /health only
 *   client    — POST /v1/resource (what fad's --proxy-cache sends)
 *   admin     — client rights + /admin/*
 *
 * A token is 32 random bytes shown ONCE at creation; only its SHA-256 is stored, so a
 * copy of the database grants nothing. Comparison is on the hash, in constant time.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const crypto = require("node:crypto");

const ROLES = ["client", "admin"];
const PREFIX = "fad_";

const hashToken = token => crypto.createHash("sha256").update(String(token)).digest("hex");

function createTokenStore(db) {
	db.exec(`CREATE TABLE IF NOT EXISTS tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hash TEXT NOT NULL UNIQUE,
		role TEXT NOT NULL,
		label TEXT,
		created_at INTEGER NOT NULL,
		revoked_at INTEGER
	)`);
	const q = {
		add: db.prepare("INSERT INTO tokens (hash, role, label, created_at) VALUES (?, ?, ?, ?)"),
		byHash: db.prepare("SELECT id, hash, role, label FROM tokens WHERE hash = ? AND revoked_at IS NULL"),
		list: db.prepare("SELECT id, role, label, created_at, revoked_at FROM tokens ORDER BY id"),
		revoke: db.prepare("UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"),
	};
	return {
		/** → { id, token } — the plaintext token is returned here and never again. */
		add({ role = "client", label = "" } = {}) {
			if (!ROLES.includes(role)) throw new Error(`role must be one of: ${ROLES.join(", ")}`);
			const token = PREFIX + crypto.randomBytes(32).toString("base64url");
			const { lastInsertRowid } = q.add.run(hashToken(token), role, String(label || ""), Date.now());
			return { id: Number(lastInsertRowid), token };
		},
		/** → { id, role, label, hash } for a valid, unrevoked token; null otherwise. */
		verify(token) {
			if (typeof token !== "string" || !token.startsWith(PREFIX) || token.length > 200) return null;
			const h = hashToken(token);
			const row = q.byHash.get(h);
			if (!row || !crypto.timingSafeEqual(Buffer.from(row.hash), Buffer.from(h))) return null;
			return { id: row.id, role: row.role, label: row.label, hash: row.hash };
		},
		list() { return q.list.all().map(r => ({ id: r.id, role: r.role, label: r.label, createdAt: r.created_at, revokedAt: r.revoked_at })); },
		revoke(id) { return q.revoke.run(Date.now(), Number(id)).changes > 0; },
	};
}

module.exports = { createTokenStore, hashToken, ROLES };
