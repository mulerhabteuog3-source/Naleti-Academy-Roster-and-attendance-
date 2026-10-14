const enc = new TextEncoder();

const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const toB64Url = (s) => s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64Url = (s) => s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);

export const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

export function safeEq(a = "", b = "") {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------- password hashing (PBKDF2) ----------
export async function hashPassword(password, saltB64) {
  const salt = saltB64 ? fromB64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  return `pbkdf2$${toB64(salt)}$${toB64(bits)}`;
}

export async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) return false;
  const salt = stored.split("$")[1];
  const again = await hashPassword(password, salt);
  return safeEq(again, stored);
}

// ---------- session token (HMAC signed) ----------
async function hmacKey(env) {
  const secret = "naleti-session:" + (env.SUPER_ADMIN_PASSWORD || "");
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

export async function signToken(env, user, hours = 12) {
  const payload = { ...user, exp: Date.now() + hours * 3600 * 1000 };
  const body = toB64Url(btoa(unescape(encodeURIComponent(JSON.stringify(payload)))));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(body));
  return body + "." + toB64Url(toB64(sig));
}

export async function authenticate(request, env) {
  const h = request.headers.get("Authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const good = toB64Url(toB64(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(body))));
  if (!safeEq(sig, good)) return null;
  try {
    const payload = JSON.parse(decodeURIComponent(escape(atob(fromB64Url(body)))));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ---------- check email + password ----------
// Database users win. If no DB row exists, the two accounts from
// Cloudflare variables (super admin, admin) are accepted.
export async function checkCredentials(env, emailRaw, password) {
  const email = String(emailRaw || "").trim().toLowerCase();
  if (!email || !password) return null;

  const row = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(email).first();
  if (row) {
    return (await verifyPassword(password, row.password_hash))
      ? { email, role: row.role, name: row.full_name || email } : null;
  }
  const lower = (v) => String(v || "").trim().toLowerCase();
  if (lower(env.SUPER_ADMIN_EMAIL) === email && safeEq(password, env.SUPER_ADMIN_PASSWORD))
    return { email, role: "super", name: "Super Admin" };
  if (lower(env.ADMIN_EMAIL) === email && safeEq(password, env.ADMIN_PASSWORD))
    return { email, role: "admin", name: "Admin" };
  return null;
}

export async function requireUser(ctx, roles) {
  const user = await authenticate(ctx.request, ctx.env);
  if (!user) return { error: json({ error: "Not logged in" }, 401) };
  if (roles && !roles.includes(user.role)) return { error: json({ error: "Not allowed" }, 403) };
  return { user };
}
