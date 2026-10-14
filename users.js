import { json, requireUser, hashPassword } from "../_lib/auth.js";

const STAFF_ROLES = ["director", "teacher", "staff", "accountant", "librarian"];

export async function onRequest(ctx) {
  const { user, error } = await requireUser(ctx, ["super", "admin"]);
  if (error) return error;
  const { request, env } = ctx;
  const url = new URL(request.url);

  if (request.method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, username AS email, full_name, role, created_at FROM users ORDER BY id DESC").all();
    return json({ users: results });
  }

  const body = await request.json().catch(() => ({}));
  const canAssign = (role) => user.role === "super" ? ["admin", ...STAFF_ROLES].includes(role) : STAFF_ROLES.includes(role);

  if (request.method === "POST") {           // create user
    const email = String(body.email || "").trim().toLowerCase();
    if (!email.includes("@")) return json({ error: "Valid email needed" }, 400);
    if (!body.password || body.password.length < 8) return json({ error: "Password min 8 characters" }, 400);
    if (!canAssign(body.role)) return json({ error: "You cannot create this role" }, 403);
    try {
      await env.DB.prepare("INSERT INTO users (username, password_hash, role, full_name) VALUES (?,?,?,?)")
        .bind(email, await hashPassword(body.password), body.role, body.full_name || "").run();
    } catch { return json({ error: "This email already exists" }, 409); }
    return json({ ok: true });
  }

  if (request.method === "PUT") {            // reset someone's password
    if (!body.id || !body.password || body.password.length < 8) return json({ error: "id and password (min 8) needed" }, 400);
    const target = await env.DB.prepare("SELECT role FROM users WHERE id = ?").bind(body.id).first();
    if (!target) return json({ error: "Not found" }, 404);
    if (!canAssign(target.role)) return json({ error: "Not allowed" }, 403);
    await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(await hashPassword(body.password), body.id).run();
    return json({ ok: true });
  }

  if (request.method === "DELETE") {
    const id = url.searchParams.get("id");
    const target = await env.DB.prepare("SELECT role FROM users WHERE id = ?").bind(id).first();
    if (!target) return json({ error: "Not found" }, 404);
    if (!canAssign(target.role)) return json({ error: "Not allowed" }, 403);
    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }
  return json({ error: "Method not allowed" }, 405);
}
