import { json, requireUser, checkCredentials, hashPassword } from "../_lib/auth.js";

export async function onRequestPost(ctx) {
  const { user, error } = await requireUser(ctx);
  if (error) return error;
  const { oldPassword, newPassword } = await ctx.request.json().catch(() => ({}));
  if (!newPassword || newPassword.length < 8) return json({ error: "New password must be at least 8 characters" }, 400);
  if (!(await checkCredentials(ctx.env, user.email, oldPassword))) return json({ error: "Old password is wrong" }, 401);

  const hash = await hashPassword(newPassword);
  const row = await ctx.env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(user.email).first();
  if (row) await ctx.env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(hash, row.id).run();
  else await ctx.env.DB.prepare("INSERT INTO users (username, password_hash, role, full_name) VALUES (?,?,?,?)")
    .bind(user.email, hash, user.role, user.name).run();
  return json({ ok: true });
}
