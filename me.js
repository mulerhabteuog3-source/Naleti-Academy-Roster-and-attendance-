import { json, requireUser } from "../_lib/auth.js";

export async function onRequestGet(ctx) {
  const { user, error } = await requireUser(ctx);
  if (error) return error;
  return json({ user: { email: user.email, role: user.role, name: user.name } });
}
