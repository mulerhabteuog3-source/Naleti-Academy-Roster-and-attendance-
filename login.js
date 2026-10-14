import { json, checkCredentials, signToken } from "../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  const { email, password } = await request.json().catch(() => ({}));
  const user = await checkCredentials(env, email, password);
  if (!user) return json({ error: "Wrong email or password" }, 401);
  return json({ token: await signToken(env, user), user });
}
