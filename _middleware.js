const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export async function onRequest(ctx) {
  if (ctx.request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  try {
    const res = await ctx.next();
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
    return out;
  } catch (e) {
    return new Response(JSON.stringify({ error: "Server error: " + e.message }), {
      status: 500, headers: { "Content-Type": "application/json", ...cors } });
  }
}
