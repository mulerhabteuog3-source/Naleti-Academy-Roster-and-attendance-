import { json, requireUser } from "../../_lib/auth.js";

const TABLES = {
  teachers:           ["name", "subject", "phone", "grade"],
  students:           ["name", "grade", "parent_phone"],
  teacher_attendance: ["teacher_id", "date", "status"],
  student_attendance: ["student_id", "date", "status"],
  fees:               ["student_id", "amount", "paid", "month"],
  inventory:          ["item", "quantity", "note"],
  employees:          ["name", "position", "phone"],
  library:            ["title", "author", "status"],
  quizzes:            ["title", "grade", "data"],
  schedule:           ["grade", "day", "period", "subject", "teacher_id"],
};

const MANAGERS = ["super", "admin", "director"];
const ALL = ["super", "admin", "director", "teacher", "staff", "accountant", "librarian"];

// who can read / write each table
const READ = { fees: [...MANAGERS, "accountant"], employees: MANAGERS };
const WRITE = {
  student_attendance: [...MANAGERS, "teacher"],
  quizzes: [...MANAGERS, "teacher"],
  fees: [...MANAGERS, "accountant"],
  library: [...MANAGERS, "librarian"],
};

export async function onRequest(ctx) {
  const table = ctx.params.table;
  const cols = TABLES[table];
  if (!cols) return json({ error: "Unknown table" }, 404);

  const method = ctx.request.method;
  const roles = method === "GET" ? (READ[table] || ALL) : (WRITE[table] || MANAGERS);
  const { error } = await requireUser(ctx, roles);
  if (error) return error;

  const db = ctx.env.DB;
  const url = new URL(ctx.request.url);
  const id = url.searchParams.get("id");

  if (method === "GET") {
    const where = [], vals = [];
    for (const c of ["id", ...cols]) {
      const v = url.searchParams.get(c);
      if (v !== null) { where.push(`${c} = ?`); vals.push(v); }
    }
    const sql = `SELECT * FROM ${table}` + (where.length ? " WHERE " + where.join(" AND ") : "") + " ORDER BY id DESC LIMIT 1000";
    const { results } = await db.prepare(sql).bind(...vals).all();
    return json({ rows: results });
  }

  const body = await ctx.request.json().catch(() => ({}));
  const pick = Object.keys(body).filter((k) => cols.includes(k));

  if (method === "POST") {
    if (!pick.length) return json({ error: "No valid fields" }, 400);
    const r = await db.prepare(
      `INSERT INTO ${table} (${pick.join(",")}) VALUES (${pick.map(() => "?").join(",")})`
    ).bind(...pick.map((k) => body[k])).run();
    return json({ ok: true, id: r.meta.last_row_id });
  }

  if (method === "PUT") {
    if (!id || !pick.length) return json({ error: "id and fields needed" }, 400);
    await db.prepare(`UPDATE ${table} SET ${pick.map((k) => k + " = ?").join(",")} WHERE id = ?`)
      .bind(...pick.map((k) => body[k]), id).run();
    return json({ ok: true });
  }

  if (method === "DELETE") {
    if (!id) return json({ error: "id needed" }, 400);
    await db.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
    return json({ ok: true });
  }
  return json({ error: "Method not allowed" }, 405);
}
