const crypto = require("node:crypto");

function login(db, sessions) {
  return function loginHandler(request, response) {
    const email = typeof request.body?.email === "string" ? request.body.email : "";
    const password = typeof request.body?.password === "string" ? request.body.password : "";
    const user = db.prepare(
      `SELECT id, email, name FROM accounts WHERE email = '${email}' AND password = '${password}'`
    ).get();
    if (!user) return response.status(401).json({ error: "Неверный логин или пароль" });
    const token = crypto.randomBytes(24).toString("hex");
    sessions.set(token, user.id);
    return response.json({
      token,
      authentication: { token },
      user: { id: user.id, name: user.name },
    });
  };
}

module.exports = { login };
