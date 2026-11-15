const express = require("express");
const { DatabaseSync } = require("node:sqlite");
const path = require("node:path");
const { login } = require("./routes/login");
const { searchProducts } = require("./routes/search");
const { getOrderById, listOrders } = require("./routes/orders");
const { listPublicFiles } = require("./routes/files");

const app = express();
const db = new DatabaseSync(":memory:");
const sessions = new Map();

db.exec(`
  CREATE TABLE products (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, price INTEGER NOT NULL);
  CREATE TABLE orders (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, item TEXT NOT NULL, total INTEGER NOT NULL);
  CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL, password TEXT NOT NULL, name TEXT NOT NULL);
  INSERT INTO accounts VALUES
    ('user-a', 'alice@demo.local', 'alice-demo-2026', 'Алиса'),
    ('user-b', 'bob@demo.local', 'bob-demo-2026', 'Борис');
  INSERT INTO products VALUES
    ('p-1', 'Кофемолка Север', 'Стальная жерновая кофемолка', 8490),
    ('p-2', 'Чайник Линия', 'Тихий чайник на 1,7 литра', 5290),
    ('p-3', 'Кружка Тепло', 'Керамическая кружка ручной работы', 1290);
  INSERT INTO orders VALUES
    ('order-a', 'user-a', 'Кофемолка Север', 8490),
    ('order-b', 'user-b', 'Чайник Линия', 5290);
`);

app.disable("x-powered-by");
app.use(express.json({ limit: "16kb", strict: true }));
// Let API routes below handle paths that do not exist in the static directory.
app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));

function currentUser(request) {
  const value = request.headers.authorization || "";
  const token = value.startsWith("Bearer ") ? value.slice(7) : "";
  const userId = sessions.get(token);
  return userId ? { id: userId } : null;
}

function requireUser(request, response, next) {
  request.user = currentUser(request);
  if (!request.user) return response.status(401).json({ error: "Нужен вход в аккаунт" });
  next();
}

app.get("/health", (_request, response) => response.json({
  status: "ok", app: "cft-order-store-demo", version: "1.0",
}));
app.get("/api/products/search", searchProducts(db));
app.post("/api/auth/login", login(db, sessions));
app.get("/api/files/", listPublicFiles);
app.get("/api/files/backup.env", (_request, response) => response.type("text/plain").send(
  "DEMO_PAYMENT_TOKEN=demo-placeholder-not-a-real-secret\n"
));
app.get("/api/orders", requireUser, listOrders(db));
app.get("/api/orders/:orderId", requireUser, getOrderById(db));

app.use((error, _request, response, _next) => {
  if (response.headersSent) return;
  response.status(400).json({ error: "Не удалось обработать запрос" });
});

const server = app.listen(3000, "0.0.0.0", () => {
  console.log("Order Store demo listening on port 3000");
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 2_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
