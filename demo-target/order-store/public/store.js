const productsNode = document.querySelector("#products");
const searchForm = document.querySelector("#searchForm");
const searchInput = document.querySelector("#searchInput");
const loginDialog = document.querySelector("#loginDialog");
const loginForm = document.querySelector("#loginForm");
const accountButton = document.querySelector("#accountButton");
const ordersNode = document.querySelector("#ordersList");
const signedInAs = document.querySelector("#signedInAs");
let token = sessionStorage.getItem("order-store-demo-token") || "";

const money = (value) => new Intl.NumberFormat("ru-RU").format(value) + " ₽";

function renderProducts(items) {
  productsNode.innerHTML = "";
  if (!items.length) {
    productsNode.innerHTML = '<p class="order-placeholder">Ничего не найдено. Попробуйте другое название.</p>';
    return;
  }
  items.forEach((item, index) => {
    const card = document.createElement("article");
    card.className = "product-card";
    card.innerHTML = `<div class="product-art"><div class="product-shape" aria-hidden="true"></div></div><div class="product-info"><div><h3>${escapeHtml(item.name)}</h3><p>${escapeHtml(item.description)}</p></div><span class="product-price">${money(item.price)}</span></div>`;
    productsNode.append(card);
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

async function search(query = "") {
  const response = await fetch(`/api/products/search?q=${encodeURIComponent(query)}`);
  const body = await response.json();
  renderProducts(Array.isArray(body.data) ? body.data : []);
}

searchForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void search(searchInput.value);
});

accountButton.addEventListener("click", () => loginDialog.showModal());
loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(loginForm);
  const response = await fetch("/api/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: data.get("email"), password: data.get("password") }),
  });
  const body = await response.json();
  if (!response.ok) return;
  token = body.token;
  sessionStorage.setItem("order-store-demo-token", token);
  loginDialog.close();
  accountButton.textContent = body.user.name;
  signedInAs.textContent = `Вы вошли как ${body.user.name}`;
  await loadOrders();
});

async function loadOrders() {
  if (!token) return;
  const response = await fetch("/api/orders", { headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) {
    token = "";
    sessionStorage.removeItem("order-store-demo-token");
    return;
  }
  const body = await response.json();
  ordersNode.innerHTML = "";
  (body.orders || []).forEach((order) => {
    const row = document.createElement("div");
    row.className = "order-row";
    row.innerHTML = `<span><b>${escapeHtml(order.id)}</b> · ${escapeHtml(order.item)}</span><span>${money(order.total)}</span>`;
    ordersNode.append(row);
  });
}

void search();
if (token) {
  accountButton.textContent = "Мой аккаунт";
  signedInAs.textContent = "Вы вошли в демо-аккаунт";
  void loadOrders();
}
