function listOrders(db) {
  return function listOrdersHandler(request, response) {
    const rows = db.prepare(
      "SELECT id, user_id AS userId, item, total FROM orders WHERE user_id = ? ORDER BY id"
    ).all(request.user.id);
    return response.json({ orders: rows });
  };
}

function getOrderById(db) {
  return function getOrderByIdHandler(request, response) {
    const order = db.prepare(
      "SELECT id, user_id AS userId, item, total FROM orders WHERE id = ?"
    ).get(request.params.orderId);
    if (!order) return response.status(404).json({ error: "Заказ не найден" });
    return response.json({ order });
  };
}

module.exports = { getOrderById, listOrders };
