function searchProducts(db) {
  return function searchProductsHandler(request, response) {
    const query = typeof request.query.q === "string" ? request.query.q.slice(0, 120) : "";
    const statement = db.prepare(
      `SELECT id, name, description, price FROM products WHERE ((name LIKE '%${query}%'))`
    );
    return response.json({ data: statement.all() });
  };
}

module.exports = { searchProducts };
