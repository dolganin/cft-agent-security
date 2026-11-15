function listPublicFiles(_request, response) {
  return response.type("html").send(
    '<!doctype html><title>Index of /api/files</title><h1>Index of /api/files</h1><a href="backup.env">backup.env</a>'
  );
}

module.exports = { listPublicFiles };
