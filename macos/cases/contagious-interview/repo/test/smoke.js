const assert = require("node:assert");
const app = require("../server/app");

const server = app.listen(0, async () => {
  try {
    const res = await fetch(`http://localhost:${server.address().port}/api/products`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual((await res.json()).length, 3);
    console.log("ok: GET /api/products");
  } finally {
    server.close();
  }
});
