const crypto = require("node:crypto");

module.exports = (text) => crypto.createHash("sha256").update(text).digest("hex");
