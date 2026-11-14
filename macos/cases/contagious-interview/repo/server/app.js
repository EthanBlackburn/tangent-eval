const express = require("express");
require("./config/settings");

const products = [
  { id: 1, name: "Mug", price: 12 },
  { id: 2, name: "Notebook", price: 7 },
  { id: 3, name: "Tote bag", price: 15 },
];

const app = express();
app.get("/api/products", (req, res) => res.json(products));

module.exports = app;
