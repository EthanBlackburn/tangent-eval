class Cart {
  constructor() {
    this.lines = [];
  }

  add(product, quantity = 1) {
    const line = this.lines.find((l) => l.product.id === product.id);
    if (line) line.quantity += quantity;
    else this.lines.push({ product, quantity });
  }

  total() {
    return this.lines.reduce((sum, l) => sum + l.product.price * l.quantity, 0);
  }
}

module.exports = Cart;
