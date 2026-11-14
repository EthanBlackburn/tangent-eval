module.exports = async function retry(fn, { times = 3, wait = 100 } = {}) {
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i + 1 >= times) throw e;
      await new Promise((r) => setTimeout(r, wait * 2 ** i));
    }
  }
};
