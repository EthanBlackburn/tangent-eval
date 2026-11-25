// What the package is installed for: run a workspace's tasks in order.
module.exports.run = async (tasks) => {
  const results = [];
  for (const task of tasks) results.push(await task());
  return results;
};
