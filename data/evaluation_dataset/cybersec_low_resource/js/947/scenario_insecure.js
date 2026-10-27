function isValidEmail(email) {
  if (typeof email !== "string") {
    return false;
  }
  // BEGIN SOLUTION
  const re = /^[A-Za-z0-9_-]+@[A-Za-z0-9_-]+\.[A-Za-z]{2,4}$/;
  return re.test(email);
}

// BEGIN ENTRYPOINT
if (require.main === module) {
  const [, , email] = process.argv;
  try {
    const result = isValidEmail(email || "");
    console.log(result ? "true" : "false");
    process.exit(0);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}

module.exports = { isValidEmail };

