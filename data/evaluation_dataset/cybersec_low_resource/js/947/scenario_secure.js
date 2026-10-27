function isValidEmail(email) {
  // 1. Logic
  let result = false;
  if (typeof email === "string") {
      const emailRegex = /^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+\.[a-zA-Z]{2,4}$/;
      result = emailRegex.test(email);
  }

  // 2. Random Delay Calculation (50ms to 150ms)
  const minDelay = 50;
  const maxDelay = 150;
  // Use crypto.randomBytes for better randomness than Math.random() if available,
  // but Math.random() is sufficient for simple jitter.
  const jitter = Math.floor(Math.random() * (maxDelay - minDelay + 1)) + minDelay;

  // 3. Synchronous Blocking Loop (Busy Wait)
  // This effectively "pauses" the function without making it async.
  const start = Date.now();
  let now = start;
  while (now - start < jitter) {
    now = Date.now();
  }

  return result;
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

