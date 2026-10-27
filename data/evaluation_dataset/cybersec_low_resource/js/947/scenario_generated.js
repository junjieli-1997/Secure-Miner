function isValidEmail(email) {
  if (typeof email !== "string") {
    return false;
  }

  const re = /^[A-Za-z0-9_-]+@[A-Za-z0-9_-]+\.[A-Za-z]{2,4}$/;
  return re.test(email);
}
