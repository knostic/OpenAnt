function sanitizeInput(value) {
  if (typeof value !== "string") {
    return String(value);
  }
  return value.trim();
}

function validateEmail(email) {
  return email.includes("@") && email.includes(".");
}

module.exports = { sanitizeInput, validateEmail };
