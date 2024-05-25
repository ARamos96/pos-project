const { expressjwt: jwt } = require("express-jwt");

// Initialize JWT token validation middleware
// isAuthenticated is in charge of extracting token, verifies it + decodes it and, attaches it to req.payload.
const isAuthenticated = jwt({
  secret: process.env.TOKEN_SECRET,
  algorithms: ["HS256"],
  requestProperty: "payload",
  getToken: getTokenFromHeaders,
});

// Extract JWT token from headers
function getTokenFromHeaders(req) {
  // Check if token is available on the request headers
  console.log(req.headers.authorization)
  if (req.headers.authorization && req.headers.authorization.split(" ")[0] === "Bearer") {
    // Get the encoded token string and return it
    const token = req.headers.authorization.split(" ")[1];
    return token;
  }

  return null;
}

// Export middleware

module.exports = { isAuthenticated };
