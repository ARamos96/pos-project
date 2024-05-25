// ℹ️ Gets access to environment variables/settings
// https://www.npmjs.com/package/dotenv
require("dotenv").config();

// ℹ️ Connects to the database
require("./db");

// Handles http requests (express is node js framework)
// https://www.npmjs.com/package/express
const express = require("express");

const app = express();

// Import authentication middleware
// isAuthenticated is in charge of extracting token, verifies it + decodes it and, attaches it to req.payload.
// Without it, req.payload will be undefined
const { isAuthenticated } = require("./middleware/jwt.middleware")

// Import role validation middleware
const { roleValidation } = require("./middleware/roleValidation.middleware");

// ℹ️ This function is getting exported from the config folder. It runs most pieces of middleware
require("./config")(app);

// 👇 Start handling routes here
const indexRoutes = require("./routes/index.routes");
app.use("/api", indexRoutes);

const authRouter = require("./routes/auth.routes");
app.use("/auth", authRouter);

const adminRouter = require("./routes/admin.routes")
app.use("/admin", isAuthenticated, roleValidation(["admin"]), adminRouter);

const productRouter = require('./routes/product.routes')
app.use("/products", isAuthenticated, roleValidation(["admin"]), productRouter);

// ❗ To handle errors. Routes that don't exist or errors that you handle in specific routes
require("./error-handling")(app);

module.exports = app;
