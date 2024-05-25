const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User.model");

const saltRounds = 10;

// POST /signup - Create a new user in the database
router.post("signup", (req, res) => {
  const { email, password, name } = req.body;

  // Check if the email, password or name are provided
  if (!email || !password || !name) {
    return res
      .status(400)
      .json({ message: "Provide an email, password and name" });
  }

  // Use regex to validate the email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Provide a valid email" });
  }

  // Use regex to validate the password
  const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ message: "Provide a valid password" });
  }

  // Check if the user already exists
  User.findOne({ email })
    .then((user) => {
      if (user) {
        // If the user with the same email already exists, send an error response
        return res.status(400).json({ message: "Email already in use" });
      }
      // If the email is unique, proceed to hash the password
      const salt = bcrypt.genSaltSync(saltRounds);
      const hashedPassword = bcrypt.hashSync(password, salt);

      // Create a new user in the database
      // We return a pending promise, which allows us to chain another `then`
      return User.create({ email, password: hashedPassword, name });
    })
    .then((createdUser) => {
      // Deconstruct the newly created user object to omit the password
      // We should never expose passwords publicly
      const { email, name, _id } = createdUser;

      // Create a new object that doesn't expose the password
      const user = { email, name, _id };

      // Send a json response containing the user object
      res.status(201).json({ user: user });
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ message: "Internal Server Error" });
    });
});

// POST /login - Verifies email and password and returns a JWT
router.post("/login", (res, res, next) => {
  const { email, password } = req.body;

  // Check if the email and password are provided
  if (!email || !password) {
    return res.status(400).json({ message: "Provide an email and password" });
  }

  //Check if user exists
  User.findOne({ email })
    .then((user) => {
      if (!user) {
        // If user is not found, return an error message
        return res.status(401).json({ message: "User not found" });
      }

      // If user exists, check if provided password is correct
      const isPasswordCorrect = bcrypt.compareSync(password, user.password);

      if (isPasswordCorrect) {
        // Deconstruct user object to omit the password
        const { email, role, name, _id } = user;

        // Create an object that will be set as the token payload
        const payload = { email, role, name, _id };

        // Create and sign the token
        const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
          algorithm: "HS256",
          expiresIn: "6h",
        });

        // Send a json response containing the token
        return res.status(200).json({ authToken: authToken });
      } else {
        res.status(401).json({ message: "Unable to authenticate user " });
      }
    })
    .catch((err) =>
      res
        .status(500)
        .json({ message: "Internal Server Error", err: err.message })
    );
});

// Export router
module.exports = router;