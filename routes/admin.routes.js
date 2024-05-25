const express = require("express");
const router = express.Router();
const { isAuthenticated } = require("../middleware/jwt.middleware");
const {roleValidation} = require("../middleware/roleValidation.middleware");
const User = require("./../models/User.model");

// Admin may modify user's role
router.patch("/assign-role", isAuthenticated, roleValidation(["admin"]), (req, res) => {
    // Get user._id
    const { _id, role } = req.body;

    User.findByIdAndUpdate(_id, {role}, { new: true })
        .then((updatedUser) => res.json(updatedUser.role))
        .catch((error) => next(error));
});

module.exports = router;