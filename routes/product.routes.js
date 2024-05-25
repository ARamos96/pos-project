const express = require("express");
const router = express.Router();
const Product = require("../models/Product.model");
const { isAuthenticated } = require("../middleware/jwt.middleware");
const {roleValidation} = require("../middleware/roleValidation.middleware");

// Get all products
router.get("/", (req, res) => {
    Product.find()
      .then(products => res.json(products))
      .catch(err => res.status(500).json({
          message: "Internal Server Error", err 
       }));
  });

  // Create new product
  // Only admins can create new products
  router.post("/", (req, res) => {
    const { name, price, description, inStock } = req.body;
    

    Product.create({ name, price, description, inStock })
      .then(newProduct => res.status(201).json(newProduct))
              .catch(err => res.status(500).json({ 
                  message: "Internal Server Error", err 
      }));
  });

  module.exports = router;