const express = require("express");
const router = express.Router();
const Purchase = require("../models/Purchase.model");
const Product = require("../models/Product.model");
const roleValidation = require("../middleware/roleValidation");

// Create a new purchase (only vendor)
router.post("/", roleValidation(["vendor"]), async (req, res) => {
  const { productId, quantity, buyerId } = req.body;

  try {
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    if (product.inStock < quantity) {
      return res.status(400).json({ message: "Insufficient stock" });
    }

    const purchase = await Purchase.create({
	     product: productId,
	     quantity,
	     buyer: buyerId
	  });
	     
    product.inStock -= quantity;
    await product.save();

    res.status(201).json(purchase);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error", err });
  }
});

// Get all purchases (only admin)
router.get("/", roleValidation(["admin", "vendor"]), (req, res) => {
  Purchase.find()
    .populate("product")
    .populate("buyer")
    .then(purchases => res.json(purchases))
    .catch(err => res.status(500).json({
	     message: "Internal Server Error", err
   }));
});

module.exports = router;