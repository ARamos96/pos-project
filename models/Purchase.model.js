const mongoose = require("mongoose");
const { Schema, model } = mongoose;

const purchaseSchema = new Schema({
  product: { type: Schema.Types.ObjectId, ref: "Product", required: true },
  quantity: { type: Number, required: true },
  buyer: { type: Schema.Types.ObjectId, ref: "User", required: true },
  date: { type: Date, default: Date.now },
});

module.exports = model("Purchase", purchaseSchema);