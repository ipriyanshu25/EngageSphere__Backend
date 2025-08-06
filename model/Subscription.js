// models/Subscription.js
const mongoose   = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const subscriptionSchema = new mongoose.Schema({
  subscriptionId: {
    type: String,
    required: true,
    unique: true,
    default: () => uuidv4()
  },
  userId: {
    type: String,
    required: true,
    ref: 'User'
  },
  planId: {
    type: String,
    required: true,
    ref: 'Plan'
  },
  pricingId: {
    type: String,
    required: true
  },
  orderId: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending','active','cancelled','expired'],
    default: 'pending'
  },
  startedAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: Date
}, { timestamps: true });

module.exports = mongoose.model('Subscription', subscriptionSchema);
