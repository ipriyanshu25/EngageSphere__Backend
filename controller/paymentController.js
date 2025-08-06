require('dotenv').config();
const Razorpay    = require('razorpay');
const crypto      = require('crypto');
const Payment     = require('../model/payment');
const Subscription= require('../model/Subscription');
const User        = require('../model/user');
const Plan        = require('../model/plan');

// ── Razorpay client ─────────────────────────────────────────────
const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ── Create Order ────────────────────────────────────────────────
exports.createOrder = async (req, res) => {
  try {
    const { userId, planId, pricingId, currency = 'USD', receipt } = req.body;
    if (!userId || !planId || !pricingId)
      return res.status(400).json({ success: false, message: 'userId, planId, pricingId required' });

    // user & plan checks
    const [ user, plan ] = await Promise.all([
      User.findOne({ userId }),
      Plan.findOne({ planId })
    ]);
    if (!user)  return res.status(404).json({ success:false, message:'User not found' });
    if (!plan)  return res.status(404).json({ success:false, message:'Plan not found' });

    // pricing tier
    const tier = plan.pricing.find(p => p.pricingId === pricingId);
    if (!tier)  return res.status(404).json({ success:false, message:'Tier not found' });

    // price -> minor units
    const amount = Math.round(parseFloat(tier.price.replace(/[^0-9.-]+/g,''))*100);

    // Razorpay order
    const order = await razorpay.orders.create({
      amount,
      currency,
      receipt: receipt || crypto.randomBytes(10).toString('hex')
    });

    // Payment + pending Subscription
    await Promise.all([
      Payment.create({
        orderId:  order.id,
        amount,
        currency,
        receipt:  order.receipt,
        userId,
        planId,
        pricingId,
        status:   'created'
      }),
      Subscription.create({
        userId,
        planId,
        pricingId,
        orderId:     order.id,
        amount,
        currency,
        status:      'pending'
      })
    ]);

    res.status(201).json({ success:true, order });
  } catch (err) {
    console.error('createOrder error:', err);
    res.status(500).json({ success:false, message:err.message });
  }
};

// ── Verify Payment ──────────────────────────────────────────────
exports.verifyPayment = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    /* 1. Signature check -------------------------------------------------- */
    const expectedSig = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
                              .update(`${razorpay_order_id}|${razorpay_payment_id}`)
                              .digest('hex');

    if (expectedSig !== razorpay_signature) {
      await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { status: 'failed' },
        { session }
      );
      await session.commitTransaction();
      return res.status(400).json({ success: false, message: 'Invalid signature' });
    }

    /* 2. Fetch payment from Razorpay -------------------------------------- */
    const rpPayment = await razorpay.payments.fetch(razorpay_payment_id);
    if (rpPayment.status !== 'captured') {
      await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { status: rpPayment.status },
        { session }
      );
      await session.commitTransaction();
      return res.status(400).json({ success: false, message: `Payment ${rpPayment.status}` });
    }

    /* 3. Update Payment doc ---------------------------------------------- */
    const paymentDoc = await Payment.findOneAndUpdate(
      { orderId: razorpay_order_id },
      {
        paymentId: razorpay_payment_id,
        signature: razorpay_signature,
        status:    'paid',
        paidAt:    new Date()
      },
      { new: true, session }
    );

    /* 4. Activate Subscription ------------------------------------------- */
    // compute expiry from plan.durationMonths (if present)
    const plan = await Plan.findOne({ planId: paymentDoc.planId }).session(session);
    let expires = null;
    if (plan && plan.durationMonths) {
      expires = new Date();
      expires.setMonth(expires.getMonth() + plan.durationMonths);
    }

    await Subscription.findOneAndUpdate(
      { orderId: razorpay_order_id },
      {
        paymentId: razorpay_payment_id,
        status:    'active',
        startedAt: new Date(),
        expiresAt: expires
      },
      { session }
    );

    /* 5. Commit + respond ------------------------------------------------- */
    await session.commitTransaction();
    res.json({ success: true, message: 'Payment verified, subscription active' });
  } catch (err) {
    await session.abortTransaction();
    console.error('verifyPayment error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    session.endSession();
  }
};