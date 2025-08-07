// controllers/subscriptionController.js
const Subscription = require('../model/Subscription');
const Plan         = require('../model/plan');

/** Owner-only rule (no admin bypass) */
const isOwner = (sub, reqUser) => sub.userId === reqUser.userId;

/* ------------------------------------------------------------------
   POST /subscriptions/user   { userId }
-------------------------------------------------------------------*/
exports.getUserSubscriptions = async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId)
      return res.status(400).json({ success:false, message:'userId is required' });

    const subs = await Subscription.find({ userId }).sort({ createdAt:-1 });
    res.json({ success:true, subscriptions: subs });
  } catch (err) {
    console.error('getUserSubscriptions error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};

/* ------------------------------------------------------------------
   POST /subscriptions/cancel  { subscriptionId }
-------------------------------------------------------------------*/
exports.cancelSubscription = async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    if (!subscriptionId)
      return res.status(400).json({ success:false, message:'subscriptionId required' });

    const sub = await Subscription.findOne({ subscriptionId });
    if (!sub) return res.status(404).json({ success:false, message:'Not found' });
    if (!isOwner(sub, req.user))
      return res.status(403).json({ success:false, message:'Forbidden' });

    sub.status      = 'cancelled';
    sub.cancelledAt = new Date();
    await sub.save();

    res.json({ success:true, subscription: sub });
  } catch (err) {
    console.error('cancelSubscription error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};

/* ------------------------------------------------------------------
   POST /subscriptions/update
   Body: { userId, planId?, pricingId?, currency?, price? }
-------------------------------------------------------------------*/
exports.updateSubscription = async (req, res) => {
  try {
    const { userId, planId, pricingId, currency, price } = req.body;
    if (!userId)
      return res.status(400).json({ success:false, message:'userId is required' });

    /* ------------------------------------------------------------------ */
    /* 1. Look for an existing subscription                               */
    /* ------------------------------------------------------------------ */
    let sub = await Subscription.findOne({ userId }).sort({ createdAt:-1 });

    /* ========== Case A – subscription exists: update it ========== */
    if (sub) {
      if (!isOwner(sub, req.user))
        return res.status(403).json({ success:false, message:'Forbidden' });

      if (planId)    sub.planId    = planId;
      if (pricingId) sub.pricingId = pricingId;
      if (currency)  sub.currency  = currency.toUpperCase();

      if (price != null) {
        const numeric = typeof price === 'number'
          ? price
          : parseFloat(String(price).replace(/[^0-9.-]+/g, ''));
        if (isNaN(numeric) || numeric <= 0)
          return res.status(400).json({ success:false, message:'Invalid price value' });
        sub.amount = Math.round(numeric * 100);
      }

      await sub.save();
      return res.json({ success:true, subscription: sub });
    }

    /* ========== Case B – no subscription: create a new one ========== */
    /* Validate mandatory fields for creation */
    if (!planId || !pricingId || !currency)
      return res.status(400).json({ success:false, message:'planId, pricingId and currency required to create new subscription' });

    /* Fetch plan to compute expiry & default price (if price not provided) */
    const plan = await Plan.findOne({ planId });
    if (!plan)
      return res.status(404).json({ success:false, message:'Plan not found' });

    /* determine amount */
    let amountMinor;
    if (price != null) {
      const numeric = typeof price === 'number'
        ? price
        : parseFloat(String(price).replace(/[^0-9.-]+/g, ''));
      if (isNaN(numeric) || numeric <= 0)
        return res.status(400).json({ success:false, message:'Invalid price value' });
      amountMinor = Math.round(numeric * 100);
    } else {
      // try to pull from the plan's pricing table
      const tier = plan.pricing.find(p => p.pricingId === pricingId);
      if (!tier)
        return res.status(400).json({ success:false, message:'Pricing tier not found in plan, and no price supplied' });
      amountMinor = Math.round(parseFloat(tier.price.replace(/[^0-9.-]+/g,''))*100);
    }

    /* expiry date */
    let expiresAt = null;
    if (plan.durationMonths) {
      expiresAt = new Date();
      expiresAt.setMonth(expiresAt.getMonth() + plan.durationMonths);
    }

    sub = await Subscription.create({
      userId,
      planId,
      pricingId,
      currency: currency.toUpperCase(),
      amount:   amountMinor,
      status:   'active',
      startedAt: new Date(),
      expiresAt
    });

    return res.status(201).json({ success:true, subscription: sub });

  } catch (err) {
    console.error('updateSubscription error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};

/* ------------------------------------------------------------------
   POST /subscriptions/renew   { subscriptionId }
-------------------------------------------------------------------*/
exports.renewSubscription = async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    if (!subscriptionId)
      return res.status(400).json({ success:false, message:'subscriptionId required' });

    const sub = await Subscription.findOne({ subscriptionId });
    if (!sub) return res.status(404).json({ success:false, message:'Not found' });
    if (!isOwner(sub, req.user))
      return res.status(403).json({ success:false, message:'Forbidden' });

    const plan = await Plan.findOne({ planId: sub.planId });
    if (!plan || !plan.durationMonths)
      return res.status(400).json({ success:false, message:'Plan has no durationMonths' });

    const now   = new Date();
    const exp   = new Date();
    exp.setMonth(exp.getMonth() + plan.durationMonths);

    sub.status    = 'active';
    sub.startedAt = now;
    sub.expiresAt = exp;
    await sub.save();

    res.json({ success:true, subscription: sub });
  } catch (err) {
    console.error('renewSubscription error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};
