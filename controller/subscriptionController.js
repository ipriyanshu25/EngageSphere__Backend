const Subscription = require('../model/Subscription');
const Plan         = require('../model/plan');

/** Helper: ensure caller is owner or admin */
const isOwnerOrAdmin = (sub, reqUser) =>
  sub.userId === reqUser.userId || reqUser.role === 'admin';

/**
 * POST /subscriptions/user
 * Body: { userId }
 */
exports.getUserSubscriptions = async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success:false, message:'userId is required' });

    const subs = await Subscription.find({ userId }).sort({ createdAt:-1 });
    res.json({ success:true, subscriptions: subs });
  } catch (err) {
    console.error('getUserSubscriptions error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};

/**
 * POST /subscriptions/all  (admin only)
 * Body: { }  (optionally accept filters / pagination later)
 */
exports.getAllSubscriptions = async (_req, res) => {
  try {
    const subs = await Subscription.find().sort({ createdAt:-1 });
    res.json({ success:true, subscriptions: subs });
  } catch (err) {
    console.error('getAllSubscriptions error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};

/**
 * POST /subscriptions/cancel
 * Body: { subscriptionId }
 */
exports.cancelSubscription = async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    if (!subscriptionId) return res.status(400).json({ success:false, message:'subscriptionId required' });

    const sub = await Subscription.findOne({ subscriptionId });
    if (!sub) return res.status(404).json({ success:false, message:'Not found' });
    if (!isOwnerOrAdmin(sub, req.user))
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

/**
 * POST /subscriptions/update
 * Body: { subscriptionId, fieldsToUpdate }
 * Allows updating planId / pricingId or custom expiry.
 */
exports.updateSubscription = async (req, res) => {
  try {
    const { subscriptionId, planId, pricingId, status, expiresAt } = req.body;
    if (!subscriptionId) return res.status(400).json({ success:false, message:'subscriptionId required' });

    const sub = await Subscription.findOne({ subscriptionId });
    if (!sub) return res.status(404).json({ success:false, message:'Not found' });
    if (!isOwnerOrAdmin(sub, req.user))
      return res.status(403).json({ success:false, message:'Forbidden' });

    if (planId)    sub.planId    = planId;
    if (pricingId) sub.pricingId = pricingId;
    if (status)    sub.status    = status;        // e.g. admin sets to expired
    if (expiresAt) sub.expiresAt = new Date(expiresAt);

    await sub.save();
    res.json({ success:true, subscription: sub });
  } catch (err) {
    console.error('updateSubscription error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};

/**
 * POST /subscriptions/renew
 * Body: { subscriptionId }
 * Extends expiry based on the plan’s durationMonths & sets status to 'active'
 */
exports.renewSubscription = async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    if (!subscriptionId) return res.status(400).json({ success:false, message:'subscriptionId required' });

    const sub = await Subscription.findOne({ subscriptionId });
    if (!sub) return res.status(404).json({ success:false, message:'Not found' });
    if (!isOwnerOrAdmin(sub, req.user))
      return res.status(403).json({ success:false, message:'Forbidden' });

    const plan = await Plan.findOne({ planId: sub.planId });
    if (!plan || !plan.durationMonths)
      return res.status(400).json({ success:false, message:'Plan has no durationMonths' });

    // Compute new expiry
    const newStart = new Date();
    const newExpiry = new Date();
    newExpiry.setMonth(newExpiry.getMonth() + plan.durationMonths);

    sub.status    = 'active';
    sub.startedAt = newStart;
    sub.expiresAt = newExpiry;
    await sub.save();

    res.json({ success:true, subscription: sub });
  } catch (err) {
    console.error('renewSubscription error:', err);
    res.status(500).json({ success:false, message:'Internal server error' });
  }
};
