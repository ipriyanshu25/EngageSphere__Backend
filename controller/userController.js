// controllers/userController.js
const express = require('express');
const jwt         = require('jsonwebtoken');
const nodemailer  = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const User        = require('../model/user');
const JWT_SECRET  = process.env.JWT_SECRET;

// configure your SMTP transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT,10),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});


exports.requestOtpUser = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  const code      = Math.floor(100000 + Math.random()*900000).toString();
  const expiresAt = new Date(Date.now() + 10*60*1000);

  try {
    await User.findOneAndUpdate(
      { email },
      { 
        $set: {
          otpCode:code,
          otpExpiresAt: expiresAt,
          otpVerified: false
        }
      },
      { upsert: true, new: true }
    );
    await transporter.sendMail({
      from: `"No-Reply" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Your Verification Code',
      text: `Your code is ${code}. It expires in 10 minutes.`
    });
    return res.json({ message: 'OTP sent to email' });
  } catch(err) {
    console.error('requestOtpUser error:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * Step 2: Verify OTP & collect rest of profile
 */
exports.verifyOtpUser = async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and otp are required' });
  }

  try {
    const user = await User.findOneAndUpdate(
      {
        email: email.trim().toLowerCase(),
        otpCode: otp.toString().trim(),
        otpExpiresAt: { $gt: new Date() }
      },
      {
        $set: { otpVerified: true },
        $unset: { otpCode: "", otpExpiresAt: "" }
      },
      { new: true }
    );

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    return res.status(200).json({ message: 'OTP verified successfully' });
  } catch (err) {
    console.error('verifyOtpUser error:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * Step 3: (Optional) If you want a separate “register” after OTP,
 * you can check otpVerified and name/password already set.
 * Otherwise, the above verifyOtpUser already seeds the user record.
 */

/**
 * Login — exactly like before but guard on otpVerified
 */
exports.loginUser = async (req, res) => {
  const { email, password } = req.body;
  if (!email||!password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !user.otpVerified) {
      return res.status(403).json({ message: 'Please verify your email first' });
    }
    const match = await user.comparePassword(password);
    if (!match) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { userId: user.userId },
      JWT_SECRET,
      { expiresIn: '100d' }
    );
    res.status(200).json({
      message: 'Login successful',
      token,
      userId: user.userId
    });
  } catch(err) {
    console.error('loginUser error:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


exports.registerUser = async (req, res) => {
  const {
    email,
    name,
    password,
    phone,
    address,
    countryId,
    country,
    callingId,
    callingcode,
    bio = '',
    gender
  } = req.body;

  // Basic validation
  if (!email || !name || !password || !countryId || !country || !callingId || !callingcode || gender == null) {
    return res.status(400).json({ message: 'Missing required registration fields' });
  }

  try {
    // 1) Fetch the user who must have otpVerified=true
    const user = await User.findOne({ email: email.trim().toLowerCase() });

    if (!user) {
      return res.status(404).json({ message: 'No OTP request found for this email' });
    }
    if (!user.otpVerified) {
      return res.status(403).json({ message: 'Email not yet verified' });
    }
    if (user.name && user.password) {
      return res.status(400).json({ message: 'User already registered' });
    }

    // 2) Apply the profile fields
    user.name        = name;
    user.password    = password;   // will be hashed by pre('save')
    user.phone       = phone;
    user.address     = address;
    user.countryId   = countryId;
    user.country     = country;
    user.callingId   = callingId;
    user.callingcode = callingcode;
    user.bio         = bio;
    user.gender      = Number(gender);

    // 3) Save (triggers password hash)
    await user.save();

    return res.status(201).json({
      message: 'User registered successfully',
      userId: user.userId
    });
  } catch (err) {
    console.error('registerUser error:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * Middleware to verify token
 */
exports.verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(403).json({ message: 'Token required' });

  const token = authHeader.split(' ')[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(403).json({ message: 'Invalid or expired token' });

    req.user = { userId: decoded.userId };
    next();
  });
};


/**
 * Get paginated users with search/sort (optional)
 * POST /user/getAll
 */
exports.getAll = async (req, res) => {
  try {
    let { page = 1, limit = 10, search = '', sortBy = 'createdAt', sortOrder = 'desc' } = req.body;

    page = Math.max(1, parseInt(page));
    limit = Math.max(1, parseInt(limit));

    const filter = {};
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }

    const sort = {
      [sortBy]: sortOrder.toLowerCase() === 'asc' ? 1 : -1,
    };

    const total = await User.countDocuments(filter);
    const users = await User.find(filter)
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(limit)
      .select('-password -__v');

    return res.status(200).json({
      data: users,
      meta: {
        total,
        page,
        perPage: limit,
        lastPage: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error('GetAll users error:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * Get all users (flat array, for Admin Dashboard)
 * GET /user/all
 */
exports.getAllUsersSimple = async (req, res) => {
  try {
    const users = await User.find()
      .select('name email phone role isActive createdAt')
      .sort({ createdAt: -1 });

    return res.status(200).json(users);
  } catch (err) {
    console.error('Error fetching all users:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * Update user profile
 * POST /user/update
 */
exports.updateProfile = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { name, phone, address, oldPassword, newPassword } = req.body;

    const user = await User.findOne({ userId });
    if (!user)
      return res.status(404).json({ message: 'User not found' });

    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (address) user.address = address;

    if (newPassword) {
      if (!oldPassword) {
        return res.status(400).json({ message: 'Old password is required' });
      }
      const isMatch = await user.comparePassword(oldPassword);
      if (!isMatch) {
        return res.status(400).json({ message: 'Old password is incorrect' });
      }
      user.password = newPassword;
    }

    await user.save();

    const safeUser = {
      id: user.userId,
      name: user.name,
      email: user.email,
      phone: user.phone,
      address: user.address,
      createdAt: user.createdAt,
    };

    return res.status(200).json({ message: 'Profile updated', user: safeUser });
  } catch (err) {
    console.error('UpdateProfile error:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


exports.getById = async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ message: 'userId is required' });
    }

    // find the user, omit password and __v
    const user = await User.findOne({ userId })
      .select('-password -__v');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({ data: user });
  } catch (err) {
    console.error('Get user by ID error:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


exports.requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  const code      = Math.floor(100000 + Math.random()*900000).toString();
  const expiresAt = new Date(Date.now() + 10*60*1000);

  try {
    const user = await User.findOneAndUpdate(
      { email: email.trim().toLowerCase() },
      {
        $set: {
          passwordResetCode: code,
          passwordResetExpiresAt: expiresAt,
          passwordResetVerified: false
        }
      },
      { new: true }
    );
    if (!user) {
      return res.status(404).json({ message: 'No user with that email' });
    }

    await transporter.sendMail({
      from: `"No-Reply" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Your Password Reset Code',
      text: `Your reset code is ${code}. It expires in 10 minutes.`
    });

    res.json({ message: 'Reset OTP sent to email' });
  } catch (err) {
    console.error('requestPasswordReset error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * 2️⃣ verifyPasswordResetOtp
 */
exports.verifyPasswordResetOtp = async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required' });
  }

  try {
    const user = await User.findOneAndUpdate(
      {
        email: email.trim().toLowerCase(),
        passwordResetCode: otp.toString().trim(),
        passwordResetExpiresAt: { $gt: new Date() }
      },
      {
        $set: { passwordResetVerified: true },
        $unset: { passwordResetCode: "", passwordResetExpiresAt: "" }
      },
      { new: true }
    );

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    res.json({ message: 'OTP verified, you may now reset your password' });
  } catch (err) {
    console.error('verifyPasswordResetOtp error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * 3️⃣ resetPassword
 */
exports.resetPassword = async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return res.status(400).json({ message: 'Email and newPassword are required' });
  }

  try {
    const user = await User.findOne({ 
      email: email.trim().toLowerCase(),
      passwordResetVerified: true
    });
    if (!user) {
      return res.status(403).json({ message: 'OTP not verified or invalid email' });
    }

    user.password              = newPassword;   // will get hashed
    user.passwordResetVerified = false;        // clear the flag
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('resetPassword error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};