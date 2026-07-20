import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const RESET_TOKEN_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Exiting.');
  process.exit(1);
}

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));
app.use(express.json());

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB successfully!'))
  .catch((err) => console.error('MongoDB connection error:', err));

// ─── Schemas ─────────────────────────────────────────────────────────────────

const UserSchema = new mongoose.Schema({
  email:            { type: String, required: true, unique: true },
  passwordHash:     { type: String, required: true },
  name:             { type: String },
  // Email verification
  isEmailVerified:        { type: Boolean, default: false },
  emailVerifyTokenHash:   { type: String,  default: null },
  emailVerifyTokenExpiry: { type: Date,    default: null },
  // Password-reset fields — only SHA-256 hash stored; raw token only lives in the email.
  resetTokenHash:   { type: String, default: null },
  resetTokenExpiry: { type: Date,   default: null },
  // tokenVersion is embedded in every JWT; bumping it invalidates all prior sessions.
  tokenVersion:     { type: Number, default: 0 },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

const DailyRecordSchema = new mongoose.Schema({
  email: { type: String, required: true },
  date:  { type: String, required: true },
  goals:       [{ goalId: String, description: String }],
  reflections: [{ goalId: String, assessment: String, reflectionText: String }],
  revisions:   [{ topic: String, sourceGoalId: String, reason: String }],
}, { timestamps: true });

DailyRecordSchema.index({ email: 1, date: 1 }, { unique: true });
const DailyRecord = mongoose.model('DailyRecord', DailyRecordSchema);

// ─── Nodemailer transporter ───────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST || 'smtp.gmail.com',
  port:   Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendEmail({ to, subject, html }) {
  try {
    await transporter.sendMail({
      from: `"SMART Goal Coach" <${process.env.FROM_EMAIL || process.env.SMTP_USER}>`,
      to,
      subject,
      html,
    });
    console.log('[Email] Sent to', to);
  } catch (err) {
    console.error('[Email] Failed to send to', to, ':', err.message);
  }
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────
// NOTE: In-memory — resets on restart. Use Redis for multi-instance deployments.
const RATE_LIMIT_MAX    = 3;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour

function makeRateLimiter() {
  const map = new Map();
  return function (email) {
    const now = Date.now();
    const entry = map.get(email);
    if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
      map.set(email, { count: 1, windowStart: now });
      return false;
    }
    if (entry.count >= RATE_LIMIT_MAX) return true;
    entry.count++;
    return false;
  };
}

const isResetRateLimited  = makeRateLimiter();
const isResendRateLimited = makeRateLimiter();

// ─── Email verification helpers ───────────────────────────────────────────────
const VERIFY_TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

async function sendVerificationEmail(email, rawToken) {
  const verifyUrl = `${FRONTEND_URL}/verify-email?token=${rawToken}&email=${encodeURIComponent(email)}`;
  await sendEmail({
    to:      email,
    subject: 'Verify your SMART account',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
        <h2 style="color:#15803d">Verify your email</h2>
        <p>Thanks for signing up for SMART Goal Coach! Please verify your email address to get started.</p>
        <a href="${verifyUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#16a34a;color:white;text-decoration:none;border-radius:8px;font-weight:bold">
          Verify Email
        </a>
        <p style="color:#64748b;font-size:13px">This link expires in 24 hours. If you didn't create this account, you can safely ignore this email.</p>
      </div>
    `,
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function timingSafeCompare(a, b) {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function signToken(user) {
  return jwt.sign(
    { userId: user._id, email: user.email, tokenVersion: user.tokenVersion },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    const token   = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }

    if (decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({ error: 'Unauthorized: Session expired. Please log in again.' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

// ─── Auth Routes ──────────────────────────────────────────────────────────────

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const salt         = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const user         = new User({ email, passwordHash, name, tokenVersion: 0 });
    await user.save();

    const token = signToken(user);
    res.status(201).json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = signToken(user);
    res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: { id: req.user._id, email: req.user.email, name: req.user.name } });
});

// ─── Forgot Password ──────────────────────────────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
  const GENERIC_RESPONSE = { message: 'If an account with that email exists, a reset link has been sent.' };

  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const limited   = isResetRateLimited(email);
    const rawToken  = crypto.randomBytes(32).toString('hex');
    const tokenHash = sha256(rawToken);
    const expiry    = new Date(Date.now() + RESET_TOKEN_EXPIRY_MS);

    const user = await User.findOne({ email });

    if (user && !limited) {
      user.resetTokenHash   = tokenHash;
      user.resetTokenExpiry = expiry;
      await user.save();

      const resetUrl = `${FRONTEND_URL}/reset-password?token=${rawToken}&email=${encodeURIComponent(email)}`;
      await sendEmail({
        to: email,
        subject: 'Reset your SMART password',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
            <h2 style="color:#15803d">Reset your password</h2>
            <p>You requested a password reset for your SMART Goal Coach account.</p>
            <p>Click the button below to set a new password. This link expires in <strong>15 minutes</strong>.</p>
            <a href="${resetUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#16a34a;color:white;text-decoration:none;border-radius:8px;font-weight:bold">
              Reset Password
            </a>
            <p style="color:#64748b;font-size:13px">If you didn't request this, you can safely ignore this email.</p>
          </div>
        `,
      });
    }

    res.json(GENERIC_RESPONSE);
  } catch (error) {
    console.error('Forgot-password error:', error);
    res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
  }
});

// ─── Reset Password ───────────────────────────────────────────────────────────
app.post('/api/auth/reset-password', async (req, res) => {
  const INVALID_ERROR = { error: 'Invalid or expired reset link.' };

  try {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
      return res.status(400).json({ error: 'Email, token, and new password are required.' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const user = await User.findOne({ email });
    if (!user || !user.resetTokenHash || !user.resetTokenExpiry) {
      return res.status(400).json(INVALID_ERROR);
    }
    if (new Date() > user.resetTokenExpiry) {
      return res.status(400).json(INVALID_ERROR);
    }

    const incomingHash = sha256(token);
    if (!timingSafeCompare(incomingHash, user.resetTokenHash)) {
      return res.status(400).json(INVALID_ERROR);
    }

    const salt        = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    user.resetTokenHash   = null;
    user.resetTokenExpiry = null;
    user.tokenVersion     = (user.tokenVersion || 0) + 1;
    await user.save();

    await sendEmail({
      to: email,
      subject: 'Your SMART password was changed',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
          <h2 style="color:#15803d">Password changed</h2>
          <p>Your SMART Goal Coach password was just successfully changed.</p>
          <p style="color:#64748b;font-size:13px">
            If you made this change, no action is needed.<br/>
            If you did <strong>not</strong> make this change, please contact support immediately.
          </p>
        </div>
      `,
    });

    res.json({ message: 'Password reset successful. You can now log in with your new password.' });
  } catch (error) {
    console.error('Reset-password error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ─── Normalize date to YYYY-MM-DD ─────────────────────────────────────────────
function normalizeDate(dateStr) {
  if (!dateStr) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return dateStr;
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().split('T')[0];
  } catch (e) { return null; }
}

// ─── Daily Records Routes ─────────────────────────────────────────────────────

app.get('/api/daily-records', authMiddleware, async (req, res) => {
  try {
    const email    = req.user.email;
    const { date } = req.query;

    if (date) {
      const normDate = normalizeDate(date);
      if (!normDate) return res.status(400).json({ error: 'Invalid date format' });
      const record = await DailyRecord.findOne({ email, date: normDate });
      return res.json(record);
    }

    const records = await DailyRecord.find({ email });
    res.json(records);
  } catch (error) {
    console.error('GET error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/daily-records', authMiddleware, async (req, res) => {
  try {
    const { date, goals, reflections, revisions } = req.body;
    const email = req.user.email;

    if (!date) return res.status(400).json({ error: 'Date is required' });
    const normDate = normalizeDate(date);
    if (!normDate) return res.status(400).json({ error: 'Invalid date format' });

    let record = await DailyRecord.findOne({ email, date: normDate });
    if (record) return res.status(409).json({ error: 'Record already exists for this date. Use PATCH.' });

    record = new DailyRecord({
      email, date: normDate,
      goals:       Array.isArray(goals)       ? goals       : [],
      reflections: Array.isArray(reflections) ? reflections : [],
      revisions:   Array.isArray(revisions)   ? revisions   : [],
    });

    await record.save();
    res.status(200).json(record);
  } catch (error) {
    console.error('POST error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.patch('/api/daily-records/:id/goals', authMiddleware, async (req, res) => {
  try {
    const { mode, goals } = req.body;
    if (!Array.isArray(goals)) return res.status(400).json({ error: 'Goals must be an array' });

    const record = await DailyRecord.findById(req.params.id);
    if (!record) return res.status(404).json({ error: 'Record not found' });
    if (record.email !== req.user.email) return res.status(403).json({ error: 'Forbidden' });

    if (mode === 'override') {
      const reflectedGoalIds = new Set(record.reflections.map(r => r.goalId));
      const lockedGoals = record.goals.filter(g => reflectedGoalIds.has(g.goalId || g._id?.toString() || g.id));
      record.goals = [...lockedGoals, ...goals];
    } else {
      record.goals.push(...goals);
    }

    await record.save();
    res.status(200).json(record);
  } catch (error) {
    console.error('PATCH goals error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.patch('/api/daily-records/:id/reflections', authMiddleware, async (req, res) => {
  try {
    const { goalId, assessment, reflectionText } = req.body;
    if (!goalId) return res.status(400).json({ error: 'goalId is required' });

    const record = await DailyRecord.findById(req.params.id);
    if (!record) return res.status(404).json({ error: 'Record not found' });
    if (record.email !== req.user.email) return res.status(403).json({ error: 'Forbidden' });

    const goalExists = record.goals.some(g => (g.goalId || g._id?.toString() || g.id) === goalId);
    if (!goalExists) return res.status(400).json({ error: 'Goal ID not found in record' });

    const alreadyReflected = record.reflections.some(r => r.goalId === goalId);
    if (alreadyReflected) return res.status(400).json({ error: 'Goal already has a reflection' });

    record.reflections.push({ goalId, assessment, reflectionText });

    if (assessment === 'insufficient') {
      record.revisions.push({ topic: goalId, sourceGoalId: goalId, reason: assessment });
    }

    await record.save();
    res.status(200).json(record);
  } catch (error) {
    console.error('PATCH reflections error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.listen(PORT, () => {
  console.log(`SMART Backend running on http://localhost:${PORT}`);
});
