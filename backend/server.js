require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { body, param, query, validationResult } = require('express-validator');

const app = express();

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

const writeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
app.use((req, res, next) => {
  if (!writeMethods.has(req.method) || !req.cookies.token || req.path === '/api/payments/mpesa/callback') return next();
  const origin = req.get('origin');
  if (origin && new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Cross-site request rejected' });
  if (!origin && req.get('sec-fetch-site') === 'cross-site') return res.status(403).json({ error: 'Cross-site request rejected' });
  next();
});

const allowedOrigins = process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(o=>o.trim()) : [];
app.use(cors({ origin(origin, callback) {
  if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
  if (!allowedOrigins.length) return callback(null, false);
  return callback(new Error('Origin is not allowed'));
}, credentials: true }));

// Basic security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

app.get('/api/admin/test-ping', auth, adminOnly, (req, res) => { res.json({ ok: true, time: Date.now() }); });

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 1*60*1000, max: 60, standardHeaders: true, legacyHeaders: false });
app.use('/api/', apiLimiter);

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, trim: true, default: '' },
  password: { type: String, required: true, minlength: 8 },
  role: { type: String, enum: ['user','admin','manager','host','kitchen'], default: 'user' },
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const reservationSchema = new mongoose.Schema({
  tableNumber: { type: Number, required: true },
  guestName: { type: String, required: true, trim: true },
  guestEmail: { type: String, trim: true },
  guestPhone: { type: String, trim: true },
  partySize: { type: Number, required: true, min: 1 },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  status: { type: String, enum: ['pending','confirmed','seated','completed','cancelled','no-show'], default: 'pending' },
  occasion: { type: String, trim: true },
  dietary: { type: String, trim: true },
  notes: { type: String, trim: true },
  createdAt: { type: Date, default: Date.now }
});
const Reservation = mongoose.model('Reservation', reservationSchema);

const menuItemSchema = new mongoose.Schema({
  catalogId: { type: String, trim: true, sparse: true, unique: true },
  name: { type: String, required: true, trim: true },
  description: { type: String, trim: true },
  price: { type: Number, required: true, min: 0 },
  category: { type: String, required: true, trim: true },
  available: { type: Boolean, default: true },
  image: { type: String, trim: true, default: '' },
  allergens: { type: [String], default: [] },
  dietary: { type: [String], default: [] },
  spiceLevel: { type: Number, default: 0, min: 0, max: 5 },
  createdAt: { type: Date, default: Date.now }
});
const MenuItem = mongoose.model('MenuItem', menuItemSchema);

const orderSchema = new mongoose.Schema({
  orderNumber: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  customerName: { type: String, trim: true },
  customerEmail: { type: String, trim: true },
  customerPhone: { type: String, trim: true },
  items: { type: [{ id: String, name: String, price: Number, qty: Number, img: String }], default: [] },
  subtotal: { type: Number, required: true, min: 0 },
  deliveryFee: { type: Number, default: 0 },
  total: { type: Number, required: true, min: 0 },
  type: { type: String, enum: ['pickup','delivery'], default: 'pickup' },
  deliveryAddress: { type: String, trim: true },
  notes: { type: String, trim: true },
  status: { type: String, enum: ['new','accepted','preparing','ready','out-for-delivery','completed','refunded','cancelled'], default: 'new' },
  paymentMethod: { type: String, enum: ['mpesa','pay-on-delivery'], default: 'pay-on-delivery' },
  paymentStatus: { type: String, enum: ['pending','paid','failed','refunded'], default: 'pending' },
  mpesaReceipt: { type: String, trim: true },
  acceptedAt: Date, preparingAt: Date, readyAt: Date, completedAt: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

const auditLogSchema = new mongoose.Schema({
  actor: { type: String, required: true },
  action: { type: String, required: true },
  endpoint: { type: String, required: true },
  details: { type: String, trim: true },
  timestamp: { type: Date, default: Date.now }
});
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

const tableSchema = new mongoose.Schema({
  number: { type: Number, required: true, min: 1, unique: true }, section: { type: String, required: true, trim: true, maxlength: 60 },
  seats: { type: Number, required: true, min: 1, max: 50 }, status: { type: String, enum: ['available','reserved','seated','blocked'], default: 'available' },
  blockReason: { type: String, trim: true, maxlength: 240, default: '' }, updatedAt: { type: Date, default: Date.now }
});
const Table = mongoose.model('Table', tableSchema);
const settingSchema = new mongoose.Schema({ key: { type: String, unique: true }, value: { type: mongoose.Schema.Types.Mixed, default: {} }, updatedAt: { type: Date, default: Date.now } });
const Setting = mongoose.model('Setting', settingSchema);
const contactSchema = new mongoose.Schema({ name: { type: String, required: true, trim: true }, email: { type: String, required: true, lowercase: true, trim: true }, phone: { type: String, trim: true }, subject: { type: String, trim: true }, message: { type: String, required: true, trim: true }, status: { type: String, enum: ['unread','read','archived'], default: 'unread' }, createdAt: { type: Date, default: Date.now } });
const ContactMessage = mongoose.model('ContactMessage', contactSchema);
const reviewSchema = new mongoose.Schema({ name: { type: String, trim: true }, rating: { type: Number, min: 1, max: 5, required: true }, comment: { type: String, trim: true, maxlength: 2000 }, reference: { type: String, trim: true }, status: { type: String, enum: ['pending','approved','hidden'], default: 'pending' }, reply: { type: String, trim: true }, createdAt: { type: Date, default: Date.now } });
const Review = mongoose.model('Review', reviewSchema);
const eventSchema = new mongoose.Schema({ title: { type: String, required: true, trim: true }, date: { type: Date, required: true }, description: { type: String, trim: true }, image: { type: String, trim: true }, capacity: { type: Number, min: 1, required: true }, price: { type: Number, min: 0, default: 0 }, type: { type: String, enum: ['private dining','tasting','live music'], required: true }, published: { type: Boolean, default: false } });
const Event = mongoose.model('Event', eventSchema);
const eventBookingSchema = new mongoose.Schema({ eventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true }, name: { type: String, trim: true }, email: { type: String, lowercase: true, trim: true }, phone: { type: String, trim: true }, guests: { type: Number, min: 1, required: true }, createdAt: { type: Date, default: Date.now } });
const EventBooking = mongoose.model('EventBooking', eventBookingSchema);
const guestNoteSchema = new mongoose.Schema({ email: { type: String, unique: true, lowercase: true, trim: true }, tags: { type: [String], default: [] }, staffNotes: { type: String, trim: true, maxlength: 2000 } });
const GuestNote = mongoose.model('GuestNote', guestNoteSchema);
const staffInviteSchema = new mongoose.Schema({ email: { type: String, required: true, lowercase: true, trim: true }, role: { type: String, enum: ['admin','manager','host','kitchen'], required: true }, tokenHash: { type: String, required: true }, expiresAt: { type: Date, required: true }, createdAt: { type: Date, default: Date.now } });
const StaffInvite = mongoose.model('StaffInvite', staffInviteSchema);

function validateRequest(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid request', details: errors.array().map(error => ({ field: error.path, message: error.msg })) });
  next();
}
function cleanReservationInput(input = {}) {
  return {
    tableNumber: Number(input.tableNumber), guestName: String(input.guestName || '').trim().slice(0,100),
    guestEmail: String(input.guestEmail || '').trim().toLowerCase().slice(0,254), guestPhone: String(input.guestPhone || '').trim().slice(0,40),
    partySize: Number(input.partySize), date: new Date(input.date), time: String(input.time || '').slice(0,5),
    status: ['pending','confirmed','seated','completed','cancelled','no-show'].includes(input.status) ? input.status : 'pending',
    occasion: String(input.occasion || '').trim().slice(0,120), dietary: String(input.dietary || '').trim().slice(0,300), notes: String(input.notes || '').trim().slice(0,500)
  };
}
function validateReservationBody(input) {
  if (!input.guestName || !Number.isInteger(Number(input.tableNumber)) || Number(input.tableNumber) < 1 || !Number.isInteger(Number(input.partySize)) || Number(input.partySize) < 1 || Number(input.partySize) > 50 || !Number.isFinite(+new Date(input.date)) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(input.time || ''))) return 'Enter a guest, valid table, party size, date, and 24-hour time.';
  return null;
}
async function reservationConflict(tableNumber, date, time, excludeId, partySize) {
  const table = await Table.findOne({ number: Number(tableNumber) });
  if (!table) return 'Choose a table that exists in the floor plan.';
  if (Number(table.seats) < Number(partySize)) return `Table ${tableNumber} seats up to ${table.seats}.`;
  const start = new Date(date); start.setHours(0,0,0,0); const end = new Date(start); end.setDate(end.getDate() + 1);
  const filter = { tableNumber: Number(tableNumber), date: { $gte: start, $lt: end }, time: String(time).slice(0,5), status: { $nin: ['cancelled','no-show'] } };
  if (excludeId) filter._id = { $ne: excludeId };
  return await Reservation.exists(filter) ? `Table ${tableNumber} is already booked for ${time}.` : null;
}

function signToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
  User.findById(req.user.id).select('name email role active').then(user => {
    if (!user || user.active === false) return res.status(401).json({ error: 'Session is no longer valid' });
    req.user.name = user.name; req.user.email = user.email; req.user.role = user.role;
    next();
  }).catch(next);
}
const authorize = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
  next();
};
function adminOnly(req, res, next) {
  return authorize('admin')(req, res, next);
}

function setAuthCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production';
  res.cookie('token', token, { httpOnly: true, secure, sameSite: 'lax', maxAge: 7*24*60*60*1000, path: '/' });
}

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const phone = String(req.body.phone || '').trim();
    if (!name || !email || !password || !phone) return res.status(400).json({ error: 'Name, email, phone, and password are required' });
    if (phone.length > 40) return res.status(400).json({ error: 'Phone number must be 40 characters or fewer' });
    if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const emailNorm = String(email).toLowerCase().trim();
    if (await User.findOne({ email: emailNorm })) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ name: String(name).trim(), email: emailNorm, phone, password: hash, role: 'user' });
    const token = signToken(user);
    setAuthCookie(res, token);
    res.json({ user: { id: user._id, name: user.name, email: user.email, phone: user.phone, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Registration failed' }); }
});

app.get('/api/site-content', async (req, res, next) => { try { const entry = await Setting.findOne({ key: 'restaurant' }).lean(); const value = entry?.value || {}; res.json({ content: { name: value.name, address: value.address, phone: value.phone, whatsapp: value.whatsapp, openingHours: value.openingHours, heroTitle: value.heroTitle, heroSubtitle: value.heroSubtitle, aboutText: value.aboutText, socialLinks: value.socialLinks || {}, gallery: value.gallery || [] } }); } catch (error) { next(error); } });
app.get('/api/admin/integrations/status', auth, adminOnly, (req, res) => res.json({ mpesa: Boolean(process.env.MPESA_CONSUMER_KEY && process.env.MPESA_CONSUMER_SECRET && process.env.MPESA_SHORTCODE && process.env.MPESA_PASSKEY), email: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD), sms: Boolean(process.env.SMS_API_KEY), analytics: Boolean(process.env.GA_MEASUREMENT_ID) }));

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const emailNorm = String(email).toLowerCase().trim();
    const user = await User.findOne({ email: emailNorm });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid email or password' });
    const token = signToken(user);
    setAuthCookie(res, token);
    res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/logout', (req, res) => { 
  const secure = process.env.NODE_ENV === 'production';
  res.clearCookie('token', { httpOnly: true, secure, sameSite: 'lax', path: '/' }); 
  res.json({ ok: true }); 
});

app.get('/api/public/status', async (req, res, next) => {
  try {
    const operations = await Setting.findOne({ key: 'operations' });
    res.json({ ordersPaused: Boolean(operations?.value?.ordersPaused) });
  } catch (error) { next(error); }
});

app.get('/api/menu', async (req, res, next) => {
  try { res.json({ menu: await MenuItem.find().sort({ category: 1, name: 1 }).lean() }); }
  catch (error) { next(error); }
});

app.post('/api/reservations', authLimiter, async (req, res, next) => {
  try {
    const body = req.body || {};
    const guestName = String(body.guestName || '').trim().slice(0, 100);
    const guestEmail = String(body.guestEmail || '').trim().toLowerCase().slice(0, 254);
    const guestPhone = String(body.guestPhone || '').trim().slice(0, 40);
    const tableNumber = Number(body.tableNumber); const partySize = Number(body.partySize);
    const date = new Date(body.date);
    const time = String(body.time || '');
    if (!guestName || !guestPhone || !Number.isInteger(tableNumber) || !Number.isInteger(partySize) || partySize < 1 || !Number.isFinite(+date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return res.status(400).json({ error: 'Complete all required reservation details.' });
    const table = await Table.findOne({ number: tableNumber });
    if (!table) return res.status(400).json({ error: 'Choose an available table from the restaurant.' });
    if (table.seats < partySize) return res.status(400).json({ error: `Table ${table.number} seats up to ${table.seats}.` });
    const rangeStart = new Date(date); rangeStart.setHours(0,0,0,0);
    const rangeEnd = new Date(rangeStart); rangeEnd.setDate(rangeEnd.getDate() + 1);
    const duplicate = await Reservation.findOne({ tableNumber, date: { $gte: rangeStart, $lt: rangeEnd }, time, status: { $nin: ['cancelled','no-show'] } });
    if (duplicate) return res.status(409).json({ error: 'That table is already reserved for this time. Please choose another table or time.' });
    const reservation = await Reservation.create({ tableNumber, guestName, guestEmail, guestPhone, partySize, date, time, occasion: String(body.occasion || '').slice(0,120), dietary: String(body.dietary || '').slice(0,300), notes: String(body.notes || '').slice(0,500), status: 'pending' });
    res.status(201).json({ ok: true, reservation: { id: reservation.id, status: reservation.status } });
  } catch (error) { next(error); }
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json({ user });
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const users = await User.find({ role: { $ne: 'user' } }).select('-password').sort({ createdAt: -1 });
  const invitations = await StaffInvite.find({ expiresAt: { $gt: new Date() } }).select('-tokenHash').sort({ createdAt: -1 }).lean();
  res.json({ users, invitations });
});

app.patch('/api/admin/users/:id', auth, adminOnly, async (req, res, next) => {
  try { const updates = {}; if (typeof req.body.name === 'string') updates.name = req.body.name.trim().slice(0,100); if (['admin','manager','host','kitchen'].includes(req.body.role)) updates.role = req.body.role; if (typeof req.body.active === 'boolean') updates.active = req.body.active; const target = await User.findById(req.params.id); if (!target || target.role === 'user') return res.status(404).json({ error: 'Staff member not found' }); if (target.role === 'admin' && updates.role && updates.role !== 'admin' && await User.countDocuments({ role: 'admin' }) <= 1) return res.status(409).json({ error: 'Cannot demote the last administrator.' }); Object.assign(target, updates); await target.save(); await logAudit(req.user.id, 'update_staff', req.path, `${target.email} role ${target.role}`); res.json({ user: { id: target.id, name: target.name, email: target.email, role: target.role, active: target.active } }); } catch (error) { next(error); }
});

app.post('/api/admin/staff-invites', auth, adminOnly, async (req, res, next) => {
  try { const email = String(req.body.email || '').trim().toLowerCase(); const role = req.body.role; if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['admin','manager','host','kitchen'].includes(role)) return res.status(400).json({ error: 'Enter a valid email and staff role.' }); if (await User.exists({ email })) return res.status(409).json({ error: 'That email already has an account.' }); const rawToken = crypto.randomBytes(32).toString('hex'); await StaffInvite.findOneAndUpdate({ email }, { email, role, tokenHash: crypto.createHash('sha256').update(rawToken).digest('hex'), expiresAt: new Date(Date.now()+7*86400000) }, { upsert: true, new: true }); await logAudit(req.user.id, 'invite_staff', req.path, `${email} (${role})`); res.status(201).json({ inviteUrl: `/staff-invite.html?token=${rawToken}`, expiresInDays: 7, delivery: 'Copy this invitation link and send it through your approved channel.' }); } catch (error) { next(error); }
});
app.post('/api/staff-invites/accept', authLimiter, async (req, res, next) => {
  try { const token = String(req.body.token || ''); const tokenHash = crypto.createHash('sha256').update(token).digest('hex'); const invite = await StaffInvite.findOne({ tokenHash, expiresAt: { $gt: new Date() } }); if (!invite) return res.status(400).json({ error: 'Invitation is expired or invalid.' }); const name = String(req.body.name || '').trim(); const password = req.body.password; if (!name || name.length > 100 || typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Enter your name and a password with at least 8 characters.' }); if (await User.exists({ email: invite.email })) return res.status(409).json({ error: 'This email already has an account.' }); const user = await User.create({ name, email: invite.email, password: await bcrypt.hash(password,12), role: invite.role }); await invite.deleteOne(); setAuthCookie(res, signToken(user)); res.status(201).json({ user: { name: user.name, email: user.email, role: user.role } }); } catch (error) { next(error); }
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete self' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid user id' });
  const target = await User.findById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'admin') {
    const adminCount = await User.countDocuments({ role: 'admin' });
    if (adminCount <= 1) return res.status(409).json({ error: 'Cannot remove the last administrator' });
  }
  await target.deleteOne();
  res.json({ ok: true });
});

async function logAudit(actor, action, endpoint, details) {
  try { await AuditLog.create({ actor: String(actor), action, endpoint, details: details ? String(details).slice(0, 500) : '' }); } catch {}
}

// ── Orders (public create, auth/admin manage) ──
app.post('/api/orders', async (req, res) => {
  try {
    const operations = await Setting.findOne({ key: 'operations' });
    if (operations?.value?.ordersPaused) return res.status(503).json({ error: 'Online ordering is paused. Please try again later.' });
    const { items = [], customerName, customerEmail, customerPhone, type = 'pickup', deliveryAddress = '', notes = '', paymentMethod = 'pay-on-delivery' } = req.body;
    if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'Cart is empty' });
    if (!customerName || !customerPhone) return res.status(400).json({ error: 'Name and phone are required' });
    if (!['pickup','delivery'].includes(type)) return res.status(400).json({ error: 'Invalid order type' });
    if (type === 'delivery' && !deliveryAddress) return res.status(400).json({ error: 'Delivery address required' });
    if (!['mpesa','pay-on-delivery'].includes(paymentMethod)) return res.status(400).json({ error: 'Invalid payment method' });
    if (paymentMethod === 'mpesa') return res.status(503).json({ error: 'M-Pesa checkout is not configured. Please choose pay on delivery.' });
    if (items.length > 30) return res.status(400).json({ error: 'An order can contain at most 30 line items' });

    // Validate against menu/prices server-side where possible
    const validated = [];
    for (const it of items) {
      if (!it || typeof it !== 'object') return res.status(400).json({ error: 'Invalid cart item' });
      const qty = Number(it.qty);
      if (!Number.isInteger(qty) || qty < 1 || qty > 20) return res.status(400).json({ error: 'Item quantity must be between 1 and 20' });
      const catalogId = String(it.id || '').slice(0, 100);
      const mi = await MenuItem.findOne({ catalogId });
      if (!mi) return res.status(400).json({ error: 'An item is no longer on the menu. Refresh the menu and try again.' });
      if (mi.available === false) return res.status(400).json({ error: `${mi.name} is currently unavailable` });
      validated.push({ id: mi.catalogId || String(mi._id), name: mi.name, price: mi.price, qty, img: mi.image || '' });
    }

    const subtotal = validated.reduce((s,i)=> s + i.price * i.qty, 0);
    const settings = await Setting.findOne({ key: 'restaurant' });
    const deliveryFee = type === 'delivery' ? Number(settings?.value?.deliveryFee ?? 150) : 0;
    const total = subtotal + deliveryFee;
    const orderNumber = 'LB-' + Date.now().toString().slice(-8) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
    const order = await Order.create({
      orderNumber,
      userId: req.user ? req.user.id : undefined,
      customerName: String(customerName).trim(),
      customerEmail: customerEmail ? String(customerEmail).trim().toLowerCase() : '',
      customerPhone: String(customerPhone).trim(),
      items: validated,
      subtotal,
      deliveryFee,
      total,
      type,
      deliveryAddress: String(deliveryAddress).trim(),
      notes: String(notes).trim().slice(0, 500),
      paymentMethod,
      paymentStatus: 'pending'
    });
    await logAudit(req.user?.id || 'guest', 'create_order', '/api/orders', order.orderNumber);
    res.status(201).json({ ok: true, orderNumber: order.orderNumber, total: order.total, status: order.status });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create order' });
  }
});

app.get('/api/orders/track/:orderNumber', async (req, res) => {
  try {
    const order = await Order.findOne({ orderNumber: req.params.orderNumber }).select('-__v');
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json({ order: { orderNumber: order.orderNumber, status: order.status, paymentStatus: order.paymentStatus, total: order.total, items: order.items, createdAt: order.createdAt, type: order.type } });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

const REPORT_TIME_ZONE = 'Africa/Nairobi';
function reportDateKey(value) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: REPORT_TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit'
  }).format(new Date(value));
}
function reportClockKey(value) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: REPORT_TIME_ZONE, weekday: 'short', hour: '2-digit', hourCycle: 'h23'
  }).formatToParts(new Date(value));
  return {
    weekday: parts.find(part => part.type === 'weekday')?.value || 'Unknown',
    hour: parts.find(part => part.type === 'hour')?.value || '00'
  };
}
function reportDateBoundary(dateKey) {
  return new Date(`${dateKey}T00:00:00+03:00`);
}
function reportPeriod(fromKey, toKey) {
  const start = reportDateBoundary(fromKey);
  const end = reportDateBoundary(toKey);
  end.setUTCDate(end.getUTCDate() + 1);
  return { start, end };
}
function reportDayCount(fromKey, toKey) {
  return Math.round((Date.parse(`${toKey}T00:00:00Z`) - Date.parse(`${fromKey}T00:00:00Z`)) / 86400000) + 1;
}
function reportShiftDate(dateKey, days) {
  const date = new Date(`${dateKey}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}
function reportShiftYear(dateKey, years) {
  const date = new Date(`${dateKey}T00:00:00Z`);
  date.setUTCFullYear(date.getUTCFullYear() + years);
  return date.toISOString().slice(0, 10);
}
function reportOrderSales(order) {
  const items = Array.isArray(order.items) ? order.items : [];
  return items.reduce((sum, item) => sum + (Number(item.price) || 0) * (Number(item.qty) || 0), 0);
}
function summarizeReportPeriod(orders, reservations, fromKey, toKey) {
  const days = new Map();
  const channels = new Map();
  const channelOrders = new Map();
  const paymentMethods = new Map();
  const menuItems = new Map();
  const orderStatuses = new Map();
  const salesHeat = new Map();
  const reservationStatuses = new Map();
  const reservationHours = new Map();
  const reservationHeat = new Map();
  const leadTimes = new Map([['< 1 day', 0], ['1–3 days', 0], ['4–7 days', 0], ['8–14 days', 0], ['15+ days', 0], ['Not recorded', 0]]);
  const partySizes = new Map();
  const itemDayData = new Map();
  const getDay = key => {
    if (!days.has(key)) days.set(key, { sales: 0, orders: 0, paidOrders: 0, reservations: 0, covers: 0 });
    return days.get(key);
  };
  let grossSales = 0;
  let refunds = 0;
  let paidOrders = 0;
  let placedOrders = 0;
  let pickupOrders = 0;
  let deliveryOrders = 0;

  for (const order of orders) {
    const orderDay = reportDateKey(order.createdAt);
    if (orderDay < fromKey || orderDay > toKey) continue;
    placedOrders += 1;
    getDay(orderDay).orders += 1;
    orderStatuses.set(order.status || 'unknown', (orderStatuses.get(order.status || 'unknown') || 0) + 1);
    const orderClock = reportClockKey(order.createdAt);
    const orderGross = Number(order.total) || 0;
    const isRefunded = order.paymentStatus === 'refunded' || order.status === 'refunded';
    const isPaid = order.paymentStatus === 'paid' || isRefunded || order.status === 'completed';
    const channel = order.type === 'delivery' ? 'Delivery' : order.type === 'pickup' ? 'Pickup' : 'Other';
    if (order.type === 'delivery') deliveryOrders += 1;
    else if (order.type === 'pickup') pickupOrders += 1;
    channelOrders.set(channel, (channelOrders.get(channel) || 0) + 1);
    if (!isPaid) continue;

    grossSales += orderGross;
    if (isRefunded) refunds += orderGross;
    else {
      paidOrders += 1;
      getDay(orderDay).paidOrders += 1;
    }

    channels.set(channel, (channels.get(channel) || 0) + (isRefunded ? 0 : orderGross));
    const method = order.paymentMethod || 'Not recorded';
    paymentMethods.set(method, (paymentMethods.get(method) || 0) + (isRefunded ? 0 : orderGross));
    if (!isRefunded) {
      for (const item of (order.items || [])) {
        const name = String(item.name || 'Unlabelled item');
        const current = menuItems.get(name) || { name, units: 0, sales: 0 };
        const quantity = Number(item.qty) || 0;
        current.units += quantity;
        current.sales += (Number(item.price) || 0) * quantity;
        menuItems.set(name, current);
        if (!itemDayData.has(name)) itemDayData.set(name, new Map());
        const itemDay = itemDayData.get(name).get(orderDay) || { units: 0, sales: 0 };
        itemDay.units += quantity;
        itemDay.sales += (Number(item.price) || 0) * quantity;
        itemDayData.get(name).set(orderDay, itemDay);
      }
    }
    if (!isRefunded) {
      getDay(orderDay).sales += orderGross;
      const heatKey = `${orderClock.weekday}|${orderClock.hour}`;
      salesHeat.set(heatKey, (salesHeat.get(heatKey) || 0) + orderGross);
    }
  }

  let bookedCovers = 0;
  let seatedCovers = 0;
  let activeReservations = 0;
  let partySizeTotal = 0;
  let partySizeCount = 0;
  for (const reservation of reservations) {
    const reservationDay = reportDateKey(reservation.date);
    if (reservationDay < fromKey || reservationDay > toKey) continue;
    const status = reservation.status || 'pending';
    const daily = getDay(reservationDay);
    daily.reservations += 1;
    reservationStatuses.set(status, (reservationStatuses.get(status) || 0) + 1);
    if (['pending', 'confirmed', 'seated', 'completed'].includes(status)) {
      activeReservations += 1;
      bookedCovers += Number(reservation.partySize) || 0;
      partySizeTotal += Number(reservation.partySize) || 0;
      partySizeCount += 1;
      daily.covers += Number(reservation.partySize) || 0;
    }
    if (status === 'seated' || status === 'completed') seatedCovers += Number(reservation.partySize) || 0;
    const hour = String(reservation.time || '').slice(0, 2);
    if (/^\d{2}$/.test(hour)) {
      reservationHours.set(hour, (reservationHours.get(hour) || 0) + 1);
      const weekday = new Intl.DateTimeFormat('en-US', { timeZone: REPORT_TIME_ZONE, weekday: 'short' }).format(new Date(reservation.date));
      const heatKey = `${weekday}|${hour}`;
      reservationHeat.set(heatKey, (reservationHeat.get(heatKey) || 0) + 1);
    }
    const size = Number(reservation.partySize) || 0;
    if (size > 0) {
      const sizeGroup = size <= 2 ? '1–2' : size <= 4 ? '3–4' : size <= 6 ? '5–6' : '7+';
      partySizes.set(sizeGroup, (partySizes.get(sizeGroup) || 0) + 1);
    }
    if (reservation.createdAt) {
      const leadDays = Math.max(0, Math.round((Date.parse(`${reservationDay}T00:00:00Z`) - Date.parse(`${reportDateKey(reservation.createdAt)}T00:00:00Z`)) / 86400000));
      const leadGroup = leadDays < 1 ? '< 1 day' : leadDays <= 3 ? '1–3 days' : leadDays <= 7 ? '4–7 days' : leadDays <= 14 ? '8–14 days' : '15+ days';
      leadTimes.set(leadGroup, (leadTimes.get(leadGroup) || 0) + 1);
    } else leadTimes.set('Not recorded', (leadTimes.get('Not recorded') || 0) + 1);
  }

  const daySeries = [];
  for (let day = fromKey; day <= toKey; day = reportShiftDate(day, 1)) {
    daySeries.push({ date: day, ...(days.get(day) || { sales: 0, orders: 0, paidOrders: 0, reservations: 0, covers: 0 }) });
  }
  const cancelled = reservationStatuses.get('cancelled') || 0;
  const noShows = reservationStatuses.get('no-show') || 0;
  const bookingCount = [...reservationStatuses.values()].reduce((sum, count) => sum + count, 0);
  const netSales = Math.max(0, grossSales - refunds);
  return {
    grossSales, netSales, refunds, paidOrders, placedOrders,
    averageOrderValue: paidOrders ? netSales / paidOrders : 0,
    pickupOrders, deliveryOrders,
    reservations: bookingCount, activeReservations, bookedCovers, seatedCovers,
    averagePartySize: partySizeCount ? partySizeTotal / partySizeCount : 0,
    cancelled, noShows,
    cancellationRate: bookingCount ? cancelled / bookingCount * 100 : 0,
    noShowRate: bookingCount ? noShows / bookingCount * 100 : 0,
    daySeries,
    orderStatuses: [...orderStatuses].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    channelOrders: [...channelOrders].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    salesHeatmap: [...salesHeat].map(([key, sales]) => { const [weekday, hour] = key.split('|'); return { weekday, hour: `${hour}:00`, sales }; }),
    reservationHeatmap: [...reservationHeat].map(([key, count]) => { const [weekday, hour] = key.split('|'); return { weekday, hour: `${hour}:00`, count }; }),
    channels: [...channels].map(([name, sales]) => ({ name, sales })).sort((a, b) => b.sales - a.sales),
    paymentMethods: [...paymentMethods].map(([name, sales]) => ({ name, sales })).sort((a, b) => b.sales - a.sales),
    reservationStatuses: [...reservationStatuses].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    reservationHours: [...reservationHours].map(([hour, count]) => ({ hour: `${hour}:00`, count })).sort((a, b) => a.hour.localeCompare(b.hour)),
    leadTimes: [...leadTimes].map(([name, count]) => ({ name, count })),
    partySizes: [...partySizes].map(([name, count]) => ({ name, count })),
    itemSeries: [...menuItems.values()].sort((a, b) => b.sales - a.sales).slice(0, 5).map(item => ({
      name: item.name,
      daySeries: [...(itemDayData.get(item.name) || new Map())].map(([date, values]) => ({ date, ...values }))
    })),
    topItems: [...menuItems.values()].sort((a, b) => b.sales - a.sales).slice(0, 10)
  };
}

app.get('/api/admin/reports/analytics', auth, adminOnly, async (req, res) => {
  try {
    const { from, to, comparison = 'previous', channel = 'all' } = req.query;
    const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
    if (!validDate(from) || !validDate(to) || from > to) {
      return res.status(400).json({ error: 'Choose a valid report date range.' });
    }
    const dayCount = reportDayCount(from, to);
    if (dayCount > 366) return res.status(400).json({ error: 'Choose a date range of 366 days or less.' });
    if (!['all', 'pickup', 'delivery'].includes(channel)) return res.status(400).json({ error: 'Choose a valid sales channel.' });
    if (!['previous', 'year', 'none'].includes(comparison)) return res.status(400).json({ error: 'Choose a valid comparison period.' });
    const currentPeriod = reportPeriod(from, to);
    let comparisonFrom = null;
    let comparisonTo = null;
    if (comparison === 'previous') {
      comparisonTo = reportShiftDate(from, -1);
      comparisonFrom = reportShiftDate(comparisonTo, -(dayCount - 1));
    } else if (comparison === 'year') {
      comparisonFrom = reportShiftYear(from, -1);
      comparisonTo = reportShiftYear(to, -1);
    }
    const comparisonPeriod = comparisonFrom ? reportPeriod(comparisonFrom, comparisonTo) : null;
    const currentFilter = { $gte: currentPeriod.start, $lt: currentPeriod.end };
    const channelFilter = channel === 'all' ? {} : { type: channel };
    const [orders, reservations, priorOrders, priorReservations] = await Promise.all([
      Order.find({ createdAt: currentFilter, ...channelFilter }).select('items total subtotal deliveryFee type paymentMethod paymentStatus status createdAt').lean(),
      Reservation.find({ date: currentFilter }).select('date time partySize status createdAt').lean(),
      comparisonPeriod ? Order.find({ createdAt: { $gte: comparisonPeriod.start, $lt: comparisonPeriod.end }, ...channelFilter }).select('items total subtotal deliveryFee type paymentMethod paymentStatus status createdAt').lean() : [],
      comparisonPeriod ? Reservation.find({ date: { $gte: comparisonPeriod.start, $lt: comparisonPeriod.end } }).select('date time partySize status createdAt').lean() : []
    ]);
    const current = summarizeReportPeriod(orders, reservations, from, to);
    const prior = comparisonPeriod ? summarizeReportPeriod(priorOrders, priorReservations, comparisonFrom, comparisonTo) : null;
    res.json({
      period: { from, to, timeZone: REPORT_TIME_ZONE, channel },
      source: { sales: 'MongoDB orders collection', reservations: 'MongoDB reservations collection', menuItems: 'Item name and unit-price snapshots on order lines' },
      comparison: { type: comparison, from: comparisonFrom, to: comparisonTo, metrics: prior },
      metrics: current,
      definitions: {
        grossSales: 'Order totals marked paid, completed, or refunded, before recorded full refunds.',
        netSales: 'Gross sales less the full order totals marked refunded. Partial refund amounts are not recorded.',
        averageOrderValue: 'Net sales divided by non-refunded paid orders.',
        seatedCovers: 'Party sizes on reservations marked seated or completed; walk-ins are not recorded.',
        reservations: 'Reservation records by service date, including cancelled and no-show bookings.',
        timeBasis: 'Order timestamps and reservation service dates are grouped in Africa/Nairobi time.'
      },
      unavailable: [
        { metric: 'Taxes, tips, discounts, voids, and refund reasons', reason: 'These fields are not stored on order records.' },
        { metric: 'Average dine-in check and spend per guest', reason: 'Dine-in POS checks and unique seated guest counts are not recorded.' },
        { metric: 'Dine-in, events, and booking channels', reason: 'Order channel is recorded only as pickup or delivery; reservation source and service period are not recorded.' },
        { metric: 'Table occupancy, turn time, wait time, and service pacing', reason: 'Table capacity and seating/order timing data are not stored.' },
        { metric: 'Events, reviews, and website analytics', reason: 'No event, feedback, review, or consented website analytics data source is connected.' },
        { metric: 'Food cost, labor, budget, waste, and gross margin', reason: 'Reliable cost, staffing, budget, and inventory data are not connected.' },
        { metric: 'Scheduled report delivery', reason: 'No authorized report recipient or email delivery integration is configured.' }
      ]
    });
  } catch (error) {
    console.error('Admin analytics report failed:', error.message);
    res.status(503).json({ error: 'Analytics data is temporarily unavailable. Check the database connection and try again.' });
  }
});

app.get('/api/admin/reports/capabilities', auth, adminOnly, (req, res) => {
  res.json({ previewAllowed: process.env.NODE_ENV === 'development' });
});

app.get('/api/admin/reports/preview', auth, adminOnly, (req, res) => {
  if (process.env.NODE_ENV !== 'development') return res.status(404).json({ error: 'Preview data is available only in development.' });
  const { from, to, comparison = 'previous', channel = 'all' } = req.query;
  const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
  if (!validDate(from) || !validDate(to) || from > to || reportDayCount(from, to) > 31) {
    return res.status(400).json({ error: 'Preview data is limited to valid ranges of 31 days or less.' });
  }
  if (!['all', 'pickup', 'delivery'].includes(channel)) return res.status(400).json({ error: 'Choose a valid sales channel.' });
  if (!['previous', 'year', 'none'].includes(comparison)) return res.status(400).json({ error: 'Choose a valid comparison period.' });
  const sampleCatalog = [
    { name: 'Nyama Choma Platter', price: 2400 }, { name: 'Whole Tilapia Fillet', price: 1850 },
    { name: 'Swahili Pilau', price: 1200 }, { name: 'Lake Victoria Prawns', price: 2800 },
    { name: 'Passion Fruit Cheesecake', price: 850 }, { name: 'Mango Masala Mocktail', price: 650 }
  ];
  function createPreviewRecords(startKey, endKey, scale = 1, orderChannel = 'all') {
    const orders = [];
    const reservations = [];
    for (let day = startKey, dayIndex = 0; day <= endKey; day = reportShiftDate(day, 1), dayIndex += 1) {
      const orderCount = 22 + ((dayIndex * 7 + 5) % 17);
      for (let index = 0; index < orderCount; index += 1) {
        const type = (index + dayIndex) % 3 === 0 ? 'delivery' : 'pickup';
        if (orderChannel !== 'all' && type !== orderChannel) continue;
        const first = sampleCatalog[(index + dayIndex) % sampleCatalog.length];
        const second = sampleCatalog[(index * 2 + dayIndex + 2) % sampleCatalog.length];
        const quantity = index % 5 === 0 ? 2 : 1;
        const items = [{ name: first.name, price: Math.round(first.price * scale), qty: quantity }, ...(index % 4 === 0 ? [{ name: second.name, price: Math.round(second.price * scale), qty: 1 }] : [])];
        const subtotal = items.reduce((sum, item) => sum + item.price * item.qty, 0);
        const deliveryFee = type === 'delivery' ? 250 : 0;
        const refunded = index % 43 === 0;
        const hour = 10 + ((index * 3 + dayIndex * 2) % 12);
        const createdAt = new Date(reportDateBoundary(day).getTime() + (hour * 60 + (index * 11) % 60) * 60000);
        orders.push({
          createdAt, items, subtotal, deliveryFee: Math.round(deliveryFee * scale), total: subtotal + Math.round(deliveryFee * scale),
          type, paymentMethod: index % 3 === 0 ? 'mpesa' : 'pay-on-delivery',
          paymentStatus: refunded ? 'refunded' : 'paid', status: refunded ? 'refunded' : (index % 4 === 0 ? 'completed' : 'preparing')
        });
      }
      const bookingCount = 12 + ((dayIndex * 5 + 3) % 13);
      for (let index = 0; index < bookingCount; index += 1) {
        const statuses = ['confirmed', 'confirmed', 'seated', 'pending', 'completed', 'cancelled', 'no-show'];
        const hour = 11 + ((index * 2 + dayIndex) % 11);
        const serviceDate = new Date(reportDateBoundary(day).getTime() + (hour * 60 + (index * 7) % 60) * 60000);
        const leadDays = (index * 3 + dayIndex) % 19;
        reservations.push({
          date: serviceDate, time: `${String(hour).padStart(2, '0')}:${String((index * 7) % 60).padStart(2, '0')}`,
          createdAt: new Date(serviceDate.getTime() - leadDays * 86400000),
          partySize: 1 + ((index + dayIndex) % 6), status: statuses[(index + dayIndex) % statuses.length]
        });
      }
    }
    return { orders, reservations };
  }
  const currentRecords = createPreviewRecords(from, to, 1, channel);
  const metrics = summarizeReportPeriod(currentRecords.orders, currentRecords.reservations, from, to);
  let comparisonFrom = null, comparisonTo = null, comparisonMetrics = null;
  const countDays = reportDayCount(from, to);
  if (comparison === 'previous') {
    comparisonTo = reportShiftDate(from, -1);
    comparisonFrom = reportShiftDate(comparisonTo, -(countDays - 1));
  } else if (comparison === 'year') {
    comparisonFrom = reportShiftYear(from, -1);
    comparisonTo = reportShiftYear(to, -1);
  }
  if (comparisonFrom) {
    const prior = createPreviewRecords(comparisonFrom, comparisonTo, .88, channel);
    comparisonMetrics = summarizeReportPeriod(prior.orders, prior.reservations, comparisonFrom, comparisonTo);
  }
  res.json({
    preview: true,
    period: { from, to, timeZone: REPORT_TIME_ZONE, channel },
    source: { sales: 'Illustrative development preview only', reservations: 'Illustrative development preview only', menuItems: 'Illustrative development preview only' },
    comparison: { type: comparison, from: comparisonFrom, to: comparisonTo, metrics: comparisonMetrics },
    metrics,
    definitions: {
      grossSales: 'Preview order totals before simulated full refunds; illustrative only.',
      netSales: 'Preview gross sales less simulated full-order refunds; illustrative only.',
      averageOrderValue: 'Preview net sales divided by non-refunded paid orders.',
      seatedCovers: 'Preview party sizes on bookings marked seated or completed.',
      reservations: 'Preview reservation records by service date.',
      timeBasis: 'Preview dates grouped in Africa/Nairobi time.'
    },
    unavailable: [
      { metric: 'Taxes, tips, discounts, voids, and refund reasons', reason: 'These fields are not represented in the preview data or production order records.' },
      { metric: 'Average dine-in check and spend per guest', reason: 'Dine-in POS checks and unique seated guest counts are not recorded.' },
      { metric: 'Table occupancy, turns, wait time, and service pacing', reason: 'Preview and production data do not include table capacity or actual seating/order timing.' },
      { metric: 'Events, reviews, website analytics, and operations costs', reason: 'No corresponding connected data source is configured.' },
      { metric: 'Scheduled report delivery', reason: 'No authorized recipient or email delivery integration is configured.' }
    ]
  });
});

app.get('/api/admin/dashboard-stats', auth, authorize('admin','manager','host','kitchen'), async (req, res) => {
  const today = new Date(); today.setHours(0,0,0,0);
  const tomorrow = new Date(today); tomorrow.setDate(tomorrow.getDate() + 1);
  const reservations = await Reservation.find({ date: { $gte: today, $lt: tomorrow } });
  const orders = await Order.find({ createdAt: { $gte: today, $lt: tomorrow } });
  const revenue = orders.reduce((sum, order) => {
    const refunded = order.paymentStatus === 'refunded' || order.status === 'refunded';
    return !refunded && (order.paymentStatus === 'paid' || order.status === 'completed') ? sum + (order.total || 0) : sum;
  }, 0);
  const paidOrdersToday = orders.filter(order => order.paymentStatus !== 'refunded' && order.status !== 'refunded' && (order.paymentStatus === 'paid' || order.status === 'completed')).length;
  const activeOrdersToday = orders.filter(order => ['new', 'accepted', 'preparing', 'ready', 'out-for-delivery'].includes(order.status)).length;
  const expectedArrivals = reservations.filter(reservation => ['pending', 'confirmed'].includes(reservation.status)).length;
  const coversToday = reservations.filter(reservation => ['pending', 'confirmed', 'seated'].includes(reservation.status)).reduce((sum, reservation) => sum + (Number(reservation.partySize) || 0), 0);
  res.json({
    reservationsToday: reservations.length,
    expectedArrivals,
    coversToday,
    confirmedToday: reservations.filter(r => r.status === 'confirmed').length,
    seatedToday: reservations.filter(r => r.status === 'seated').length,
    ordersToday: orders.length,
    activeOrdersToday,
    paidOrdersToday,
    revenueToday: revenue,
    totalUsers: await User.countDocuments(),
    totalMenuItems: await MenuItem.countDocuments(),
    totalOrders: await Order.countDocuments()
  });
});

// ── Reservations ──
app.get('/api/admin/reservations', auth, authorize('admin','manager','host'), async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1), limit = Math.min(100, Math.max(1, Number(req.query.limit) || 100));
  const filter = {}; if (req.query.status) filter.status = String(req.query.status); if (req.query.date) { const start = new Date(req.query.date); if (Number.isFinite(+start)) { start.setHours(0,0,0,0); const end = new Date(start); end.setDate(end.getDate()+1); filter.date = { $gte: start, $lt: end }; } }
  if (req.query.q) { const q = String(req.query.q).slice(0,100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); filter.$or = ['guestName','guestEmail','guestPhone'].map(field => ({ [field]: { $regex: q, $options: 'i' } })); }
  const [list,total] = await Promise.all([Reservation.find(filter).sort({ date: 1, time: 1 }).skip((page-1)*limit).limit(limit), Reservation.countDocuments(filter)]);
  res.json({ reservations: list, page, limit, total, pages: Math.ceil(total/limit) });
});

app.post('/api/admin/reservations', auth, authorize('admin','manager','host'), async (req, res, next) => {
  const body = cleanReservationInput(req.body); const validationError = validateReservationBody(body); if (validationError) return res.status(400).json({ error: validationError });
  const conflict = await reservationConflict(body.tableNumber, body.date, body.time, null, body.partySize); if (conflict) return res.status(409).json({ error: conflict });
  const r = await Reservation.create(body);
  await logAudit(req.user.id || 'admin', 'create_reservation', '/api/admin/reservations', `Table ${r.tableNumber}`);
  res.json({ ok: true, reservation: r });
});

app.patch('/api/admin/reservations/:id', auth, authorize('admin','manager','host'), async (req, res) => {
  const existing = await Reservation.findById(req.params.id); if (!existing) return res.status(404).json({ error: 'Reservation not found' });
  const body = cleanReservationInput({ ...existing.toObject(), ...req.body }); const validationError = validateReservationBody(body); if (validationError) return res.status(400).json({ error: validationError });
  const conflict = await reservationConflict(body.tableNumber, body.date, body.time, existing._id, body.partySize); if (conflict) return res.status(409).json({ error: conflict });
  const r = await Reservation.findByIdAndUpdate(req.params.id, body, { new: true, runValidators: true });
  await logAudit(req.user.id || 'admin', 'update_reservation', `/api/admin/reservations/${req.params.id}`, `Status: ${r.status}`);
  res.json({ ok: true, reservation: r });
});

app.delete('/api/admin/reservations/:id', auth, authorize('admin','manager','host'), async (req, res) => {
  await Reservation.findByIdAndDelete(req.params.id);
  await logAudit(req.user.id || 'admin', 'delete_reservation', `/api/admin/reservations/${req.params.id}`, 'Deleted');
  res.json({ ok: true });
});

// ── Menu Items ──
app.get('/api/admin/menu', auth, authorize('admin','manager','kitchen'), async (req, res) => {
  const filter = {}; if (req.query.q) { const q = String(req.query.q).slice(0,100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); filter.$or = ['name','category'].map(field => ({ [field]: { $regex: q, $options: 'i' } })); }
  const list = await MenuItem.find(filter).sort({ category: 1, name: 1 }).limit(500);
  res.json({ menu: list });
});

app.post('/api/admin/menu', auth, authorize('admin','manager'), async (req, res) => {
  const item = await MenuItem.create(req.body);
  await logAudit(req.user.id || 'admin', 'create_menu_item', '/api/admin/menu', item.name);
  res.json({ ok: true, item });
});

app.patch('/api/admin/menu/:id', auth, authorize('admin','manager'), async (req, res) => {
  const item = await MenuItem.findByIdAndUpdate(req.params.id, req.body, { new: true });
  await logAudit(req.user.id || 'admin', 'update_menu_item', `/api/admin/menu/${req.params.id}`, item.name);
  res.json({ ok: true, item });
});

app.delete('/api/admin/menu/:id', auth, authorize('admin','manager'), async (req, res) => {
  await MenuItem.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

// ── Orders ──
app.get('/api/admin/orders', auth, authorize('admin','manager','kitchen'), async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1), limit = Math.min(100, Math.max(1, Number(req.query.limit) || 100)); const filter = {};
  if (req.query.status) filter.status = String(req.query.status); if (req.query.date) { const start = new Date(req.query.date); if (Number.isFinite(+start)) { start.setHours(0,0,0,0); const end = new Date(start); end.setDate(end.getDate()+1); filter.createdAt = { $gte: start, $lt: end }; } }
  if (req.query.q) { const q = String(req.query.q).slice(0,100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); filter.$or = ['orderNumber','customerName','customerPhone','customerEmail'].map(field => ({ [field]: { $regex: q, $options: 'i' } })); }
  const [list,total] = await Promise.all([Order.find(filter).sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit), Order.countDocuments(filter)]);
  res.json({ orders: list, page, limit, total, pages: Math.ceil(total/limit) });
});

app.patch('/api/admin/orders/:id', auth, authorize('admin','manager','kitchen'), async (req, res) => {
  const allowed = ['new','accepted','preparing','ready','out-for-delivery','completed','refunded','cancelled']; if (!allowed.includes(req.body.status)) return res.status(400).json({ error: 'Invalid order status' });
  const updates = { status: req.body.status, updatedAt: new Date() }; const timestamp = { accepted: 'acceptedAt', preparing: 'preparingAt', ready: 'readyAt', completed: 'completedAt' }[req.body.status]; if (timestamp) updates[timestamp] = new Date();
  const order = await Order.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true }); if (!order) return res.status(404).json({ error: 'Order not found' });
  await logAudit(req.user.id || 'admin', 'update_order', `/api/admin/orders/${req.params.id}`, `Status: ${order.status}`);
  res.json({ ok: true, order });
});

// ── Audit Logs ──
app.get('/api/admin/audit-logs', auth, adminOnly, async (req, res) => {
  const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
  res.json({ logs });
});

// Restaurant operations, floor management, guest CRM, events, inbox and settings.
app.get('/api/tables', async (req, res, next) => {
  try { res.json({ tables: await Table.find({ status: 'available' }).sort({ number: 1 }).lean() }); }
  catch (error) { next(error); }
});
app.get('/api/admin/tables', auth, authorize('admin','manager','host'), async (req, res, next) => {
  try {
    const tables = await Table.find().sort({ section: 1, number: 1 }).lean();
    const date = req.query.date ? new Date(req.query.date) : new Date();
    const start = new Date(date); start.setHours(0,0,0,0); const end = new Date(start); end.setDate(end.getDate()+1);
    const filter = { date: { $gte: start, $lt: end }, status: { $nin: ['cancelled','no-show'] } };
    if (req.query.time) filter.time = String(req.query.time).slice(0,5);
    const reservations = await Reservation.find(filter).sort({ time: 1 }).lean();
    res.json({ tables: tables.map(table => ({ ...table, serviceStatus: table.status === 'blocked' ? 'blocked' : reservations.some(r => r.tableNumber === table.number && r.status === 'seated') ? 'seated' : reservations.some(r => r.tableNumber === table.number) ? 'reserved' : table.status, reservation: reservations.find(r => r.tableNumber === table.number) || null })) });
  } catch (error) { next(error); }
});
app.post('/api/admin/tables', auth, authorize('admin','manager'), [body('number').isInt({ min: 1 }), body('section').trim().isLength({ min: 1, max: 60 }), body('seats').isInt({ min: 1, max: 50 }), validateRequest], async (req, res, next) => {
  try { const table = await Table.create({ number: Number(req.body.number), section: req.body.section, seats: Number(req.body.seats) }); await logAudit(req.user.id, 'create_table', '/api/admin/tables', `Table ${table.number}`); res.status(201).json({ table }); }
  catch (error) { next(error); }
});
app.patch('/api/admin/tables/:id', auth, authorize('admin','manager'), async (req, res, next) => {
  try { const { section, seats, number } = req.body; const updates = {}; if (section !== undefined) updates.section = String(section).trim().slice(0,60); if (Number.isInteger(Number(seats)) && seats > 0) updates.seats = Number(seats); if (Number.isInteger(Number(number)) && number > 0) updates.number = Number(number); const table = await Table.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true }); if (!table) return res.status(404).json({ error: 'Table not found' }); await logAudit(req.user.id, 'update_table', req.path, `Table ${table.number}`); res.json({ table }); }
  catch (error) { next(error); }
});
app.patch('/api/admin/tables/:id/status', auth, authorize('admin','manager','host'), async (req, res, next) => {
  try { const { status, reason = '' } = req.body; if (!['available','blocked','seated'].includes(status)) return res.status(400).json({ error: 'Invalid table status' }); const table = await Table.findByIdAndUpdate(req.params.id, { status, blockReason: status === 'blocked' ? String(reason).slice(0,240) : '', updatedAt: new Date() }, { new: true, runValidators: true }); if (!table) return res.status(404).json({ error: 'Table not found' }); await logAudit(req.user.id, 'set_table_status', req.path, `Table ${table.number}: ${status}`); res.json({ table }); }
  catch (error) { next(error); }
});
app.delete('/api/admin/tables/:id', auth, authorize('admin','manager'), async (req, res, next) => {
  try { const table = await Table.findById(req.params.id); if (!table) return res.status(404).json({ error: 'Table not found' }); if (await Reservation.exists({ tableNumber: table.number, status: { $nin: ['cancelled','no-show'] }, date: { $gte: new Date() } })) return res.status(409).json({ error: 'This table has upcoming reservations and cannot be removed.' }); await table.deleteOne(); res.json({ ok: true }); }
  catch (error) { next(error); }
});

app.post('/api/admin/walkins', auth, authorize('admin','manager','host'), async (req, res, next) => {
  try { const tableNumber = Number(req.body.tableNumber), partySize = Number(req.body.partySize), guestName = String(req.body.guestName || '').trim().slice(0,100); const table = await Table.findOne({ number: tableNumber }); if (!table || table.status !== 'available') return res.status(409).json({ error: 'Choose an available table.' }); if (!guestName || !Number.isInteger(partySize) || partySize < 1 || partySize > table.seats) return res.status(400).json({ error: 'Enter a guest name and a party size within table capacity.' }); const now = new Date(); const reservation = await Reservation.create({ tableNumber, partySize, guestName, date: now, time: now.toTimeString().slice(0,5), status: 'seated', occasion: 'Walk-in' }); table.status = 'seated'; await table.save(); await logAudit(req.user.id, 'seat_walk_in', req.path, `${guestName} at table ${tableNumber}`); res.status(201).json({ reservation }); }
  catch (error) { next(error); }
});

app.get('/api/admin/operations', auth, adminOnly, async (req, res, next) => { try { const entry = await Setting.findOne({ key: 'operations' }); res.json(entry?.value || { ordersPaused: false }); } catch (error) { next(error); } });
app.patch('/api/admin/operations', auth, adminOnly, async (req, res, next) => { try { const ordersPaused = Boolean(req.body.ordersPaused); const entry = await Setting.findOneAndUpdate({ key: 'operations' }, { $set: { value: { ordersPaused }, updatedAt: new Date() } }, { upsert: true, new: true }); await logAudit(req.user.id, 'toggle_online_orders', req.path, ordersPaused ? 'Paused' : 'Resumed'); res.json(entry.value); } catch (error) { next(error); } });
app.patch('/api/admin/menu/:id/availability', auth, authorize('admin','manager','kitchen'), async (req, res, next) => { try { if (typeof req.body.available !== 'boolean') return res.status(400).json({ error: 'Availability must be true or false.' }); const item = await MenuItem.findByIdAndUpdate(req.params.id, { available: req.body.available }, { new: true }); if (!item) return res.status(404).json({ error: 'Menu item not found' }); await logAudit(req.user.id, 'toggle_menu_availability', req.path, `${item.name}: ${item.available ? 'available' : 'sold out'}`); res.json({ item }); } catch (error) { next(error); } });

app.post('/api/contact', authLimiter, [body('name').trim().isLength({ min: 1, max: 100 }), body('email').isEmail().normalizeEmail(), body('message').trim().isLength({ min: 1, max: 3000 }), validateRequest], async (req, res, next) => { try { const message = await ContactMessage.create({ name: req.body.name, email: req.body.email, phone: String(req.body.phone || '').slice(0,40), subject: String(req.body.subject || '').slice(0,120), message: req.body.message }); res.status(201).json({ ok: true, id: message.id }); } catch (error) { next(error); } });
app.get('/api/admin/inbox', auth, authorize('admin','manager'), async (req, res, next) => { try { const filter = {}; if (req.query.q) { const q = String(req.query.q).slice(0,100); filter.$or = ['name','email','subject','message'].map(key => ({ [key]: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } })); } res.json({ messages: await ContactMessage.find(filter).sort({ createdAt: -1 }).limit(200).lean() }); } catch (error) { next(error); } });
app.patch('/api/admin/inbox/:id', auth, authorize('admin','manager'), async (req, res, next) => { try { if (!['unread','read','archived'].includes(req.body.status)) return res.status(400).json({ error: 'Invalid message status' }); const message = await ContactMessage.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); if (!message) return res.status(404).json({ error: 'Message not found' }); res.json({ message }); } catch (error) { next(error); } });

app.get('/api/events', async (req, res, next) => { try { res.json({ events: await Event.find({ published: true, date: { $gte: new Date() } }).sort({ date: 1 }).lean() }); } catch (error) { next(error); } });
app.get('/api/admin/events', auth, authorize('admin','manager'), async (req, res, next) => { try { const events = await Event.find().sort({ date: 1 }).lean(); const bookings = await EventBooking.aggregate([{ $group: { _id: '$eventId', guests: { $sum: '$guests' }, bookings: { $sum: 1 } } }]); res.json({ events: events.map(event => ({ ...event, bookings: bookings.find(item => String(item._id) === String(event._id))?.bookings || 0, bookedGuests: bookings.find(item => String(item._id) === String(event._id))?.guests || 0 })) }); } catch (error) { next(error); } });
app.post('/api/admin/events', auth, authorize('admin','manager'), async (req, res, next) => { try { const { title, date, description, image, capacity, price, type, published } = req.body; if (!String(title || '').trim() || !Number.isFinite(Date.parse(date)) || !Number.isInteger(Number(capacity)) || Number(capacity) < 1 || !['private dining','tasting','live music'].includes(type)) return res.status(400).json({ error: 'Complete valid event details.' }); const event = await Event.create({ title: String(title).trim().slice(0,120), date, description: String(description || '').slice(0,2000), image: String(image || '').slice(0,500), capacity: Number(capacity), price: Math.max(0, Number(price) || 0), type, published: Boolean(published) }); await logAudit(req.user.id, 'create_event', req.path, event.title); res.status(201).json({ event }); } catch (error) { next(error); } });
app.post('/api/events/:id/bookings', authLimiter, async (req, res, next) => { try { const event = await Event.findOne({ _id: req.params.id, published: true }); if (!event) return res.status(404).json({ error: 'Event not found' }); const guests = Number(req.body.guests); if (!String(req.body.name || '').trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(req.body.email || '')) || !Number.isInteger(guests) || guests < 1) return res.status(400).json({ error: 'Enter your contact details and guest count.' }); const booked = await EventBooking.aggregate([{ $match: { eventId: event._id } }, { $group: { _id: null, guests: { $sum: '$guests' } } }]); if ((booked[0]?.guests || 0) + guests > event.capacity) return res.status(409).json({ error: 'This event is at capacity.' }); const booking = await EventBooking.create({ eventId: event._id, name: req.body.name, email: req.body.email, phone: req.body.phone, guests }); res.status(201).json({ ok: true, bookingId: booking.id }); } catch (error) { next(error); } });

app.get('/api/admin/guests', auth, authorize('admin','manager','host'), async (req, res, next) => { try { const reservations = await Reservation.find({ guestEmail: { $ne: '' } }).lean(); const orders = await Order.find({ customerEmail: { $ne: '' } }).lean(); const map = new Map(); for (const row of reservations) { const key = row.guestEmail.toLowerCase(); const guest = map.get(key) || { email: key, name: row.guestName, phone: row.guestPhone, visits: 0, spend: 0, lastVisit: row.date, dietary: new Set() }; if (['confirmed','seated','completed'].includes(row.status)) guest.visits++; if (row.dietary) guest.dietary.add(row.dietary); if (new Date(row.date) > new Date(guest.lastVisit)) guest.lastVisit = row.date; map.set(key, guest); } for (const row of orders) { const key = row.customerEmail.toLowerCase(); const guest = map.get(key) || { email: key, name: row.customerName, phone: row.customerPhone, visits: 0, spend: 0, lastVisit: row.createdAt, dietary: new Set() }; if (row.paymentStatus === 'paid' && row.status !== 'refunded') guest.spend += row.total; guest.visits++; if (new Date(row.createdAt) > new Date(guest.lastVisit)) guest.lastVisit = row.createdAt; map.set(key, guest); } let guests = [...map.values()].map(g => ({ ...g, dietary: [...g.dietary] })); if (req.query.q) { const q = String(req.query.q).toLowerCase(); guests = guests.filter(g => `${g.name} ${g.email} ${g.phone}`.toLowerCase().includes(q)); } const notes = await GuestNote.find({ email: { $in: guests.map(g => g.email) } }).lean(); guests = guests.map(g => ({ ...g, ...(notes.find(n => n.email === g.email) || {}), visits: g.visits, spend: g.spend, dietary: g.dietary })); res.json({ guests }); } catch (error) { next(error); } });
app.patch('/api/admin/guests/:email', auth, authorize('admin','manager'), async (req, res, next) => { try { const email = decodeURIComponent(req.params.email).toLowerCase(); const tags = Array.isArray(req.body.tags) ? req.body.tags.filter(tag => ['VIP','Regular'].includes(tag)) : []; const staffNotes = String(req.body.staffNotes || '').slice(0,2000); const note = await GuestNote.findOneAndUpdate({ email }, { email, tags, staffNotes }, { new: true, upsert: true, runValidators: true }); res.json({ guest: note }); } catch (error) { next(error); } });

app.get('/api/admin/reviews', auth, authorize('admin','manager'), async (req, res, next) => { try { res.json({ reviews: await Review.find().sort({ createdAt: -1 }).limit(200).lean() }); } catch (error) { next(error); } });
app.post('/api/reviews', authLimiter, async (req, res, next) => { try { const rating = Number(req.body.rating); if (!Number.isInteger(rating) || rating < 1 || rating > 5 || String(req.body.comment || '').trim().length < 3) return res.status(400).json({ error: 'Review must include a rating from 1 to 5 and a comment.' }); const review = await Review.create({ name: String(req.body.name || 'Guest').slice(0,100), rating, comment: String(req.body.comment).slice(0,2000), reference: String(req.body.reference || '').slice(0,100) }); res.status(201).json({ ok: true, reviewId: review.id }); } catch (error) { next(error); } });
app.patch('/api/admin/reviews/:id', auth, authorize('admin','manager'), async (req, res, next) => { try { const updates = {}; if (['approved','hidden','pending'].includes(req.body.status)) updates.status = req.body.status; if (typeof req.body.reply === 'string') updates.reply = req.body.reply.slice(0,2000); const review = await Review.findByIdAndUpdate(req.params.id, updates, { new: true }); if (!review) return res.status(404).json({ error: 'Review not found' }); res.json({ review }); } catch (error) { next(error); } });
app.get('/api/reviews', async (req, res, next) => { try { const reviews = await Review.find({ status: 'approved' }).sort({ createdAt: -1 }).limit(100).lean(); const average = reviews.length ? reviews.reduce((sum, item) => sum + item.rating, 0) / reviews.length : null; res.json({ reviews, count: reviews.length, average }); } catch (error) { next(error); } });

app.get('/api/admin/settings', auth, adminOnly, async (req, res, next) => { try { const entry = await Setting.findOne({ key: 'restaurant' }); res.json({ settings: entry?.value || {} }); } catch (error) { next(error); } });
app.patch('/api/admin/settings', auth, adminOnly, async (req, res, next) => { try { const allowed = ['name','address','phone','whatsapp','deliveryFee','deliveryRadiusKm','taxPercent','serviceChargePercent','openingHours','reservationSlotMinutes','maximumPartySize','leadTimeHours','cutoffHours','heroTitle','heroSubtitle','aboutText','socialLinks','gallery']; const updates = {}; for (const key of allowed) if (req.body[key] !== undefined) updates[key] = typeof req.body[key] === 'string' ? req.body[key].trim().slice(0,5000) : req.body[key]; for (const field of ['deliveryFee','deliveryRadiusKm','taxPercent','serviceChargePercent','reservationSlotMinutes','maximumPartySize','leadTimeHours','cutoffHours']) if (updates[field] !== undefined && (!Number.isFinite(Number(updates[field])) || Number(updates[field]) < 0 || ['taxPercent','serviceChargePercent'].includes(field) && Number(updates[field]) > 100)) return res.status(400).json({ error: `Invalid ${field}` }); if (Array.isArray(updates.gallery)) updates.gallery = updates.gallery.slice(0,50).map(item => String(item).slice(0,500)); const entry = await Setting.findOne({ key: 'restaurant' }) || new Setting({ key: 'restaurant', value: {} }); entry.value = { ...(entry.value || {}), ...updates }; entry.updatedAt = new Date(); await entry.save(); await logAudit(req.user.id, 'update_restaurant_settings', req.path, 'Restaurant settings updated'); res.json({ settings: entry.value }); } catch (error) { next(error); } });

app.get('/api/admin/notifications', auth, authorize('admin','manager','host','kitchen'), async (req, res, next) => { try { const since = new Date(Date.now() - 24*60*60*1000); const [orders,reservations,messages,unavailable] = await Promise.all([Order.countDocuments({ status: 'new', createdAt: { $gte: since } }), Reservation.countDocuments({ status: 'pending', createdAt: { $gte: since } }), ContactMessage.countDocuments({ status: 'unread' }), MenuItem.countDocuments({ available: false })]); res.json({ alerts: [{ type: 'orders', count: orders, label: 'New orders' },{ type: 'reservations', count: reservations, label: 'New reservations' },{ type: 'messages', count: messages, label: 'Unread messages' },{ type: 'menu', count: unavailable, label: 'Unavailable menu items' }].filter(item => item.count) }); } catch (error) { next(error); } });

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = error.status || (error.name === 'ValidationError' || error.name === 'CastError' ? 400 : error.code === 11000 ? 409 : 500);
  if (status >= 500) console.error('Request failed:', error.message);
  res.status(status).json({ error: status >= 500 ? 'The server could not complete the request.' : error.message || 'Invalid request' });
});

app.use(express.static(path.join(__dirname, '../frontend'), { maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0 }));

app.get('/admin', auth, authorize('admin','manager','host','kitchen'), (req, res) => {
  res.sendFile(path.resolve(__dirname, '../frontend/admin.html'), { dotfiles: 'allow' });
});
app.get('/login', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../frontend/login.html'), { dotfiles: 'allow' });
});
app.get('/order-confirmation.html', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../frontend/order-confirmation.html'), { dotfiles: 'allow' });
});
app.get('/404.html', (req, res) => {
  res.status(404).sendFile(path.resolve(__dirname, '../frontend/404.html'), { dotfiles: 'allow' });
});
app.use((req, res) => {
  res.status(404).sendFile(path.resolve(__dirname, '../frontend/404.html'), { dotfiles: 'allow' });
});

async function seedAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const exists = await User.findOne({ email });
  if (!exists) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await User.create({ name: 'Administrator', email, password: hash, role: 'admin' });
    console.log('Admin seeded:', email);
  }

  const menuCount = await MenuItem.countDocuments();
  if (menuCount === 0) {
    await MenuItem.create([
      { name: 'Nyama Choma Platter', description: 'Slow-grilled goat ribs marinated in East African spice blend', price: 2400, category: 'Mains', available: true, allergens: [], dietary: [], spiceLevel: 3 },
      { name: 'Whole Tilapia Fillet', description: 'Victoria Lake tilapia pan-seared in herb butter', price: 1850, category: 'Seafood', available: true, allergens: ['fish'], dietary: [], spiceLevel: 1 },
      { name: 'Swahili Pilau', description: 'Aromatic basmati rice slow-cooked with whole spices', price: 1200, category: 'Mains', available: true, allergens: [], dietary: ['vegetarian'], spiceLevel: 2 },
      { name: 'Lavish Sunday Brunch', description: 'All-you-can-eat buffet with 40+ stations', price: 3500, category: 'Brunch', available: true, allergens: [], dietary: [], spiceLevel: 0 }
    ]);
    console.log('Menu seeded');
  }

  const menuHtml = fs.readFileSync(path.join(__dirname, '../frontend/menu.html'), 'utf8');
  for (const match of menuHtml.matchAll(/<button\b[^>]*class="btn btn-primary add-to-cart-btn"[^>]*>/g)) {
    const tag = match[0];
    const attr = name => tag.match(new RegExp(`${name}="([^"]*)"`))?.[1];
    const catalogId = attr('data-id'); const name = attr('data-name'); const price = Number(attr('data-price'));
    if (!catalogId || !name || !Number.isFinite(price)) continue;
    const before = menuHtml.slice(Math.max(0, match.index - 2500), match.index);
    const category = before.match(/data-cat="([^"]+)"/g)?.at(-1)?.match(/"([^"]+)"/)?.[1] || 'menu';
    const image = before.match(/<img[^>]+src="([^"]*)"/)?.[1] || '';
    await MenuItem.findOneAndUpdate({ $or: [{ catalogId }, { name }] }, { $setOnInsert: { name, price, category, available: true }, $set: { catalogId, image } }, { upsert: true, new: true, setDefaultsOnInsert: true });
  }

  if (!(await Table.countDocuments())) {
    await Table.create(Array.from({ length: 12 }, (_, index) => ({ number: index + 1, section: index < 6 ? 'Indoor' : index < 10 ? 'Patio' : 'Lakeside', seats: index % 3 === 0 ? 6 : 4 })));
  }
  if (!(await Setting.exists({ key: 'restaurant' }))) await Setting.create({ key: 'restaurant', value: { name: 'LakeBite', address: 'Waiyaki Way, Westlands, Nairobi', phone: '+254700000000', whatsapp: '+254700000000', deliveryFee: 150, deliveryRadiusKm: 10, taxPercent: 0, serviceChargePercent: 0, openingHours: 'Mon–Thu 11:00–22:00; Fri–Sat 11:00–00:00; Sun 10:00–21:00', reservationSlotMinutes: 90, maximumPartySize: 12, leadTimeHours: 1, cutoffHours: 2 } });
  if (!(await Setting.exists({ key: 'operations' }))) await Setting.create({ key: 'operations', value: { ordersPaused: false } });

  const resCount = await Reservation.countDocuments();
  if (resCount === 0) {
    const today = new Date(); today.setHours(12,0,0,0);
    await Reservation.create([
      { tableNumber: 5, guestName: 'Amara Ochieng', guestEmail: 'amara@example.com', guestPhone: '+254 700 000 001', partySize: 4, date: today, time: '12:30', status: 'confirmed', occasion: 'Anniversary', dietary: 'None', notes: 'Window seat preferred' },
      { tableNumber: 12, guestName: 'James Rao', guestEmail: 'james@example.com', guestPhone: '+254 700 000 002', partySize: 2, date: today, time: '13:00', status: 'pending', occasion: 'Business lunch', dietary: 'Halal', notes: '' },
      { tableNumber: 3, guestName: 'Fatuma Wanjiku', guestEmail: 'fatuma@example.com', guestPhone: '+254 700 000 003', partySize: 6, date: today, time: '19:00', status: 'pending', occasion: 'Family dinner', dietary: 'Vegetarian', notes: 'High chair needed' }
    ]);
    console.log('Reservations seeded');
  }

  const orderCount = await Order.countDocuments();
  if (orderCount === 0) {
    await Order.create([
      { orderNumber: 'LB-1001', items: [{ name: 'Nyama Choma Platter', price: 2400, qty: 1 }], total: 2400, status: 'preparing', paymentStatus: 'paid' },
      { orderNumber: 'LB-1002', items: [{ name: 'Whole Tilapia Fillet', price: 1850, qty: 1 }, { name: 'Swahili Pilau', price: 1200, qty: 1 }], total: 3050, status: 'new', paymentStatus: 'pending' }
    ]);
    console.log('Orders seeded');
  }
}

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server on port ' + port));

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log('MongoDB connected');
    await seedAdmin();
  })
  .catch(e => console.error('MongoDB connection failed; website pages remain available, but database features are offline:', e.message));
