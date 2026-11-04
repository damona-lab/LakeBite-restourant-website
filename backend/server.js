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

const app = express();

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

const allowedOrigins = process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(o=>o.trim()) : true;
app.use(cors({ origin: allowedOrigins, credentials: true }));

// Basic security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

app.get('/api/admin/test-ping', (req, res) => { res.json({ ok: true, time: Date.now() }); });

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 1*60*1000, max: 60, standardHeaders: true, legacyHeaders: false });
app.use('/api/', apiLimiter);

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 8 },
  role: { type: String, enum: ['user','admin'], default: 'user' },
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

function signToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

function setAuthCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production';
  res.cookie('token', token, { httpOnly: true, secure, sameSite: 'lax', maxAge: 7*24*60*60*1000, path: '/' });
}

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const emailNorm = String(email).toLowerCase().trim();
    if (await User.findOne({ email: emailNorm })) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ name: String(name).trim(), email: emailNorm, password: hash, role: 'user' });
    const token = signToken(user);
    setAuthCookie(res, token);
    res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Registration failed' }); }
});

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

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json({ user });
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const users = await User.find().select('-password').sort({ createdAt: -1 });
  res.json({ users });
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete self' });
  await User.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

async function logAudit(actor, action, endpoint, details) {
  try { await AuditLog.create({ actor: String(actor), action, endpoint, details: details ? String(details).slice(0, 500) : '' }); } catch {}
}

// ── Orders (public create, auth/admin manage) ──
app.post('/api/orders', async (req, res) => {
  try {
    const { items = [], customerName, customerEmail, customerPhone, type = 'pickup', deliveryAddress = '', notes = '', paymentMethod = 'pay-on-delivery' } = req.body;
    if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'Cart is empty' });
    if (!customerName || !customerPhone) return res.status(400).json({ error: 'Name and phone are required' });
    if (!['pickup','delivery'].includes(type)) return res.status(400).json({ error: 'Invalid order type' });
    if (type === 'delivery' && !deliveryAddress) return res.status(400).json({ error: 'Delivery address required' });
    if (!['mpesa','pay-on-delivery'].includes(paymentMethod)) return res.status(400).json({ error: 'Invalid payment method' });

    // Validate against menu/prices server-side where possible
    const validated = [];
    for (const it of items) {
      const qty = Math.max(1, Math.min(20, parseInt(it.qty) || 1));
      if (it.id) {
        const mi = await MenuItem.findOne({ _id: it.id });
        if (mi && mi.available === false) return res.status(400).json({ error: `${mi.name} is currently unavailable` });
        if (mi) {
          validated.push({ id: String(mi._id), name: mi.name, price: mi.price, qty, img: mi.image || it.img || '' });
          continue;
        }
      }
      // fallback to client price but cap; better to trust menu
      const price = Number(it.price);
      if (isNaN(price) || price < 0) return res.status(400).json({ error: 'Invalid item price' });
      validated.push({ id: it.id || '', name: String(it.name||'Item').slice(0,80), price, qty, img: it.img || '' });
    }

    const subtotal = validated.reduce((s,i)=> s + i.price * i.qty, 0);
    const deliveryFee = type === 'delivery' ? 150 : 0;
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
      paymentStatus: paymentMethod === 'mpesa' ? 'pending' : 'pending'
    });
    res.json({ ok: true, orderNumber: order.orderNumber, total: order.total, status: order.status });
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
app.get('/api/admin/dashboard-stats', auth, adminOnly, async (req, res) => {
  const today = new Date(); today.setHours(0,0,0,0);
  const tomorrow = new Date(today); tomorrow.setDate(tomorrow.getDate() + 1);
  const reservations = await Reservation.find({ date: { $gte: today, $lt: tomorrow } });
  const orders = await Order.find({ createdAt: { $gte: today, $lt: tomorrow } });
  const revenue = orders.reduce((s, o) => (o.paymentStatus === 'paid' || o.status === 'completed') ? s + (o.total || 0) : s, 0);
  const paidOrdersToday = orders.filter(o => o.paymentStatus === 'paid' || o.status === 'completed').length;
  res.json({
    reservationsToday: reservations.length,
    confirmedToday: reservations.filter(r => r.status === 'confirmed').length,
    seatedToday: reservations.filter(r => r.status === 'seated').length,
    ordersToday: orders.length,
    paidOrdersToday,
    revenueToday: revenue,
    totalUsers: await User.countDocuments(),
    totalMenuItems: await MenuItem.countDocuments(),
    totalOrders: await Order.countDocuments()
  });
});

// ── Reservations ──
app.get('/api/admin/reservations', auth, adminOnly, async (req, res) => {
  const list = await Reservation.find().sort({ date: 1, time: 1 });
  res.json({ reservations: list });
});

app.post('/api/admin/reservations', auth, adminOnly, async (req, res) => {
  const r = await Reservation.create(req.body);
  await logAudit(req.user.id || 'admin', 'create_reservation', '/api/admin/reservations', `Table ${r.tableNumber}`);
  res.json({ ok: true, reservation: r });
});

app.patch('/api/admin/reservations/:id', auth, adminOnly, async (req, res) => {
  const r = await Reservation.findByIdAndUpdate(req.params.id, req.body, { new: true });
  await logAudit(req.user.id || 'admin', 'update_reservation', `/api/admin/reservations/${req.params.id}`, `Status: ${r.status}`);
  res.json({ ok: true, reservation: r });
});

app.delete('/api/admin/reservations/:id', auth, adminOnly, async (req, res) => {
  await Reservation.findByIdAndDelete(req.params.id);
  await logAudit(req.user.id || 'admin', 'delete_reservation', `/api/admin/reservations/${req.params.id}`, 'Deleted');
  res.json({ ok: true });
});

// ── Menu Items ──
app.get('/api/admin/menu', auth, adminOnly, async (req, res) => {
  const list = await MenuItem.find().sort({ category: 1, name: 1 });
  res.json({ menu: list });
});

app.post('/api/admin/menu', auth, adminOnly, async (req, res) => {
  const item = await MenuItem.create(req.body);
  await logAudit(req.user.id || 'admin', 'create_menu_item', '/api/admin/menu', item.name);
  res.json({ ok: true, item });
});

app.patch('/api/admin/menu/:id', auth, adminOnly, async (req, res) => {
  const item = await MenuItem.findByIdAndUpdate(req.params.id, req.body, { new: true });
  await logAudit(req.user.id || 'admin', 'update_menu_item', `/api/admin/menu/${req.params.id}`, item.name);
  res.json({ ok: true, item });
});

app.delete('/api/admin/menu/:id', auth, adminOnly, async (req, res) => {
  await MenuItem.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

// ── Orders ──
app.get('/api/admin/orders', auth, adminOnly, async (req, res) => {
  const list = await Order.find().sort({ createdAt: -1 });
  res.json({ orders: list });
});

app.patch('/api/admin/orders/:id', auth, adminOnly, async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true });
  await logAudit(req.user.id || 'admin', 'update_order', `/api/admin/orders/${req.params.id}`, `Status: ${order.status}`);
  res.json({ ok: true, order });
});

// ── Audit Logs ──
app.get('/api/admin/audit-logs', auth, adminOnly, async (req, res) => {
  const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
  res.json({ logs });
});

app.use(express.static(path.join(__dirname, '../frontend'), { maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0 }));

app.get('/admin', auth, adminOnly, (req, res) => {
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
