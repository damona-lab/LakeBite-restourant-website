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

app.get('/api/admin/dashboard-stats', auth, adminOnly, async (req, res) => {
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
