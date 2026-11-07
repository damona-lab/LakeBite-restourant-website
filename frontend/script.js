
/* ============================================================
 LakeBite — script.js
 Global JavaScript: Theme, Cart, Navigation, Animations
 ============================================================ */

// ── Theme Toggle ──────────────────────────────────────────
const root = document.documentElement;
window.escapeHtml = function (value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
};
function safeImageUrl(value) {
  const url = String(value || '').trim();
  return /^(https:\/\/|\/|\.\/|imege\/)/i.test(url) && !/^\/\//.test(url) ? url : '';
}
function renderPublicMenuItems(menu) {
  const grid = document.getElementById('menuGrid');
  if (!grid) return;
  const existingNames = new Set([...grid.querySelectorAll('.menu-card h3')].map(title => title.textContent.trim().toLowerCase()));
  const tabs = document.querySelector('.menu-tabs');
  const slugify = value => String(value || 'other').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'other';
  const categoryFor = value => {
    const category = String(value || '').trim();
    const normalized = category.toLowerCase();
    if (/kenyan|mains|main course|local/.test(normalized)) return 'kenyan';
    if (/seafood|fish/.test(normalized)) return 'seafood';
    if (/fast\s?food|burger|pizza/.test(normalized)) return 'fastfood';
    if (/vegetarian|vegan/.test(normalized)) return 'vegetarian';
    if (/dessert|sweet/.test(normalized)) return 'desserts';
    if (/drink|beverage|cocktail/.test(normalized)) return 'drinks';
    return slugify(category);
  };
  for (const item of menu) {
    if (!item.name || existingNames.has(String(item.name).trim().toLowerCase())) continue;
    const category = String(item.category || 'Other').trim() || 'Other';
    const categorySlug = categoryFor(category);
    if (tabs && !tabs.querySelector(`.tab-btn[data-cat="${CSS.escape(categorySlug)}"]`)) {
      const tab = document.createElement('button');
      tab.type = 'button'; tab.className = 'tab-btn'; tab.dataset.cat = categorySlug; tab.textContent = category;
      tab.addEventListener('click', () => {
        tabs.querySelectorAll('.tab-btn').forEach(button => button.classList.toggle('active', button === tab));
        grid.querySelectorAll('.menu-card').forEach(card => { card.style.display = categorySlug === 'all' || card.dataset.cat === categorySlug ? '' : 'none'; });
      });
      tabs.appendChild(tab);
    }
    const card = document.createElement('article');
    card.className = 'menu-card'; card.dataset.cat = categorySlug;
    const imageUrl = safeImageUrl(item.image);
    if (imageUrl) {
      const imageWrap = document.createElement('div'); imageWrap.className = 'mc-img';
      const image = document.createElement('img'); image.src = imageUrl; image.alt = item.name; image.loading = 'lazy';
      imageWrap.appendChild(image); card.appendChild(imageWrap);
    }
    const body = document.createElement('div'); body.className = 'mc-body';
    const categoryLabel = document.createElement('div'); categoryLabel.className = 'mc-cat'; categoryLabel.textContent = category;
    const title = document.createElement('h3'); title.textContent = item.name;
    const description = document.createElement('p'); description.textContent = item.description || '';
    const footer = document.createElement('div'); footer.className = 'mc-footer';
    const price = document.createElement('span'); price.className = 'mc-price'; price.textContent = `KES ${Number(item.price || 0).toLocaleString()}`;
    const button = document.createElement('button'); button.type = 'button'; button.className = 'btn btn-primary add-to-cart-btn';
    button.dataset.id = item.catalogId || item._id; button.dataset.name = item.name; button.dataset.price = item.price; button.dataset.img = imageUrl;
    button.disabled = item.available === false; button.setAttribute('aria-label', button.disabled ? `${item.name} sold out` : `Add ${item.name} to cart`);
    button.title = button.disabled ? 'Sold out' : `Add ${item.name} to cart`;
    button.innerHTML = button.disabled ? 'Sold out' : '<i class="fa-solid fa-plus"></i>';
    footer.append(price, button); body.append(categoryLabel, title, description, footer); card.appendChild(body);
    if (button.disabled) { card.classList.add('is-sold-out'); const badge = document.createElement('span'); badge.className = 'availability-badge'; badge.textContent = 'Sold out'; card.querySelector('.mc-img')?.appendChild(badge); }
    const activeCategory = tabs?.querySelector('.tab-btn.active')?.dataset.cat || 'all';
    if (activeCategory !== 'all' && activeCategory !== categorySlug) card.style.display = 'none';
    grid.appendChild(card); existingNames.add(String(item.name).trim().toLowerCase());
  }
}
function loadPublicContent() {
  fetch('/api/site-content', { cache: 'no-store', credentials: 'same-origin' }).then(response => response.ok ? response.json() : null).then(result => {
    const content = result?.content; if (!content) return;
    document.querySelectorAll('[data-cms]').forEach(element => {
      const key = element.dataset.cms, value = content[key];
      if (typeof value === 'string' && value.trim()) element.textContent = value;
    });
    document.querySelectorAll('.footer-contact-item [data-cms="address"], .contact-info-card [data-cms="address"]').forEach(element => { if (content.address) element.textContent = content.address; });
    document.querySelectorAll('[data-cms="phone"]').forEach(element => { if (content.phone) element.textContent = content.phone; });
    document.querySelectorAll('[data-cms="openingHours"]').forEach(element => { if (content.openingHours) element.textContent = content.openingHours; });
    const about = document.querySelector('[data-cms="aboutText"]'); if (about && content.aboutText) about.textContent = content.aboutText;
    const galleryRaw = Array.isArray(content.galleryItems) ? content.galleryItems : (Array.isArray(content.gallery) ? content.gallery : []);
    const galleryItems = galleryRaw.map(item => typeof item === 'string' ? { url: item, category: 'uncategorized', description: '' } : { url: item?.url || '', category: item?.category || 'uncategorized', description: item?.description || item?.caption || '' }).filter(i => i.url);
    document.querySelectorAll('[data-cms-gallery-cat]').forEach(container => {
      const cat = container.dataset.cmsGalleryCat;
      const items = galleryItems.filter(i => i.category === cat && i.url);
      if (!items.length) return; // keep default/static markup when no managed items for this category
      container.replaceChildren();
      const isRooms = cat === 'rooms';
      items.forEach((item, index) => {
        const url = safeImageUrl(item.url);
        const desc = String(item.description || '').trim();
        if (isRooms) {
          const card = document.createElement('div');
          card.className = 'room-item reveal visible';
          card.innerHTML = `<div class="room-img"><img src="${window.escapeHtml ? window.escapeHtml(url) : url}" alt="${window.escapeHtml ? window.escapeHtml(desc || 'LakeBite room') : (desc || 'LakeBite room')}" loading="lazy"></div><div class="room-label"><h3>${window.escapeHtml ? window.escapeHtml(desc || 'Our Room') : (desc || 'Our Room')}</h3><p></p></div>`;
          container.appendChild(card);
          return;
        }
        const wrap = document.createElement('div');
        wrap.className = 'gallery-item reveal visible' + (index === 0 && items.length > 3 ? ' gi-large' : (index === 4 ? ' gi-wide' : ''));
        const img = document.createElement('img'); img.src = url; img.alt = desc || `LakeBite gallery photo`; img.loading = 'lazy';
        const overlay = document.createElement('div'); overlay.className = 'gi-overlay';
        const span = document.createElement('span'); span.textContent = desc || 'LakeBite';
        overlay.appendChild(span); wrap.append(img, overlay); container.appendChild(wrap);
      });
    });
    // legacy single-container support
    if (galleryItems.length && document.querySelector('[data-cms-gallery="managed"]')) {
      const gallery = document.querySelector('[data-cms-gallery="managed"]'); gallery.replaceChildren();
      galleryItems.forEach((item, index) => {
        const wrap = document.createElement('div'); wrap.className = 'gallery-item reveal visible';
        const img = document.createElement('img'); img.src = safeImageUrl(item.url); img.alt = item.description || `LakeBite gallery photo ${index + 1}`; img.loading = 'lazy';
        const overlay = document.createElement('div'); overlay.className = 'gi-overlay'; overlay.innerHTML = `<span>${window.escapeHtml ? window.escapeHtml(item.description || 'LakeBite') : (item.description || 'LakeBite')}</span>`;
        wrap.append(img, overlay); gallery.appendChild(wrap);
      });
    }
  }).catch(() => {});
}
function loadPublicEventsAndReviews() {
  const eventsTarget = document.getElementById('publicEventsList');
  if (eventsTarget) fetch('/api/events').then(response => response.json()).then(({ events = [] }) => {
    eventsTarget.replaceChildren();
    eventsTarget.classList.remove('experience-grid--empty');
    if (!events.length) { eventsTarget.classList.add('experience-grid--empty'); eventsTarget.innerHTML = '<div class="experience-empty"><i class="fa-regular fa-calendar"></i><p>There are no upcoming experiences at the moment. Check back soon.</p></div>'; return; }
    for (const event of events) {
      const card = document.createElement('article'); card.className = 'experience-card';
      const media = document.createElement('div'); media.className = 'experience-media';
      const image = document.createElement('img'); image.src = safeImageUrl(event.image); image.alt = event.title || 'LakeBite experience'; image.loading = 'lazy'; image.decoding = 'async';
      const badge = document.createElement('span'); badge.className = 'experience-badge'; badge.innerHTML = `<i class="fa-solid fa-sparkles"></i> ${window.escapeHtml ? window.escapeHtml(event.type || 'Experience') : (event.type || 'Experience')}`;
      media.append(image, badge);
      const body = document.createElement('div'); body.className = 'experience-body';
      const title = document.createElement('h3'); title.className = 'experience-title'; title.textContent = event.title || 'Upcoming experience';
      const meta = document.createElement('div'); meta.className = 'experience-meta';
      const date = event.date ? new Date(event.date) : null;
      const dateText = date && !isNaN(date) ? date.toLocaleString(undefined, { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : 'Date to be announced';
      const price = Number(event.price || 0);
      meta.innerHTML = `<span><i class="fa-regular fa-clock"></i> ${dateText}</span><span><i class="fa-solid fa-user-group"></i> ${Number(event.capacity || 0)} places</span><span><i class="fa-solid fa-tag"></i> ${price > 0 ? `KES ${price.toLocaleString()}` : 'Complimentary'}</span>`;
      const description = document.createElement('p'); description.className = 'experience-desc'; description.textContent = event.description || 'Join us for a memorable LakeBite experience.';
      const form = document.createElement('form'); form.className = 'experience-form'; form.dataset.eventBooking = event._id;
      form.innerHTML = '<div class="experience-form-grid"><label><span>Name</span><input class="form-control" name="name" required maxlength="100" autocomplete="name"></label><label><span>Email</span><input class="form-control" name="email" type="email" required autocomplete="email"></label><label><span>Guests</span><input class="form-control" name="guests" type="number" min="1" value="1" required></label></div><button class="btn btn-primary experience-submit" type="submit"><i class="fa-regular fa-calendar-check"></i> Reserve your spot</button><p class="experience-status" role="status" aria-live="polite"></p>';
      body.append(title, meta, description, form); card.append(media, body); eventsTarget.appendChild(card);
    }
  }).catch(() => { eventsTarget.classList.add('experience-grid--empty'); eventsTarget.innerHTML = '<div class="experience-empty"><p>Event information is temporarily unavailable.</p></div>'; });
  const reviewsTarget = document.getElementById('publicReviewsList');
  if (reviewsTarget) fetch('/api/reviews').then(response => response.json()).then(data => {
    reviewsTarget.replaceChildren(); const summary = document.getElementById('publicReviewSummary');
    if (data.average !== null) { summary.textContent = `${Number(data.average).toFixed(1)} out of 5 based on ${data.count} approved guest reviews.`; const ld = document.getElementById('aggregateReviews'); if (ld) ld.textContent = JSON.stringify({ '@context': 'https://schema.org', '@type': 'Restaurant', name: 'LakeBite', aggregateRating: { '@type': 'AggregateRating', ratingValue: Number(data.average).toFixed(1), reviewCount: data.count } }); }
    for (const review of data.reviews || []) { const article = document.createElement('article'); article.className = 'menu-card'; const heading = document.createElement('h3'); heading.textContent = `${review.rating} / 5 · ${review.name || 'Guest'}`; const comment = document.createElement('p'); comment.textContent = review.comment; article.append(heading, comment); reviewsTarget.appendChild(article); }
  }).catch(() => { reviewsTarget.textContent = 'Guest reviews are temporarily unavailable.'; });
}

function applyTheme(theme) {
  root.setAttribute('data-theme', theme);
  localStorage.setItem('lb-theme', theme);
  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.innerHTML = theme === 'dark'
      ? '<i class="fa-solid fa-sun"></i>'
      : '<i class="fa-solid fa-moon"></i>';
    btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  });
}

(function initTheme() {
  const saved = localStorage.getItem('lb-theme') || 'light';
  applyTheme(saved);
})();

document.addEventListener('click', e => {
  if (e.target.closest('.theme-btn')) {
    const current = root.getAttribute('data-theme') || 'light';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  }
});

// ── Mobile Drawer ────────────────────────────────────────────
const navToggle = document.getElementById('navToggle');
const mobileDrawer = document.getElementById('mobileDrawer');
const drawerOverlay = document.getElementById('drawerOverlay');
const drawerClose = document.getElementById('drawerClose');
const drawerLinks = document.querySelectorAll('.drawer-link');

const openDrawer = () => {
  navToggle.classList.add('open');
  navToggle.setAttribute('aria-expanded', 'true');
  mobileDrawer.classList.add('open');
  mobileDrawer.removeAttribute('hidden');
  document.body.style.overflow = 'hidden';
  drawerOverlay.focus();
};

const closeDrawer = () => {
  navToggle.classList.remove('open');
  navToggle.setAttribute('aria-expanded', 'false');
  mobileDrawer.classList.remove('open');
  mobileDrawer.setAttribute('hidden', '');
  document.body.style.overflow = '';
};

if (navToggle && mobileDrawer) {
  navToggle.addEventListener('click', openDrawer);
  drawerClose.addEventListener('click', closeDrawer);
  drawerOverlay.addEventListener('click', closeDrawer);
  drawerLinks.forEach(link => link.addEventListener('click', closeDrawer));
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && mobileDrawer.classList.contains('open')) closeDrawer();
  });
}

// Scroll spy: mark active nav link based on visible section
const scrollSections = document.querySelectorAll('main [id], section[id]');
const inPageNavigation = document.querySelectorAll('.nav-link[href^="#"], .drawer-link[href^="#"]');
if ('IntersectionObserver' in window && scrollSections.length && inPageNavigation.length) {
const observerOptions = { rootMargin: '-30% 0% -70% 0%', threshold: 0 };
const scrollSpy = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const id = entry.target.getAttribute('id');
      document.querySelectorAll('.nav-link, .drawer-link').forEach(l => {
        l.classList.toggle('active', l.getAttribute('href') === `#${id}`);
      });
    }
  });
}, observerOptions);

scrollSections.forEach(el => scrollSpy.observe(el));
}

// ── Cart System ────────────────────────────────────────────
let cart = JSON.parse(localStorage.getItem('lb-cart') || '[]');
function saveCart() {
  try { localStorage.setItem('lb-cart', JSON.stringify(cart)); } catch {}
}
function updateCartUI() {
  const total = cart.reduce((s, i) => s + i.qty, 0);
  document.querySelectorAll('.cart-count').forEach(el => {
    el.textContent = total;
    el.parentElement.classList.toggle('has-items', total > 0);
  });
  renderCartDrawer();
}

function addToCart(id, name, price, img) {
  if (!currentUser) { showToast('Please sign in to add items to your cart'); location.href = 'login.html'; return; }
  const button = [...document.querySelectorAll('.add-to-cart-btn')].find(candidate => candidate.dataset.id === id);
  if (button?.disabled) { showToast('This dish is sold out'); return; }
  const existing = cart.find(i => i.id === id);
  if (existing) {
    existing.qty++;
  } else {
    cart.push({ id, name, price: parseFloat(price), img, qty: 1 });
  }
  saveCart();
  updateCartUI();
  showToast(`${name} added to cart`);
}

function openCheckoutModal() {
  location.href = 'checkout.html';
}

function initCheckoutPage() {
  const form = document.getElementById('checkoutForm');
  if (!form) return;
  if (!cart.length) { location.replace('menu.html'); return; }
  const total = cart.reduce((sum, item) => sum + (Number(item.price) || 0) * (Number(item.qty) || 0), 0);
  document.getElementById('checkoutTotal').textContent = `KES ${total.toLocaleString('en-KE')}`;
  document.getElementById('checkoutItems').innerHTML = cart.map(item => `<li><span>${window.escapeHtml(item.name)} × ${Number(item.qty) || 0}</span><strong>KES ${((Number(item.price) || 0) * (Number(item.qty) || 0)).toLocaleString('en-KE')}</strong></li>`).join('');
  document.getElementById('checkoutType').addEventListener('change', event => {
    const isDelivery = event.target.value === 'delivery';
    document.getElementById('checkoutAddressGroup').hidden = !isDelivery;
    document.getElementById('checkoutAddress').required = isDelivery;
  });
  fetch('/api/public/status').then(response => response.json()).then(status => {
    if (status.ordersPaused) { document.querySelector('.checkout-pause-message').hidden = false; document.getElementById('checkoutSubmit').disabled = true; }
  }).catch(() => {});
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.currentTarget; if (!form.reportValidity()) return;
    const submit = document.getElementById('checkoutSubmit'), error = document.getElementById('checkoutError');
    submit.disabled = true; submit.textContent = 'Placing order…'; error.hidden = true;
    const data = new FormData(form);
    try {
      const response = await fetch('/api/orders', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ customerName: data.get('name'), customerPhone: data.get('phone'), customerEmail: data.get('email'), type: data.get('type'), deliveryAddress: data.get('address'), notes: data.get('notes'), paymentMethod: data.get('paymentMethod'), items: cart.map(item => ({ id: item.id, name: item.name, qty: item.qty })) }) });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'Could not place order.');
      cart = []; saveCart(); updateCartUI();
      location.href = `order-confirmation.html?order=${encodeURIComponent(result.orderNumber)}`;
    } catch (failure) {
      error.textContent = failure.message; error.hidden = false; submit.disabled = false; submit.textContent = 'Place order';
    }
  });
}

async function loadPublicMenuState() {
  if (!document.querySelector('.menu-grid')) return;
  try {
    const [menuResponse, statusResponse] = await Promise.all([fetch('/api/menu'), fetch('/api/public/status')]);
    if (menuResponse.ok) {
      const { menu = [] } = await menuResponse.json();
      renderPublicMenuItems(menu);
      for (const item of menu) {
        const card = document.querySelector(`.menu-card .add-to-cart-btn[data-id="${CSS.escape(item.catalogId || '')}"]`)?.closest('.menu-card');
        if (!card) continue;
        const button = card.querySelector('.add-to-cart-btn');
        button.disabled = !item.available;
        button.setAttribute('aria-label', item.available ? `Add ${item.name} to cart` : `${item.name} sold out`);
        button.title = item.available ? 'Add to cart' : 'Sold out';
        card.classList.toggle('is-sold-out', !item.available);
        let badge = card.querySelector('.availability-badge');
        if (!item.available && !badge) { badge = document.createElement('span'); badge.className = 'availability-badge'; badge.textContent = 'Sold out'; card.querySelector('.mc-img')?.appendChild(badge); }
        if (item.available) badge?.remove();
      }
    }
    const status = await statusResponse.json();
    if (status.ordersPaused) {
      let banner = document.getElementById('onlineOrderPauseBanner');
      if (!banner) { banner = document.createElement('p'); banner.id = 'onlineOrderPauseBanner'; banner.className = 'admin-alert admin-alert-info'; banner.setAttribute('role', 'status'); banner.textContent = 'Online ordering is paused. Please try again later.'; document.querySelector('.menu-grid')?.before(banner); }
      document.querySelectorAll('.add-to-cart-btn').forEach(button => { button.disabled = true; });
    }
  } catch { /* Static menu remains usable if the menu API is offline. */ }
}

function removeFromCart(id) {
  cart = cart.filter(i => i.id !== id);
  saveCart();
  updateCartUI();
}

function changeQty(id, delta) {
  const item = cart.find(i => i.id === id);
  if (!item) return;
  item.qty += delta;
  if (item.qty <= 0) removeFromCart(id);
  else { saveCart(); updateCartUI(); }
}

function renderCartDrawer() {
  const itemsEl = document.querySelector('.cart-items');
  const totalEl = document.querySelector('.cart-total .total-price');
  if (!itemsEl) return;

  // Recover photos for older saved cart entries when the matching menu card is present.
  let recoveredCartImage = false;
  cart.forEach(item => {
    if (item.img) return;
    const button = [...document.querySelectorAll('.add-to-cart-btn')].find(candidate => (candidate.dataset.id || candidate.dataset.name) === item.id);
    const image = button?.closest('.menu-card, .dish-card, .menu-item, .product-card')?.querySelector('.mc-img img, .dish-img-wrap img, img');
    if (image?.getAttribute('src')) { item.img = image.getAttribute('src'); recoveredCartImage = true; }
  });
  if (recoveredCartImage) saveCart();

  if (cart.length === 0) {
    itemsEl.innerHTML = `
      <div class="cart-empty">
        <i class="fa-solid fa-bag-shopping"></i>
        <p>Your cart is empty</p>
        <a href="menu.html" class="btn btn-outline" style="font-size:0.78rem;padding:0.6rem 1.4rem">Browse Menu</a>
      </div>`;
  } else {
    itemsEl.innerHTML = cart.map(item => `
      <div class="cart-item">
        <div class="cart-item-img">${safeImageUrl(item.img) ? `<img src="${window.escapeHtml(safeImageUrl(item.img))}" alt="${window.escapeHtml(item.name)}" onerror="this.remove();this.parentElement.classList.add('image-missing')">` : '<i class="fa-solid fa-utensils" aria-hidden="true"></i>'}</div>
        <div class="cart-item-info">
          <h4>${window.escapeHtml(item.name)}</h4>
          <div class="price">KES ${(Number(item.price || 0) * Number(item.qty || 0)).toLocaleString()}</div>
          <div class="cart-item-qty">
            <button class="qty-btn" data-id="${window.escapeHtml(item.id)}" data-act="dec" aria-label="Decrease ${window.escapeHtml(item.name)} quantity">−</button>
            <span class="qty-val">${Math.max(0, Number(item.qty) || 0)}</span>
            <button class="qty-btn" data-id="${window.escapeHtml(item.id)}" data-act="inc" aria-label="Increase ${window.escapeHtml(item.name)} quantity">+</button>
          </div>
        </div>
        <button class="remove-item-btn" data-id="${window.escapeHtml(item.id)}" aria-label="Remove ${window.escapeHtml(item.name)} from cart">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>`).join('');
  }

  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  if (totalEl) totalEl.textContent = `KES ${total.toLocaleString()}`;
}

// Cart drawer toggle
document.addEventListener('click', e => {
  if (e.target.closest('.cart-btn')) openCart();
  if (e.target.closest('.cart-overlay') || e.target.closest('.cart-close-btn')) closeCart();
  if (e.target.closest('.add-to-cart-btn')) {
    e.preventDefault();
    const btn = e.target.closest('.add-to-cart-btn');
    const itemCard = btn.closest('.menu-card, .dish-card, .menu-item, .product-card');
    const foodImage = itemCard?.querySelector('.mc-img img, .dish-img-wrap img, img');
    addToCart(
      btn.dataset.id || btn.dataset.name,
      btn.dataset.name || 'Item',
      btn.dataset.price || 0,
      btn.dataset.img || btn.querySelector('img')?.getAttribute('src') || foodImage?.getAttribute('src') || ''
    );
  }
  if (e.target.closest('.qty-btn')) {
    const btn = e.target.closest('.qty-btn');
    changeQty(btn.dataset.id, btn.dataset.act === 'inc' ? 1 : -1);
  }
  if (e.target.closest('.remove-item-btn')) {
    const btn = e.target.closest('.remove-item-btn');
    removeFromCart(btn.dataset.id);
  }
  if (e.target.closest('.checkout-btn')) {
    const total = cart.reduce((s, i) => s + (Number(i.price)||0) * (Number(i.qty)||0), 0);
    if (cart.length === 0) { showToast('Your cart is empty'); return; }
    closeCart();
    openCheckoutModal(total);
  }
});

function openCart() {
  document.querySelector('.cart-drawer')?.classList.add('open');
  document.querySelector('.cart-overlay')?.classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeCart() {
  document.querySelector('.cart-drawer')?.classList.remove('open');
  document.querySelector('.cart-overlay')?.classList.remove('open');
  document.body.style.overflow = '';
}

// ── Auth ───────────────────────────────────────────────────
const LOGIN_LINKS = document.querySelectorAll('#loginLink');
const userAccount = document.getElementById('userAccount');
const accountDropdown = document.getElementById('accountDropdown');
const userAccountBtn = document.querySelector('.user-account-btn');
const userNameEl = document.querySelector('.user-name');
const accountLoginItem = document.getElementById('accountLoginItem');
const accountLogoutItem = document.getElementById('accountLogoutItem');
const userDisplayName = document.querySelector('.user-display-name');
const userDisplayEmail = document.querySelector('.user-display-email');

// Keep the account control at the end of the header actions, immediately after the theme toggle.
const themeToggle = document.querySelector('.header-actions .theme-btn');
if (userAccount && themeToggle) {
  themeToggle.after(userAccount);
  userAccount.closest('.nav-cta')?.remove();
}

let currentUser = null;
function isLoggedIn() { return !!currentUser; }

async function requireSignedIn(returnPage) {
  try {
    const response = await fetch('/api/me', { credentials: 'include' });
    if (response.ok) return true;
  } catch { /* Treat an unavailable session check as signed out. */ }
  location.href = `login.html?return=${encodeURIComponent(returnPage)}`;
  return false;
}

async function loadUser() {
  try {
    const r = await fetch('/api/me', { credentials: 'include' });
    if (r.ok) {
      const d = await r.json();
      if (d.user) {
        currentUser = d.user;
        const name = d.user.name || d.user.email.split('@')[0];
        if (userNameEl) userNameEl.textContent = name.trim().split(/\s+/)[0];
        if (userAccountBtn) userAccountBtn.setAttribute('aria-label', `Account menu for ${name}`);
        if (userDisplayName) userDisplayName.textContent = name;
        if (userDisplayEmail) userDisplayEmail.textContent = d.user.email;
      }
      return d.user;
    }
  } catch {}
  currentUser = null;
  return null;
}

async function logout() {
  try {
    await fetch('/api/logout', { method: 'POST', credentials: 'include' });
  } catch {}
  currentUser = null;
  updateAuthUI();
  location.href = '/index.html';
}
function updateAuthUI() {
  const loggedIn = isLoggedIn();
  document.querySelector('.site-header')?.classList.toggle('has-account', loggedIn);
  if (userAccountBtn) {
    if (loggedIn) {
      userAccountBtn.href = '#';
      userAccountBtn.setAttribute('aria-label', `Account menu for ${currentUser.name || 'you'}`);
      if (userNameEl) userNameEl.textContent = (currentUser.name || 'Account').trim().split(/\s+/)[0];
    } else {
      userAccountBtn.href = 'login.html';
      userAccountBtn.setAttribute('aria-label', 'Sign in');
      if (userNameEl) userNameEl.textContent = 'Sign in';
    }
  }

  LOGIN_LINKS.forEach(link => {
    link.textContent = loggedIn ? 'Logout' : 'Login';
    link.href = loggedIn ? '#' : 'login.html';
    link.dataset.authAction = loggedIn ? 'logout' : '';
  });

  const footerLink = document.getElementById('footerLoginLink');
  if (footerLink) {
    footerLink.textContent = loggedIn ? 'Logout' : 'Login';
    footerLink.href = loggedIn ? '#' : 'login.html';
    footerLink.dataset.authAction = loggedIn ? 'logout' : '';
  }

  const mobileLink = document.getElementById('mobileLoginLink');
  if (mobileLink) {
    mobileLink.textContent = loggedIn ? 'Logout' : 'Login';
    mobileLink.href = loggedIn ? '#' : 'login.html';
    mobileLink.dataset.authAction = loggedIn ? 'logout' : '';
  }

  if (accountLoginItem) accountLoginItem.style.display = loggedIn ? 'none' : 'block';
  if (accountLogoutItem) accountLogoutItem.style.display = loggedIn ? 'block' : 'none';

  if (accountLogoutItem) {
    accountLogoutItem.dataset.authAction = 'logout';
  }

  if (accountLoginItem) {
    accountLoginItem.dataset.authAction = 'login';
  }

  if (userAccountBtn) userAccountBtn.blur();
}

document.addEventListener('click', e => {
  const authLink = e.target.closest('[data-auth-action]');
  if (!authLink) return;
  if (authLink.dataset.authAction === 'logout') { e.preventDefault(); logout(); }
  if (authLink.dataset.authAction === 'login') { e.preventDefault(); location.href = 'login.html'; }
});

if (userAccountBtn && accountDropdown) {
  userAccountBtn.addEventListener('click', e => {
    e.stopPropagation();
    if (!isLoggedIn()) return;
    e.preventDefault();
    accountDropdown.classList.toggle('open');
  });

  document.addEventListener('click', e => {
    if (userAccount && !userAccount.contains(e.target)) {
      accountDropdown.classList.remove('open');
    }
  });
}

// ── Toast ──────────────────────────────────────────────────
function showToast(msg) {
  const toast = document.querySelector('.toast');
  if (!toast) return;
  toast.textContent = String(msg ?? '');
  toast.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => toast.classList.remove('show'), 2600);
}

// ── Scroll Animations ──────────────────────────────────────
function initReveal() {
  const els = document.querySelectorAll('.reveal, .reveal-left, .reveal-right');
  if (!els.length) return;

  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('visible');
        observer.unobserve(e.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

  els.forEach(el => observer.observe(el));
}

// ── Init ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  initCheckoutPage();
  await loadUser();
  updateAuthUI();
  updateCartUI();
  if (new URLSearchParams(location.search).get('cart') === '1') openCart();
  loadPublicMenuState();
  loadPublicContent();
  loadPublicEventsAndReviews();
  initReveal();
});

document.addEventListener('submit', async event => {
  const form = event.target.closest('form[data-event-booking]'); if (!form) return;
  event.preventDefault(); const status = form.querySelector('[role="status"]'), submit = form.querySelector('[type="submit"]'); submit.disabled = true;
  try { const values = new FormData(form); const response = await fetch(`/api/events/${encodeURIComponent(form.dataset.eventBooking)}/bookings`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.fromEntries(values)) }); const result = await response.json().catch(() => ({})); if (!response.ok) throw new Error(result.error || 'Could not book this event.'); status.textContent = 'Your event enquiry is recorded. LakeBite will follow up using your contact details.'; form.reset(); } catch (error) { status.textContent = error.message; } finally { submit.disabled = false; }
});
