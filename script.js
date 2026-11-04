
/* ============================================================
 LakeBite — script.js
 Global JavaScript: Theme, Cart, Navigation, Animations
 ============================================================ */

// ── Theme Toggle ──────────────────────────────────────────
const themeBtn = document.querySelectorAll('.theme-btn');
const root = document.documentElement;

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

// ── Mobile Menu ────────────────────────────────────────────
const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
const mobileNav = document.querySelector('.mobile-nav');

if (mobileMenuBtn && mobileNav) {
  mobileMenuBtn.addEventListener('click', () => {
    mobileNav.classList.toggle('open');
    mobileMenuBtn.classList.toggle('active');
  });

  document.addEventListener('click', e => {
    if (!e.target.closest('.mobile-menu-btn') && !e.target.closest('.mobile-nav')) {
      mobileNav.classList.remove('open');
    }
  });
}

// Mark active nav link
(function setActiveNav() {
  const page = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-links a, .mobile-nav a').forEach(a => {
    const href = a.getAttribute('href');
    if (href && href.includes(page)) a.classList.add('active');
    if (page === 'index.html' && (href === 'index.html' || href === './' || href === '#')) {
      a.classList.add('active');
    }
  });
})();

// ── Cart System ────────────────────────────────────────────
let cart = JSON.parse(localStorage.getItem('lb-cart') || '[]');

function saveCart() {
  localStorage.setItem('lb-cart', JSON.stringify(cart));
}

function updateCartUI() {
  const total = cart.reduce((s, i) => s + i.qty, 0);
  document.querySelectorAll('.cart-count').forEach(el => {
    el.textContent = total;
    el.classList.toggle('show', total > 0);
  });
  renderCartDrawer();
}

function addToCart(id, name, price, img) {
  const existing = cart.find(i => i.id === id);
  if (existing) {
    existing.qty++;
  } else {
    cart.push({ id, name, price: parseFloat(price), img, qty: 1 });
  }
  saveCart();
  updateCartUI();
  showToast(`<i class="fa-solid fa-circle-check"></i> Added to cart`);
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
        <div class="cart-item-img"><img src="${item.img || ''}" alt="${item.name}"></div>
        <div class="cart-item-info">
          <h4>${item.name}</h4>
          <div class="price">KES ${(item.price * item.qty).toLocaleString()}</div>
          <div class="cart-item-qty">
            <button class="qty-btn" onclick="changeQty('${item.id}', -1)">−</button>
            <span class="qty-val">${item.qty}</span>
            <button class="qty-btn" onclick="changeQty('${item.id}', 1)">+</button>
          </div>
        </div>
        <button class="remove-item-btn" onclick="removeFromCart('${item.id}')">
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
    if (!localStorage.getItem('lb_token')) { window.location.href='/login.html'; return; }
    const btn = e.target.closest('.add-to-cart-btn');
    addToCart(
      btn.dataset.id,
      btn.dataset.name,
      btn.dataset.price,
      btn.dataset.img || ''
    );
  }
  if (e.target.closest('.checkout-btn')) {
    if (!localStorage.getItem('lb_token')) { window.location.href='/login.html'; return; }
    showToast('<i class="fa-solid fa-check"></i> Order placed! We\'ll contact you soon.');
    cart = [];
    saveCart();
    updateCartUI();
    closeCart();
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

function isLoggedIn() {
  return !!localStorage.getItem('lb_token');
}

async function loadUser() {
  if (!isLoggedIn()) return;
  try {
    const r = await fetch('/api/me', { credentials: 'include' });
    if (r.ok) {
      const d = await r.json();
      if (d.user) {
        const name = d.user.name || d.user.email.split('@')[0];
        if (userNameEl) userNameEl.textContent = name;
        if (userDisplayName) userDisplayName.textContent = name;
        if (userDisplayEmail) userDisplayEmail.textContent = d.user.email;
      }
    }
  } catch {}
}

async function logout() {
  try {
    await fetch('/api/logout', { method: 'POST', credentials: 'include' });
  } catch {}
  localStorage.removeItem('lb_token');
  updateAuthUI();
  location.href = '/index.html';
}
function updateAuthUI() {
  const loggedIn = isLoggedIn();

  LOGIN_LINKS.forEach(link => {
    link.textContent = loggedIn ? 'Logout' : 'Login';
    link.href = loggedIn ? 'javascript:void(0)' : 'login.html';
    link.onclick = loggedIn ? e => { e.preventDefault(); logout(); } : null;
  });

  const footerLink = document.getElementById('footerLoginLink');
  if (footerLink) {
    footerLink.textContent = loggedIn ? 'Logout' : 'Login';
    footerLink.href = loggedIn ? 'javascript:void(0)' : 'login.html';
    footerLink.onclick = loggedIn ? e => { e.preventDefault(); logout(); } : null;
  }

  const mobileLink = document.getElementById('mobileLoginLink');
  if (mobileLink) {
    mobileLink.textContent = loggedIn ? 'Logout' : 'Login';
    mobileLink.href = loggedIn ? 'javascript:void(0)' : 'login.html';
    mobileLink.onclick = loggedIn ? e => { e.preventDefault(); logout(); } : null;
  }

  if (accountLoginItem) accountLoginItem.style.display = loggedIn ? 'none' : 'block';
  if (accountLogoutItem) accountLogoutItem.style.display = loggedIn ? 'block' : 'none';

  if (accountLogoutItem) {
    accountLogoutItem.onclick = e => { e.preventDefault(); logout(); };
  }

  if (accountLoginItem) {
    accountLoginItem.onclick = e => { e.preventDefault(); location.href = 'login.html'; };
  }

  if (userAccountBtn) userAccountBtn.blur();
}

if (userAccountBtn && accountDropdown) {
  userAccountBtn.addEventListener('click', e => {
    e.stopPropagation();
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
  toast.innerHTML = msg;
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

// ── Header scroll shadow ───────────────────────────────────
function initHeaderScroll() {
  const header = document.querySelector('.site-header');
  if (!header) return;
  window.addEventListener('scroll', () => {
    header.style.boxShadow = window.scrollY > 10
      ? '0 4px 24px rgba(0,0,0,0.10)'
      : 'none';
  }, { passive: true });
}

// ── Init ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  updateAuthUI();
  await loadUser();
  updateCartUI();
  initReveal();
  initHeaderScroll();
});
