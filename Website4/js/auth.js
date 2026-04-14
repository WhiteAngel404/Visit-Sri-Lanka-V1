// Simple client-side auth for this static site (localStorage + WebCrypto).
// Note: This is suitable for demos/portfolio sites, not for real security.

(function () {
  const USERS_KEY = 'vsl_auth_users_v1';
  const SESSION_KEY = 'vsl_auth_session_v1';

  const PBKDF2_ITERATIONS = 150000;
  const PBKDF2_HASH = 'SHA-256';

  function safeNotify(message, type = 'info') {
    if (typeof window.showNotification === 'function') {
      window.showNotification(message, type);
      return;
    }
    // Fallback if main.js isn't loaded yet
    alert(message);
  }

  function getUsers() {
    try {
      return JSON.parse(localStorage.getItem(USERS_KEY) || '[]');
    } catch {
      return [];
    }
  }

  function setUsers(users) {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  }

  function getSession() {
    try {
      return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null');
    } catch {
      return null;
    }
  }

  function setSession(session) {
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  }

  function clearSession() {
    localStorage.removeItem(SESSION_KEY);
  }

  function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
  }

  function uint8ToB64(uint8) {
    let bin = '';
    for (let i = 0; i < uint8.length; i++) bin += String.fromCharCode(uint8[i]);
    return btoa(bin);
  }

  function b64ToUint8(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function pbkdf2Hash(password, saltUint8, iterations = PBKDF2_ITERATIONS) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(String(password)),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltUint8, iterations, hash: PBKDF2_HASH },
      keyMaterial,
      256
    );
    return new Uint8Array(bits);
  }

  async function createUser({ name, email, password }) {
    const users = getUsers();
    const normEmail = normalizeEmail(email);
    if (!normEmail) throw new Error('Email is required.');
    if (users.some(u => u.email === normEmail)) throw new Error('An account with this email already exists.');
    if (!password || String(password).length < 6) throw new Error('Password must be at least 6 characters.');

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await pbkdf2Hash(password, salt);

    const user = {
      id: 'u_' + Math.random().toString(36).slice(2) + Date.now().toString(36),
      name: String(name || '').trim() || normEmail.split('@')[0],
      email: normEmail,
      password: {
        alg: 'PBKDF2',
        hash: PBKDF2_HASH,
        iterations: PBKDF2_ITERATIONS,
        saltB64: uint8ToB64(salt),
        hashB64: uint8ToB64(hash)
      },
      createdAt: new Date().toISOString()
    };

    users.push(user);
    setUsers(users);
    return { id: user.id, name: user.name, email: user.email };
  }

  async function verifyUser(email, password) {
    const users = getUsers();
    const normEmail = normalizeEmail(email);
    const user = users.find(u => u.email === normEmail);
    if (!user) return null;

    const salt = b64ToUint8(user.password.saltB64);
    const hash = await pbkdf2Hash(password, salt, user.password.iterations);
    const hashB64 = uint8ToB64(hash);
    if (hashB64 !== user.password.hashB64) return null;

    return { id: user.id, name: user.name, email: user.email };
  }

  function renderAuthNav() {
    const navWrapper = document.querySelector('.nav-wrapper');
    if (!navWrapper) return;

    // Remove legacy placement (li inside ul) if present
    const legacy = document.getElementById('authNav');
    if (legacy && legacy.tagName.toLowerCase() === 'li') legacy.remove();

    let container = document.getElementById('authNav');
    if (!container) {
      container = document.createElement('div');
      container.id = 'authNav';
      container.className = 'nav-auth';

      // Place auth buttons on the right side of the navbar
      const search = navWrapper.querySelector('.nav-search');
      const toggle = navWrapper.querySelector('#mobileMenuToggle');
      if (toggle) {
        navWrapper.insertBefore(container, toggle);
      } else if (search && search.nextSibling) {
        navWrapper.insertBefore(container, search.nextSibling);
      } else {
        navWrapper.appendChild(container);
      }
    }

    const session = getSession();
    if (!session || !session.user) {
      container.innerHTML = `
        <div class="auth-actions">
          <a href="login.html" class="btn btn-outline btn-auth">Login</a>
          <a href="signup.html" class="btn btn-primary btn-auth">Sign Up</a>
        </div>
      `;
      return;
    }

    const safeName = (session.user.name || session.user.email || 'Account').replace(/</g, '&lt;');
    container.innerHTML = `
      <div class="auth-actions">
        <a href="trip-planner.html" class="btn btn-outline btn-auth" title="Your account">${safeName}</a>
        <button type="button" class="btn btn-primary btn-auth" id="logoutBtn">Logout</button>
      </div>
    `;
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        clearSession();
        safeNotify('Logged out successfully.', 'success');
        renderAuthNav();
      });
    }
  }

  function getNextParam() {
    const params = new URLSearchParams(window.location.search);
    return params.get('next');
  }

  function redirectAfterLogin() {
    const next = getNextParam();
    window.location.href = next ? decodeURIComponent(next) : 'index.html';
  }

  function protectPageIfNeeded() {
    const requires = document.body && document.body.dataset && document.body.dataset.requireAuth === 'true';
    if (!requires) return;
    const session = getSession();
    if (session && session.user) return;
    const next = encodeURIComponent(window.location.pathname.split('/').pop() + window.location.search + window.location.hash);
    window.location.href = `login.html?next=${next}`;
  }

  function initAuthForms() {
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
      signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = signupForm.querySelector('[name="name"]')?.value || '';
        const email = signupForm.querySelector('[name="email"]')?.value || '';
        const password = signupForm.querySelector('[name="password"]')?.value || '';
        const confirm = signupForm.querySelector('[name="confirm"]')?.value || '';

        if (password !== confirm) {
          safeNotify('Passwords do not match.', 'error');
          return;
        }

        try {
          const user = await createUser({ name, email, password });
          setSession({ user, createdAt: new Date().toISOString() });
          safeNotify('Account created! You are now logged in.', 'success');
          redirectAfterLogin();
        } catch (err) {
          safeNotify(err?.message || 'Signup failed.', 'error');
        }
      });
    }

    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = loginForm.querySelector('[name="email"]')?.value || '';
        const password = loginForm.querySelector('[name="password"]')?.value || '';

        try {
          const user = await verifyUser(email, password);
          if (!user) {
            safeNotify('Invalid email or password.', 'error');
            return;
          }
          setSession({ user, createdAt: new Date().toISOString() });
          safeNotify('Welcome back!', 'success');
          redirectAfterLogin();
        } catch (err) {
          safeNotify(err?.message || 'Login failed.', 'error');
        }
      });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    protectPageIfNeeded();
    renderAuthNav();
    initAuthForms();
  });

  // Expose minimal API for other scripts if needed
  window.VSLAuth = {
    getSession,
    clearSession,
    renderAuthNav
  };
})();

