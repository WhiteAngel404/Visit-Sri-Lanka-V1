// Authentication with backend API

(function () {
  const API_BASE = window.location.origin + '/api';

  function safeNotify(message, type = 'info') {
    if (typeof window.showNotification === 'function') {
      window.showNotification(message, type);
      return;
    }
    // Fallback if main.js isn't loaded yet
    alert(message);
  }

  async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    // Include credentials for cookies
    config.credentials = 'include';

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    const response = await fetch(url, config);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Request failed');
    }

    return data;
  }

  async function createUser({ name, email, password }) {
    return await apiRequest('/signup', {
      method: 'POST',
      body: { name, email, password }
    });
  }

  async function verifyUser(email, password) {
    const data = await apiRequest('/login', {
      method: 'POST',
      body: { email, password }
    });
    return data.user;
  }

  async function logoutUser() {
    await apiRequest('/logout', { method: 'POST' });
  }

  async function getCurrentUser() {
    try {
      const data = await apiRequest('/user');
      return data.user;
    } catch (error) {
      return null;
    }
  }

  async function renderAuthNav() {
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

    try {
      const user = await getCurrentUser();
      if (!user) {
        container.innerHTML = `
          <div class="auth-actions">
            <a href="login.html" class="btn btn-outline btn-auth">Login</a>
            <a href="signup.html" class="btn btn-primary btn-auth">Sign Up</a>
          </div>
        `;
        return;
      }

      const safeName = (user.name || user.email || 'Account').replace(/</g, '&lt;');
      container.innerHTML = `
        <div class="auth-actions">
          <a href="trip-planner.html" class="btn btn-outline btn-auth" title="Your account">${safeName}</a>
          <button type="button" class="btn btn-primary btn-auth" id="logoutBtn">Logout</button>
        </div>
      `;
      const logoutBtn = document.getElementById('logoutBtn');
      if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
          try {
            await logoutUser();
            safeNotify('Logged out successfully.', 'success');
            renderAuthNav();
          } catch (error) {
            safeNotify('Logout failed.', 'error');
          }
        });
      }
    } catch (error) {
      container.innerHTML = `
        <div class="auth-actions">
          <a href="login.html" class="btn btn-outline btn-auth">Login</a>
          <a href="signup.html" class="btn btn-primary btn-auth">Sign Up</a>
        </div>
      `;
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

  async function protectPageIfNeeded() {
    const requires = document.body && document.body.dataset && document.body.dataset.requireAuth === 'true';
    if (!requires) return;
    try {
      const user = await getCurrentUser();
      if (user) return;
    } catch (error) {
      // Not authenticated
    }
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
          await createUser({ name, email, password });
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
          await verifyUser(email, password);
          safeNotify('Welcome back!', 'success');
          redirectAfterLogin();
        } catch (err) {
          safeNotify(err?.message || 'Login failed.', 'error');
        }
      });
    }
  }

  document.addEventListener('DOMContentLoaded', async () => {
    await protectPageIfNeeded();
    await renderAuthNav();
    initAuthForms();
  });

  // Expose minimal API for other scripts if needed
  window.VSLAuth = {
    getCurrentUser,
    renderAuthNav
  };
})();

