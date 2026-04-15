# Firebase Authentication Setup Guide

## Step 1: Create a Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click **"Add project"**
3. Enter project name: **"VisitSriLanka"**
4. Disable Google Analytics (optional, for Spark plan)
5. Click **"Create project"**

---

## Step 2: Register Your Web App

1. In your Firebase project, click the **gear icon** → **Project settings**
2. Scroll down to **"Your apps"** section
3. Click the **web icon** (`</>`)
4. Enter app nickname: **"VisitSriLanka Web"**
5. **Don't** check "Firebase Hosting"
6. Click **"Register app"**

---

## Step 3: Copy Your Config Keys

You'll see a config like this:

```javascript
const firebaseConfig = {
    apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXX",
    authDomain: "visitsrilanka-xxxxx.firebaseapp.com",
    projectId: "visitsrilanka-xxxxx",
    storageBucket: "visitsrilanka-xxxxx.appspot.com",
    messagingSenderId: "123456789012",
    appId: "1:123456789012:web:abcdef123456"
};
```

---

## Step 4: Paste Keys into partner-portal.html

1. Open `partner-portal.html` in a text editor
2. Find the **Firebase Configuration** section (around line 30)
3. Replace the placeholder values:

```javascript
const firebaseConfig = {
    apiKey: "PASTE_YOUR_API_KEY_HERE",           // ← Replace this
    authDomain: "PASTE_YOUR_AUTH_DOMAIN_HERE",   // ← Replace this
    projectId: "PASTE_YOUR_PROJECT_ID_HERE",      // ← Replace this
    storageBucket: "PASTE_YOUR_STORAGE_BUCKET_HERE", // ← Replace this
    messagingSenderId: "PASTE_YOUR_MESSAGING_SENDER_ID_HERE", // ← Replace this
    appId: "PASTE_YOUR_APP_ID_HERE"              // ← Replace this
};
```

---

## Step 5: Enable Email Authentication

1. In Firebase Console, go to **"Build"** → **"Authentication"**
2. Click **"Get started"**
3. Click **"Email/Password"** in the "Native providers" section
4. **Enable** "Email/Password"
5. Click **"Save"**

---

## Step 6: Test Your Setup

1. Open `partner-portal.html` in your browser
2. Try to **Register** a new account
3. Check Firebase Console → Authentication → Users to see the new user
4. Try to **Login** with the registered account

---

## Firebase Spark Plan Limits (FREE)

✅ **10,000 active users per month**
✅ **Unlimited sign-ups**
✅ **Email/password authentication**
✅ **125 MB Cloud Storage**

**Note:** Spark plan is 100% free! No credit card needed.

---

## Troubleshooting

### "Firebase not configured" error
- Make sure you pasted all 6 keys correctly
- Check for missing quotes or commas

### "Auth/network-request-failed" error
- Check your internet connection
- Firebase might be temporarily unavailable

### Users not appearing in Firebase Console
- Make sure you enabled Email/Password in Authentication settings

---

## Support

- Firebase Documentation: https://firebase.google.com/docs/auth
- Firebase Console: https://console.firebase.google.com/
