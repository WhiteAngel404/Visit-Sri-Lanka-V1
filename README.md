# Visit Sri Lanka - Tourist Website

A comprehensive tourist website for Sri Lanka with user authentication, partner portal, and trip planning features.

## 🚀 Free Deployment Guide

This guide will help you deploy the website for free using Supabase (database) and Vercel (hosting).

### 1. Set up Supabase (Free Database)

1. Go to [supabase.com](https://supabase.com) and create a free account
2. Create a new project
3. Go to Settings → API to get your project URL and anon key
4. Go to the SQL Editor and run the contents of `database-setup.sql`

### 2. Deploy Backend to Vercel (Free)

1. Go to [vercel.com](https://vercel.com) and create a free account
2. Install Vercel CLI: `npm install -g vercel`
3. In your project folder, run: `vercel`
4. Add environment variables in Vercel dashboard:
   - `SUPABASE_URL`: Your Supabase project URL
   - `SUPABASE_ANON_KEY`: Your Supabase anon key
   - `JWT_SECRET`: A random secret string (generate one)
   - `NODE_ENV`: `production`
   - `FRONTEND_URL`: Your Vercel domain (e.g., `https://your-app.vercel.app`)

### 3. Deploy Frontend

The frontend is already included in the backend deployment. Your website will be live at the Vercel URL.

### 4. Update DNS (Optional)

If you have a custom domain, you can connect it to Vercel for free.

## 🛠 Local Development

```bash
# Install dependencies
npm install

# Set up environment variables (.env file)
SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_key
JWT_SECRET=your_jwt_secret
NODE_ENV=development

# Run locally
npm run dev
```

## 📁 Project Structure

- `server.js` - Express backend with Supabase integration
- `js/auth.js` - Frontend authentication logic
- `js/partner-auth.js` - Partner authentication (uses Supabase)
- `*.html` - Static HTML pages
- `css/` - Stylesheets
- `assets/` - Images and media

## 🔐 Authentication Features

- User registration and login
- Partner registration and login
- JWT-based session management
- Protected routes
- Password hashing with bcrypt

## 🎯 Key Features

- Trip planner
- Destination guides
- Partner business listings
- User reviews
- Gallery
- Contact forms

## 📧 Support

For issues or questions, check the code comments or create an issue in the repository.