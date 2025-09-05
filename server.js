// server.js - VoxSpei Family Tasks API (Simplified for Testing)
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

console.log('🚀 Starting VoxSpei Family Tasks API...');

// In-memory storage (we'll add Supabase later)
const db = {
  users: new Map(),
  children: new Map(),
  tasks: new Map(),
  taskOccurrences: new Map(),
  completions: new Map(),
  rewardsLedger: new Map(),
  settings: new Map()
};

// Helper functions
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

const hashPassword = async (password) => {
  return await bcrypt.hash(password, 12);
};

const validatePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Health check
app.get('/health', (req, res) => {
  console.log('✅ Health check requested');
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    service: 'VoxSpei Family Tasks API',
    message: 'Your app is working perfectly! 🎉'
  });
});

// Homepage
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to VoxSpei Family Tasks API! 🏠',
    status: 'running',
    endpoints: {
      health: '/health',
      signup: 'POST /auth/signup',
      login: 'POST /auth/login',
      tasks: 'GET /tasks',
      dashboard: 'GET /reports/parent-dashboard'
    }
  });
});

// Auth Routes
app.post('/auth/signup', async (req, res) => {
  try {
    console.log('📝 Signup request received');
    const { email, password, name, role = 'parent' } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    // Check if user already exists
    const existingUser = Array.from(db.users.values()).find(u => u.email === email);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hashedPassword = await hashPassword(password);
    const userId = uuidv4();
    
    const user = {
      id: userId,
      email,
      password: hashedPassword,
      name,
      role,
      parent_id: null,
      created_at: new Date().toISOString()
    };

    db.users.set(userId, user);

    const token = generateToken(user);
    const { password: _, ...userResponse } = user;

    console.log(`✅ User created: ${email}`);
    res.status(201).json({
      message: 'User created successfully',
      user: userResponse,
      token
    });
  } catch (error) {
    console.error('❌ Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    console.log('🔐 Login request received');
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = Array.from(db.users.values()).find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await validatePassword(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);
    const { password: _, ...userResponse } = user;

    console.log(`✅ User logged in: ${email}`);
    res.json({
      message: 'Login successful',
      user: userResponse,
      token
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Simple task route for testing
app.get('/tasks', authenticateToken, (req, res) => {
  console.log('📋 Tasks requested');
  res.json({
    message: 'Tasks endpoint working!',
    tasks: [],
    user: req.user
  });
});

// Simple dashboard for testing
app.get('/reports/parent-dashboard', authenticateToken, (req, res) => {
  console.log('📊 Dashboard requested');
  if (req.user.role !== 'parent') {
    return res.status(403).json({ error: 'Parent access required' });
  }

  res.json({
    message: 'Dashboard working!',
    dashboard: {
      summary: {
        total_children: 0,
        total_tasks: 0,
        total_rewards: 0
      }
    }
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  console.log(`❓ 404 - Route not found: ${req.originalUrl}`);
  res.status(404).json({ 
    error: 'Route not found',
    available_routes: ['/', '/health', '/auth/signup', '/auth/login']
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 VoxSpei Family Tasks API running on port ${PORT}`);
  console.log(`🌐 Visit: http://localhost:${PORT}/health`);
  console.log(`📱 API ready for families! 🏠`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 Shutting down gracefully');
});

process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

module.exports = app;
