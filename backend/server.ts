import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv';
import * as path from 'path';
import * as fs from 'fs';
import { Pool } from 'pg';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';

// Import Zod schemas
import { 
  userEntitySchema, 
  createUserInputSchema, 
  updateUserInputSchema,
  postEntitySchema,
  createPostInputSchema,
  updatePostInputSchema,
  commentEntitySchema,
  createCommentInputSchema,
  updateCommentInputSchema
} from './schema.ts';

dotenv.config();

// ESM workaround for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Error response utility
interface ErrorResponse {
  success: false;
  message: string;
  error_code?: string;
  details?: any;
  timestamp: string;
}

function createErrorResponse(
  message: string,
  error?: any,
  errorCode?: string
): ErrorResponse {
  const response: ErrorResponse = {
    success: false,
    message,
    timestamp: new Date().toISOString()
  };

  if (errorCode) {
    response.error_code = errorCode;
  }

  if (error) {
    response.details = {
      name: error.name,
      message: error.message,
      stack: error.stack
    };
  }

  return response;
}

// Database configuration
const { DATABASE_URL, PGHOST, PGDATABASE, PGUSER, PGPASSWORD, PGPORT = 5432, JWT_SECRET = 'eco4-secret-key' } = process.env;

const pool = new Pool(
  DATABASE_URL
    ? { 
        connectionString: DATABASE_URL, 
        ssl: { require: true } 
      }
    : {
        host: PGHOST,
        database: PGDATABASE,
        user: PGUSER,
        password: PGPASSWORD,
        port: Number(PGPORT),
        ssl: { require: true },
      }
);

const app = express();
const port = process.env.PORT || 3000;

// Middleware setup
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));

app.use(morgan('combined'));
app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(__dirname, 'public')));

// Create storage directory if it doesn't exist
const storageDir = path.join(__dirname, 'storage');
if (!fs.existsSync(storageDir)) {
  fs.mkdirSync(storageDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, storageDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|mp4|webm/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Auth middleware for protected routes
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json(createErrorResponse('Access token required', null, 'AUTH_TOKEN_REQUIRED'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [decoded.user_id]);
    
    if (result.rows.length === 0) {
      return res.status(401).json(createErrorResponse('Invalid token', null, 'AUTH_TOKEN_INVALID'));
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(403).json(createErrorResponse('Invalid or expired token', error, 'AUTH_TOKEN_INVALID'));
  }
};

// Helper function to generate mock carbon footprint calculation
/*
  Mock function for carbon footprint calculation
  In production, this would integrate with environmental APIs or databases
  containing emission factors for different activities
*/
function calculateCarbonFootprint(activityDetails) {
  // Mock calculation based on activity type
  const mockEmissionFactors = {
    transportation: {
      car: 0.21, // kg CO2 per km
      bike: 0.0, // kg CO2 per km
      walking: 0.0,
      bus: 0.08,
      train: 0.04
    },
    energy: {
      electricity: 0.5, // kg CO2 per kWh
      gas: 2.0 // kg CO2 per cubic meter
    },
    diet: {
      meat: 5.0, // kg CO2 per meal
      vegetarian: 1.5,
      vegan: 0.8
    },
    waste: {
      recycling: -0.5, // negative = CO2 saved
      composting: -0.3,
      landfill: 1.0
    }
  };

  let co2Saved = 0;
  const { category, activity_type, quantity = 1, unit = 'unit' } = activityDetails;

  if (mockEmissionFactors[category] && mockEmissionFactors[category][activity_type]) {
    const factor = mockEmissionFactors[category][activity_type];
    co2Saved = Math.abs(factor * quantity);
  } else {
    // Default calculation for unknown activities
    co2Saved = Math.random() * 2 + 0.5; // Random between 0.5-2.5 kg
  }

  return Math.round(co2Saved * 100) / 100; // Round to 2 decimal places
}

// Helper function to generate eco-impact score
/*
  Mock function for eco-impact score calculation
  This would analyze user's complete activity history and calculate
  a comprehensive sustainability score
*/
function calculateEcoImpactScore(userId, totalCo2Saved, activitiesCount) {
  // Mock calculation: base score + bonus for consistency + CO2 impact
  const baseScore = Math.min(20, activitiesCount * 2); // Up to 20 points for activity count
  const co2Score = Math.min(50, totalCo2Saved * 2); // Up to 50 points for CO2 saved
  const consistencyBonus = activitiesCount > 10 ? 30 : activitiesCount > 5 ? 15 : 0; // Consistency bonus
  
  return Math.min(100, Math.round(baseScore + co2Score + consistencyBonus));
}

// AUTH ENDPOINTS

/*
  User registration endpoint
  Creates new user account and returns JWT token for immediate login
  Stores password in plain text for development purposes
*/
app.post('/api/auth/register', async (req, res) => {
  try {
    const validatedData = createUserInputSchema.parse({
      username: req.body.username,
      email: req.body.email,
      password_hash: req.body.password
    });

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1 OR username = $2', 
      [validatedData.email.toLowerCase(), validatedData.username]);
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json(createErrorResponse('User with this email or username already exists', null, 'USER_ALREADY_EXISTS'));
    }

    // Create user (no password hashing for development)
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [validatedData.username.trim(), validatedData.email.toLowerCase().trim(), validatedData.password_hash]
    );

    const user = result.rows[0];

    // Generate JWT
    const token = jwt.sign(
      { user_id: user.id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      },
      token
    });
  } catch (error) {
    if (error.name === 'ZodError') {
      return res.status(400).json(createErrorResponse('Validation failed', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Registration error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  User login endpoint
  Authenticates user credentials and returns JWT token
  Uses plain text password comparison for development
*/
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json(createErrorResponse('Email and password are required', null, 'MISSING_REQUIRED_FIELDS'));
    }

    // Find user (no password hashing for development)
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (result.rows.length === 0) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    const user = result.rows[0];

    // Check password (direct comparison for development)
    if (password !== user.password_hash) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    // Generate JWT
    const token = jwt.sign(
      { user_id: user.id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Token verification endpoint
  Validates JWT token and returns user information
*/
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    message: 'Token is valid',
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      created_at: req.user.created_at
    }
  });
});

// USER PROFILE ENDPOINTS

/*
  Get current user profile
  Returns detailed user information including eco-badges and statistics
*/
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get user basic info
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];

    // Get user's posts count (representing various eco-activities)
    const postsResult = await pool.query('SELECT COUNT(*) as activities_count FROM posts WHERE user_id = $1', [userId]);
    const activitiesCount = parseInt(postsResult.rows[0].activities_count);

    // Mock eco-badges and stats
    const mockEcoBadges = [
      { id: 'green_commuter', name: 'Green Commuter', icon_url: 'https://picsum.photos/seed/badge1/64/64' },
      { id: 'recycling_hero', name: 'Recycling Hero', icon_url: 'https://picsum.photos/seed/badge2/64/64' }
    ];

    const totalCo2Saved = activitiesCount * 2.5; // Mock calculation
    const ecoImpactScore = calculateEcoImpactScore(userId, totalCo2Saved, activitiesCount);

    res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        bio: `Eco-warrior since ${user.created_at.getFullYear()}`,
        profile_picture_url: `https://picsum.photos/seed/user${user.id}/200/200`,
        created_at: user.created_at,
        eco_badges_earned: mockEcoBadges,
        stats: {
          total_co2_saved: totalCo2Saved,
          activities_count: activitiesCount,
          eco_impact_score: ecoImpactScore,
          challenges_completed: Math.floor(activitiesCount / 3)
        }
      }
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Update user profile
  Allows users to update their bio, goals, and profile picture
*/
app.put('/api/user/profile', authenticateToken, upload.single('profile_picture'), async (req, res) => {
  try {
    const userId = req.user.id;
    const { username, bio, goals } = req.body;
    
    let profilePictureUrl = null;
    if (req.file) {
      profilePictureUrl = `/api/files/${req.file.filename}`;
    }

    // Update user info
    const updateFields = [];
    const updateValues = [];
    let paramCounter = 1;

    if (username) {
      updateFields.push(`username = $${paramCounter++}`);
      updateValues.push(username.trim());
    }

    updateValues.push(userId);
    
    if (updateFields.length > 0) {
      const updateQuery = `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${paramCounter} RETURNING *`;
      await pool.query(updateQuery, updateValues);
    }

    // Get updated user
    const result = await pool.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        bio: bio || `Eco-warrior since ${user.created_at.getFullYear()}`,
        goals: goals || 'Making the world more sustainable, one step at a time',
        profile_picture_url: profilePictureUrl || `https://picsum.photos/seed/user${user.id}/200/200`,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// CARBON FOOTPRINT ENDPOINTS

/*
  Log carbon footprint activity
  Records user's eco-friendly activities and calculates CO2 impact
  Uses posts table to store activity data with JSON content
*/
app.post('/api/carbon-footprint', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { category, activity_details } = req.body;

    if (!category || !activity_details) {
      return res.status(400).json(createErrorResponse('Category and activity details are required', null, 'MISSING_REQUIRED_FIELDS'));
    }

    // Calculate CO2 impact
    const co2Saved = calculateCarbonFootprint(activity_details);
    
    // Store activity as a post
    const entryId = uuidv4();
    const title = `${category.charAt(0).toUpperCase() + category.slice(1)} Activity`;
    const content = JSON.stringify({
      type: 'carbon_footprint_entry',
      entry_id: entryId,
      category,
      activity_details,
      co2_saved,
      logged_at: new Date().toISOString()
    });

    const result = await pool.query(
      'INSERT INTO posts (user_id, title, content) VALUES ($1, $2, $3) RETURNING id, created_at',
      [userId, title, content]
    );

    res.status(201).json({
      entry_id: entryId,
      co2_saved,
      category,
      activity_details,
      logged_at: result.rows[0].created_at,
      message: `Great job! You saved ${co2Saved}kg of CO2 with this activity.`
    });
  } catch (error) {
    console.error('Carbon footprint logging error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get carbon footprint dashboard data
  Returns user's CO2 savings over different time periods with visualizations
*/
app.get('/api/carbon-footprint/dashboard', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { timeframe = 'month' } = req.query;

    // Get carbon footprint entries from posts
    const result = await pool.query(
      `SELECT content, created_at FROM posts 
       WHERE user_id = $1 AND title LIKE '%Activity' 
       ORDER BY created_at DESC`,
      [userId]
    );

    const activities = result.rows
      .map(row => {
        try {
          const content = JSON.parse(row.content);
          if (content.type === 'carbon_footprint_entry') {
            return {
              ...content,
              logged_at: row.created_at
            };
          }
        } catch (e) {
          return null;
        }
      })
      .filter(Boolean);

    // Calculate statistics
    const totalCo2Saved = activities.reduce((sum, activity) => sum + (activity.co2_saved || 0), 0);
    const activitiesCount = activities.length;
    const ecoImpactScore = calculateEcoImpactScore(userId, totalCo2Saved, activitiesCount);

    // Generate trend data for visualization
    const trendData = [];
    const now = new Date();
    const daysBack = timeframe === 'week' ? 7 : timeframe === 'month' ? 30 : 365;
    
    for (let i = daysBack - 1; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dayActivities = activities.filter(a => {
        const activityDate = new Date(a.logged_at);
        return activityDate.toDateString() === date.toDateString();
      });
      
      trendData.push({
        date: date.toISOString().split('T')[0],
        co2_saved: dayActivities.reduce((sum, a) => sum + (a.co2_saved || 0), 0),
        activities_count: dayActivities.length
      });
    }

    res.json({
      summary: {
        total_co2_saved: Math.round(totalCo2Saved * 100) / 100,
        activities_count: activitiesCount,
        eco_impact_score: ecoImpactScore,
        avg_daily_savings: Math.round((totalCo2Saved / daysBack) * 100) / 100
      },
      trend_data: trendData,
      recent_activities: activities.slice(0, 10),
      category_breakdown: {
        transportation: activities.filter(a => a.category === 'transportation').length,
        energy: activities.filter(a => a.category === 'energy').length,
        diet: activities.filter(a => a.category === 'diet').length,
        waste: activities.filter(a => a.category === 'waste').length
      }
    });
  } catch (error) {
    console.error('Dashboard fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// CHALLENGES ENDPOINTS

/*
  Get available challenges
  Returns list of sustainability challenges users can join
*/
app.get('/api/challenges', authenticateToken, async (req, res) => {
  try {
    const { status = 'active', limit = 10, offset = 0 } = req.query;

    // Mock challenges data (in production this would come from a dedicated challenges table)
    const mockChallenges = [
      {
        challenge_id: 'plastic-free-july',
        title: 'Plastic-Free July',
        description: 'Eliminate single-use plastics for the entire month',
        category: 'waste',
        duration_days: 31,
        difficulty: 'intermediate',
        status: 'active',
        participants_count: 1247,
        start_date: '2024-07-01',
        end_date: '2024-07-31',
        badge_reward: 'Plastic-Free Warrior',
        banner_url: 'https://picsum.photos/seed/challenge1/400/200'
      },
      {
        challenge_id: 'bike-to-work-week',
        title: 'Bike to Work Week',
        description: 'Cycle to work for 5 consecutive days',
        category: 'transportation',
        duration_days: 7,
        difficulty: 'beginner',
        status: 'active',
        participants_count: 892,
        start_date: '2024-06-10',
        end_date: '2024-06-16',
        badge_reward: 'Green Commuter',
        banner_url: 'https://picsum.photos/seed/challenge2/400/200'
      },
      {
        challenge_id: 'meatless-mondays',
        title: 'Meatless Mondays',
        description: 'Go vegetarian every Monday for a month',
        category: 'diet',
        duration_days: 28,
        difficulty: 'beginner',
        status: 'active',
        participants_count: 2103,
        start_date: '2024-06-01',
        end_date: '2024-06-28',
        badge_reward: 'Plant-Based Pioneer',
        banner_url: 'https://picsum.photos/seed/challenge3/400/200'
      }
    ];

    const filteredChallenges = mockChallenges
      .filter(c => status === 'all' || c.status === status)
      .slice(offset, offset + limit);

    res.json({
      challenges: filteredChallenges,
      total_count: mockChallenges.length,
      has_more: offset + limit < mockChallenges.length
    });
  } catch (error) {
    console.error('Challenges fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Join a challenge
  Registers user participation in a sustainability challenge
*/
app.post('/api/challenges/:challengeId/join', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { challengeId } = req.params;

    // Check if user already joined this challenge
    const existingParticipation = await pool.query(
      `SELECT id FROM posts WHERE user_id = $1 AND content LIKE '%"challenge_id":"${challengeId}"%'`,
      [userId]
    );

    if (existingParticipation.rows.length > 0) {
      return res.status(400).json(createErrorResponse('You are already participating in this challenge', null, 'ALREADY_PARTICIPATING'));
    }

    // Create participation record
    const participationId = uuidv4();
    const title = `Challenge Participation: ${challengeId}`;
    const content = JSON.stringify({
      type: 'challenge_participation',
      participation_id: participationId,
      challenge_id: challengeId,
      user_id: userId,
      joined_at: new Date().toISOString(),
      progress: {},
      status: 'active'
    });

    await pool.query(
      'INSERT INTO posts (user_id, title, content) VALUES ($1, $2, $3)',
      [userId, title, content]
    );

    res.status(201).json({
      participation_id: participationId,
      challenge_id: challengeId,
      status: 'active',
      message: 'Successfully joined the challenge! Good luck!'
    });
  } catch (error) {
    console.error('Challenge join error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Update challenge progress
  Records user's progress in an ongoing challenge
*/
app.put('/api/challenges/:challengeId/progress', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { challengeId } = req.params;
    const { progress_data } = req.body;

    // Find user's participation
    const participationResult = await pool.query(
      `SELECT id, content FROM posts 
       WHERE user_id = $1 AND content LIKE '%"challenge_id":"${challengeId}"%'`,
      [userId]
    );

    if (participationResult.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Challenge participation not found', null, 'PARTICIPATION_NOT_FOUND'));
    }

    const participation = JSON.parse(participationResult.rows[0].content);
    participation.progress = { ...participation.progress, ...progress_data };
    participation.updated_at = new Date().toISOString();

    // Update progress
    await pool.query(
      'UPDATE posts SET content = $1 WHERE id = $2',
      [JSON.stringify(participation), participationResult.rows[0].id]
    );

    res.json({
      challenge_id: challengeId,
      progress: participation.progress,
      message: 'Progress updated successfully!'
    });
  } catch (error) {
    console.error('Challenge progress update error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// FORUM ENDPOINTS

/*
  Get forum topics
  Returns available discussion topics in the community forum
*/
app.get('/api/forum/topics', authenticateToken, async (req, res) => {
  try {
    // Mock forum topics (in production this would come from a dedicated topics table)
    const mockTopics = [
      {
        topic_id: 'renewable-energy',
        title: 'Renewable Energy',
        description: 'Discuss solar, wind, and other renewable energy solutions',
        posts_count: 234,
        latest_post_at: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
        icon_url: 'https://picsum.photos/seed/topic1/64/64'
      },
      {
        topic_id: 'sustainable-fashion',
        title: 'Sustainable Fashion',
        description: 'Share tips on eco-friendly clothing and sustainable brands',
        posts_count: 156,
        latest_post_at: new Date(Date.now() - 7200000).toISOString(), // 2 hours ago
        icon_url: 'https://picsum.photos/seed/topic2/64/64'
      },
      {
        topic_id: 'zero-waste-living',
        title: 'Zero Waste Living',
        description: 'Tips and tricks for reducing waste in daily life',
        posts_count: 189,
        latest_post_at: new Date(Date.now() - 1800000).toISOString(), // 30 minutes ago
        icon_url: 'https://picsum.photos/seed/topic3/64/64'
      }
    ];

    res.json({ topics: mockTopics });
  } catch (error) {
    console.error('Forum topics fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get posts in a forum topic
  Returns discussion posts for a specific topic with pagination
*/
app.get('/api/forum/topics/:topicId/posts', authenticateToken, async (req, res) => {
  try {
    const { topicId } = req.params;
    const { limit = 10, offset = 0 } = req.query;

    // Get forum posts (using posts table with specific content pattern)
    const result = await pool.query(
      `SELECT p.*, u.username, u.email 
       FROM posts p 
       JOIN users u ON p.user_id = u.id 
       WHERE p.content LIKE '%"topic_id":"${topicId}"%' 
       ORDER BY p.created_at DESC 
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    const posts = result.rows.map(row => {
      let postContent;
      try {
        postContent = JSON.parse(row.content);
      } catch (e) {
        postContent = { content: row.content };
      }

      return {
        post_id: row.id.toString(),
        title: row.title,
        content: postContent.content || postContent.text || 'No content',
        author: {
          user_id: row.user_id.toString(),
          username: row.username,
          avatar_url: `https://picsum.photos/seed/user${row.user_id}/40/40`
        },
        media_url: row.image_url,
        created_at: row.created_at,
        replies_count: Math.floor(Math.random() * 15) // Mock replies count
      };
    });

    res.json({
      posts,
      total_count: posts.length,
      has_more: result.rows.length === parseInt(limit)
    });
  } catch (error) {
    console.error('Forum posts fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Create forum post
  Allows users to create new discussion posts in forum topics
*/
app.post('/api/forum/topics/:topicId/posts', authenticateToken, upload.single('media'), async (req, res) => {
  try {
    const userId = req.user.id;
    const { topicId } = req.params;
    const { title, content } = req.body;

    if (!title || !content) {
      return res.status(400).json(createErrorResponse('Title and content are required', null, 'MISSING_REQUIRED_FIELDS'));
    }

    let mediaUrl = null;
    if (req.file) {
      mediaUrl = `/api/files/${req.file.filename}`;
    }

    const postContent = JSON.stringify({
      type: 'forum_post',
      topic_id: topicId,
      content: content,
      created_at: new Date().toISOString()
    });

    const result = await pool.query(
      'INSERT INTO posts (user_id, title, content, image_url) VALUES ($1, $2, $3, $4) RETURNING id, created_at',
      [userId, title, postContent, mediaUrl]
    );

    res.status(201).json({
      post_id: result.rows[0].id.toString(),
      topic_id: topicId,
      title,
      content,
      media_url: mediaUrl,
      created_at: result.rows[0].created_at,
      message: 'Post created successfully!'
    });
  } catch (error) {
    console.error('Forum post creation error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get comments for a forum post
  Returns replies/comments for a specific forum post
*/
app.get('/api/forum/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    const { limit = 20, offset = 0 } = req.query;

    const result = await pool.query(
      `SELECT c.*, u.username 
       FROM comments c 
       JOIN users u ON c.user_id = u.id 
       WHERE c.post_id = $1 
       ORDER BY c.created_at ASC 
       LIMIT $2 OFFSET $3`,
      [postId, limit, offset]
    );

    const comments = result.rows.map(row => ({
      comment_id: row.id.toString(),
      content: row.content,
      author: {
        user_id: row.user_id.toString(),
        username: row.username,
        avatar_url: `https://picsum.photos/seed/user${row.user_id}/32/32`
      },
      created_at: row.created_at
    }));

    res.json({
      comments,
      total_count: comments.length,
      has_more: result.rows.length === parseInt(limit)
    });
  } catch (error) {
    console.error('Forum comments fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Create comment on forum post
  Allows users to reply to forum posts
*/
app.post('/api/forum/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { postId } = req.params;
    const { content } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json(createErrorResponse('Comment content is required', null, 'MISSING_REQUIRED_FIELDS'));
    }

    const result = await pool.query(
      'INSERT INTO comments (user_id, post_id, content) VALUES ($1, $2, $3) RETURNING id, created_at',
      [userId, postId, content.trim()]
    );

    res.status(201).json({
      comment_id: result.rows[0].id.toString(),
      post_id: postId,
      content: content.trim(),
      created_at: result.rows[0].created_at,
      message: 'Comment posted successfully!'
    });
  } catch (error) {
    console.error('Comment creation error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// EDUCATIONAL CONTENT ENDPOINTS

/*
  Get educational courses
  Returns available sustainability courses and learning materials
*/
app.get('/api/educational/courses', authenticateToken, async (req, res) => {
  try {
    const { category = 'all', limit = 10, offset = 0 } = req.query;

    // Mock educational courses data
    const mockCourses = [
      {
        course_id: 'climate-101',
        title: 'Climate Change 101',
        description: 'Understanding the basics of climate science and environmental impact',
        category: 'science',
        duration_minutes: 45,
        difficulty: 'beginner',
        modules_count: 5,
        thumbnail_url: 'https://picsum.photos/seed/course1/300/200',
        instructor: 'Dr. Sarah Green',
        rating: 4.8,
        enrolled_count: 1523
      },
      {
        course_id: 'sustainable-living',
        title: 'Sustainable Living Guide',
        description: 'Practical tips for reducing your environmental footprint at home',
        category: 'lifestyle',
        duration_minutes: 60,
        difficulty: 'beginner',
        modules_count: 8,
        thumbnail_url: 'https://picsum.photos/seed/course2/300/200',
        instructor: 'Mike Earth',
        rating: 4.6,
        enrolled_count: 2341
      },
      {
        course_id: 'renewable-energy-tech',
        title: 'Renewable Energy Technologies',
        description: 'Deep dive into solar, wind, and other clean energy solutions',
        category: 'technology',
        duration_minutes: 90,
        difficulty: 'intermediate',
        modules_count: 12,
        thumbnail_url: 'https://picsum.photos/seed/course3/300/200',
        instructor: 'Prof. Alex Power',
        rating: 4.9,
        enrolled_count: 892
      }
    ];

    const filteredCourses = mockCourses
      .filter(c => category === 'all' || c.category === category)
      .slice(offset, offset + limit);

    res.json({
      courses: filteredCourses,
      total_count: mockCourses.length,
      has_more: offset + limit < mockCourses.length
    });
  } catch (error) {
    console.error('Educational courses fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get course modules
  Returns detailed modules/lessons for a specific educational course
*/
app.get('/api/educational/courses/:courseId/modules', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;

    // Mock course modules data
    const mockModules = {
      'climate-101': [
        {
          module_id: 'module-1',
          title: 'What is Climate Change?',
          content_type: 'video',
          duration_minutes: 8,
          media_url: 'https://picsum.photos/seed/video1/640/360',
          description: 'Introduction to climate change concepts',
          order: 1
        },
        {
          module_id: 'module-2',
          title: 'Greenhouse Effect Explained',
          content_type: 'interactive',
          duration_minutes: 12,
          media_url: 'https://picsum.photos/seed/interactive1/640/360',
          description: 'Understanding how greenhouse gases work',
          order: 2
        },
        {
          module_id: 'module-3',
          title: 'Human Impact on Climate',
          content_type: 'video',
          duration_minutes: 15,
          media_url: 'https://picsum.photos/seed/video2/640/360',
          description: 'How human activities affect global climate',
          order: 3
        }
      ],
      'sustainable-living': [
        {
          module_id: 'module-sl-1',
          title: 'Energy Efficiency at Home',
          content_type: 'video',
          duration_minutes: 10,
          media_url: 'https://picsum.photos/seed/sl-video1/640/360',
          description: 'Simple ways to reduce energy consumption',
          order: 1
        },
        {
          module_id: 'module-sl-2',
          title: 'Water Conservation Tips',
          content_type: 'article',
          duration_minutes: 7,
          media_url: 'https://picsum.photos/seed/article1/640/360',
          description: 'Practical water-saving techniques',
          order: 2
        }
      ]
    };

    const modules = mockModules[courseId] || [];

    res.json({
      course_id: courseId,
      modules,
      total_modules: modules.length
    });
  } catch (error) {
    console.error('Course modules fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get resource library
  Returns downloadable resources like guides, PDFs, and documents
*/
app.get('/api/educational/resources', authenticateToken, async (req, res) => {
  try {
    const { type = 'all', category = 'all', limit = 15, offset = 0 } = req.query;

    // Mock resource library data
    const mockResources = [
      {
        resource_id: 'guide-1',
        title: 'Complete Guide to Home Composting',
        description: 'Step-by-step guide to starting your own compost system',
        type: 'pdf',
        category: 'waste',
        file_size_mb: 2.3,
        download_url: '/api/files/composting-guide.pdf',
        thumbnail_url: 'https://picsum.photos/seed/resource1/200/250',
        downloads_count: 5420
      },
      {
        resource_id: 'video-1',
        title: 'Plastic Pollution Documentary',
        description: 'Award-winning documentary about ocean plastic pollution',
        type: 'video',
        category: 'environmental',
        file_size_mb: 850.5,
        download_url: '/api/files/plastic-pollution-doc.mp4',
        thumbnail_url: 'https://picsum.photos/seed/resource2/200/250',
        downloads_count: 8932
      },
      {
        resource_id: 'podcast-1',
        title: 'Sustainable Business Practices',
        description: 'Podcast series on green business strategies',
        type: 'audio',
        category: 'business',
        file_size_mb: 45.2,
        download_url: '/api/files/sustainable-business-podcast.mp3',
        thumbnail_url: 'https://picsum.photos/seed/resource3/200/250',
        downloads_count: 2156
      }
    ];

    const filteredResources = mockResources
      .filter(r => (type === 'all' || r.type === type) && (category === 'all' || r.category === category))
      .slice(offset, offset + limit);

    res.json({
      resources: filteredResources,
      total_count: mockResources.length,
      has_more: offset + limit < mockResources.length
    });
  } catch (error) {
    console.error('Resource library fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// NOTIFICATIONS ENDPOINTS

/*
  Get user notifications
  Returns user's notifications with read/unread status
*/
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 20, offset = 0, status = 'all' } = req.query;

    // Mock notifications data (in production this would come from a notifications table)
    const mockNotifications = [
      {
        notification_id: 'notif-1',
        message: 'Congratulations! You earned the "Green Commuter" badge!',
        type: 'achievement',
        read_at: null,
        created_at: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
        action_url: '/profile'
      },
      {
        notification_id: 'notif-2',
        message: 'New challenge available: "Zero Waste Weekend"',
        type: 'challenge',
        read_at: new Date(Date.now() - 1800000).toISOString(), // 30 minutes ago
        created_at: new Date(Date.now() - 7200000).toISOString(), // 2 hours ago
        action_url: '/challenges/zero-waste-weekend'
      },
      {
        notification_id: 'notif-3',
        message: 'Someone replied to your forum post about renewable energy',
        type: 'forum',
        read_at: null,
        created_at: new Date(Date.now() - 10800000).toISOString(), // 3 hours ago
        action_url: '/forum/posts/123'
      },
      {
        notification_id: 'notif-4',
        message: 'Daily eco-tip: Try using reusable water bottles today!',
        type: 'tip',
        read_at: new Date(Date.now() - 5400000).toISOString(), // 1.5 hours ago
        created_at: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
        action_url: '/tips'
      }
    ];

    const filteredNotifications = mockNotifications
      .filter(n => {
        if (status === 'unread') return !n.read_at;
        if (status === 'read') return n.read_at;
        return true;
      })
      .slice(offset, offset + limit);

    const unreadCount = mockNotifications.filter(n => !n.read_at).length;

    res.json({
      notifications: filteredNotifications,
      unread_count: unreadCount,
      total_count: mockNotifications.length,
      has_more: offset + limit < mockNotifications.length
    });
  } catch (error) {
    console.error('Notifications fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Mark notification as read
  Updates the read status of a specific notification
*/
app.put('/api/notifications/:notificationId/read', authenticateToken, async (req, res) => {
  try {
    const { notificationId } = req.params;
    
    // Mock marking as read (in production this would update notifications table)
    const readAt = new Date().toISOString();

    res.json({
      notification_id: notificationId,
      read_at: readAt,
      message: 'Notification marked as read'
    });
  } catch (error) {
    console.error('Notification read update error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// USER SETTINGS ENDPOINTS

/*
  Get user settings
  Returns user's privacy and notification preferences
*/
app.get('/api/user/settings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // Mock user settings (in production this would come from user_settings table)
    const mockSettings = {
      notification_preferences: {
        email_digest: true,
        push_notifications: true,
        challenge_reminders: true,
        forum_replies: true,
        achievement_alerts: true,
        daily_tips: false
      },
      privacy_settings: {
        profile_visibility: 'public',
        share_progress: true,
        show_in_leaderboards: true,
        allow_friend_requests: true,
        data_sharing_research: false
      },
      app_preferences: {
        theme: 'light',
        language: 'en',
        units: 'metric',
        dashboard_layout: 'cards'
      }
    };

    res.json({
      user_id: userId.toString(),
      settings: mockSettings,
      last_updated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Settings fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Update user settings
  Updates user's privacy and notification preferences
*/
app.put('/api/user/settings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { notification_preferences, privacy_settings, app_preferences } = req.body;

    // Mock settings update (in production this would update user_settings table)
    const updatedSettings = {
      notification_preferences: notification_preferences || {},
      privacy_settings: privacy_settings || {},
      app_preferences: app_preferences || {}
    };

    res.json({
      user_id: userId.toString(),
      settings: updatedSettings,
      last_updated: new Date().toISOString(),
      message: 'Settings updated successfully'
    });
  } catch (error) {
    console.error('Settings update error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// DAILY ECO-TIPS ENDPOINT

/*
  Get daily eco-tips
  Returns personalized sustainability tips based on user behavior and goals
*/
app.get('/api/eco-tips', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { category = 'all', limit = 5 } = req.query;

    // Mock personalized eco-tips
    const mockTips = [
      {
        tip_id: 'tip-1',
        title: 'Switch to LED Light Bulbs',
        content: 'LED bulbs use 75% less energy and last 25 times longer than incandescent bulbs.',
        category: 'energy',
        difficulty: 'easy',
        estimated_co2_savings: '1.2kg per month',
        implementation_time: '5 minutes',
        icon_url: 'https://picsum.photos/seed/tip1/64/64'
      },
      {
        tip_id: 'tip-2',
        title: 'Start a Carpool Group',
        content: 'Share rides with coworkers or neighbors to reduce transportation emissions.',
        category: 'transportation',
        difficulty: 'moderate',
        estimated_co2_savings: '15kg per month',
        implementation_time: '1 week to organize',
        icon_url: 'https://picsum.photos/seed/tip2/64/64'
      },
      {
        tip_id: 'tip-3',
        title: 'Reduce Meat Consumption',
        content: 'Try "Meatless Mondays" to reduce your dietary carbon footprint.',
        category: 'diet',
        difficulty: 'easy',
        estimated_co2_savings: '8kg per month',
        implementation_time: 'Immediate',
        icon_url: 'https://picsum.photos/seed/tip3/64/64'
      },
      {
        tip_id: 'tip-4',
        title: 'Use Reusable Shopping Bags',
        content: 'Keep reusable bags in your car or by your door to remember them every time.',
        category: 'waste',
        difficulty: 'easy',
        estimated_co2_savings: '0.3kg per month',
        implementation_time: 'Immediate',
        icon_url: 'https://picsum.photos/seed/tip4/64/64'
      },
      {
        tip_id: 'tip-5',
        title: 'Unplug Electronics When Not in Use',
        content: 'Phantom power usage accounts for 5-10% of residential electricity consumption.',
        category: 'energy',
        difficulty: 'easy',
        estimated_co2_savings: '2.1kg per month',
        implementation_time: 'Daily habit',
        icon_url: 'https://picsum.photos/seed/tip5/64/64'
      }
    ];

    const filteredTips = mockTips
      .filter(tip => category === 'all' || tip.category === category)
      .slice(0, limit);

    res.json({
      tips: filteredTips,
      personalized_for: userId.toString(),
      generated_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('Eco-tips fetch error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// FILE SERVING ENDPOINT

/*
  Serve uploaded files
  Returns files from the storage directory for profile pictures, media, etc.
*/
app.get('/api/files/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(storageDir, filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json(createErrorResponse('File not found', null, 'FILE_NOT_FOUND'));
    }

    res.sendFile(filePath);
  } catch (error) {
    console.error('File serving error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// HEALTH CHECK ENDPOINT
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'eco4-backend',
    version: '1.0.0'
  });
});

// Catch-all route for SPA routing (excluding API routes)
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

export { app, pool };

// Start the server
app.listen(port, '0.0.0.0', () => {
  console.log(`🌱 eco4 server running on port ${port} and listening on 0.0.0.0`);
  console.log(`📊 Health check available at http://localhost:${port}/api/health`);
});