const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// SQLite (lightweight local DB, no separate server required)
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

const app = express();

// =====================
// Config
// =====================

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_change_in_production';

const DB_DIR = path.join(__dirname, 'db');
const DB_FILE = path.join(DB_DIR, 'fitness.sqlite');

let db; // sqlite connection (initialized on startup)

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// =====================
// Helpers
// =====================

function generateId() {
  return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

function safeParseJson(maybeJson, fallback) {
  try {
    if (maybeJson === null || maybeJson === undefined) return fallback;
    if (typeof maybeJson !== 'string') return maybeJson;
    return JSON.parse(maybeJson);
  } catch {
    return fallback;
  }
}

async function initDb() {
  // Ensure folders exist
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });

  db = await open({
    filename: DB_FILE,
    driver: sqlite3.Database,
  });

  // Improve concurrency + durability for mobile/dev usage
  await db.exec('PRAGMA journal_mode = WAL;');
  await db.exec('PRAGMA foreign_keys = ON;');

  // Users
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      age INTEGER,
      weight REAL,
      height REAL,
      fitnessGoal TEXT,
      experienceLevel TEXT,
      createdAt TEXT
    );
  `);

  // Exercises (normalized so we can "populate" exercises in workouts)
  await db.exec(`
    CREATE TABLE IF NOT EXISTS exercises (
      id TEXT PRIMARY KEY,
      name TEXT,
      description TEXT,
      muscleGroup TEXT,
      difficulty TEXT,
      equipment TEXT,
      instructions TEXT,          -- JSON string
      caloriesPerMinute REAL,
      createdAt TEXT
    );
  `);

  // The rest are stored as JSON blobs for maximum compatibility with your existing Flutter models.
  await db.exec(`
    CREATE TABLE IF NOT EXISTS workouts (
      id TEXT PRIMARY KEY,
      userId TEXT,
      data TEXT,                  -- JSON string
      createdAt TEXT,
      FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS progress (
      id TEXT PRIMARY KEY,
      userId TEXT,
      data TEXT,                  -- JSON string
      date TEXT,
      FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS stats (
      id TEXT PRIMARY KEY,
      userId TEXT,
      data TEXT,                  -- JSON string
      date TEXT,
      FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS workout_plans (
      id TEXT PRIMARY KEY,
      userId TEXT,
      data TEXT,                  -- JSON string
      createdAt TEXT,
      FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
}

// =====================
// Auth middleware
// =====================

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// =====================
// Auth routes
// =====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, age, weight, height, fitnessGoal, experienceLevel } = req.body;

    const existing = await db.get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const id = generateId();
    const createdAt = new Date().toISOString();

    await db.run(
      `INSERT INTO users (id, name, email, password, age, weight, height, fitnessGoal, experienceLevel, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      , [id, name, email, hashedPassword, age ?? null, weight ?? null, height ?? null, fitnessGoal ?? null, experienceLevel ?? null, createdAt]
    );

    const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      token,
      user: {
        id,
        name,
        email,
        age,
        weight,
        height,
        fitnessGoal,
        experienceLevel,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        age: user.age,
        weight: user.weight,
        height: user.height,
        fitnessGoal: user.fitnessGoal,
        experienceLevel: user.experienceLevel,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// User routes
// =====================

app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await db.get('SELECT * FROM users WHERE id = ?', [req.userId]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    delete user.password;
    // Keep the same shape as before (_id in JSON-file version)
    res.json({ _id: user.id, ...user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await db.get('SELECT * FROM users WHERE id = ?', [req.userId]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Only allow updating these fields (same rules as your JSON backend)
    const updates = { ...req.body };
    delete updates.password;
    delete updates.email;
    delete updates._id;
    delete updates.id;

    const allowed = ['name', 'age', 'weight', 'height', 'fitnessGoal', 'experienceLevel'];
    const toSet = {};
    for (const k of allowed) if (k in updates) toSet[k] = updates[k];

    const fields = Object.keys(toSet);
    if (fields.length > 0) {
      const sql = `UPDATE users SET ${fields.map(f => `${f} = ?`).join(', ')} WHERE id = ?`;
      await db.run(sql, [...fields.map(f => toSet[f]), req.userId]);
    }

    const updated = await db.get('SELECT * FROM users WHERE id = ?', [req.userId]);
    delete updated.password;
    res.json({ _id: updated.id, ...updated });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Exercise routes
// =====================

app.get('/api/exercises', async (req, res) => {
  try {
    const { muscleGroup, difficulty, equipment } = req.query;
    const where = [];
    const args = [];
    if (muscleGroup) { where.push('muscleGroup = ?'); args.push(muscleGroup); }
    if (difficulty) { where.push('difficulty = ?'); args.push(difficulty); }
    if (equipment) { where.push('equipment = ?'); args.push(equipment); }

    const sql = `SELECT * FROM exercises ${where.length ? 'WHERE ' + where.join(' AND ') : ''}`;
    const rows = await db.all(sql, args);
    const exercises = rows.map(r => ({
      _id: r.id,
      name: r.name,
      description: r.description,
      muscleGroup: r.muscleGroup,
      difficulty: r.difficulty,
      equipment: r.equipment,
      instructions: safeParseJson(r.instructions, []),
      caloriesPerMinute: r.caloriesPerMinute,
      createdAt: r.createdAt,
    }));

    res.json(exercises);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/exercises/:id', async (req, res) => {
  try {
    const r = await db.get('SELECT * FROM exercises WHERE id = ?', [req.params.id]);
    if (!r) return res.status(404).json({ error: 'Exercise not found' });
    res.json({
      _id: r.id,
      name: r.name,
      description: r.description,
      muscleGroup: r.muscleGroup,
      difficulty: r.difficulty,
      equipment: r.equipment,
      instructions: safeParseJson(r.instructions, []),
      caloriesPerMinute: r.caloriesPerMinute,
      createdAt: r.createdAt,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/exercises', authMiddleware, async (req, res) => {
  try {
    const id = generateId();
    const createdAt = new Date().toISOString();

    const body = req.body || {};
    await db.run(
      `INSERT INTO exercises (id, name, description, muscleGroup, difficulty, equipment, instructions, caloriesPerMinute, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      , [
        id,
        body.name ?? null,
        body.description ?? null,
        body.muscleGroup ?? null,
        body.difficulty ?? null,
        body.equipment ?? null,
        JSON.stringify(body.instructions ?? []),
        body.caloriesPerMinute ?? null,
        createdAt,
      ]
    );

    res.status(201).json({ _id: id, ...body, createdAt });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Workout routes
// =====================

async function getExercisesMap() {
  const rows = await db.all('SELECT * FROM exercises');
  const map = new Map();
  for (const r of rows) {
    map.set(r.id, {
      _id: r.id,
      name: r.name,
      description: r.description,
      muscleGroup: r.muscleGroup,
      difficulty: r.difficulty,
      equipment: r.equipment,
      instructions: safeParseJson(r.instructions, []),
      caloriesPerMinute: r.caloriesPerMinute,
      createdAt: r.createdAt,
    });
  }
  return map;
}

function populateWorkoutExercises(workout, exercisesMap) {
  const exercises = Array.isArray(workout.exercises) ? workout.exercises : [];
  const populated = exercises.map(ex => ({
    ...ex,
    exerciseId: exercisesMap.get(ex.exerciseId) || null,
  }));
  return { ...workout, exercises: populated };
}

app.get('/api/workouts', authMiddleware, async (req, res) => {
  try {
    const rows = await db.all('SELECT * FROM workouts WHERE userId = ?', [req.userId]);
    const exercisesMap = await getExercisesMap();

    const workouts = rows.map(r => {
      const data = safeParseJson(r.data, {});
      const workout = { _id: r.id, userId: r.userId, ...data, createdAt: r.createdAt };
      return populateWorkoutExercises(workout, exercisesMap);
    });

    res.json(workouts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/workouts/:id', authMiddleware, async (req, res) => {
  try {
    const r = await db.get('SELECT * FROM workouts WHERE id = ? AND userId = ?', [req.params.id, req.userId]);
    if (!r) return res.status(404).json({ error: 'Workout not found' });

    const exercisesMap = await getExercisesMap();
    const data = safeParseJson(r.data, {});
    const workout = { _id: r.id, userId: r.userId, ...data, createdAt: r.createdAt };
    res.json(populateWorkoutExercises(workout, exercisesMap));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/workouts', authMiddleware, async (req, res) => {
  try {
    const id = generateId();
    const createdAt = new Date().toISOString();
    const data = req.body || {};

    await db.run(
      'INSERT INTO workouts (id, userId, data, createdAt) VALUES (?, ?, ?, ?)'
      , [id, req.userId, JSON.stringify(data), createdAt]
    );

    const exercisesMap = await getExercisesMap();
    const workout = { _id: id, userId: req.userId, ...data, createdAt };
    res.status(201).json(populateWorkoutExercises(workout, exercisesMap));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/workouts/:id', authMiddleware, async (req, res) => {
  try {
    const existing = await db.get('SELECT * FROM workouts WHERE id = ? AND userId = ?', [req.params.id, req.userId]);
    if (!existing) return res.status(404).json({ error: 'Workout not found' });

    // Replace data blob with whatever Flutter sends (same behavior as JSON version)
    const data = req.body || {};
    await db.run('UPDATE workouts SET data = ? WHERE id = ? AND userId = ?', [JSON.stringify(data), req.params.id, req.userId]);

    const exercisesMap = await getExercisesMap();
    const workout = { _id: req.params.id, userId: req.userId, ...data, createdAt: existing.createdAt };
    res.json(populateWorkoutExercises(workout, exercisesMap));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/workouts/:id', authMiddleware, async (req, res) => {
  try {
    const existing = await db.get('SELECT id FROM workouts WHERE id = ? AND userId = ?', [req.params.id, req.userId]);
    if (!existing) return res.status(404).json({ error: 'Workout not found' });
    await db.run('DELETE FROM workouts WHERE id = ? AND userId = ?', [req.params.id, req.userId]);
    res.json({ message: 'Workout deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Progress routes
// =====================

app.get('/api/progress', authMiddleware, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const rows = await db.all('SELECT * FROM progress WHERE userId = ?', [req.userId]);
    const workoutsRows = await db.all('SELECT * FROM workouts WHERE userId = ?', [req.userId]);
    const workoutsMap = new Map(workoutsRows.map(r => [r.id, { _id: r.id, userId: r.userId, ...safeParseJson(r.data, {}), createdAt: r.createdAt }]));

    let progressList = rows.map(r => ({
      _id: r.id,
      userId: r.userId,
      ...safeParseJson(r.data, {}),
      date: r.date,
    }));

    if (startDate) progressList = progressList.filter(p => new Date(p.date) >= new Date(startDate));
    if (endDate) progressList = progressList.filter(p => new Date(p.date) <= new Date(endDate));

    const populated = progressList.map(p => ({
      ...p,
      workoutId: workoutsMap.get(p.workoutId) || null,
    }));

    populated.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(populated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/progress', authMiddleware, async (req, res) => {
  try {
    const id = generateId();
    const date = new Date().toISOString();
    const data = req.body || {};

    await db.run(
      'INSERT INTO progress (id, userId, data, date) VALUES (?, ?, ?, ?)'
      , [id, req.userId, JSON.stringify(data), date]
    );

    const workoutRow = data.workoutId
      ? await db.get('SELECT * FROM workouts WHERE id = ? AND userId = ?', [data.workoutId, req.userId])
      : null;
    const workoutObj = workoutRow ? ({ _id: workoutRow.id, userId: workoutRow.userId, ...safeParseJson(workoutRow.data, {}), createdAt: workoutRow.createdAt }) : null;

    res.status(201).json({
      _id: id,
      userId: req.userId,
      ...data,
      date,
      workoutId: workoutObj,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Stats routes
// =====================

app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const rows = await db.all('SELECT * FROM stats WHERE userId = ?', [req.userId]);
    const list = rows
      .map(r => ({ _id: r.id, userId: r.userId, ...safeParseJson(r.data, {}), date: r.date }))
      .sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(list);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/stats', authMiddleware, async (req, res) => {
  try {
    const id = generateId();
    const date = new Date().toISOString();
    const data = req.body || {};

    await db.run(
      'INSERT INTO stats (id, userId, data, date) VALUES (?, ?, ?, ?)'
      , [id, req.userId, JSON.stringify(data), date]
    );

    res.status(201).json({ _id: id, userId: req.userId, ...data, date });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Workout plan routes
// =====================

app.get('/api/workout-plans', authMiddleware, async (req, res) => {
  try {
    const rows = await db.all('SELECT * FROM workout_plans WHERE userId = ?', [req.userId]);
    const workoutsRows = await db.all('SELECT * FROM workouts WHERE userId = ?', [req.userId]);
    const workoutsMap = new Map(workoutsRows.map(r => [r.id, { _id: r.id, userId: r.userId, ...safeParseJson(r.data, {}), createdAt: r.createdAt }]));

    const plans = rows.map(r => {
      const data = safeParseJson(r.data, {});
      const plan = { _id: r.id, userId: r.userId, ...data, createdAt: r.createdAt };
      const schedule = Array.isArray(plan.schedule) ? plan.schedule : [];
      return {
        ...plan,
        schedule: schedule.map(s => ({
          ...s,
          workoutId: workoutsMap.get(s.workoutId) || null,
        })),
      };
    });

    res.json(plans);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/workout-plans', authMiddleware, async (req, res) => {
  try {
    const id = generateId();
    const createdAt = new Date().toISOString();
    const data = req.body || {};

    await db.run(
      'INSERT INTO workout_plans (id, userId, data, createdAt) VALUES (?, ?, ?, ?)'
      , [id, req.userId, JSON.stringify(data), createdAt]
    );

    const workoutsRows = await db.all('SELECT * FROM workouts WHERE userId = ?', [req.userId]);
    const workoutsMap = new Map(workoutsRows.map(r => [r.id, { _id: r.id, userId: r.userId, ...safeParseJson(r.data, {}), createdAt: r.createdAt }]));
    const schedule = Array.isArray(data.schedule) ? data.schedule : [];

    res.status(201).json({
      _id: id,
      userId: req.userId,
      ...data,
      createdAt,
      schedule: schedule.map(s => ({
        ...s,
        workoutId: workoutsMap.get(s.workoutId) || null,
      })),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Dashboard/analytics
// =====================

app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const progressRows = await db.all('SELECT * FROM progress WHERE userId = ?', [req.userId]);
    const statsRows = await db.all('SELECT * FROM stats WHERE userId = ?', [req.userId]);
    const planRows = await db.all('SELECT * FROM workout_plans WHERE userId = ?', [req.userId]);
    const workoutsRows = await db.all('SELECT * FROM workouts WHERE userId = ?', [req.userId]);

    const workoutsMap = new Map(workoutsRows.map(r => [r.id, { _id: r.id, userId: r.userId, ...safeParseJson(r.data, {}), createdAt: r.createdAt }]));

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const userProgress = progressRows.map(r => ({
      _id: r.id,
      userId: r.userId,
      ...safeParseJson(r.data, {}),
      date: r.date,
    }));

    const totalWorkouts = userProgress.length;
    const recentProgress = userProgress.filter(p => new Date(p.date) >= thirtyDaysAgo);
    const totalCalories = recentProgress.reduce((sum, p) => sum + (p.caloriesBurned || 0), 0);
    const totalDuration = recentProgress.reduce((sum, p) => sum + (p.duration || 0), 0);

    const userStats = statsRows.map(r => ({ _id: r.id, userId: r.userId, ...safeParseJson(r.data, {}), date: r.date }));
    const latestStats = userStats.sort((a, b) => new Date(b.date) - new Date(a.date))[0] || null;

    const plans = planRows.map(r => ({ _id: r.id, userId: r.userId, ...safeParseJson(r.data, {}), createdAt: r.createdAt }));
    const activePlan = plans.find(p => p.isActive) || null;

    const recentProgressWithWorkouts = recentProgress
      .map(p => ({ ...p, workoutId: workoutsMap.get(p.workoutId) || null }))
      .sort((a, b) => new Date(b.date) - new Date(a.date))
      .slice(0, 10);

    res.json({
      totalWorkouts,
      workoutsThisMonth: recentProgress.length,
      totalCaloriesBurned: totalCalories,
      totalDuration,
      latestStats,
      activePlan,
      recentProgress: recentProgressWithWorkouts,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Seed data
// =====================

app.post('/api/seed', async (req, res) => {
  try {
    const existing = await db.get('SELECT id FROM exercises LIMIT 1');
    if (existing) {
      return res.json({ message: 'Exercises already exist (seed skipped)' });
    }

    const now = new Date().toISOString();
    const exercises = [
      {
        name: 'Push-ups',
        description: 'Classic bodyweight exercise for chest and triceps',
        muscleGroup: 'Chest',
        difficulty: 'Beginner',
        equipment: 'None',
        instructions: ['Start in plank position', 'Lower body until chest nearly touches floor', 'Push back up', 'Repeat'],
        caloriesPerMinute: 7,
      },
      {
        name: 'Squats',
        description: 'Lower body compound exercise',
        muscleGroup: 'Legs',
        difficulty: 'Beginner',
        equipment: 'None',
        instructions: ['Stand with feet shoulder-width apart', 'Lower hips back and down', 'Keep chest up', 'Return to standing'],
        caloriesPerMinute: 8,
      },
      {
        name: 'Bench Press',
        description: 'Upper body strength exercise',
        muscleGroup: 'Chest',
        difficulty: 'Intermediate',
        equipment: 'Barbell',
        instructions: ['Lie on bench', 'Grip bar slightly wider than shoulders', 'Lower bar to chest', 'Press up'],
        caloriesPerMinute: 6,
      },
      {
        name: 'Deadlift',
        description: 'Full body compound movement',
        muscleGroup: 'Back',
        difficulty: 'Advanced',
        equipment: 'Barbell',
        instructions: ['Stand with feet hip-width', 'Grip bar outside legs', 'Keep back straight', 'Lift by extending hips'],
        caloriesPerMinute: 9,
      },
      {
        name: 'Pull-ups',
        description: 'Upper body pulling exercise',
        muscleGroup: 'Back',
        difficulty: 'Intermediate',
        equipment: 'Pull-up Bar',
        instructions: ['Hang from bar with palms facing away', 'Pull body up until chin over bar', 'Lower with control'],
        caloriesPerMinute: 8,
      },
      {
        name: 'Plank',
        description: 'Core stability exercise',
        muscleGroup: 'Core',
        difficulty: 'Beginner',
        equipment: 'None',
        instructions: ['Forearms on ground', 'Body in straight line', 'Hold position', 'Engage core'],
        caloriesPerMinute: 5,
      },
      {
        name: 'Lunges',
        description: 'Single leg lower body exercise',
        muscleGroup: 'Legs',
        difficulty: 'Beginner',
        equipment: 'None',
        instructions: ['Step forward with one leg', 'Lower hips until both knees bent at 90°', 'Push back to start', 'Alternate legs'],
        caloriesPerMinute: 7,
      },
      {
        name: 'Shoulder Press',
        description: 'Overhead pressing movement',
        muscleGroup: 'Shoulders',
        difficulty: 'Intermediate',
        equipment: 'Dumbbells',
        instructions: ['Hold dumbbells at shoulder height', 'Press overhead', 'Lower with control', 'Repeat'],
        caloriesPerMinute: 6,
      },
    ];

    for (const ex of exercises) {
      const id = generateId();
      await db.run(
        `INSERT INTO exercises (id, name, description, muscleGroup, difficulty, equipment, instructions, caloriesPerMinute, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        , [id, ex.name, ex.description, ex.muscleGroup, ex.difficulty, ex.equipment, JSON.stringify(ex.instructions), ex.caloriesPerMinute, now]
      );
    }

    res.json({ message: 'Database seeded successfully', count: exercises.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// Startup
// =====================

initDb().then(() => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Using SQLite database at: ${DB_FILE}`);
  });
}).catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
