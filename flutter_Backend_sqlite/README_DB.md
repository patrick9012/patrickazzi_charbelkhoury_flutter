# Backend switched to SQLite (no JSON files)

Your Flutter app can keep calling the **same API endpoints**.

## What changed
- The backend now uses a local **SQLite** database file instead of `./data/*.json`.
- The database file is created automatically at: `flutter_Backend/db/fitness.sqlite`

## Run
```bash
cd flutter_Backend

# install dependencies (creates node_modules)
npm install

# start
npm start

# or dev mode
npm run dev
```

## Environment (optional)
You can set a stronger JWT secret:

**Windows PowerShell**
```powershell
$env:JWT_SECRET="a-very-long-random-secret"
npm start
```

**macOS / Linux**
```bash
export JWT_SECRET="a-very-long-random-secret"
npm start
```

## Seeding sample exercises
POST `http://localhost:3000/api/seed`

This will insert a small starter list of exercises.
