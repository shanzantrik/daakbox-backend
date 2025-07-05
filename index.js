require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { Parser } = require('json2csv');

const app = express();
try {
  app.use(cors({
    origin: [
      'http://localhost:3000',
      'https://daakbox-frontend-production.up.railway.app'
    ],
    credentials: true,
    methods: 'GET,POST,PUT,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type,Authorization'
  }));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  const uploadsPath = path.join(__dirname, 'uploads');
  app.use('/uploads', (req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
  }, express.static(uploadsPath));
} catch (err) {
  console.error('Error during app setup:', err);
  process.exit(1);
}

// MySQL connection pool
let pool;
if (process.env.MYSQL_URL) {
  pool = mysql.createPool({
    uri: process.env.MYSQL_URL,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
} else {
  pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Madeuta1313#',
    database: 'daakbox_dbx',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
}

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const JWT_EXPIRES_IN = '1d';

// Set up uploads directory
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  }
});
const upload = multer({ storage });

// Helper: get user by username/email
async function getUserByUsernameOrEmail(identifier) {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1',
      [identifier, identifier]
    );
    return rows[0];
  } catch (err) {
    console.error('Error in getUserByUsernameOrEmail:', err);
    throw err;
  }
}

// Helper: get roles for user (new user_roles table)
async function getUserRoles(userId) {
  const [rows] = await pool.query(
    `SELECT r.name FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = ?`,
    [userId]
  );
  return rows.map(r => r.name);
}

// JWT Auth middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// RBAC middleware (case-insensitive, simple role names)
function authorizeRoles(...allowedRoles) {
  // Normalize allowed roles to lowercase
  const allowed = allowedRoles.map(r => r.toLowerCase());
  return async (req, res, next) => {
    const userId = req.user.id;
    const roles = (await getUserRoles(userId)).map(r => r.toLowerCase());
    if (roles.some(role => allowed.includes(role))) {
      next();
    } else {
      res.status(403).json({ message: 'Forbidden: insufficient role' });
    }
  };
}

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    const user = await getUserByUsernameOrEmail(username);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    // Passwords are hashed with bcrypt
    const bcrypt = require('bcryptjs');
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Invalid credentials' });
    const roles = await getUserRoles(user.id);
    const token = jwt.sign({ id: user.id, username: user.username, roles }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ token, user: { id: user.id, first_name: user.first_name, last_name: user.last_name, email: user.email, username: user.username, roles } });
  } catch (err) {
    console.error('Error in /login:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get current user info
app.get('/me', authenticateJWT, async (req, res) => {
  const user = await getUserByUsernameOrEmail(req.user.username);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const roles = await getUserRoles(user.id);
  res.json({ id: user.id, first_name: user.first_name, last_name: user.last_name, email: user.email, username: user.username, roles });
});

// Example protected route (admin only)
app.get('/admin', authenticateJWT, authorizeRoles('admin', 'superadmin'), (req, res) => {
  res.json({ message: 'Welcome, admin!' });
});

// Helper: get user by id
async function getUserById(userId) {
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
  return rows[0];
}

// Helper: set user roles
async function setUserRoles(userId, roles) {
  // Remove existing roles
  await pool.query('DELETE FROM user_roles WHERE user_id = ?', [userId]);
  if (!roles || !roles.length) return;
  // Accept both role names and IDs
  for (const role of roles) {
    let roleId = role;
    if (typeof role === 'string') {
      const [rows] = await pool.query('SELECT id FROM roles WHERE name = ?', [role]);
      if (rows.length) roleId = rows[0].id;
    }
    if (roleId) {
      await pool.query('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [userId, roleId]);
    }
  }
}

// Helper: get user safe fields (now includes roles)
async function userSafeFieldsWithRoles(user) {
  const roles = await getUserRoles(user.id);
  return {
    id: user.id,
    first_name: user.first_name,
    last_name: user.last_name,
    email: user.email,
    username: user.username,
    organization: user.organization,
    phone_number: user.phone_number,
    address: user.address,
    state: user.state,
    zip_code: user.zip_code,
    country: user.country,
    language: user.language,
    timezone: user.timezone,
    currency: user.currency,
    profile_image: user.profile_image,
    roles
  };
}

// --- USER CRUD ENDPOINTS ---

// Get all users (admin only)
app.get('/users', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM users');
    const users = await Promise.all(rows.map(userSafeFieldsWithRoles));
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching users', error: err.message });
  }
});

// Get user by id (admin only)
app.get('/users/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const user = await getUserById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(await userSafeFieldsWithRoles(user));
  } catch (err) {
    res.status(500).json({ message: 'Error fetching user', error: err.message });
  }
});

// Create user (admin only, with image upload)
app.post('/users', authenticateJWT, authorizeRoles('admin', 'superadmin'), upload.single('profile_image'), async (req, res) => {
  try {
    const { email, username, password, first_name, last_name, organization, phone_number, address, state, zip_code, country, language, timezone, currency } = req.body;
    let roles = req.body.roles;
    if (typeof roles === 'string') {
      try { roles = JSON.parse(roles); } catch { roles = [roles]; }
    }
    if (!first_name || !last_name || !email || !username || !password) return res.status(400).json({ message: 'Missing required fields' });
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(password, 10);
    const profile_image = req.file ? `/uploads/${req.file.filename}` : null;
    const [result] = await pool.query(
      `INSERT INTO users (email, username, password, first_name, last_name, organization, phone_number, address, state, zip_code, country, language, timezone, currency, profile_image)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)` ,
      [email, username, hashedPassword, first_name, last_name, organization, phone_number, address, state, zip_code, country, language, timezone, currency, profile_image]
    );
    await setUserRoles(result.insertId, roles);
    const user = await getUserById(result.insertId);
    res.status(201).json(await userSafeFieldsWithRoles(user));
  } catch (err) {
    res.status(500).json({ message: 'Error creating user', error: err.message });
  }
});

// Update user (admin only, with image upload)
app.put('/users/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), upload.single('profile_image'), async (req, res) => {
  try {
    const fields = [];
    const values = [];
    const allowed = ['email', 'username', 'password', 'first_name', 'last_name', 'organization', 'phone_number', 'address', 'state', 'zip_code', 'country', 'language', 'timezone', 'currency'];
    for (const key of allowed) {
      if (req.body[key]) {
        if (key === 'password') {
          const bcrypt = require('bcryptjs');
          const hashedPassword = await bcrypt.hash(req.body[key], 10);
          fields.push('password = ?');
          values.push(hashedPassword);
        } else {
          fields.push(`${key} = ?`);
          values.push(req.body[key]);
        }
      }
    }
    if (req.file) {
      fields.push('profile_image = ?');
      values.push(`/uploads/${req.file.filename}`);
    }
    let roles = req.body.roles;
    if (typeof roles === 'string') {
      try { roles = JSON.parse(roles); } catch { roles = [roles]; }
    }
    if (fields.length === 0 && !roles) return res.status(400).json({ message: 'No fields to update' });
    if (fields.length) {
      values.push(req.params.id);
      await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values);
    }
    if (roles) {
      await setUserRoles(req.params.id, roles);
    }
    const user = await getUserById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(await userSafeFieldsWithRoles(user));
  } catch (err) {
    res.status(500).json({ message: 'Error updating user', error: err.message });
  }
});

// Delete user (admin only)
app.delete('/users/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting user', error: err.message });
  }
});

// --- ROLE CRUD ENDPOINTS ---

// Get all roles (admin only)
app.get('/roles', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name FROM roles');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching roles', error: err.message });
  }
});

// Get role by id (admin only)
app.get('/roles/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name FROM roles WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ message: 'Role not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching role', error: err.message });
  }
});

// Create role (admin only)
app.post('/roles', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: 'Missing required field: name' });
    const [result] = await pool.query('INSERT INTO roles (name) VALUES (?)', [name]);
    res.status(201).json({ id: result.insertId, name });
  } catch (err) {
    res.status(500).json({ message: 'Error creating role', error: err.message });
  }
});

// Update role (admin only)
app.put('/roles/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: 'Missing required field: name' });
    await pool.query('UPDATE roles SET name = ? WHERE id = ?', [name, req.params.id]);
    const [rows] = await pool.query('SELECT id, name FROM roles WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ message: 'Role not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Error updating role', error: err.message });
  }
});

// Delete role (admin only)
app.delete('/roles/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM roles WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Role not found' });
    res.json({ message: 'Role deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting role', error: err.message });
  }
});

// --- PINCODE CRUD ENDPOINTS ---

const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;

// Helper: get areas for a pincode
async function getAreasForPincode(pincodeId) {
  const [areas] = await pool.query('SELECT * FROM pincode_areas WHERE pincode_id = ? AND (deleted_at IS NULL)', [pincodeId]);
  return areas;
}

// GET /pincodes (list all, with optional search/filter)
app.get('/pincodes', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { search } = req.query;
    let query = 'SELECT * FROM pincodes WHERE deleted_at IS NULL';
    let params = [];
    if (search) {
      query += ' AND (pincode LIKE ? OR city LIKE ? OR district LIKE ? OR state LIKE ?)';
      params = Array(4).fill(`%${search}%`);
    }
    const [rows] = await pool.query(query, params);
    for (const row of rows) {
      row.areas = await getAreasForPincode(row.id);
    }
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching pincodes', error: err.message });
  }
});

// GET /pincodes/:id (get single pincode with areas)
app.get('/pincodes/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM pincodes WHERE id = ? AND deleted_at IS NULL', [req.params.id]);
    if (!rows.length) return res.status(404).json({ message: 'Pincode not found' });
    const pincode = rows[0];
    pincode.areas = await getAreasForPincode(pincode.id);
    res.json(pincode);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching pincode', error: err.message });
  }
});

// POST /pincodes (create, with Google Maps API lookup for state/district/city or manual entry)
app.post('/pincodes', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { pincode, state, district, city, is_active = 1 } = req.body;
    if (!pincode) return res.status(400).json({ message: 'Pincode is required' });

    // If state, district, and city are provided, allow manual save (skip Google Maps)
    if (
      typeof state === 'string' && state.trim() &&
      typeof district === 'string' && district.trim() &&
      typeof city === 'string' && city.trim()
    ) {
      const [resultInsert] = await pool.query(
        'INSERT INTO pincodes (pincode, admin_area_level_1, admin_area_level_2, locality, is_active) VALUES (?, ?, ?, ?, ?)',
        [pincode, state.trim(), district.trim(), city.trim(), is_active]
      );
      const [rows] = await pool.query('SELECT * FROM pincodes WHERE id = ?', [resultInsert.insertId]);
      return res.status(201).json(rows[0]);
    }

    // Otherwise, try Google Maps lookup
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${pincode}&components=country:IN&key=${GOOGLE_MAPS_API_KEY}`;
    const response = await axios.get(url);
    const result = response.data.results[0];
    if (!result) return res.status(400).json({ message: 'Invalid pincode or not found in Google Maps' });
    let stateAuto = '', districtAuto = '', cityAuto = '';
    for (const comp of result.address_components) {
      if (comp.types.includes('administrative_area_level_1')) stateAuto = comp.long_name;
      if (comp.types.includes('administrative_area_level_2')) districtAuto = comp.long_name;
      if (comp.types.includes('locality')) cityAuto = comp.long_name;
      if (!cityAuto && comp.types.includes('sublocality_level_1')) cityAuto = comp.long_name;
    }
    const [resultInsert] = await pool.query(
      'INSERT INTO pincodes (pincode, admin_area_level_1, admin_area_level_2, locality, is_active, lat, lng, formatted_address, place_id, location_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        pincode,
        stateAuto,
        districtAuto,
        cityAuto,
        is_active,
        result.geometry.location.lat,
        result.geometry.location.lng,
        result.formatted_address,
        result.place_id,
        result.geometry.location_type || null
      ]
    );
    const [rows] = await pool.query('SELECT * FROM pincodes WHERE id = ?', [resultInsert.insertId]);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Error creating pincode', error: err.message });
  }
});

// PUT /pincodes/:id (update, including status)
app.put('/pincodes/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const allowed = ['pincode', 'state', 'district', 'city', 'is_active'];
    const fields = [];
    const values = [];
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        fields.push(`${key} = ?`);
        values.push(req.body[key]);
      }
    }
    if (!fields.length) return res.status(400).json({ message: 'No fields to update' });
    values.push(req.params.id);
    await pool.query(`UPDATE pincodes SET ${fields.join(', ')} WHERE id = ?`, values);
    const [rows] = await pool.query('SELECT * FROM pincodes WHERE id = ?', [req.params.id]);
    res.json(rows[0]);
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ message: 'Duplicate pincode', error: err.message });
    } else {
      res.status(500).json({ message: 'Error updating pincode', error: err.message });
    }
  }
});

// DELETE /pincodes/:id (soft delete)
app.delete('/pincodes/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    await pool.query('UPDATE pincodes SET deleted_at = NOW() WHERE id = ?', [req.params.id]);
    res.json({ message: 'Pincode deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting pincode', error: err.message });
  }
});

// GET /pincodes/by-code/:pincode (get single pincode by its value)
app.get('/pincodes/by-code/:pincode', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM pincodes WHERE pincode = ? AND deleted_at IS NULL AND is_active = 1',
      [req.params.pincode]
    );
    if (!rows.length) return res.status(404).json({ message: 'Pincode not found or inactive in database' });
    const pincode = rows[0];
    pincode.areas = await getAreasForPincode(pincode.id);
    res.json(pincode);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching pincode', error: err.message });
  }
});

// --- PINCODE AREAS CRUD ENDPOINTS ---

// POST /pincodes/:pincodeId/areas (add area to pincode)
app.post('/pincodes/:pincodeId/areas', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { area_name, latitude, longitude, is_active = 1 } = req.body;
    if (!area_name || latitude === undefined || longitude === undefined) return res.status(400).json({ message: 'Missing required fields' });
    const [resultInsert] = await pool.query(
      'INSERT INTO pincode_areas (pincode_id, area_name, latitude, longitude, is_active) VALUES (?, ?, ?, ?, ?)',
      [req.params.pincodeId, area_name, latitude, longitude, is_active]
    );
    const [rows] = await pool.query('SELECT * FROM pincode_areas WHERE id = ?', [resultInsert.insertId]);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Error creating area', error: err.message });
  }
});

// PUT /pincodes/:pincodeId/areas/:areaId (update area)
app.put('/pincodes/:pincodeId/areas/:areaId', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const allowed = ['area_name', 'latitude', 'longitude', 'is_active'];
    const fields = [];
    const values = [];
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        fields.push(`${key} = ?`);
        values.push(req.body[key]);
      }
    }
    if (!fields.length) return res.status(400).json({ message: 'No fields to update' });
    values.push(req.params.areaId, req.params.pincodeId);
    await pool.query(`UPDATE pincode_areas SET ${fields.join(', ')} WHERE id = ? AND pincode_id = ?`, values);
    const [rows] = await pool.query('SELECT * FROM pincode_areas WHERE id = ?', [req.params.areaId]);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Error updating area', error: err.message });
  }
});

// DELETE /pincodes/:pincodeId/areas/:areaId (soft delete)
app.delete('/pincodes/:pincodeId/areas/:areaId', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    await pool.query('UPDATE pincode_areas SET deleted_at = NOW() WHERE id = ? AND pincode_id = ?', [req.params.areaId, req.params.pincodeId]);
    res.json({ message: 'Area deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting area', error: err.message });
  }
});

// --- FRANCHISEE CRUD ENDPOINTS ---

// Helper: get franchisee by id (with service areas and pincodes)
async function getFranchiseeById(id) {
  const [rows] = await pool.query('SELECT * FROM franchisees WHERE id = ?', [id]);
  if (!rows.length) return null;
  const franchisee = rows[0];
  // Get service areas
  const [serviceAreas] = await pool.query(
    `SELECT fsa.id, fsa.pincode_area_id, pa.area_name, pa.pincode_id, pa.latitude, pa.longitude
     FROM franchisee_service_areas fsa
     JOIN pincode_areas pa ON pa.id = fsa.pincode_area_id
     WHERE fsa.franchisee_id = ?`,
    [id]
  );
  franchisee.service_areas = serviceAreas;
  // Get pincodes
  const [pincodes] = await pool.query(
    `SELECT fp.id, fp.pincode
     FROM franchisee_pincodes fp
     WHERE fp.franchisee_id = ?`,
    [id]
  );
  franchisee.pincodes = pincodes;
  return franchisee;
}

// List all franchisees
app.get('/franchisees', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { search } = req.query;
    let query = 'SELECT * FROM franchisees WHERE deleted_at IS NULL';
    let params = [];
    if (search) {
      query += ' AND (name LIKE ? OR email LIKE ? OR code LIKE ? OR franchise_id LIKE ?)';
      params = Array(4).fill(`%${search}%`);
    }
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching franchisees', error: err.message });
  }
});

// Get franchisee by id (with service areas and pincodes)
app.get('/franchisees/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const franchisee = await getFranchiseeById(req.params.id);
    if (!franchisee) return res.status(404).json({ message: 'Franchisee not found' });
    res.json(franchisee);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching franchisee', error: err.message });
  }
});

// Create franchisee (with file uploads)
app.post('/franchisees', authenticateJWT, authorizeRoles('admin', 'superadmin'), upload.fields([
  { name: 'pan_file', maxCount: 1 },
  { name: 'gst_file', maxCount: 1 },
  { name: 'photo', maxCount: 1 },
  { name: 'cheque_file', maxCount: 1 },
  { name: 'address_proof_file', maxCount: 1 }
]), async (req, res) => {
  try {
    const body = req.body;
    // Required fields
    const required = [
      'user_id', 'franchise_id', 'code', 'name', 'contact_person', 'email', 'aadhar_number',
      'pincode_area_id', 'building_name', 'locality', 'concern_name', 'firm_name',
      'pan_number', 'qualification', 'prime_mobile', 'bank_name', 'account_number',
      'ifsc_code', 'guardian_name', 'guardian_phone', 'birth_date', 'address_proof_type'
    ];
    for (const field of required) {
      if (!body[field]) return res.status(400).json({ message: `Missing required field: ${field}` });
    }
    // File fields
    const pan_file = req.files['pan_file'] ? `/uploads/${req.files['pan_file'][0].filename}` : null;
    const gst_file = req.files['gst_file'] ? `/uploads/${req.files['gst_file'][0].filename}` : null;
    const photo = req.files['photo'] ? `/uploads/${req.files['photo'][0].filename}` : null;
    const cheque_file = req.files['cheque_file'] ? `/uploads/${req.files['cheque_file'][0].filename}` : null;
    const address_proof_file = req.files['address_proof_file'] ? `/uploads/${req.files['address_proof_file'][0].filename}` : null;
    // Insert franchisee
    const [result] = await pool.query(
      `INSERT INTO franchisees (
        user_id, franchise_id, code, name, contact_person, email, is_active, aadhar_number, pincode_area_id, building_name, locality, landmark, state, district, city, concern_name, firm_name, company_logo, firm_address_same_as_office, firm_address, firm_state, firm_district, firm_city, firm_pincode, firm_building_name, firm_locality, firm_landmark, pan_number, pan_file, gst_number, gst_file, qualification, qualification_file, prime_mobile, alternate_mobile, photo, bank_name, account_number, ifsc_code, cheque_file, residence_address_same_as_office, residence_address, guardian_name, guardian_phone, spouse_name, spouse_phone, anniversary_date, birth_date, address_proof_type, address_proof_file, terms_accepted, created_by, updated_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)` ,
      [
        body.user_id, body.franchise_id, body.code, body.name, body.contact_person, body.email, body.is_active || 1, body.aadhar_number, body.pincode_area_id, body.building_name, body.locality, body.landmark, body.state, body.district, body.city, body.concern_name, body.firm_name, body.company_logo || null, body.firm_address_same_as_office || 0, body.firm_address || null, body.firm_state || null, body.firm_district || null, body.firm_city || null, body.firm_pincode || null, body.firm_building_name || null, body.firm_locality || null, body.firm_landmark || null, body.pan_number, pan_file, body.gst_number || null, gst_file, body.qualification, body.qualification_file || null, body.prime_mobile, body.alternate_mobile || null, photo, body.bank_name, body.account_number, body.ifsc_code, cheque_file, body.residence_address_same_as_office || 0, body.residence_address || null, body.guardian_name, body.guardian_phone, body.spouse_name || null, body.spouse_phone || null, body.anniversary_date || null, body.birth_date, body.address_proof_type, address_proof_file, body.terms_accepted || 0, req.user.id, req.user.id
      ]
    );
    const franchisee_id = result.insertId;
    // Service areas (array of pincode_area_id)
    let service_areas = body.service_areas;
    if (typeof service_areas === 'string') {
      try { service_areas = JSON.parse(service_areas); } catch { service_areas = [service_areas]; }
    }
    if (Array.isArray(service_areas)) {
      for (const areaId of service_areas) {
        await pool.query('INSERT INTO franchisee_service_areas (franchisee_id, pincode_area_id) VALUES (?, ?)', [franchisee_id, areaId]);
      }
    }
    // Pincodes (array of pincode)
    let pincodes = body.pincodes;
    if (typeof pincodes === 'string') {
      try { pincodes = JSON.parse(pincodes); } catch { pincodes = [pincodes]; }
    }
    if (Array.isArray(pincodes)) {
      for (const pincode of pincodes) {
        await pool.query('INSERT INTO franchisee_pincodes (franchisee_id, pincode) VALUES (?, ?)', [franchisee_id, pincode]);
      }
    }
    res.status(201).json(await getFranchiseeById(franchisee_id));
  } catch (err) {
    res.status(500).json({ message: 'Error creating franchisee', error: err.message });
  }
});

// Update franchisee (with file uploads)
app.put('/franchisees/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), upload.fields([
  { name: 'pan_file', maxCount: 1 },
  { name: 'gst_file', maxCount: 1 },
  { name: 'photo', maxCount: 1 },
  { name: 'cheque_file', maxCount: 1 },
  { name: 'address_proof_file', maxCount: 1 }
]), async (req, res) => {
  try {
    const body = req.body;
    const fields = [];
    const values = [];
    const allowed = [
      'user_id', 'franchise_id', 'code', 'name', 'contact_person', 'email', 'is_active', 'aadhar_number', 'pincode_area_id', 'building_name', 'locality', 'landmark', 'state', 'district', 'city', 'concern_name', 'firm_name', 'company_logo', 'firm_address_same_as_office', 'firm_address', 'firm_state', 'firm_district', 'firm_city', 'firm_pincode', 'firm_building_name', 'firm_locality', 'firm_landmark', 'pan_number', 'gst_number', 'qualification', 'qualification_file', 'prime_mobile', 'alternate_mobile', 'bank_name', 'account_number', 'ifsc_code', 'residence_address_same_as_office', 'residence_address', 'guardian_name', 'guardian_phone', 'spouse_name', 'spouse_phone', 'anniversary_date', 'birth_date', 'address_proof_type', 'terms_accepted', 'updated_by'
    ];
    for (const key of allowed) {
      if (body[key] !== undefined) {
        fields.push(`${key} = ?`);
        values.push(body[key]);
      }
    }
    // File fields
    if (req.files['pan_file']) {
      fields.push('pan_file = ?');
      values.push(`/uploads/${req.files['pan_file'][0].filename}`);
    }
    if (req.files['gst_file']) {
      fields.push('gst_file = ?');
      values.push(`/uploads/${req.files['gst_file'][0].filename}`);
    }
    if (req.files['photo']) {
      fields.push('photo = ?');
      values.push(`/uploads/${req.files['photo'][0].filename}`);
    }
    if (req.files['cheque_file']) {
      fields.push('cheque_file = ?');
      values.push(`/uploads/${req.files['cheque_file'][0].filename}`);
    }
    if (req.files['address_proof_file']) {
      fields.push('address_proof_file = ?');
      values.push(`/uploads/${req.files['address_proof_file'][0].filename}`);
    }
    if (!fields.length) return res.status(400).json({ message: 'No fields to update' });
    values.push(req.params.id);
    await pool.query(`UPDATE franchisees SET ${fields.join(', ')} WHERE id = ?`, values);
    // Update service areas
    let service_areas = body.service_areas;
    if (typeof service_areas === 'string') {
      try { service_areas = JSON.parse(service_areas); } catch { service_areas = [service_areas]; }
    }
    if (Array.isArray(service_areas)) {
      await pool.query('DELETE FROM franchisee_service_areas WHERE franchisee_id = ?', [req.params.id]);
      for (const areaId of service_areas) {
        await pool.query('INSERT INTO franchisee_service_areas (franchisee_id, pincode_area_id) VALUES (?, ?)', [req.params.id, areaId]);
      }
    }
    // Update pincodes
    let pincodes = body.pincodes;
    if (typeof pincodes === 'string') {
      try { pincodes = JSON.parse(pincodes); } catch { pincodes = [pincodes]; }
    }
    if (Array.isArray(pincodes)) {
      await pool.query('DELETE FROM franchisee_pincodes WHERE franchisee_id = ?', [req.params.id]);
      for (const pincode of pincodes) {
        await pool.query('INSERT INTO franchisee_pincodes (franchisee_id, pincode) VALUES (?, ?)', [req.params.id, pincode]);
      }
    }
    res.json(await getFranchiseeById(req.params.id));
  } catch (err) {
    res.status(500).json({ message: 'Error updating franchisee', error: err.message });
  }
});

// Delete franchisee (soft delete)
app.delete('/franchisees/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    await pool.query('UPDATE franchisees SET deleted_at = NOW() WHERE id = ?', [req.params.id]);
    res.json({ message: 'Franchisee deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting franchisee', error: err.message });
  }
});

// --- FRANCHISEE SERVICE AREAS ---
// Add service area
app.post('/franchisees/:id/service-areas', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { pincode_area_id } = req.body;
    if (!pincode_area_id) return res.status(400).json({ message: 'Missing pincode_area_id' });
    await pool.query('INSERT INTO franchisee_service_areas (franchisee_id, pincode_area_id) VALUES (?, ?)', [req.params.id, pincode_area_id]);
    res.json({ message: 'Service area added' });
  } catch (err) {
    res.status(500).json({ message: 'Error adding service area', error: err.message });
  }
});
// Remove service area
app.delete('/franchisees/:id/service-areas/:areaId', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM franchisee_service_areas WHERE franchisee_id = ? AND id = ?', [req.params.id, req.params.areaId]);
    res.json({ message: 'Service area removed' });
  } catch (err) {
    res.status(500).json({ message: 'Error removing service area', error: err.message });
  }
});

// --- FRANCHISEE PINCODES ---
// Add pincode
app.post('/franchisees/:id/pincodes', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { pincode } = req.body;
    if (!pincode) return res.status(400).json({ message: 'Missing pincode' });
    await pool.query('INSERT INTO franchisee_pincodes (franchisee_id, pincode) VALUES (?, ?)', [req.params.id, pincode]);
    res.json({ message: 'Pincode added' });
  } catch (err) {
    res.status(500).json({ message: 'Error adding pincode', error: err.message });
  }
});
// Remove pincode
app.delete('/franchisees/:id/pincodes/:pincodeId', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM franchisee_pincodes WHERE franchisee_id = ? AND id = ?', [req.params.id, req.params.pincodeId]);
    res.json({ message: 'Pincode removed' });
  } catch (err) {
    res.status(500).json({ message: 'Error removing pincode', error: err.message });
  }
});

// --- CORPORATE CRUD ENDPOINTS ---

// Helper: get corporate by id (with franchisee and user info)
async function getCorporateById(id) {
  const [rows] = await pool.query('SELECT * FROM corporates WHERE id = ?', [id]);
  if (!rows.length) return null;
  const corporate = rows[0];
  // Get franchisee info
  if (corporate.franchisee_id) {
    const [franchiseeRows] = await pool.query('SELECT id, name, code FROM franchisees WHERE id = ?', [corporate.franchisee_id]);
    corporate.franchisee = franchiseeRows[0] || null;
  }
  // Get user info
  if (corporate.user_id) {
    const [userRows] = await pool.query('SELECT id, first_name, last_name, email FROM users WHERE id = ?', [corporate.user_id]);
    corporate.user = userRows[0] || null;
  }
  return corporate;
}

// List all corporates
app.get('/corporates', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { search } = req.query;
    let query = 'SELECT * FROM corporates WHERE deleted_at IS NULL';
    let params = [];
    if (search) {
      query += ' AND (company_name LIKE ? OR email LIKE ? OR pan_number LIKE ? OR gst_number LIKE ? OR industry LIKE ?)';
      params = Array(5).fill(`%${search}%`);
    }
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching corporates', error: err.message });
  }
});

// Get corporate by id (with franchisee and user info)
app.get('/corporates/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const corporate = await getCorporateById(req.params.id);
    if (!corporate) return res.status(404).json({ message: 'Corporate not found' });
    res.json(corporate);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching corporate', error: err.message });
  }
});

// Create corporate (with file uploads)
app.post('/corporates', authenticateJWT, authorizeRoles('admin', 'superadmin'), upload.fields([
  { name: 'company_logo', maxCount: 1 },
  { name: 'memorandum_file', maxCount: 1 }
]), async (req, res) => {
  try {
    const body = req.body;
    // Required fields
    const required = [
      'user_id', 'franchisee_id', 'company_name', 'company_address', 'contact_name', 'phone', 'email', 'industry'
    ];
    for (const field of required) {
      if (!body[field]) return res.status(400).json({ message: `Missing required field: ${field}` });
    }
    // File fields
    const company_logo = req.files['company_logo'] ? `/uploads/${req.files['company_logo'][0].filename}` : null;
    const memorandum_file = req.files['memorandum_file'] ? `/uploads/${req.files['memorandum_file'][0].filename}` : null;
    // Insert corporate
    const [result] = await pool.query(
      `INSERT INTO corporates (
        user_id, franchisee_id, company_name, company_logo, gst_number, pan_number, registration_number, company_address, contact_name, phone, email, industry, bank_name, account_number, ifsc_code, memorandum_file, enrollment_date, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [
        body.user_id, body.franchisee_id, body.company_name, company_logo, body.gst_number || null, body.pan_number || null, body.registration_number || null, body.company_address, body.contact_name, body.phone, body.email, body.industry, body.bank_name || null, body.account_number || null, body.ifsc_code || null, memorandum_file, body.enrollment_date || null
      ]
    );
    res.status(201).json(await getCorporateById(result.insertId));
  } catch (err) {
    res.status(500).json({ message: 'Error creating corporate', error: err.message });
  }
});

// Update corporate (with file uploads)
app.put('/corporates/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), upload.fields([
  { name: 'company_logo', maxCount: 1 },
  { name: 'memorandum_file', maxCount: 1 }
]), async (req, res) => {
  try {
    const body = req.body;
    const fields = [];
    const values = [];
    const allowed = [
      'user_id', 'franchisee_id', 'company_name', 'gst_number', 'pan_number', 'registration_number', 'company_address', 'contact_name', 'phone', 'email', 'industry', 'bank_name', 'account_number', 'ifsc_code', 'enrollment_date'
    ];
    for (const key of allowed) {
      if (body[key] !== undefined) {
        fields.push(`${key} = ?`);
        values.push(body[key]);
      }
    }
    // File fields
    if (req.files['company_logo']) {
      fields.push('company_logo = ?');
      values.push(`/uploads/${req.files['company_logo'][0].filename}`);
    }
    if (req.files['memorandum_file']) {
      fields.push('memorandum_file = ?');
      values.push(`/uploads/${req.files['memorandum_file'][0].filename}`);
    }
    if (!fields.length) return res.status(400).json({ message: 'No fields to update' });
    values.push(req.params.id);
    await pool.query(`UPDATE corporates SET ${fields.join(', ')} WHERE id = ?`, values);
    res.json(await getCorporateById(req.params.id));
  } catch (err) {
    res.status(500).json({ message: 'Error updating corporate', error: err.message });
  }
});

// Delete corporate (soft delete)
app.delete('/corporates/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    await pool.query('UPDATE corporates SET deleted_at = NOW() WHERE id = ?', [req.params.id]);
    res.json({ message: 'Corporate deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting corporate', error: err.message });
  }
});

// --- CORPORATE BY FRANCHISEE ENDPOINT ---
app.get('/corporates/by-franchisee/:franchisee_id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { franchisee_id } = req.params;
    const [rows] = await pool.query('SELECT id, company_name FROM corporates WHERE franchisee_id = ? AND deleted_at IS NULL', [franchisee_id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching corporates', error: err.message });
  }
});

// --- BOOKING CODE MANAGER ENDPOINTS ---

// List all booking masters
app.get('/booking-masters', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [masters] = await pool.query(`
      SELECT bm.*, f.name as franchisee_name, c.company_name as corporate_name, COUNT(bc.id) as code_count
      FROM booking_masters bm
      LEFT JOIN franchisees f ON f.id = bm.franchisee_id
      LEFT JOIN corporates c ON c.id = bm.corporate_id
      LEFT JOIN booking_codes bc ON bc.booking_master_id = bm.id
      GROUP BY bm.id
      ORDER BY bm.created_at DESC
    `);
    res.json(masters.map(m => ({
      ...m,
      corporate_name: m.corporate_id ? m.corporate_name : 'Self'
    })));
  } catch (err) {
    res.status(500).json({ message: 'Error fetching booking masters', error: err.message });
  }
});

// Get booking master details and generated codes
app.get('/booking-masters/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [masters] = await pool.query(`
      SELECT bm.*, f.name as franchisee_name, c.company_name as corporate_name
      FROM booking_masters bm
      LEFT JOIN franchisees f ON f.id = bm.franchisee_id
      LEFT JOIN corporates c ON c.id = bm.corporate_id
      WHERE bm.id = ?
    `, [req.params.id]);
    if (!masters.length) return res.status(404).json({ message: 'Booking master not found' });
    const master = masters[0];
    const [codes] = await pool.query('SELECT code FROM booking_codes WHERE booking_master_id = ? ORDER BY code', [req.params.id]);
    master.codes = codes.map(c => c.code);
    master.corporate_name = master.corporate_id ? master.corporate_name : 'Self';
    res.json(master);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching booking master', error: err.message });
  }
});

// Create booking master and generate codes
app.post('/booking-masters', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { franchisee_id, corporate_id, range_from, range_to } = req.body;
    if (!franchisee_id || !range_from || !range_to) return res.status(400).json({ message: 'Missing required fields' });
    const start = parseInt(range_from, 10);
    const end = parseInt(range_to, 10);
    if (isNaN(start) || isNaN(end) || start > end) return res.status(400).json({ message: 'Invalid code range' });
    // Check for already assigned codes
    const codeList = [];
    for (let i = start; i <= end; i++) {
      codeList.push(i.toString()); // No leading zeros
    }
    const [existing] = await pool.query(
      'SELECT code FROM booking_codes WHERE code IN (?)', [codeList]
    );
    if (existing.length > 0) {
      return res.status(409).json({ message: 'Some codes in the range are already assigned', codes: existing.map(e => e.code) });
    }
    // Insert booking master
    const [result] = await pool.query(
      'INSERT INTO booking_masters (franchisee_id, corporate_id, range_from, range_to, status, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
      [franchisee_id, corporate_id || null, range_from, range_to, 'active']
    );
    const booking_master_id = result.insertId;
    // Insert codes
    const codeRows = codeList.map(code => [franchisee_id, corporate_id || null, booking_master_id, code]);
    await pool.query(
      'INSERT INTO booking_codes (franchisee_id, corporate_id, booking_master_id, code, created_at) VALUES ?', [codeRows.map(row => [...row, new Date()])]
    );
    res.json({ message: 'Booking codes generated', booking_master_id });
  } catch (err) {
    res.status(500).json({ message: 'Error creating booking master', error: err.message });
  }
});

// Delete booking master and its codes
app.delete('/booking-masters/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM booking_masters WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Booking master not found' });
    res.json({ message: 'Booking master and codes deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting booking master', error: err.message });
  }
});

// List all codes for a booking master
app.get('/booking-codes/:booking_master_id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [codes] = await pool.query('SELECT code FROM booking_codes WHERE booking_master_id = ? ORDER BY code', [req.params.booking_master_id]);
    res.json(codes.map(c => c.code));
  } catch (err) {
    res.status(500).json({ message: 'Error fetching codes', error: err.message });
  }
});

// Export codes as CSV
app.get('/booking-codes/export/:booking_master_id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [codes] = await pool.query('SELECT code FROM booking_codes WHERE booking_master_id = ? ORDER BY code', [req.params.booking_master_id]);
    const parser = new Parser({ fields: ['code'] });
    const csv = parser.parse(codes);
    res.header('Content-Type', 'text/csv');
    res.attachment('codes.csv');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ message: 'Error exporting codes', error: err.message });
  }
});

// --- GET UNUSED BOOKING CODES FOR FRANCHISEE & CORPORATE ---
app.get('/booking-codes', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { franchisee_id, corporate_id } = req.query;
    if (!franchisee_id || !corporate_id) {
      return res.status(400).json({ message: 'franchisee_id and corporate_id are required' });
    }
    // Find all codes for this franchisee and corporate that are not used in courier_bookings
    const [codes] = await pool.query(
      `SELECT bc.code
       FROM booking_codes bc
       LEFT JOIN courier_bookings cb ON cb.tracking_number = bc.code
       WHERE bc.franchisee_id = ? AND bc.corporate_id = ?
         AND cb.id IS NULL
       ORDER BY bc.code`,
      [franchisee_id, corporate_id]
    );
    res.json(codes);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching barcodes', error: err.message });
  }
});

// --- RATES MANAGER ENDPOINTS ---

// List all rates
app.get('/rate-masters', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rates] = await pool.query('SELECT * FROM rate_masters WHERE deleted_at IS NULL ORDER BY id DESC');
    res.json(rates);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching rates', error: err.message });
  }
});

// Get a single rate
app.get('/rate-masters/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM rate_masters WHERE id = ? AND deleted_at IS NULL', [req.params.id]);
    if (!rows.length) return res.status(404).json({ message: 'Rate not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching rate', error: err.message });
  }
});

// Create a rate
app.post('/rate-masters', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { start_weight, end_weight, unit_type, rate_price, distance_type, is_active } = req.body;
    if (!start_weight || !end_weight || !unit_type || !rate_price || !distance_type) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const [result] = await pool.query(
      'INSERT INTO rate_masters (start_weight, end_weight, unit_type, rate_price, distance_type, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
      [start_weight, end_weight, unit_type, rate_price, distance_type, is_active ? 1 : 0]
    );
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ message: 'Error creating rate', error: err.message });
  }
});

// Update a rate
app.put('/rate-masters/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const { start_weight, end_weight, unit_type, rate_price, distance_type, is_active } = req.body;
    const [result] = await pool.query(
      'UPDATE rate_masters SET start_weight=?, end_weight=?, unit_type=?, rate_price=?, distance_type=?, is_active=?, updated_at=NOW() WHERE id=?',
      [start_weight, end_weight, unit_type, rate_price, distance_type, is_active ? 1 : 0, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Rate not found' });
    res.json({ message: 'Rate updated' });
  } catch (err) {
    res.status(500).json({ message: 'Error updating rate', error: err.message });
  }
});

// Delete a rate (soft delete)
app.delete('/rate-masters/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [result] = await pool.query('UPDATE rate_masters SET deleted_at = NOW() WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Rate not found' });
    res.json({ message: 'Rate deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting rate', error: err.message });
  }
});

// --- COURIER BOOKINGS ADMIN ENDPOINTS ---

// Helper: get safe fields for courier booking
function courierBookingSafeFields(row) {
  return {
    id: row.id,
    franchisee_id: row.franchisee_id,
    tracking_number: row.tracking_number,
    sender_franchisee_id: row.sender_franchisee_id,
    sender_name: row.sender_name,
    sender_phone: row.sender_phone,
    sender_address: row.sender_address,
    sender_pincode: row.sender_pincode,
    receiver_franchisee_id: row.receiver_franchisee_id,
    receiver_name: row.receiver_name,
    receiver_phone: row.receiver_phone,
    receiver_address: row.receiver_address,
    receiver_pincode: row.receiver_pincode,
    service_type: row.service_type,
    Modes_of_Services: row.Modes_of_Services,
    Consignment_nature: row.Consignment_nature,
    weight: row.weight,
    length: row.length,
    width: row.width,
    height: row.height,
    volumetric_weight: row.volumetric_weight,
    declared_value: row.declared_value,
    freight_charges: row.freight_charges,
    payment_mode: row.payment_mode,
    cod_amount: row.cod_amount,
    total_amount: row.total_amount,
    payment_status: row.payment_status,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
    deleted_at: row.deleted_at,
    created_by: row.created_by,
    updated_by: row.updated_by
  };
}

// List all courier bookings (admin only)
app.get('/courier-bookings', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM courier_bookings WHERE deleted_at IS NULL ORDER BY id DESC');
    res.json(rows.map(courierBookingSafeFields));
  } catch (err) {
    res.status(500).json({ message: 'Error fetching courier bookings', error: err.message });
  }
});

// Get courier booking by id (admin only)
app.get('/courier-bookings/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM courier_bookings WHERE id = ? AND deleted_at IS NULL', [req.params.id]);
    if (!rows.length) return res.status(404).json({ message: 'Courier booking not found' });
    res.json(courierBookingSafeFields(rows[0]));
  } catch (err) {
    res.status(500).json({ message: 'Error fetching courier booking', error: err.message });
  }
});

// Create courier booking (admin only)
app.post('/courier-bookings', authenticateJWT, authorizeRoles('admin', 'superadmin'), upload.any(), async (req, res) => {
  try {
    // Do not destructure req.body, access fields directly
    const body = req.body;
    const [result] = await pool.query(
      `INSERT INTO courier_bookings (
        franchisee_id, tracking_number, sender_franchisee_id, sender_name, sender_phone, sender_address, sender_pincode,
        receiver_franchisee_id, receiver_name, receiver_phone, receiver_address, receiver_pincode,
        service_type, Modes_of_Services, Consignment_nature, weight, length, width, height, volumetric_weight,
        declared_value, freight_charges, payment_mode, cod_amount, total_amount, payment_status, status, created_by, updated_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        body.franchisee_id, body.tracking_number, body.sender_franchisee_id, body.sender_name, body.sender_phone, body.sender_address, body.sender_pincode,
        body.receiver_franchisee_id, body.receiver_name, body.receiver_phone, body.receiver_address, body.receiver_pincode,
        body.service_type, body.Modes_of_Services, body.Consignment_nature, body.weight, body.length, body.width, body.height, body.volumetric_weight,
        body.declared_value, body.freight_charges, body.payment_mode, body.cod_amount, body.total_amount, body.payment_status, body.status, body.created_by, body.updated_by
      ]
    );
    const [rows] = await pool.query('SELECT * FROM courier_bookings WHERE id = ?', [result.insertId]);
    res.status(201).json(courierBookingSafeFields(rows[0]));
  } catch (err) {
    res.status(500).json({ message: 'Error creating courier booking', error: err.message });
  }
});

// Update courier booking (admin only)
app.put('/courier-bookings/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const allowed = [
      'franchisee_id', 'tracking_number', 'sender_franchisee_id', 'sender_name', 'sender_phone', 'sender_address', 'sender_pincode',
      'receiver_franchisee_id', 'receiver_name', 'receiver_phone', 'receiver_address', 'receiver_pincode',
      'service_type', 'Modes_of_Services', 'Consignment_nature', 'weight', 'length', 'width', 'height', 'volumetric_weight',
      'declared_value', 'freight_charges', 'payment_mode', 'cod_amount', 'total_amount', 'payment_status', 'status', 'created_by', 'updated_by'
    ];
    const fields = [];
    const values = [];
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        fields.push(`${key} = ?`);
        values.push(req.body[key]);
      }
    }
    if (!fields.length) return res.status(400).json({ message: 'No fields to update' });
    fields.push('updated_at = NOW()');
    values.push(req.params.id);
    await pool.query(`UPDATE courier_bookings SET ${fields.join(', ')} WHERE id = ?`, values);
    const [rows] = await pool.query('SELECT * FROM courier_bookings WHERE id = ?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ message: 'Courier booking not found' });
    res.json(courierBookingSafeFields(rows[0]));
  } catch (err) {
    res.status(500).json({ message: 'Error updating courier booking', error: err.message });
  }
});

// Delete courier booking (soft delete, admin only)
app.delete('/courier-bookings/:id', authenticateJWT, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  try {
    const [result] = await pool.query('UPDATE courier_bookings SET deleted_at = NOW() WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Courier booking not found' });
    res.json({ message: 'Courier booking deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting courier booking', error: err.message });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
