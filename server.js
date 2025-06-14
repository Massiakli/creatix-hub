const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI);

const JWT_SECRET = process.env.JWT_SECRET || 'enrigma-secret';

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: String
});

const projectSchema = new mongoose.Schema({
  title: String,
  description: String,
  status: String,
  tasks: Array,
  clientId: String,
  team: Array,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);

function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Access denied');
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch {
    res.status(400).send('Invalid Token');
  }
}

app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashed, role });
  await user.save();
  res.json({ message: 'User created' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send('User not found');
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).send('Invalid credentials');
  const token = jwt.sign({ _id: user._id, role: user.role }, JWT_SECRET);
  res.json({ token });
});

app.get('/api/projects', authMiddleware, async (req, res) => {
  const projects = await Project.find();
  res.json(projects);
});

app.post('/api/projects', authMiddleware, async (req, res) => {
  const project = new Project(req.body);
  await project.save();
  res.json(project);
});

app.listen(5000, () => console.log('Server running at http://localhost:5000'));
