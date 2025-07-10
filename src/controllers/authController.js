const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendActivationEmail } = require('../utils/email');
const db = require('../../models');
const User = db.User;
const { v4: uuidv4 } = require('uuid');

exports.register = async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) return res.status(400).json({ message: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const activationToken = uuidv4();
    const user = await User.create({
      email,
      password: hashedPassword,
      isActive: false,
      activationToken
    });
    const activationLink = `${req.protocol}://${req.get('host')}/api/auth/activate/${activationToken}`;
    sendActivationEmail(email, activationLink);
    res.status(201).json({ message: 'Registration successful. Check your email for activation link.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

exports.activate = async (req, res) => {
  const { token } = req.params;
  try {
    const user = await User.findOne({ where: { activationToken: token } });
    if (!user) return res.status(400).json({ message: 'Invalid activation token' });
    user.isActive = true;
    user.activationToken = null;
    await user.save();
    res.json({ message: 'Account activated. You can now login.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (!user.isActive) return res.status(403).json({ message: 'Account not activated' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET || 'supersecretkey', { expiresIn: '1d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};