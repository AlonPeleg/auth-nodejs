const router = require("express").Router();
const User = require("../model/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { registerValidation, loginValidation } = require("../validation");

// Register User
router.post("/register", async (req, res) => {
  const { error } = registerValidation(req.body);
  if (error) return res.status(400).send({ msg: error.details[0].message });

  // Check if User exists
  const emailExist = await User.findOne({ email: req.body.email });
  if (emailExist) return res.status(400).send({ msg: "Email already exists" });

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(req.body.password, salt);

  // Create a new User
  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashPassword,
  });

  try {
    const savedUser = await user.save();
    res.send({ user: user._id });
  } catch (err) {
    res.status(400).json({ msg: err });
  }
});

// Login User
router.post("/login", async (req, res) => {
  // Validate
  const { error } = loginValidation(req.body);
  if (error) return res.status(400).send({ msg: error.details[0].message });

  // Checking if email exists
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return res.status(400).send({ success: false, msg: "Wrong credentials" });

  // Check Password
  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass)
    return res.status(400).send({ success: false, msg: "Wrong credentials" });

  // Create and assign token
  const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET);
  res
    .header("auth-token", token)
    .send({ success: true, msg: "Logged in successfully ", token });
});

module.exports = router;
