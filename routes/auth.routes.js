const Router = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");
const User = require("../models/User");
const router = new Router();

router.post("/registration",
  [
    check("email", "Uncorrect email").isEmail(),
    check("password", "Password must be longer than 3").isLength({ min: 3 })
  ],
  async (req, res) => {
    try {
      console.log(req.body);
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ message: "Uncorrect request", errors })
      };

      const { email, password, name } = req.body;
      const candidate = await User.findOne({ email });

      if (candidate) {
        return res.status(400).json({ message: `User with email ${email} already exist` });
      };
      const hashPassword = await bcrypt.hash(password, 8);
      const user = new User({ email, password: hashPassword, name });
      await user.save();
      return res.json({ message: "User was created" })

    } catch (e) {
      console.log(e);
      res.send({ message: "Server error" })
    }
  })

router.post("/login",
  async (req, res) => {
    try {
      console.log(req.body);
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      console.log(user)
      const isPassValid = bcrypt.compareSync(password, user.password);
      if (!isPassValid) {
        return res.status(404).json({ message: "Invalid password" });
      }
      const token = jwt.sign({ id: user.id }, config.get("secretKey"), { expiresIn: "1h" })
      return res.json({
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          avatar: user.avatar
        }
      })
    } catch (e) {
      console.log(e);
      res.send({ message: "Server error" })
    }
  })

module.exports = router;