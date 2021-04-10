const router = require("express").Router();
const verify = require("./verifyToken");
const User = require("../model/User");

router.get("/", verify, async (req, res) => {
  const user = await User.findOne({ _id: req.user._id });
  if (user) return res.send({ msg: "ok", name: user.name });
});
module.exports = router;
