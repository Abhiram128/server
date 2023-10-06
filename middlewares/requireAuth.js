const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

const requireAuth = async (req, res, next) => {
  // Verify authentication
  const { authorization } = req.headers;

  if (!authorization) {
    return res.status(401).json({ error: "Authorization token required" });
  }

  const token = authorization.split(" ")[1];

  try {
    const { id, type } = jwt.verify(token, process.env.SECRET);

    // Find the user by ID
    const user = await User.findOne({ _id: id });

    if (!user) {
      return res.status(401).json({ error: "Token is not authorized" });
    }

    // Check if the user is verified for email authentication (add your field name accordingly)
    if (!user.isVerified && type === "emailVerification") {
      return res.status(401).json({ error: "Email is not verified" });
    }

    // Attach the user object to the request for further use in routes
    req.user = user;

    next();
  } catch (err) {
    res.status(401).json({ error: "Token is not authorized" });
  }
};

module.exports = requireAuth;
