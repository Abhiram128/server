const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const nodemailer = require("nodemailer");

// Function to create a Nodemailer transporter
const createTransporter = () => {
  return nodemailer.createTransport({
    service: "Gmail", // e.g., "Gmail" for Gmail
    auth: {
      user: "abhiramsayani@gmail.com",
      pass: "qxaalasxbnlkixmz",
    },
  });
};

// Function to send a verification email
const sendVerificationEmail = (user, verificationToken) => {
  const transporter = createTransporter();

  const mailOptions = {
    from: "abhiramsayani@gmail.com",
    to: user.email,
    subject: "Email Verification",
    text: `Click the following link to verify your email: http://43.204.116.188:3000/verify/${verificationToken}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
};

// Function to send a password reset email
const sendPasswordResetEmail = (user, resetToken) => {
  const transporter = createTransporter();

  const mailOptions = {
    from: "abhiramsayani@gmail.com",
    to: user.email,
    subject: "Password Reset",
    text: `Click the following link to reset your password: https://example.com/reset-password/${resetToken}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
};

// Signup user with email verification
const signupUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Create a new user
    const user = await User.signup(email, password);

    // Generate a verification token
    const verificationToken = jwt.sign({ email: user.email, type: "emailVerification" }, process.env.SECRET, { expiresIn: "1h" });

    // Send a verification email
    sendVerificationEmail(user, verificationToken);

    res.status(201).json({ message: "User created. Check your email for verification." });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

// Verify user email based on the verification token
const verifyEmail = async (req, res) => {
  const { token } = req.params;

  try {
    // Verify the token
    const decodedToken = jwt.verify(token, process.env.SECRET);

    // Update the user's email verification status in the database
    const user = await User.findOneAndUpdate(
      { email: decodedToken.email },
      { isVerified: true },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.status(200).json({ message: "Email verification successful." });
  } catch (error) {
    res.status(400).json({ error: "Invalid or expired token." });
  }
};

// Request a password reset
const requestPasswordReset = async (req, res) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Generate a password reset token
    const resetToken = jwt.sign({ email: user.email, type: "passwordReset" }, process.env.SECRET, { expiresIn: "1h" });

    // Send a password reset email
    sendPasswordResetEmail(user, resetToken);

    res.status(200).json({ message: "Password reset instructions sent to your email." });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

// Login user
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.login(email, password);

    // Check if the user is verified
    if (!user.isVerified) {
      return res.status(401).json({ error: "Email not verified. Please check your email for verification instructions." });
    }

    // Create a token
    const token = jwt.sign({ id: user._id }, process.env.SECRET, { expiresIn: "7d" });

    res.status(200).json({ email, token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

module.exports = { signupUser, verifyEmail, requestPasswordReset, loginUser };
