
import User from "../models/user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { adminAuth } from "../firebaseAdmin.js";
import { sendWelcomeMail } from "../utils/sendWelcomeMail.js"; // ✅ new import

const JWT_SECRET = process.env.JWT_SECRET || "fallbackSecretKey";

// =============================
// ✅ Manual Signup Controller
// =============================
export const signup = async (req, res) => {
  const { fullName, email, phone, password } = req.body;
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists." });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({ fullName, email, phone, password: hashedPassword });
    await user.save();

    // ✅ Send welcome mail after successful signup
    try {
      await sendWelcomeMail(email, fullName);
      console.log(`✅ Welcome email sent to ${email}`);
    } catch (mailError) {
      console.error("⚠️ Failed to send welcome email:", mailError.message);
    }

    res.status(201).json({
      message: "User created successfully.",
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
      },
    });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ message: err.message });
  }
};

// =============================
// ✅ Manual Login Controller
// =============================
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid email or password." });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: err.message });
  }
};

// =============================
// ✅ Firebase Google Login
// =============================
export const googleFirebaseLogin = async (req, res) => {
  const { token } = req.body;
  try {
    // Verify Firebase token
    const decodedToken = await adminAuth.verifyIdToken(token);
    const { uid, email, name, phone_number } = decodedToken;

    let user = await User.findOne({ email });
    let isNewUser = false;

    // Create new user if not found
    if (!user) {
      user = await User.create({
        fullName: name,
        email,
        phone: phone_number || "N/A",
        password: uid, // temporary password
      });
      isNewUser = true;
    }

    // Generate JWT
    const jwtToken = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    // ✅ Send Welcome Email if first-time login via Google
    if (isNewUser) {
      try {
        await sendWelcomeMail(user.email, user.fullName);
        console.log(`✅ Google signup welcome email sent to ${email}`);
      } catch (mailError) {
        console.error("⚠️ Failed to send Google welcome email:", mailError.message);
      }
    }

    res.status(200).json({
      message: "Login successful",
      token: jwtToken,
      user,
    });
  } catch (err) {
    console.error("Firebase Google Auth Error:", err);
    res.status(500).json({ message: "Google authentication failed" });
  }
};

// =============================
// ✅ Update Profile
// =============================
export const updateProfile = async (req, res) => {
  const userId = req.userId;
  const { fullName, phone, address } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { fullName, phone, address },
      { new: true }
    );

    res
      .status(200)
      .json({ message: "Profile updated successfully", user: updatedUser });
  } catch (err) {
    console.error("Update Profile Error:", err);
    res.status(500).json({ message: err.message });
  }
};
