import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, required: true, match: /^[6-9]\d{9}$/ },
    role: { type: String, enum: ["user"], default: "user" },
    password: { type: String, required: true },

    // ✅ free-text address (numbers, letters, symbols sab allowed)
    address: { type: String, default: "" },

    // ✅ gender + dob fields
    gender: {
      type: String,
      enum: ["Male", "Female", "Other", "Prefer not to say"],
      default: "Prefer not to say",
    },
    dob: { type: Date },

    resetOTP: String,
    resetOTPExpires: Date,
  },
  { timestamps: true }
);

export default mongoose.model("User", userSchema);
