import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

/**
 * TODO: Define User schema
 *
 * Fields:
 * - name: String, required, trim, minlength 2, maxlength 50
 * - email: String, required, unique, lowercase, trim
 *   Use regex validation: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
 * - password: String, required, minlength 6
 *   IMPORTANT: Add { select: false } so password isn't returned by default
 * - role: String, enum ['user', 'admin'], default 'user'
 *
 * Options:
 * - Enable timestamps (createdAt, updatedAt)
 */
const userSchema = new mongoose.Schema(
  {
    // Your schema fields here
    name: {
      type: String,
      required: [true, "name is required"],
      trim: true
    },

    email: {
      type: String,
      required: [true, 'email is required'],
      trim: true,
      validate: {
        validator: function (value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) },
        message: "Invalid email format"
      },
      unique: true,
      lowercase: true
    },
    password: {
      type: String,
      required: [true, "password is required"],
      select: false,
      minlength: 6
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    }
  },

  {
    // Schema options here\
    timestamps: true
  }
);

/**
 * TODO: Add pre-save hook to hash password
 *
 * Before saving a user:
 * 1. Check if password is modified (if not, skip hashing)
 * 2. Hash password using bcrypt.hash(password, 10)
 * 3. Replace plain text password with hashed version
 *
 * Example structure:
 * userSchema.pre('save', async function(next) {
 *   // Only hash if password is modified
 *   
 *   // Hash password and replace
 *   
 * });
 */
userSchema.pre('save', async function (next) {

  if (!this.isModified('password')) {
    return next()
  }

  this.password = await bcrypt.hash(this.password, 10)
  next()
}
)
// TODO: Create and export the User model
export const User = mongoose.model('User', userSchema)