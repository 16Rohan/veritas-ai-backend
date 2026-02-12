import { Router, Request, Response } from "express";
import { supabaseAdmin } from "../lib/supabase";
import { generateToken } from "../lib/jwt";
import { authMiddleware } from "../lib/auth-middleware";
import * as bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

const router = Router();

interface SignUpRequest extends Request {
  body: {
    username: string;
    email_id: string;
    password: string;
  };
}

interface SignInRequest extends Request {
  body: {
    email_id: string;
    password: string;
  };
}

// Sign Up (using admin API to bypass rate limits)
router.post("/signup", async (req: SignUpRequest, res: Response): Promise<void> => {
  try {
    const { username, email_id, password } = req.body;

    if (!username || !email_id || !password) {
      res.status(400).json({ error: "Missing required fields" });
      return;
    }

    // Check if user already exists in profiles
    const { data: existingUser } = await supabaseAdmin
      .from("user-profiles")
      .select("id")
      .eq("email_id", email_id)
      .single();

    if (existingUser) {
      res.status(409).json({ error: "User already exists" });
      return;
    }

    // Hash password locally
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    // Store user info with hashed password
    const { error: insertError } = await supabaseAdmin.from("user-profiles").insert([
      {
        id: userId,
        email_id,
        username,
        password_hash: hashedPassword,
        subscription_tier: 0,
        created_at: new Date().toISOString(),
      },
    ]);

    if (insertError) {
      console.error("Insert error:", insertError);
      res.status(400).json({ error: "Failed to store user data" });
      return;
    }

    const token = generateToken({
      id: userId,
      email: email_id,
      name: username,
    });

    res.status(201).json({
      message: "User created successfully",
      token,
      user: { id: userId, email_id, username },
    });
  } catch (error) {
    console.error("Sign up error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Sign In
router.post("/signin", async (req: SignInRequest, res: Response): Promise<void> => {
  try {
    const { email_id, password } = req.body;

    console.log("Signin attempt for:", email_id);

    if (!email_id || !password) {
      res.status(400).json({ error: "Missing email or password" });
      return;
    }

    // Fetch user from database
    const { data: userData, error: userError } = await supabaseAdmin
      .from("user-profiles")
      .select("id, email_id, username, password_hash")
      .eq("email_id", email_id)
      .single();

    if (userError || !userData) {
      console.error("User not found:", email_id);
      res.status(401).json({ error: "Invalid email or password" });
      return;
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, userData.password_hash);

    if (!passwordMatch) {
      console.error("Invalid password for:", email_id);
      res.status(401).json({ error: "Invalid email or password" });
      return;
    }

    const token = generateToken({
      id: userData.id,
      email: userData.email_id,
      name: userData.username,
    });

    console.log("Signin successful for:", userData.id);

    res.status(200).json({
      message: "Sign in successful",
      token,
      user: { id: userData.id, email_id: userData.email_id, username: userData.username },
    });
  } catch (error) {
    console.error("Sign in error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Verify Token
router.get("/verify", authMiddleware, (req: Request, res: Response) => {
  res.status(200).json({
    message: "Token is valid",
    user: req.user,
  });
});

// Get Current User
router.get("/me", authMiddleware, (req: Request, res: Response) => {
  res.status(200).json({
    user: req.user,
  });
});

// Logout (client-side token removal is handled by frontend)
router.post("/logout", authMiddleware, (req: Request, res: Response) => {
  res.status(200).json({
    message: "Logout successful",
  });
});

export default router;
