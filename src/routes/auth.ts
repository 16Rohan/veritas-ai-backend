import { Router, Request, Response } from 'express';
import { supabase } from '../lib/supabase';
import { generateToken } from '../lib/jwt';
import { authMiddleware } from '../lib/auth-middleware';

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

// Sign Up
router.post('/signup', async (req: SignUpRequest, res: Response): Promise<void> => {
  try {
    const { username, email_id, password } = req.body;

    if (!username || !email_id || !password) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }

    // Check if user already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email_id', email_id)
      .single();

    if (existingUser) {
      res.status(409).json({ error: 'User already exists' });
      return;
    }

    // Create new user in Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signUpWithPassword({
      email: email_id,
      password,
    });

    if (authError || !authData.user) {
      res.status(400).json({ error: authError?.message || 'Failed to create user' });
      return;
    }

    // Store user info in custom users table
    const { error: insertError } = await supabase.from('users').insert([
      {
        id: authData.user.id,
        email_id,
        username,
        subscription_tier: 0,
        created_at: new Date().toISOString(),
      },
    ]);

    if (insertError) {
      console.error('Insert error:', insertError);
      res.status(400).json({ error: 'Failed to store user data' });
      return;
    }

    const token = generateToken({
      id: authData.user.id,
      email: email_id,
      name: username,
    });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: authData.user.id, email_id, username },
    });
  } catch (error) {
    console.error('Sign up error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Sign In
router.post('/signin', async (req: SignInRequest, res: Response): Promise<void> => {
  try {
    const { email_id, password } = req.body;

    if (!email_id || !password) {
      res.status(400).json({ error: 'Missing email or password' });
      return;
    }

    // Authenticate with Supabase
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: email_id,
      password,
    });

    if (authError || !authData.user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Get user info from custom users table
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('id, email_id, username')
      .eq('id', authData.user.id)
      .single();

    if (userError || !userData) {
      res.status(400).json({ error: 'User not found' });
      return;
    }

    const token = generateToken({
      id: userData.id,
      email: userData.email_id,
      name: userData.username,
    });

    res.status(200).json({
      message: 'Sign in successful',
      token,
      user: { id: userData.id, email_id: userData.email_id, username: userData.username },
    });
  } catch (error) {
    console.error('Sign in error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify Token
router.get('/verify', authMiddleware, (req: Request, res: Response) => {
  res.status(200).json({
    message: 'Token is valid',
    user: req.user,
  });
});

// Get Current User
router.get('/me', authMiddleware, (req: Request, res: Response) => {
  res.status(200).json({
    user: req.user,
  });
});

export default router;
