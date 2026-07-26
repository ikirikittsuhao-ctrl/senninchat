const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

// Renderなどのリバースプロキシ配下でセッションを正しく扱う設定
app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// セッション設定 (SESSION_SECRET が未設定の場合のフォールバックを追加)
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-super-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // 本番(HTTPS)環境で自動的にクッキーを保護
    maxAge: 24 * 60 * 60 * 1000 // 24時間保持
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// 1. 認可リクエストへのリダイレクト
app.get('/auth/login', (req, res) => {
  const authorizeUrl = `${process.env.AUTH_SERVER}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(process.env.CLIENT_ID)}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}`;
  res.redirect(authorizeUrl);
});

// 2. コールバック処理（REDIRECT_URI = https://senninchat9ok.onrender.com/api/auth/callback に対応）
app.get('/api/auth/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    console.error('認可エラー:', error);
    return res.status(400).send(`認可エラーが発生しました: ${error || 'codeが取得できませんでした'}`);
  }

  try {
    // (A) トークン取得リクエスト (Client Secretをサーバー間通信で保持)
    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      code: code,
      redirect_uri: process.env.REDIRECT_URI
    });

    const tokenRes = await axios.post(`${process.env.AUTH_SERVER}/oauth/token`, tokenParams.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const accessToken = tokenRes.data.access_token;

    // (B) ユーザー情報取得リクエスト
    const userRes = await axios.get(`${process.env.AUTH_SERVER}/oauth/userinfo`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    // セッションにユーザー情報を保存
    req.session.user = {
      id: userRes.data.id,
      username: userRes.data.username,
      email: userRes.data.email,
      avatarUrl: userRes.data.avatarUrl || 'https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y'
    };

    // ログイン成功後、トップ画面へリダイレクト
    res.redirect('/');
  } catch (err) {
    console.error('=== OAuth Error Details ===');
    if (err.response) {
      console.error('Status:', err.response.status);
      console.error('Data:', err.response.data);
    } else {
      console.error('Message:', err.message);
    }
    res.status(500).send('認証処理（トークン・ユーザー情報取得）中にエラーが発生しました。');
  }
});

// 3. ログイン状態確認 ＆ フロントエンド側（index.html）に必要な設定を渡すAPI
app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ authenticated: false });
  }
  res.json({
    authenticated: true,
    user: req.session.user,
    supabaseConfig: {
      url: process.env.SUPABASE_URL,
      key: process.env.SUPABASE_ANON_KEY // フロントエンド用には ANON KEY のみを渡します
    }
  });
});

// 4. ログアウト処理
app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
