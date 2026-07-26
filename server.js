const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // HTTPS環境では true に設定
}));

app.use(express.static(path.join(__dirname, 'public')));

// 1. 認可リクエストへのリダイレクト（Client IDを保持して送信）
app.get('/auth/login', (req, res) => {
  const authorizeUrl = `${process.env.AUTH_SERVER}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(process.env.CLIENT_ID)}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}`;
  res.redirect(authorizeUrl);
});

// 2. コールバック処理 (認可コードの受け取り ＆ サーバー間でのトークン交換)
app.get('/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    return res.status(400).send(`認可エラー: ${error || 'codeがありません'}`);
  }

  try {
    // (A) トークン取得リクエスト (Client Secretをサーバー間で送信)
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

    res.redirect('/');
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send('認証処理中にエラーが発生しました。');
  }
});

// 3. ログイン状態確認用API & Supabase設定渡すAPI
app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ authenticated: false });
  }
  res.json({
    authenticated: true,
    user: req.session.user,
    supabaseConfig: {
      url: process.env.SUPABASE_URL,
      key: process.env.SUPABASE_ANON_KEY
    }
  });
});

// 4. ログアウト
app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(process.env.PORT, () => {
  console.log(`Server running at http://localhost:${process.env.PORT}`);
});
