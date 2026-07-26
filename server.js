
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

// Render等のプロキシヘッダー（X-Forwarded-Protoなど）を信頼する設定
app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// セッション設定の最適化
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-super-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    // Render上の本番環境(HTTPS)では secure: true、ローカル(HTTP)では false
    secure: process.env.NODE_ENV === 'production' || process.env.RENDER === 'true',
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24時間
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// AUTH_SERVER の末尾スラッシュ（/）を除去して整形する関数
const getAuthServer = () => {
  const server = process.env.AUTH_SERVER || 'https://sennin-acount.onrender.com';
  return server.replace(/\/+$/, '');
};

// 1. 認可リクエストへのリダイレクト
app.get('/auth/login', (req, res) => {
  const authServer = getAuthServer();
  const clientId = process.env.CLIENT_ID;
  const redirectUri = process.env.REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(500).send('環境変数 CLIENT_ID または REDIRECT_URI が設定されていません。');
  }

  const authorizeUrl = `${authServer}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  
  console.log('Redirecting to:', authorizeUrl);
  res.redirect(authorizeUrl);
});

// 2. コールバック処理（確実にセッションを保存してからリダイレクト）
app.get('/api/auth/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    console.error('認可エラー:', error);
    return res.status(400).send(`認可エラーが発生しました: ${error || 'codeが取得できませんでした'}`);
  }

  try {
    const authServer = getAuthServer();

    // (A) トークン取得リクエスト
    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      code: code,
      redirect_uri: process.env.REDIRECT_URI
    });

    const tokenRes = await axios.post(`${authServer}/oauth/token`, tokenParams.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const accessToken = tokenRes.data.access_token;

    // (B) ユーザー情報取得リクエスト
    const userRes = await axios.get(`${authServer}/oauth/userinfo`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    // セッションにユーザー情報をセット
    req.session.user = {
      id: userRes.data.id,
      username: userRes.data.username,
      email: userRes.data.email,
      avatarUrl: userRes.data.avatarUrl || 'https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y'
    };

    // ★重要: セッションの保存が完了してからリダイレクトさせる
    req.session.save((err) => {
      if (err) {
        console.error('セッション保存エラー:', err);
        return res.status(500).send('セッションの保存に失敗しました。');
      }
      console.log('セッション保存成功:', req.session.user.username);
      res.redirect('/');
    });

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

// 3. ログイン状態確認 ＆ フロントエンド設定出力
app.get('/api/me', (req, res) => {
  if (!req.session || !req.session.user) {
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
