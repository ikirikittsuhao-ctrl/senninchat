require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// OAuth 2.0 認可プロバイダーの設定 (sennin-acount.onrender.com)
const OAUTH_CONFIG = {
  providerUrl: process.env.OAUTH_PROVIDER_URL || 'https://sennin-acount.onrender.com',
  clientId: process.env.OAUTH_CLIENT_ID || 'client_89f7dcfbd6e397a2',
  clientSecret: process.env.OAUTH_CLIENT_SECRET || 'secret_be89e49969411eaa079f766ce74dcbc2',
  redirectUri: process.env.OAUTH_REDIRECT_URI || 'https://senninchat9ok.onrender.com/api/auth/callback'
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 設定情報をフロントエンドに渡すAPI
app.get('/api/config', (req, res) => {
  res.json({
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY,
    oauthProviderUrl: OAUTH_CONFIG.providerUrl
  });
});

// 新規ユーザー初期化ヘルパーAPI
app.post('/api/register-profile', async (req, res) => {
  const { userId, name } = req.body;
  if (!userId || !name) return res.status(400).json({ error: 'Missing parameters' });

  // ランダムなユーザーコード発行 (例: USER-A1B2)
  const userCode = 'USER-' + Math.random().toString(36).substring(2, 6).toUpperCase();

  const { data, error } = await supabase.from('profiles').upsert([
    { id: userId, name: name, user_code: userCode }
  ]).select();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, profile: data[0] });
});

// =================================================================
// OAuth 2.0 (認可コードフロー) 認証エンドポイント
// =================================================================

// 1. OAuth 認可画面へのリダイレクト
app.get('/api/auth/login', (req, res) => {
  const authorizeUrl = new URL(`${OAUTH_CONFIG.providerUrl}/oauth/authorize`);
  authorizeUrl.searchParams.append('client_id', OAUTH_CONFIG.clientId);
  authorizeUrl.searchParams.append('redirect_uri', OAUTH_CONFIG.redirectUri);
  authorizeUrl.searchParams.append('response_type', 'code');

  res.redirect(authorizeUrl.toString());
});

// 2. OAuth コールバック処理 (code 交換 -> トークン取得 -> ユーザー情報同期)
app.get('/api/auth/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    return res.status(400).send('OAuth 認証エラー: 認可コードを取得できませんでした。');
  }

  try {
    // 2a. 認可コード (code) を Access Token と交換
    const tokenResponse = await fetch(`${OAUTH_CONFIG.providerUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: OAUTH_CONFIG.clientId,
        client_secret: OAUTH_CONFIG.clientSecret,
        code: String(code)
      })
    });

    if (!tokenResponse.ok) {
      const errData = await tokenResponse.json();
      return res.status(401).json({ error: 'トークン交換に失敗しました', details: errData });
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // 2b. Access Token を使ってユーザー情報を取得
    const userinfoResponse = await fetch(`${OAUTH_CONFIG.providerUrl}/oauth/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    if (!userinfoResponse.ok) {
      return res.status(401).send('ユーザー情報の取得に失敗しました。');
    }

    const oauthUser = await userinfoResponse.json();

    // 2c. ユーザー情報を Supabase プロファイルテーブルに同期 (Upsert)
    const userCode = 'USER-' + oauthUser.id.substring(0, 4).toUpperCase();
    const { error: profileError } = await supabase.from('profiles').upsert([
      {
        id: oauthUser.id,
        name: oauthUser.username || oauthUser.email.split('@')[0],
        user_code: userCode,
        avatar_url: `https://api.dicebear.com/7.x/bottts/svg?seed=${oauthUser.id}`
      }
    ]);

    if (profileError) {
      console.error('Profile sync error:', profileError);
    }

    // クライアント側へ認証完了情報 (userId) を渡すためにリダイレクト
    res.redirect(`/?oauth_user_id=${encodeURIComponent(oauthUser.id)}`);
  } catch (err) {
    console.error('OAuth Auth Callback Error:', err);
    res.status(500).send('OAuth 認証処理中にサーバーエラーが発生しました。');
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
