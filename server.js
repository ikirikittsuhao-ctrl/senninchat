require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// RLSをバイパスするために SERVICE_ROLE_KEY を優先使用
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(process.env.SUPABASE_URL, supabaseKey);

// OAuth設定（.env から読み込み、未設定時はデフォルト値）
const OAUTH_CONFIG = {
  providerUrl: process.env.OAUTH_PROVIDER_URL || 'https://sennin-acount.onrender.com',
  clientId: process.env.OAUTH_CLIENT_ID || 'client_89f7dcfbd6e397a2',
  clientSecret: process.env.OAUTH_CLIENT_SECRET || 'secret_be89e49969411eaa079f766ce74dcbc2',
  redirectUri: process.env.OAUTH_REDIRECT_URI || 'https://senninchat9ok.onrender.com/api/auth/callback'
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// フロントエンド用設定共有 API
app.get('/api/config', (req, res) => {
  res.json({
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY,
    oauthProviderUrl: OAUTH_CONFIG.providerUrl
  });
});

// 1. OAuth ログイン開始
app.get('/api/auth/login', (req, res) => {
  const authorizeUrl = new URL(`${OAUTH_CONFIG.providerUrl}/oauth/authorize`);
  authorizeUrl.searchParams.append('response_type', 'code');
  authorizeUrl.searchParams.append('client_id', OAUTH_CONFIG.clientId);
  authorizeUrl.searchParams.append('redirect_uri', OAUTH_CONFIG.redirectUri);

  res.redirect(authorizeUrl.toString());
});

// 2. OAuth コールバック
app.get('/api/auth/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    console.error('OAuth Code Error:', error);
    return res.redirect('/index.html?error=oauth_code_failed');
  }

  try {
    // (A) アクセストークン取得
    const tokenResponse = await fetch(`${OAUTH_CONFIG.providerUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: OAUTH_CONFIG.clientId,
        client_secret: OAUTH_CONFIG.clientSecret,
        code: String(code),
        redirect_uri: OAUTH_CONFIG.redirectUri
      })
    });

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      console.error('Token Exchange Failed:', tokenData);
      return res.redirect('/index.html?error=token_exchange_failed');
    }

    // (B) ユーザー情報取得
    const userinfoResponse = await fetch(`${OAUTH_CONFIG.providerUrl}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    const oauthUser = await userinfoResponse.json();

    if (!userinfoResponse.ok) {
      console.error('Userinfo Request Failed:', oauthUser);
      return res.redirect('/index.html?error=userinfo_failed');
    }

    // (C) UUID 形式のチェック & 決定論的UUIDv4生成
    let validUserId = String(oauthUser.id || oauthUser.sub || '');
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    
    if (!uuidRegex.test(validUserId)) {
      const hexHash = crypto.createHash('md5').update(validUserId || 'default_user').digest('hex');
      validUserId = `${hexHash.substr(0,8)}-${hexHash.substr(8,4)}-4${hexHash.substr(13,3)}-a${hexHash.substr(17,3)}-${hexHash.substr(20,12)}`;
    }

    // (D) プロフィール項目の準備
    const rawIdStr = String(oauthUser.id || oauthUser.sub || '0000');
    const userCode = 'USER-' + rawIdStr.substring(0, 4).toUpperCase();
    const userName = oauthUser.username || oauthUser.name || (oauthUser.email ? oauthUser.email.split('@')[0] : 'User');
    const avatarUrl = oauthUser.avatarUrl || oauthUser.avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${validUserId}`;

    // (E) Supabase profiles テーブルヘ登録 / 更新 (Service Role Keyで実行)
    const { error: profileError } = await supabase.from('profiles').upsert([
      {
        id: validUserId,
        name: userName,
        user_code: userCode,
        avatar_url: avatarUrl,
        updated_at: new Date().toISOString()
      }
    ], { onConflict: 'id' });

    if (profileError) {
      console.error('Profile Upsert Error:', profileError);
    }

    // (F) アプリ画面 (/app.html) へユーザーID付きでリダイレクト
    res.redirect(`/app.html?oauth_user_id=${encodeURIComponent(validUserId)}`);

  } catch (err) {
    console.error('OAuth Callback Error:', err);
    res.redirect('/index.html?error=server_error');
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
