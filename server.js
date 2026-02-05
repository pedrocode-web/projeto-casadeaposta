require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const db = require('./db');
const { verifyIdentity } = require('./identity');

const app = express();
const MIN_AGE = parseInt(process.env.MIN_AGE || '18', 10);
const RECAPTCHA_SITE_KEY = process.env.RECAPTCHA_SITE_KEY || null;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || null;
const SMTP_HOST = process.env.SMTP_HOST || null;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER || null;
const SMTP_PASS = process.env.SMTP_PASS || null;
const SMTP_FROM = process.env.SMTP_FROM || 'no-reply@example.com';
const nodemailer = require('nodemailer');
const BRAND_NAME = process.env.BRAND_NAME || 'Casa de Apostas Breckson';
const PIX_KEY = process.env.PIX_KEY || null;
const PIX_NAME = process.env.PIX_NAME || BRAND_NAME;
const PIX_CITY = process.env.PIX_CITY || 'SAO PAULO';
const WEBHOOK_TOKEN = process.env.WEBHOOK_TOKEN || null;
const PLUGGY_CLIENT_ID = process.env.PLUGGY_CLIENT_ID || null;
const PLUGGY_CLIENT_SECRET = process.env.PLUGGY_CLIENT_SECRET || null;
const PLUGGY_ITEM_ID = process.env.PLUGGY_ITEM_ID || null;
const PLUGGY_BASE_URL = process.env.PLUGGY_BASE_URL || 'https://api.pluggy.ai';
const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production';

const { QrCodePix } = require('qrcode-pix');

// Configurações básicas
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// Debug: log incoming traffic to Crash start endpoint to diagnose 404 reports
app.use('/games/crash/start', (req, res, next) => { console.log('[debug] incoming', req.method, req.path); next(); });
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// Branding disponível em todos os templates
app.locals.brandName = BRAND_NAME;
app.locals.isDev = process.env.NODE_ENV !== 'production';

// Sessão: 1 dia de duração e renovação a cada acesso (rolling)
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.sqlite' }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 1 dia
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Secure apenas em prod
    },
  })
);

// Helper: exigir login
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// Valida CPF
function validateCPF(rawCpf) {
  if (!rawCpf) return false;
  const cpf = String(rawCpf).replace(/\D/g, '');
  if (cpf.length !== 11) return false;
  const blacklist = new Set(['12345678909', '01234567890']);
  if (blacklist.has(cpf)) return false;
  if (/^(\d)\1{10}$/.test(cpf)) return false;

  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(cpf.charAt(i), 10) * (10 - i);
  }
  let firstCheck = (sum * 10) % 11;
  if (firstCheck === 10) firstCheck = 0;
  if (firstCheck !== parseInt(cpf.charAt(9), 10)) return false;

  sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(cpf.charAt(i), 10) * (11 - i);
  }
  let secondCheck = (sum * 10) % 11;
  if (secondCheck === 10) secondCheck = 0;
  if (secondCheck !== parseInt(cpf.charAt(10), 10)) return false;

  return true;
}

// Valida senha forte
function validatePassword(pwd) {
  if (!pwd || pwd.length < 8) return false;
  const upper = /[A-Z]/.test(pwd);
  const lower = /[a-z]/.test(pwd);
  const digit = /\d/.test(pwd);
  const special = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]/.test(pwd);
  return upper && lower && digit && special;
}

// Maioridade 18+
function isAdult(dobStr) {
  const dob = new Date(dobStr);
  if (isNaN(dob.getTime())) return false;
  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) {
    age--;
  }
  return age >= MIN_AGE;
}

// Data máxima para cadastro (18 anos)
function getMaxDateStr() {
  const today = new Date();
  const maxDob = new Date(
    today.getFullYear() - MIN_AGE,
    today.getMonth(),
    today.getDate()
  );
  return maxDob.toISOString().slice(0, 10);
}

async function verifyRecaptcha(token) {
  if (!RECAPTCHA_SECRET) return true; // se não configurado, não bloquear em dev
  try {
    const params = new URLSearchParams({
      secret: RECAPTCHA_SECRET,
      response: token || '',
    });
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const data = await res.json();
    return !!data.success;
  } catch (e) {
    return false;
  }
}

// Rotas
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/inicio');
  }
  return res.redirect('/login');
});

// Compatibilidade: redireciona a antiga rota /dashboard para /inicio
app.get('/dashboard', (req, res) => {
  return res.redirect('/inicio');
});

app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/inicio');
  res.render('login', { error: null, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
});

app.post('/login', async (req, res) => {
  const { cpf, password, 'g-recaptcha-response': recaptcha } = req.body;
  const maxDate = getMaxDateStr();
  const recOk = await verifyRecaptcha(recaptcha);
  if (!recOk) return res.render('login', { error: 'Falha na verificação reCAPTCHA.', recaptchaSiteKey: RECAPTCHA_SITE_KEY });
  const cleanCpf = String(cpf || '').replace(/\D/g, '');

  db.get('SELECT * FROM users WHERE cpf = ?', [cleanCpf], async (err, user) => {
    if (err) return res.render('login', { error: 'Erro interno ao buscar usuário.', recaptchaSiteKey: RECAPTCHA_SITE_KEY });
    if (!user) return res.render('login', { error: 'CPF ou senha inválidos.', recaptchaSiteKey: RECAPTCHA_SITE_KEY });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.render('login', { error: 'CPF ou senha inválidos.', recaptchaSiteKey: RECAPTCHA_SITE_KEY });

    req.session.userId = user.id;
    db.run('UPDATE users SET last_login_at = ? WHERE id = ?', [new Date().toISOString(), user.id]);
    res.redirect('/inicio');
  });
});

app.get('/register', (req, res) => {
  const maxDate = getMaxDateStr();
  res.render('register', { error: null, maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
});

app.post('/register', async (req, res) => {
  const { firstName, lastName, cpf, dob, password, email, 'g-recaptcha-response': recaptcha } = req.body;
  const accepted = req.body.accept === 'on' || req.body.accept === 'true' || req.body.accept === true;
  const cleanCpf = String(cpf || '').replace(/\D/g, '');
  const maxDate = getMaxDateStr();
  const recOk = await verifyRecaptcha(recaptcha);
  if (!recOk) return res.render('register', { error: 'Falha na verificação reCAPTCHA.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });

  if (!accepted) {
    return res.render('register', { error: 'Você deve aceitar os Termos de Uso e a Política de Privacidade para continuar.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
  }

  if (!firstName || !lastName) {
    return res.render('register', { error: 'Nome e sobrenome são obrigatórios.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
  }
  if (!validateCPF(cleanCpf)) {
    return res.render('register', { error: 'CPF inválido.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
  }
  if (!isAdult(dob)) {
    return res.render('register', { error: `É necessário ser maior de ${MIN_AGE} anos.`, maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
  }
  if (!validatePassword(password)) {
    return res.render('register', { error: 'Senha deve ter 8+ caracteres, maiúscula, minúscula, número e especial.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
  }

  db.get('SELECT id FROM users WHERE cpf = ?', [cleanCpf], async (err, existing) => {
    if (err) return res.render('register', { error: 'Erro interno ao verificar CPF.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
    if (existing) return res.render('register', { error: 'CPF já cadastrado.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });

    // Verificação externa opcional
    const idApiUrl = process.env.IDENTITY_API_URL || null;
    const idApiToken = process.env.IDENTITY_API_TOKEN || null;
    const verify = await verifyIdentity({
      apiUrl: idApiUrl,
      apiToken: idApiToken,
      cpf: cleanCpf,
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      dob,
    });
    if (!verify.ok && idApiUrl && idApiToken) {
      return res.render('register', { error: 'Dados não conferem com a base oficial.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
    }

    try {
      const passwordHash = await bcrypt.hash(password, 10);
      const now = new Date().toISOString();
      const emailToken = randomToken();
      db.run(
        'INSERT INTO users (first_name, last_name, cpf, dob, email, email_verification_token, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [firstName.trim(), lastName.trim(), cleanCpf, dob, email || null, emailToken, passwordHash, now],
        function (insertErr) {
          if (insertErr) return res.render('register', { error: 'Erro ao salvar cadastro.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
          // Enviar e-mail de verificação se transporte existir
          const transport = getTransport();
          if (transport && email) {
            const verifyUrl = `${APP_URL}/verify-email?token=${encodeURIComponent(emailToken)}`;
            transport.sendMail({
              from: SMTP_FROM,
              to: email,
              subject: 'Verifique seu e-mail',
              text: `Clique para verificar: ${verifyUrl}`,
              html: `<p>Clique para verificar: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
            }).catch(() => {});
          }
          req.session.userId = this.lastID;
          res.redirect('/inicio');
        }
      );
    } catch (e) {
      return res.render('register', { error: 'Erro ao processar senha.', maxDate, recaptchaSiteKey: RECAPTCHA_SITE_KEY });
    }
  });
});

// Verificação de e-mail
app.get('/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Token inválido.');
  db.get('SELECT id FROM users WHERE email_verification_token = ?', [token], (err, user) => {
    if (err || !user) return res.status(400).send('Token inválido.');
    db.run('UPDATE users SET email_verified = 1, email_verification_token = NULL WHERE id = ?', [user.id], () => {
      res.send('E-mail verificado com sucesso.');
    });
  });
});

// Recuperação de senha
app.get('/forgot', (req, res) => {
  res.render('forgot', { error: null, info: null });
});

app.post('/forgot', (req, res) => {
  const { email } = req.body;
  if (!email) return res.render('forgot', { error: 'Informe o e-mail.', info: null });
  db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.render('forgot', { error: 'Erro interno.', info: null });
    if (!user) return res.render('forgot', { error: 'E-mail não encontrado.', info: null });
    const token = randomToken();
    const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1h
    db.run('UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?', [token, expires, user.id], () => {
      const transport = getTransport();
      if (transport) {
        const resetUrl = `${APP_URL}/reset-password?token=${encodeURIComponent(token)}`;
        transport.sendMail({
          from: SMTP_FROM,
          to: email,
          subject: 'Recuperação de senha',
          text: `Link para reset: ${resetUrl}`,
          html: `<p>Link para reset: <a href="${resetUrl}">${resetUrl}</a></p>`,
        }).catch(() => {});
      }
      res.render('forgot', { error: null, info: 'Se o e-mail existir, um link foi enviado.' });
    });
  });
});

app.get('/reset-password', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Token inválido.');
  res.render('reset', { error: null, token });
});

app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.render('reset', { error: 'Dados faltando.', token });
  db.get('SELECT id, password_reset_expires FROM users WHERE password_reset_token = ?', [token], async (err, user) => {
    if (err || !user) return res.render('reset', { error: 'Token inválido.', token });
    if (new Date(user.password_reset_expires) < new Date()) return res.render('reset', { error: 'Token expirado.', token });
    if (!/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]).{8,}$/.test(password)) {
      return res.render('reset', { error: 'Senha fraca.', token });
    }
    const hash = await bcrypt.hash(password, 10);
    db.run('UPDATE users SET password_hash = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?', [hash, user.id], () => {
      res.redirect('/login');
    });
  });
});

app.get('/inicio', requireAuth, (req, res) => {
  db.get('SELECT id, first_name, last_name, last_login_at, email, cpf, is_admin, balance_cents FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.redirect('/logout');
    const msg = req.query.msg || null;
    const error = req.query.error || null;
    const showAdmin = (user.is_admin === 1);
    const nowIso = new Date().toISOString();
  db.get('SELECT id, user_id, amount_cents, status, txid, qr_code, qr_code_base64, expires_at, created_at FROM deposits WHERE user_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY id DESC LIMIT 1', [user.id, 'pending', nowIso], (dErr, pendingDeposit) => {
      // Mostrar o QR apenas uma vez após criação
      let depositToShow = null;
      if (pendingDeposit && req.session.allowShowDepositOnce === true && req.session.lastDepositId === pendingDeposit.id) {
        depositToShow = pendingDeposit;
      }
      // Reset flag para próximos loads
      req.session.allowShowDepositOnce = false;
      res.render('inicio', { user, msg, error, showAdmin, pendingDeposit: depositToShow, pixKey: PIX_KEY });
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Utilitário: promover o usuário atual a admin (DESATIVADO PARA SEGURANÇA)
// Use o seed ou o painel admin para promover usuários.
app.get('/admin/grant-self', requireAuth, (req, res) => {
  return res.status(403).send('Funcionalidade desativada por segurança.');
});

// Configurações do usuário
app.post('/settings/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!validatePassword(newPassword)) {
    return res.redirect('/inicio?error=Senha fraca.');
  }
  db.get('SELECT password_hash FROM users WHERE id = ?', [req.session.userId], async (err, user) => {
    if (err || !user) return res.redirect('/logout');
    const ok = await bcrypt.compare(currentPassword || '', user.password_hash);
    if (!ok) return res.redirect('/inicio?error=Senha atual incorreta.');
    const hash = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.session.userId], () => {
      return res.redirect('/inicio?msg=Senha atualizada com sucesso.');
    });
  });
});

app.post('/settings/change-email', requireAuth, (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.redirect('/inicio?error=E-mail inválido.');
  }
  const token = randomToken();
  db.run('UPDATE users SET email = ?, email_verified = 0, email_verification_token = ? WHERE id = ?', [email, token, req.session.userId], (err) => {
    if (err) return res.redirect('/inicio?error=Erro ao atualizar e-mail.');
    const transport = getTransport();
    if (transport) {
      const verifyUrl = `${APP_URL}/verify-email?token=${encodeURIComponent(token)}`;
      transport.sendMail({
        from: SMTP_FROM,
        to: email,
        subject: 'Verifique seu novo e-mail',
        text: `Clique para verificar: ${verifyUrl}`,
        html: `<p>Clique para verificar: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
      }).catch(() => {});
    }
    return res.redirect('/inicio?msg=E-mail atualizado, verifique sua caixa de entrada.');
  });
});

app.post('/settings/delete-account', requireAuth, (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.session.userId], (err) => {
    if (err) return res.redirect('/inicio?error=Não foi possível excluir a conta.');
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  });
});

// Depósito via Pix: criar solicitação (mínimo R$ 1,00)
app.post('/deposit/create', requireAuth, (req, res) => {
  const raw = String(req.body.amount || '0').replace(/\./g, '').replace(',', '.');
  let value = Math.round(parseFloat(raw) * 100) || 0;
  if (value < 100) {
    return res.redirect('/inicio?error=Valor mínimo para depósito é R$ 1,00');
  }
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const txid = 'DEP-' + randomToken().slice(0, 10);
  // Gera payload e QR base64 conforme padrão BR Code (valor fixo)
  (async () => {
    try {
      const qrCodePix = QrCodePix({
        version: '01',
        key: PIX_KEY,
        name: PIX_NAME,
        city: PIX_CITY,
        message: `DEP ${txid}`,
        value: value / 100,
      });
      const payload = await qrCodePix.payload();
      const base64 = await qrCodePix.base64();
      db.run(
        'INSERT INTO deposits (user_id, amount_cents, status, txid, provider, provider_payment_id, qr_code, qr_code_base64, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [req.session.userId, value, 'pending', txid, 'local', null, payload, base64, expiresAt, now],
        function (err) {
          if (err) return res.redirect('/inicio?error=Falha ao criar depósito');
          try {
            req.session.lastDepositId = this.lastID;
            req.session.allowShowDepositOnce = true;
          } catch (_) {}
          return res.redirect('/inicio?msg=Depósito criado. Escaneie o QR para pagar.');
        }
      );
    } catch (e) {
      console.error('Erro gerando QR Pix', e);
      return res.redirect('/inicio?error=Falha ao gerar QR Pix');
    }
  })();
});

// DEV: Simular pagamento (apenas em desenvolvimento)
app.post('/deposit/:id/simulate-pay', requireAuth, (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(403).send('Forbidden in production');
  const depId = parseInt(req.params.id, 10);
  if (!Number.isInteger(depId)) return res.redirect('/inicio?error=ID inválido');
  
  db.get('SELECT * FROM deposits WHERE id = ? AND user_id = ? AND status = ?', [depId, req.session.userId, 'pending'], (err, dep) => {
    if (err || !dep) return res.redirect('/inicio?error=Depósito não encontrado');
    const now = new Date().toISOString();
    db.run('UPDATE deposits SET status = ?, paid_at = ? WHERE id = ?', ['paid', now, dep.id], (uErr) => {
      if (uErr) return res.redirect('/inicio?error=Erro ao atualizar');
      db.run('UPDATE users SET balance_cents = COALESCE(balance_cents,0) + ? WHERE id = ?', [dep.amount_cents, dep.user_id], (bErr) => {
        return res.redirect('/inicio?msg=Depósito simulado com sucesso!');
      });
    });
  });
});

// Webhook genérico para aprovação automática de depósitos
// Configure seu agregador (Pluggy/Belvo/etc) para enviar: { txid, amount_cents }
app.post('/webhook/pix', (req, res) => {
  const token = req.get('X-Webhook-Token') || req.query.token || (req.body && req.body.token);
  if (!WEBHOOK_TOKEN || token !== WEBHOOK_TOKEN) {
    return res.status(401).send('Unauthorized');
  }
  const { txid, amount_cents } = req.body || {};
  if (!txid || typeof amount_cents !== 'number') return res.status(400).send('Missing fields');
  const nowIso = new Date().toISOString();
  db.get('SELECT id, user_id, amount_cents, status, expires_at FROM deposits WHERE txid = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)', [txid, 'pending', nowIso], (err, dep) => {
    if (err || !dep) return res.status(404).send('Deposit not found');
    if (dep.amount_cents !== amount_cents) return res.status(400).send('Amount mismatch');
    const now = new Date().toISOString();
    db.run('UPDATE deposits SET status = ?, paid_at = ? WHERE id = ?', ['paid', now, dep.id], (uErr) => {
      if (uErr) return res.status(500).send('Failed to update deposit');
  db.run('UPDATE users SET balance_cents = COALESCE(balance_cents,0) + ? WHERE id = ?', [dep.amount_cents, dep.user_id], (bErr) => {
        if (bErr) return res.status(500).send('Failed to credit balance');
        return res.json({ ok: true });
      });
  });
});
});

// =============================
// Jogos
// =============================
function ensureAuthJson(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'auth_required' });
  next();
}

// Crash: iniciar
function handleCrashStart(req, res) {
  console.log('[crash] start called');
  const raw = String(req.body && req.body.amount || '').replace(/\./g, '').replace(/,/g, '.');
  let amount = Math.round(parseFloat(raw) * 100) || 0;
  if (amount < 100) return res.status(400).json({ error: 'min_bet_1_real' });
  db.get('SELECT id, balance_cents FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.status(500).json({ error: 'user_not_found' });
    if ((user.balance_cents || 0) < amount) return res.status(400).json({ error: 'insufficient_funds' });
    const createdAt = new Date().toISOString();
    // Ponto de crash aleatório entre 1.01x e 5.00x
    const crashPoint = Math.max(1.01, Math.round((1 + Math.random() * 4) * 100) / 100);
    const metadata = { crashPoint, startAt: createdAt };
    db.run('UPDATE users SET balance_cents = balance_cents - ? WHERE id = ?', [amount, user.id], (uErr) => {
      if (uErr) return res.status(500).json({ error: 'debit_failed' });
      db.run('INSERT INTO bets (user_id, game, amount_cents, state, created_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)', [user.id, 'crash', amount, 'in_progress', createdAt, JSON.stringify(metadata)], function (bErr) {
        if (bErr) return res.status(500).json({ error: 'bet_create_failed' });
        db.get('SELECT balance_cents FROM users WHERE id = ?', [user.id], (be, u2) => {
          res.json({ betId: this.lastID, crashPoint, balance_cents: u2 ? u2.balance_cents : null });
        });
      });
    });
  });
}
app.post('/games/crash/start', ensureAuthJson, handleCrashStart);
app.get('/games/crash/start', ensureAuthJson, handleCrashStart);

// Crash: cashout
app.post('/games/crash/cashout', ensureAuthJson, (req, res) => {
  const betId = req.body && req.body.betId;
  const atMultiplier = parseFloat(req.body && req.body.multiplier);
  if (!betId || !atMultiplier) return res.status(400).json({ error: 'missing_fields' });
  db.get('SELECT id, user_id, amount_cents, state, metadata_json FROM bets WHERE id = ? AND user_id = ?', [betId, req.session.userId], (err, bet) => {
    if (err || !bet) return res.status(404).json({ error: 'bet_not_found' });
    if (bet.state !== 'in_progress') return res.status(400).json({ error: 'bet_not_active' });
    let metadata; try { metadata = JSON.parse(bet.metadata_json || '{}'); } catch (_) { metadata = {}; }
    const crashPoint = metadata.crashPoint || 1.01;
    const finishedAt = new Date().toISOString();
    if (atMultiplier >= crashPoint) {
      // Crash aconteceu antes do cashout
      db.run('UPDATE bets SET state = ?, finished_at = ? WHERE id = ?', ['lose', finishedAt, bet.id], (uErr) => {
        if (uErr) return res.status(500).json({ error: 'update_failed' });
        db.get('SELECT balance_cents FROM users WHERE id = ?', [req.session.userId], (be, u2) => {
          res.json({ result: 'lose', crashPoint, balance_cents: u2 ? u2.balance_cents : null });
        });
      });
    } else {
      const payout = Math.round(bet.amount_cents * atMultiplier);
      db.run('UPDATE bets SET state = ?, payout_cents = ?, finished_at = ? WHERE id = ?', ['win', payout, finishedAt, bet.id], (uErr) => {
        if (uErr) return res.status(500).json({ error: 'update_failed' });
        db.run('UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?', [payout, bet.user_id], (cErr) => {
          if (cErr) return res.status(500).json({ error: 'credit_failed' });
          db.get('SELECT balance_cents FROM users WHERE id = ?', [req.session.userId], (be, u2) => {
            res.json({ result: 'win', crashPoint, payout_cents: payout, balance_cents: u2 ? u2.balance_cents : null });
          });
        });
      });
    }
  });
});

// Campo Minado: iniciar
app.post('/games/mines/start', ensureAuthJson, (req, res) => {
  let amount = Math.round(parseFloat(String(req.body && req.body.amount || '0').replace(/\./g, '').replace(/,/g, '.')) * 100) || 0;
  const bombs = Math.max(1, Math.min(20, parseInt(req.body && req.body.bombs || 3, 10)));
  if (amount < 100) return res.status(400).json({ error: 'min_bet_1_real' });
  db.get('SELECT id, balance_cents FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.status(500).json({ error: 'user_not_found' });
    if ((user.balance_cents || 0) < amount) return res.status(400).json({ error: 'insufficient_funds' });
    const createdAt = new Date().toISOString();
    const gridSize = 36;
    const bombsPos = new Set();
    while (bombsPos.size < bombs) bombsPos.add(Math.floor(Math.random() * gridSize));
    const metadata = { grid: 6, bombs, bombsPos: Array.from(bombsPos), revealed: [] };
    db.run('UPDATE users SET balance_cents = balance_cents - ? WHERE id = ?', [amount, user.id], (uErr) => {
      if (uErr) return res.status(500).json({ error: 'debit_failed' });
      db.run('INSERT INTO bets (user_id, game, amount_cents, state, created_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)', [user.id, 'mines', amount, 'in_progress', createdAt, JSON.stringify(metadata)], function (bErr) {
        if (bErr) return res.status(500).json({ error: 'bet_create_failed' });
        db.get('SELECT balance_cents FROM users WHERE id = ?', [user.id], (be, u2) => {
          res.json({ betId: this.lastID, balance_cents: u2 ? u2.balance_cents : null });
        });
      });
    });
  });
});

// Campo Minado: revelar célula
app.post('/games/mines/reveal', ensureAuthJson, (req, res) => {
  const betId = req.body && req.body.betId;
  const index = parseInt(req.body && req.body.index, 10);
  if (!betId || isNaN(index)) return res.status(400).json({ error: 'missing_fields' });
  db.get('SELECT id, user_id, amount_cents, state, metadata_json FROM bets WHERE id = ? AND user_id = ?', [betId, req.session.userId], (err, bet) => {
    if (err || !bet) return res.status(404).json({ error: 'bet_not_found' });
    if (bet.state !== 'in_progress') return res.status(400).json({ error: 'bet_not_active' });
    let md; try { md = JSON.parse(bet.metadata_json || '{}'); } catch (_) { md = {}; }
    if (!md.revealed) md.revealed = [];
    if (md.revealed.includes(index)) return res.json({ already: true });
    const isBomb = (md.bombsPos || []).includes(index);
    const finishedAt = new Date().toISOString();
    if (isBomb) {
      db.run('UPDATE bets SET state = ?, finished_at = ?, metadata_json = ? WHERE id = ?', ['lose', finishedAt, JSON.stringify(md), bet.id], (uErr) => {
        if (uErr) return res.status(500).json({ error: 'update_failed' });
        db.get('SELECT balance_cents FROM users WHERE id = ?', [req.session.userId], (be, u2) => {
          res.json({ boom: true, balance_cents: u2 ? u2.balance_cents : null });
        });
      });
    } else {
      md.revealed.push(index);
      // Multiplicador simples baseado em bombas e casas seguras abertas
      const safe = md.revealed.length;
      const multiplier = Math.round((1 + safe * (md.bombs / 36) * 1.2) * 100) / 100; // cresce com mais bombas
      db.run('UPDATE bets SET metadata_json = ? WHERE id = ?', [JSON.stringify(md), bet.id], (uErr) => {
        if (uErr) return res.status(500).json({ error: 'update_failed' });
        res.json({ boom: false, safe, potentialMultiplier: multiplier });
      });
    }
  });
});

// Campo Minado: encerrar e receber
app.post('/games/mines/cashout', ensureAuthJson, (req, res) => {
  const betId = req.body && req.body.betId;
  if (!betId) return res.status(400).json({ error: 'missing_fields' });
  db.get('SELECT id, user_id, amount_cents, state, metadata_json FROM bets WHERE id = ? AND user_id = ?', [betId, req.session.userId], (err, bet) => {
    if (err || !bet) return res.status(404).json({ error: 'bet_not_found' });
    if (bet.state !== 'in_progress') return res.status(400).json({ error: 'bet_not_active' });
    let md; try { md = JSON.parse(bet.metadata_json || '{}'); } catch (_) { md = {}; }
    const safe = (md.revealed || []).length;
    const multiplier = Math.round((1 + safe * (md.bombs / 36) * 1.2) * 100) / 100;
    const payout = Math.max(0, Math.round(bet.amount_cents * multiplier));
    const finishedAt = new Date().toISOString();
    db.run('UPDATE bets SET state = ?, payout_cents = ?, finished_at = ? WHERE id = ?', ['win', payout, finishedAt, bet.id], (uErr) => {
      if (uErr) return res.status(500).json({ error: 'update_failed' });
      db.run('UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?', [payout, bet.user_id], (cErr) => {
        if (cErr) return res.status(500).json({ error: 'credit_failed' });
        db.get('SELECT balance_cents FROM users WHERE id = ?', [req.session.userId], (be, u2) => {
          res.json({ result: 'win', payout_cents: payout, balance_cents: u2 ? u2.balance_cents : null });
        });
      });
    });
  });
});

// Slots: girar
app.post('/games/slots/spin', ensureAuthJson, (req, res) => {
  let amount = Math.round(parseFloat(String(req.body && req.body.amount || '0').replace(/\./g, '').replace(/,/g, '.')) * 100) || 0;
  if (amount < 100) return res.status(400).json({ error: 'min_bet_1_real' });
  db.get('SELECT id, balance_cents FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.status(500).json({ error: 'user_not_found' });
    if ((user.balance_cents || 0) < amount) return res.status(400).json({ error: 'insufficient_funds' });
    db.run('UPDATE users SET balance_cents = balance_cents - ? WHERE id = ?', [amount, user.id], (uErr) => {
      if (uErr) return res.status(500).json({ error: 'debit_failed' });
      const createdAt = new Date().toISOString();
      const n1 = 1 + Math.floor(Math.random() * 5);
      const n2 = 1 + Math.floor(Math.random() * 5);
      const n3 = 1 + Math.floor(Math.random() * 5);
      const win = (n1 === n2 && n2 === n3);
      const payout = win ? amount * 2 : 0;
      const state = win ? 'win' : 'lose';
      const md = { n1, n2, n3 };
      db.run('INSERT INTO bets (user_id, game, amount_cents, state, payout_cents, created_at, finished_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [user.id, 'slots', amount, state, payout, createdAt, createdAt, JSON.stringify(md)], (bErr) => {
        if (bErr) return res.status(500).json({ error: 'bet_create_failed' });
        function respond() {
          res.json({ n1, n2, n3, result: state, payout_cents: payout, balance_cents: userBalance });
        }
        let userBalance;
        if (payout > 0) {
          db.run('UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?', [payout, user.id], (cErr) => {
            if (cErr) return res.status(500).json({ error: 'credit_failed' });
            db.get('SELECT balance_cents FROM users WHERE id = ?', [user.id], (be, u2) => { userBalance = u2 ? u2.balance_cents : null; respond(); });
          });
        } else {
          db.get('SELECT balance_cents FROM users WHERE id = ?', [user.id], (be, u2) => { userBalance = u2 ? u2.balance_cents : null; respond(); });
        }
      });
    });
  });
});

const PORT = process.env.PORT || 3000;

// Seed de Admin e Start
function seedAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPass = process.env.ADMIN_PASSWORD;
  if (!adminEmail || !adminPass) return;

  db.get('SELECT id FROM users WHERE email = ?', [adminEmail], async (err, user) => {
    if (err) return;
    if (!user) {
      console.log(`[Seed] Criando admin inicial: ${adminEmail}`);
      const hash = await bcrypt.hash(adminPass, 10);
      const now = new Date().toISOString();
      // CPF Fictício para o admin de sistema (000...)
      const adminCpf = '000.000.000-00';
      db.run(
        'INSERT OR IGNORE INTO users (first_name, last_name, cpf, dob, email, password_hash, is_admin, balance_cents, created_at, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        ['Admin', 'System', adminCpf, '2000-01-01', adminEmail, hash, 1, 0, now, 1],
        (err) => {
          if (err) console.error('[Seed] Falha ao criar admin:', err.message);
          else console.log('[Seed] Admin criado com sucesso.');
        }
      );
    }
  });
}

app.listen(PORT, () => {
  console.log(`${BRAND_NAME} iniciado em ${APP_URL}`);
  seedAdmin();
});

// ---- Reconciliação Pluggy (polling) ----
// Usa as credenciais do .env para buscar transações e marcar depósitos como pagos
async function pluggyFetch(url, opts = {}) {
  // Usa fetch nativo se disponível; senão, importa node-fetch dinamicamente
  const f = (typeof fetch === 'function')
    ? fetch
    : ((...args) => import('node-fetch').then(({ default: nf }) => nf(...args)));
  return f(url, opts);
}

async function pluggyAuth() {
  if (!PLUGGY_CLIENT_ID || !PLUGGY_CLIENT_SECRET) return null;
  try {
    const res = await pluggyFetch(`${PLUGGY_BASE_URL}/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ clientId: PLUGGY_CLIENT_ID, clientSecret: PLUGGY_CLIENT_SECRET })
    });
    const data = await res.json().catch(async () => {
      const txt = await res.text().catch(() => '');
      return { _raw: txt };
    });
    const apiKey = data.apiKey || data.accessToken || data.access_token || null;
    if (!apiKey) {
      console.warn(`[pluggyAuth] status=${res.status} body=${JSON.stringify(data).slice(0,200)}`);
    }
    return apiKey || null;
  } catch (e) {
    console.warn('Pluggy auth falhou:', e.message);
    return null;
  }
}

async function pluggyGetAccounts(token) {
  if (!PLUGGY_ITEM_ID) return [];
  try {
    // Preferir endpoint por itemId
    const urlByItem = new URL(`${PLUGGY_BASE_URL}/accounts`);
    urlByItem.searchParams.set('itemId', PLUGGY_ITEM_ID);
    urlByItem.searchParams.set('page', '1');
    urlByItem.searchParams.set('pageSize', '100');
    let res = await pluggyFetch(urlByItem.toString(), { headers: { 'X-API-Key': token, Accept: 'application/json' } });
    let data = await res.json().catch(() => []);
    let accounts = Array.isArray(data) ? data : data.accounts || [];
    if (!accounts || accounts.length === 0) {
      // Fallback: endpoint aninhado
      res = await pluggyFetch(`${PLUGGY_BASE_URL}/items/${PLUGGY_ITEM_ID}/accounts`, {
        headers: { 'X-API-Key': token, Accept: 'application/json' }
      });
      data = await res.json().catch(() => []);
      accounts = Array.isArray(data) ? data : data.accounts || [];
    }
    return accounts || [];
  } catch (e) {
    console.warn('Pluggy accounts falhou:', e.message);
    return [];
  }
}

async function pluggyGetItem(token) {
  if (!PLUGGY_ITEM_ID) return null;
  try {
    const res = await pluggyFetch(`${PLUGGY_BASE_URL}/items/${PLUGGY_ITEM_ID}`, {
      headers: { 'X-API-Key': token, Accept: 'application/json' }
    });
    const data = await res.json().catch(() => ({}));
    return data;
  } catch (e) {
    console.warn('Pluggy item falhou:', e.message);
    return null;
  }
}

async function pluggyGetTransactions(token, accountId, fromIso, toIso) {
  try {
    const url = new URL(`${PLUGGY_BASE_URL}/accounts/${accountId}/transactions`);
    url.searchParams.set('from', fromIso);
    url.searchParams.set('to', toIso);
    url.searchParams.set('page', '1');
    url.searchParams.set('pageSize', '100');
    const res = await pluggyFetch(url.toString(), { headers: { 'X-API-Key': token, Accept: 'application/json' } });
    const data = await res.json().catch(() => ({ transactions: [] }));
    const txns = Array.isArray(data) ? data : data.transactions || [];
    return txns || [];
  } catch (e) {
    console.warn('Pluggy transactions falhou:', e.message);
    return [];
  }
}

async function pluggyGetItemTransactions(token, fromIso, toIso) {
  try {
    // Preferir endpoint por itemId
    const url = new URL(`${PLUGGY_BASE_URL}/transactions`);
    url.searchParams.set('itemId', PLUGGY_ITEM_ID);
    url.searchParams.set('from', fromIso);
    url.searchParams.set('to', toIso);
    url.searchParams.set('page', '1');
    url.searchParams.set('pageSize', '100');
    const res = await pluggyFetch(url.toString(), { headers: { 'X-API-Key': token, Accept: 'application/json' } });
    const data = await res.json().catch(() => ({ transactions: [] }));
    const txns = Array.isArray(data) ? data : data.transactions || [];
    return txns || [];
  } catch (e) {
    console.warn('Pluggy item transactions falhou:', e.message);
    return [];
  }
}

function normalizeAmountCents(val) {
  const n = Number(val);
  if (!isFinite(n)) return null;
  return Math.round(n * 100);
}

async function reconcilePluggyOnce() {
  if (!PLUGGY_CLIENT_ID || !PLUGGY_CLIENT_SECRET || !PLUGGY_ITEM_ID) return;
  const token = await pluggyAuth();
  if (!token) {
    console.warn('[reconcile] auth Pluggy falhou: token ausente');
    return;
  }
  const accounts = await pluggyGetAccounts(token);
  let useItemLevel = false;
  if (!accounts || accounts.length === 0) {
    console.warn('[reconcile] nenhuma conta retornada para ITEM_ID atual');
    const item = await pluggyGetItem(token);
    if (item) {
      console.warn(`[reconcile] item status=${item.status} institution=${item.institution && item.institution.name}`);
    }
    useItemLevel = true;
  } else {
    console.log(`[reconcile] início: contas=${accounts.length}`);
  }
  const toIso = new Date().toISOString();
  const fromIso = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(); // últimas 2h
  const nowIso = new Date().toISOString();
  // Buscar depósitos pendentes atuais para reduzir I/O
  db.all('SELECT id, user_id, amount_cents, status, txid, created_at, expires_at FROM deposits WHERE status = ? AND (expires_at IS NULL OR expires_at > ?)', ['pending', nowIso], async (err, pendingList) => {
    if (err || !pendingList || pendingList.length === 0) {
      return;
    }
    console.log(`[reconcile] pendentes=${pendingList.length}, janela=${fromIso}..${toIso}`);
    const pendings = pendingList;
    if (useItemLevel) {
      const txns = await pluggyGetItemTransactions(token, fromIso, toIso);
      console.log(`[reconcile] item txns=${txns.length}`);
      for (const t of txns) {
        try {
          const desc = String(t.description || t.descriptionRaw || '').toUpperCase();
          const status = String(t.status || '').toUpperCase();
          const isCredit = Number(t.amount || t.value || 0) > 0;
          if (!isCredit) continue;
          if (status && !['POSTED', 'SUCCESS'].includes(status)) continue;
          const cents = normalizeAmountCents(t.amount || t.value);
          if (cents == null) continue;
          // Tentar extrair um txid se vier na descrição (DEP <txid>)
          let foundTxid = null;
          const m = desc.match(/DEP\s+([A-Z0-9\-\.\_]+)/);
          if (m && m[1]) foundTxid = m[1];
          // endToEndId/identificadores
          const endToEnd = t.endToEndId || t.externalId || t.identifier || t.reference || null;
          // Estratégia de matching: preferir txid, senão por valor único
          let match = null;
          if (foundTxid) {
            match = pendings.find((d) => d.txid && String(d.txid).toUpperCase() === foundTxid);
          }
          if (!match && endToEnd) {
            match = pendings.find((d) => d.txid && String(d.txid).toUpperCase() === String(endToEnd).toUpperCase());
          }
          if (!match) {
            const sameAmount = pendings.filter((d) => d.amount_cents === cents);
            if (sameAmount.length === 1) match = sameAmount[0];
          }
          if (!match) {
            // Heurística temporal: escolher depósito por valor com data de criação mais próxima
            const sameAmountMany = pendings.filter((d) => d.amount_cents === cents);
            if (sameAmountMany.length > 1) {
              sameAmountMany.sort((a, b) => {
                const at = new Date(a.created_at).getTime();
                const bt = new Date(b.created_at).getTime();
                const tt = new Date(t.date || t.postDate || Date.now()).getTime();
                return Math.abs(at - tt) - Math.abs(bt - tt);
              });
              match = sameAmountMany[0];
            }
          }
          if (!match) continue;
          // Atualiza depósito e credita
          const paidAt = new Date().toISOString();
          db.run('UPDATE deposits SET status = ?, paid_at = ? WHERE id = ?', ['paid', paidAt, match.id], (uErr) => {
            if (uErr) return;
            db.run('UPDATE users SET balance_cents = COALESCE(balance_cents,0) + ? WHERE id = ?', [match.amount_cents, match.user_id], () => {});
          });
          console.log(`[reconcile] reconhecido depId=${match.id} user=${match.user_id} valor=${match.amount_cents} cents via item desc="${desc}" txidEncontrado=${foundTxid || 'N/A'} endToEnd=${endToEnd || 'N/A'} status=${status || 'N/A'}`);
        } catch (_) {}
      }
    } else {
      for (const acc of accounts) {
        const accId = acc.id || acc.accountId || acc._id || acc.uuid;
        if (!accId) continue;
        const txns = await pluggyGetTransactions(token, accId, fromIso, toIso);
        console.log(`[reconcile] conta=${accId} txns=${txns.length}`);
        for (const t of txns) {
          try {
            const desc = String(t.description || t.descriptionRaw || '').toUpperCase();
            const status = String(t.status || '').toUpperCase();
            const isCredit = Number(t.amount || t.value || 0) > 0;
            if (!isCredit) continue;
            if (status && !['POSTED', 'SUCCESS'].includes(status)) continue;
            const cents = normalizeAmountCents(t.amount || t.value);
            if (cents == null) continue;
            let foundTxid = null;
            const m = desc.match(/DEP\s+([A-Z0-9\-\.\_]+)/);
            if (m && m[1]) foundTxid = m[1];
            const endToEnd = t.endToEndId || t.externalId || t.identifier || t.reference || null;
            let match = null;
            if (foundTxid) {
              match = pendings.find((d) => d.txid && String(d.txid).toUpperCase() === foundTxid);
            }
            if (!match && endToEnd) {
              match = pendings.find((d) => d.txid && String(d.txid).toUpperCase() === String(endToEnd).toUpperCase());
            }
            if (!match) {
              const sameAmount = pendings.filter((d) => d.amount_cents === cents);
              if (sameAmount.length === 1) match = sameAmount[0];
            }
            if (!match) {
              const sameAmountMany = pendings.filter((d) => d.amount_cents === cents);
              if (sameAmountMany.length > 1) {
                sameAmountMany.sort((a, b) => {
                  const at = new Date(a.created_at).getTime();
                  const bt = new Date(b.created_at).getTime();
                  const tt = new Date(t.date || t.postDate || Date.now()).getTime();
                  return Math.abs(at - tt) - Math.abs(bt - tt);
                });
                match = sameAmountMany[0];
              }
            }
            if (!match) continue;
            const paidAt = new Date().toISOString();
            db.run('UPDATE deposits SET status = ?, paid_at = ? WHERE id = ?', ['paid', paidAt, match.id], (uErr) => {
              if (uErr) return;
              db.run('UPDATE users SET balance_cents = COALESCE(balance_cents,0) + ? WHERE id = ?', [match.amount_cents, match.user_id], () => {});
            });
            console.log(`[reconcile] reconhecido depId=${match.id} user=${match.user_id} valor=${match.amount_cents} cents via conta=${accId} desc="${desc}" txidEncontrado=${foundTxid || 'N/A'} endToEnd=${endToEnd || 'N/A'} status=${status || 'N/A'}`);
          } catch (_) {}
        }
      }
    }
  });
}

// Executa a cada 60s, se credenciais estiverem presentes
setInterval(() => {
  try { reconcilePluggyOnce(); } catch (e) { /* noop */ }
}, 60000);

// Endpoint manual para forçar reconciliação imediata
app.post('/admin/reconcile-now', requireAdmin, async (req, res) => {
  try {
    await reconcilePluggyOnce();
    return res.redirect('/admin?msg=Reconciliação executada');
  } catch (e) {
    return res.redirect('/admin?error=Falha na reconciliação');
  }
});

// Endpoint de debug: status do Pluggy (item, contas, transações na janela)
app.get('/admin/pluggy-status', requireAdmin, async (req, res) => {
  try {
    const token = await pluggyAuth();
    if (!token) return res.status(500).json({ error: 'Falha na autenticação Pluggy' });
    const item = await pluggyGetItem(token);
    const accounts = await pluggyGetAccounts(token);
    const toIso = new Date().toISOString();
    const fromIso = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    const itemTxns = await pluggyGetItemTransactions(token, fromIso, toIso);
    return res.json({
      item,
      accountsCount: accounts ? accounts.length : 0,
      accountsIds: (accounts || []).map((a) => a.id || a.accountId || a._id || a.uuid),
      itemTransactionsCount: itemTxns ? itemTxns.length : 0,
      sampleItemTransactions: (itemTxns || []).slice(0, 5).map((t) => ({
        amount: t.amount || t.value,
        status: t.status,
        description: t.description || t.descriptionRaw,
        endToEndId: t.endToEndId || t.externalId || t.identifier || t.reference || null,
        date: t.date || t.postDate || null,
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Erro interno' });
  }
});
function getTransport() {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

function randomToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}
// Helper: exigir admin
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  db.get('SELECT is_admin FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.redirect('/logout');
    const isAdmin = user.is_admin === 1;
    if (!isAdmin) return res.status(403).send('Acesso negado');
    req.isAdmin = true;
    next();
  });
}
// Admin: painel
app.get('/admin', requireAdmin, (req, res) => {
  db.all('SELECT id, first_name, last_name, cpf, email, created_at, is_admin, balance_cents FROM users ORDER BY created_at DESC', [], (err, users) => {
    if (err) return res.status(500).send('Erro ao carregar usuários');
    const qIdStr = String(req.query.userId || '').trim();
    const renderWithDeposits = (selectedUser, selectedUserId) => {
      const nowIso = new Date().toISOString();
      db.all('SELECT d.id, d.user_id, d.amount_cents, d.txid, d.created_at, u.first_name, u.last_name, u.cpf FROM deposits d JOIN users u ON u.id = d.user_id WHERE d.status = ? AND (d.expires_at IS NULL OR d.expires_at > ?) ORDER BY d.created_at DESC LIMIT 20', ['pending', nowIso], (dErr, pendingDeposits) => {
        return res.render('admin', { users, selectedUser, selectedUserId, pendingDeposits: pendingDeposits || [], msg: null, error: null });
      });
    };
    if (qIdStr) {
      db.get('SELECT id, first_name, last_name, cpf, email, is_admin, balance_cents FROM users WHERE id = ?', [qIdStr], (err2, sel) => {
        const selectedUser = (err2 ? null : sel) || null;
        return renderWithDeposits(selectedUser, qIdStr);
      });
    } else {
      return renderWithDeposits(null, null);
    }
  });
});

// Admin: ajustar saldo
app.post('/admin/adjust-balance', requireAdmin, (req, res) => {
  const { userId, amount, op } = req.body;
  const num = String(amount || '0').replace(/\./g, '').replace(',', '.');
  const value = Math.round(parseFloat(num) * 100) || 0;
  const delta = op === 'remove' ? -value : value;
  db.run('UPDATE users SET balance_cents = COALESCE(balance_cents,0) + ? WHERE id = ?', [delta, userId], (err) => {
    if (err) return res.redirect('/admin?error=Falha ao ajustar saldo');
    return res.redirect('/admin?msg=Saldo atualizado');
  });
});

// Admin: conceder admin por CPF
app.post('/admin/grant-admin', requireAdmin, (req, res) => {
  const { cpf } = req.body;
  const clean = String(cpf || '').replace(/\D/g, '');
  db.run('UPDATE users SET is_admin = 1 WHERE cpf = ?', [clean], function (err) {
    if (err || this.changes === 0) return res.redirect('/admin?error=CPF não encontrado');
    return res.redirect('/admin?msg=Permissão de administrador concedida');
  });
});

app.post('/admin/revoke-admin', requireAdmin, (req, res) => {
  const { cpf } = req.body;
  const clean = String(cpf || '').replace(/\D/g, '');
  db.run('UPDATE users SET is_admin = 0 WHERE cpf = ?', [clean], function (err) {
    if (err || this.changes === 0) return res.redirect('/admin?error=CPF não encontrado');
    return res.redirect('/admin?msg=Permissão de administrador removida');
  });
});

// Admin: marcar depósito como pago manualmente
app.post('/admin/deposits/:id/mark-paid', requireAdmin, (req, res) => {
  const depId = parseInt(req.params.id, 10);
  if (!Number.isInteger(depId)) return res.redirect('/admin?error=ID de depósito inválido');
  const nowIso = new Date().toISOString();
  db.get(
    'SELECT id, user_id, amount_cents, status, expires_at FROM deposits WHERE id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)',
    [depId, 'pending', nowIso],
    (err, dep) => {
      if (err || !dep) return res.redirect('/admin?error=Depósito não encontrado ou expirado');
      const paidAt = new Date().toISOString();
      db.run('UPDATE deposits SET status = ?, paid_at = ? WHERE id = ?', ['paid', paidAt, dep.id], (uErr) => {
        if (uErr) return res.redirect('/admin?error=Falha ao atualizar depósito');
        db.run('UPDATE users SET balance_cents = COALESCE(balance_cents,0) + ? WHERE id = ?', [dep.amount_cents, dep.user_id], (bErr) => {
          if (bErr) return res.redirect('/admin?error=Falha ao creditar saldo');
          return res.redirect(`/admin?msg=Depósito #${dep.id} marcado como pago`);
        });
      });
    }
  );
});

// Admin: atualizar dados básicos (nome, email, senha opcional)
app.post('/admin/update-user', requireAdmin, async (req, res) => {
  const { userId, firstName, lastName, email, password } = req.body;
  if (!firstName || !lastName) return res.redirect('/admin?error=Nome e sobrenome são obrigatórios');
  const updates = [firstName.trim(), lastName.trim(), email || null, userId];
  db.run('UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?', updates, async (err) => {
    if (err) return res.redirect('/admin?error=Erro ao atualizar dados');
    if (password && !validatePassword(password)) {
      return res.redirect('/admin?error=Senha fraca para atualização');
    }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, userId], (err2) => {
        if (err2) return res.redirect('/admin?error=Erro ao atualizar senha');
        return res.redirect('/admin?msg=Usuário atualizado');
      });
    } else {
      return res.redirect('/admin?msg=Usuário atualizado');
    }
  });
});

// Admin: excluir usuário
app.post('/admin/delete-user', requireAdmin, (req, res) => {
  const { userId } = req.body;
  db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
    if (err) return res.redirect('/admin?error=Falha ao excluir usuário');
    return res.redirect('/admin?msg=Usuário excluído');
  });
});

// Admin: criar usuário
app.post('/admin/create-user', requireAdmin, async (req, res) => {
  const { firstName, lastName, cpf, dob, email, password, isAdmin } = req.body;
  const cleanCpf = String(cpf || '').replace(/\D/g, '');
  if (!firstName || !lastName || !validateCPF(cleanCpf) || !isAdult(dob) || !validatePassword(password)) {
    return res.redirect('/admin?error=Dados inválidos para criação');
  }
  db.get('SELECT id FROM users WHERE cpf = ?', [cleanCpf], async (err, existing) => {
    if (err) return res.redirect('/admin?error=Erro ao verificar CPF');
    if (existing) return res.redirect('/admin?error=CPF já cadastrado');
    try {
      const passwordHash = await bcrypt.hash(password, 10);
      const now = new Date().toISOString();
      db.run(
        'INSERT INTO users (first_name, last_name, cpf, dob, email, password_hash, created_at, is_admin, balance_cents) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
        [firstName.trim(), lastName.trim(), cleanCpf, dob, email || null, passwordHash, now, isAdmin ? 1 : 0],
        (insertErr) => {
          if (insertErr) return res.redirect('/admin?error=Erro ao criar usuário');
          return res.redirect('/admin?msg=Usuário criado');
        }
      );
    } catch (e) {
      return res.redirect('/admin?error=Erro interno ao criar usuário');
    }
  });
});
// Página do Crash
app.get('/games/crash', requireAuth, (req, res) => {
  db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.redirect('/logout');
    const msg = req.query.msg || null;
    const error = req.query.error || null;
    const showAdmin = (user.is_admin === 1);
    res.render('game_crash', { user, msg, error, showAdmin });
  });
});
