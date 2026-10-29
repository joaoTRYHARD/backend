const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Configurações: troque a senha pela do seu MySQL
const DB = { host: 'localhost', user: 'root', password: '', database: 'csdr' };
const SEGREDO = 'troque-este-segredo';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(require('path').join(__dirname, '..')));


const db = mysql.createPool({ ...DB, decimalNumbers: true });

// ---------- Funções de apoio ----------
const tratar = (fn) => (req, res) =>
  fn(req, res).catch((err) => {
    console.error(err);
    res.status(500).json({ erro: 'Erro no servidor.' });
  });

function logado(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.usuario = jwt.verify(token, SEGREDO);
    next();
  } catch {
    res.status(401).json({ erro: 'Sessão inválida. Faça login novamente.' });
  }
}

function soAdmin(req, res, next) {
  if (req.usuario.perfil !== 'admin') {
    return res.status(403).json({ erro: 'Apenas administradores.' });
  }
  next();
}

// ---------- Cadastro e login ----------
app.post('/cadastro', tratar(async (req, res) => {
  const { nome, senha } = req.body;
  const email = (req.body.email || '').trim().toLowerCase();

  if (!nome || !email || !senha || senha.length < 6) {
    return res.status(400).json({ erro: 'Preencha tudo (senha com no mínimo 6 caracteres).' });
  }

  const [existe] = await db.query('SELECT id FROM usuarios WHERE email = ?', [email]);
  if (existe.length > 0) {
    return res.status(409).json({ erro: 'Este e-mail já está cadastrado.' });
  }

  const senhaHash = await bcrypt.hash(senha, 10);
  await db.query(
    'INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)',
    [nome, email, senhaHash]
  );
  res.status(201).json({ ok: true });
}));

app.post('/login', tratar(async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const [linhas] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
  const usuario = linhas[0];

  if (!usuario || !(await bcrypt.compare(req.body.senha || '', usuario.senha_hash))) {
    return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
  }

  const token = jwt.sign({ id: usuario.id, perfil: usuario.perfil }, SEGREDO, { expiresIn: '2h' });
  res.json({ token });
}));

app.get('/me', logado, tratar(async (req, res) => {
  const [linhas] = await db.query(
    'SELECT id, nome, email, perfil FROM usuarios WHERE id = ?',
    [req.usuario.id]
  );
  if (linhas.length === 0) {
    return res.status(401).json({ erro: 'Usuário não encontrado.' });
  }

  const [aceites] = await db.query(
    'SELECT id FROM consentimentos WHERE usuario_id = ? LIMIT 1',
    [req.usuario.id]
  );
  res.json({ ...linhas[0], consentimento: aceites.length > 0 });
}));

// ---------- Consentimento (LGPD) ----------
app.post('/consentimento', logado, tratar(async (req, res) => {
  await db.query(
    'INSERT INTO consentimentos (usuario_id, versao_termo) VALUES (?, ?)',
    [req.usuario.id, req.body.versao || '1.0']
  );
  res.status(201).json({ ok: true });
}));

// ---------- Aplicativos ----------
app.get('/apps', logado, tratar(async (req, res) => {
  const busca = req.query.busca || '';
  const [linhas] = await db.query(
    'SELECT * FROM aplicativos WHERE nome LIKE ? ORDER BY nome',
    [`%${busca}%`]
  );
  res.json(linhas);
}));

app.post('/apps', logado, soAdmin, tratar(async (req, res) => {
  const { nome, espaco, ram, cpu } = req.body;
  if (!nome || espaco == null || ram == null || !cpu) {
    return res.status(400).json({ erro: 'Preencha todos os campos obrigatórios.' });
  }

  await db.query(
    'INSERT INTO aplicativos (nome, espaco, ram, cpu) VALUES (?, ?, ?, ?)',
    [nome, espaco, ram, cpu]
  );
  res.status(201).json({ ok: true });
}));

app.delete('/apps/:id', logado, soAdmin, tratar(async (req, res) => {
  await db.query('DELETE FROM aplicativos WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
}));

// ---------- Histórico ----------
app.get('/historico', logado, tratar(async (req, res) => {
  const [linhas] = await db.query(
    `SELECT d.id, a.nome, d.compativel, d.feito_em
     FROM diagnosticos d
     JOIN aplicativos a ON a.id = d.aplicativo_id
     WHERE d.usuario_id = ?
     ORDER BY d.feito_em DESC, d.id DESC`,
    [req.usuario.id]
  );
  res.json(linhas);
}));

app.post('/historico', logado, tratar(async (req, res) => {
  await db.query(
    'INSERT INTO diagnosticos (usuario_id, aplicativo_id, compativel) VALUES (?, ?, ?)',
    [req.usuario.id, req.body.aplicativo_id, req.body.compativel]
  );
  res.status(201).json({ ok: true });
}));

app.delete('/historico', logado, tratar(async (req, res) => {
  await db.query('DELETE FROM diagnosticos WHERE usuario_id = ?', [req.usuario.id]);
  res.json({ ok: true });
}));

// ---------- Início ----------
async function criarAdmin() {
  const [linhas] = await db.query('SELECT id FROM usuarios WHERE email = ?', ['admin@csdr.com']);
  if (linhas.length > 0) return;

  await db.query(
    'INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES (?, ?, ?, ?)',
    ['Administrador', 'admin@csdr.com', await bcrypt.hash('admin123', 10), 'admin']
  );
}

criarAdmin()
  .then(() => app.listen(3000, () => console.log('Servidor rodando em http://localhost:3000')))
  .catch((err) => console.error('Erro ao conectar no MySQL:', err.message));
