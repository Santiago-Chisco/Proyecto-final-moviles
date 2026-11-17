const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'uniminuto-secret-cambiar';
const IVA = 0.19, ENVIO = 8000;
const DB_FILE = path.join(__dirname, 'db.json');

let db = { users: [], resets: [], orders: [] };
if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

const P = (id, name, category, price, description) => ({
  id, name, category, price, description,
  image: `https://picsum.photos/seed/prod${id}/600/600`,
});
const products = [
  P(1, 'Camiseta básica', 'Ropa', 39900, 'Camiseta de algodón 100% suave y cómoda, ideal para el día a día.'),
  P(2, 'Chaqueta jean', 'Ropa', 129900, 'Chaqueta de jean clásica con cierre de botones y bolsillos frontales.'),
  P(3, 'Zapatillas urbanas', 'Ropa', 189900, 'Zapatillas ligeras con suela antideslizante para uso diario.'),
  P(4, 'Audífonos Bluetooth', 'Electrónica', 149900, 'Audífonos inalámbricos con cancelación de ruido y 20 h de batería.'),
  P(5, 'Smartwatch Fit', 'Electrónica', 219900, 'Reloj inteligente con monitor cardíaco, GPS y resistencia al agua.'),
  P(6, 'Parlante portátil', 'Electrónica', 99900, 'Parlante Bluetooth resistente al agua con sonido de 360°.'),
  P(7, 'Cargador rápido 30W', 'Electrónica', 59900, 'Cargador USB-C de carga rápida compatible con celulares y tablets.'),
  P(8, 'Lámpara de escritorio', 'Hogar', 69900, 'Lámpara LED con tres niveles de brillo y brazo flexible.'),
  P(9, 'Set de sábanas', 'Hogar', 119900, 'Set de sábanas de microfibra para cama doble, 4 piezas.'),
  P(10, 'Cafetera eléctrica', 'Hogar', 159900, 'Cafetera de goteo con capacidad para 12 tazas y temporizador.'),
  P(11, 'Balón de fútbol', 'Deportes', 79900, 'Balón profesional tamaño 5, costuras reforzadas.'),
  P(12, 'Mat de yoga', 'Deportes', 54900, 'Mat antideslizante de 6 mm con correa para transporte.'),
];

const app = express();
app.use(cors());
app.use(express.json());

const fail = (res, code, error, field) => res.status(code).json({ error, field });
const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const pub = (u) => ({ id: u.id, nombre: u.nombre, apellidos: u.apellidos, username: u.username, email: u.email });
const sign = (u) => jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' });
const s = (v) => (typeof v === 'string' ? v.trim() : '');

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const { id } = jwt.verify(token, SECRET);
    req.user = db.users.find((u) => u.id === id);
    if (!req.user) throw new Error('no user');
    next();
  } catch (e) {
    fail(res, 401, 'Sesión inválida o expirada');
  }
}

// ---------- Autenticación ----------
app.post('/api/auth/register', (req, res) => {
  const nombre = s(req.body.nombre), apellidos = s(req.body.apellidos);
  const username = s(req.body.username), email = s(req.body.email).toLowerCase();
  const password = req.body.password || '';
  if (!nombre || !apellidos || !username || !email || !password) return fail(res, 400, 'Todos los campos son obligatorios');
  if (!emailRx.test(email)) return fail(res, 400, 'Correo no válido', 'email');
  if (password.length < 8) return fail(res, 400, 'La contraseña debe tener mínimo 8 caracteres', 'password');
  if (db.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) return fail(res, 409, 'El username ya está en uso', 'username');
  if (db.users.some((u) => u.email === email)) return fail(res, 409, 'El correo ya está registrado', 'email');
  const user = { id: String(Date.now()), nombre, apellidos, username, email, hash: bcrypt.hashSync(password, 10) };
  db.users.push(user);
  save();
  res.status(201).json({ user: pub(user) });
});

app.get('/api/auth/check-username', (req, res) => {
  const u = s(req.query.username).toLowerCase();
  res.json({ available: !db.users.some((x) => x.username.toLowerCase() === u) });
});

app.post('/api/auth/login', (req, res) => {
  const id = s(req.body.identifier).toLowerCase();
  const user = db.users.find((u) => u.username.toLowerCase() === id || u.email === id);
  if (!user || !bcrypt.compareSync(req.body.password || '', user.hash)) return fail(res, 401, 'Credenciales incorrectas');
  res.json({ token: sign(user), user: pub(user) });
});

// Recuperación: genera un código de 6 dígitos y lo "envía" por correo.
// Sin SMTP configurado, el código se imprime en la consola del servidor
// y se devuelve en `devCode` para poder hacer la demo.
app.post('/api/auth/forgot', (req, res) => {
  const email = s(req.body.email).toLowerCase();
  const user = db.users.find((u) => u.email === email);
  let devCode;
  if (user) {
    devCode = String(Math.floor(100000 + Math.random() * 900000));
    db.resets = db.resets.filter((r) => r.email !== email);
    db.resets.push({ email, code: devCode, exp: Date.now() + 15 * 60 * 1000 });
    save();
    console.log(`[RECUPERACIÓN] Código para ${email}: ${devCode}`);
  }
  res.json({ message: 'Si el correo existe, se envió un código de recuperación.', devCode });
});

app.post('/api/auth/reset', (req, res) => {
  const email = s(req.body.email).toLowerCase();
  const r = db.resets.find((x) => x.email === email && x.code === s(req.body.code) && x.exp > Date.now());
  if (!r) return fail(res, 400, 'Código inválido o vencido', 'code');
  if ((req.body.password || '').length < 8) return fail(res, 400, 'La contraseña debe tener mínimo 8 caracteres', 'password');
  const user = db.users.find((u) => u.email === email);
  user.hash = bcrypt.hashSync(req.body.password, 10);
  db.resets = db.resets.filter((x) => x !== r);
  save();
  res.json({ message: 'Contraseña actualizada' });
});

// ---------- Perfil ----------
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));

app.put('/api/me', auth, (req, res) => {
  const nombre = s(req.body.nombre), apellidos = s(req.body.apellidos), username = s(req.body.username);
  if (!nombre || !apellidos || username.length < 3) return fail(res, 400, 'Datos inválidos');
  if (db.users.some((u) => u.id !== req.user.id && u.username.toLowerCase() === username.toLowerCase()))
    return fail(res, 409, 'El username ya está en uso', 'username');
  Object.assign(req.user, { nombre, apellidos, username });
  save();
  res.json(pub(req.user));
});

app.put('/api/me/password', auth, (req, res) => {
  if (!bcrypt.compareSync(req.body.actual || '', req.user.hash)) return fail(res, 400, 'La contraseña actual es incorrecta');
  if ((req.body.nueva || '').length < 8) return fail(res, 400, 'La nueva contraseña debe tener mínimo 8 caracteres');
  req.user.hash = bcrypt.hashSync(req.body.nueva, 10);
  save();
  res.json({ message: 'Contraseña actualizada' });
});

// ---------- Productos ----------
app.get('/api/products', (req, res) => {
  const { category, q } = req.query;
  let list = products;
  if (category && category !== 'Todos') list = list.filter((p) => p.category === category);
  if (q) list = list.filter((p) => p.name.toLowerCase().includes(String(q).toLowerCase()));
  res.json(list);
});

app.get('/api/products/:id', (req, res) => {
  const p = products.find((x) => x.id === Number(req.params.id));
  p ? res.json(p) : fail(res, 404, 'Producto no encontrado');
});

// ---------- Pedidos (simulación de compra) ----------
app.post('/api/orders', auth, (req, res) => {
  const items = [];
  for (const it of req.body.items || []) {
    const p = products.find((x) => x.id === Number(it.productId));
    const qty = Math.max(1, parseInt(it.qty, 10) || 1);
    if (p) items.push({ productId: p.id, name: p.name, price: p.price, qty });
  }
  if (!items.length) return fail(res, 400, 'El carrito está vacío');
  const subtotal = items.reduce((a, i) => a + i.price * i.qty, 0);
  const iva = Math.round(subtotal * IVA);
  const total = subtotal + iva + ENVIO;
  const order = { id: db.orders.length + 1, userId: req.user.id, date: new Date().toISOString(), items, subtotal, iva, envio: ENVIO, total };
  db.orders.push(order);
  save();
  res.status(201).json(order);
});

app.get('/api/orders', auth, (req, res) =>
  res.json(db.orders.filter((o) => o.userId === req.user.id).reverse()));

app.listen(PORT, '0.0.0.0', () => console.log(`API lista en http://localhost:${PORT}/api`));
