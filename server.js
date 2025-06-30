import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log('Conectado ao MongoDB'))
  .catch((error) => console.error('Erro ao conectar', error));

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// Signup (criar usuário)
app.post('/users', async (req, res) => {
  const { email, password } = req.body;

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Senha inválida ou não informada.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ email: newUser.email, _id: newUser._id });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar usuário...', detalhes: error.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Email e senha são obrigatórios.' });

  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) return res.status(401).json({ error: 'Senha incorreta.' });

    // Criar token JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Login realizado com sucesso!',
      token,
      userId: user._id,
      email: user.email,
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro no login.', detalhes: error.message });
  }
});

// Middleware para rotas protegidas
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // O token geralmente vem no formato "Bearer token"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token não fornecido.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido.' });
    req.user = user;
    next();
  });
}

// Exemplo de rota protegida
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: `Bem-vindo, usuário ${req.user.email}!`, user: req.user });
});

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
