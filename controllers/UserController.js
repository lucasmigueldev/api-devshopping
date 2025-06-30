import User from '../models/User.js';
import bcrypt from 'bcrypt';

export const createUser = async (req, res) => {
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
};
