import User from '../models/User.js';
import bcrypt from 'bcrypt';

export const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha são obrigatórios.' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Senha incorreta.' });

    res.status(200).json({ message: 'Login realizado com sucesso!', userId: user._id, email: user.email });
  } catch (error) {
    res.status(500).json({ error: 'Erro no login.', detalhes: error.message });
  }
};
