const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);

// Segredos dos tokens
const ACCESS_TOKEN_SECRET = "access_secret";
const REFRESH_TOKEN_SECRET = "refresh_secret";

// Base fictícia de usuários
const USERS = [
  {
    id: 1,
    username: "Alan",
    email: "alan@gmail.com",
    password: "123456",
    roles: [2001, 1984, 5150],
  },
  {
    id: 2,
    username: "Ronaldo",
    email: "ronaldo@gmail.com",
    password: "123456",
    roles: [2001],
  },
  {
    id: 3,
    username: "Carlos",
    email: "carlos@gmail.com",
    password: "123456",
    roles: [2001, 1984],
  },
];

// Função utilitária para gerar tokens
const generateTokens = (user) => {
  const payload = {
    id: user.id,
    username: user.username,
    email: user.email,
  };

  const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
    expiresIn: "10m",
  });

  const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

// Middleware para autenticar com access token
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, ACCESS_TOKEN_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
};

// Login
app.post("/auth/login", (req, res) => {
  const { user: email, pwd: password } = req.body;

  const user = USERS.find((u) => u.email === email && u.password === password);

  if (!user) {
    return res.status(401).json({ message: "Credenciais inválidas" });
  }

  const { accessToken, refreshToken } = generateTokens(user);

  // Cookie com o refresh token
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    sameSite: "Lax",
    secure: false, // colocar true em produção com HTTPS
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 dias
  });

  return res.json({
    accessToken,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles,
    },
  });
});

// Refresh Token
app.post("/auth/refresh", (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.sendStatus(401);

  try {
    const user = jwt.verify(token, REFRESH_TOKEN_SECRET);
    const { accessToken } = generateTokens(user);
    return res.json({
      accessToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        roles: user.roles,
      },
    });
  } catch (err) {
    return res.sendStatus(403);
  }
});

// Logout
app.post("/auth/logout", (req, res) => {
  res.clearCookie("jwt", {
    httpOnly: true,
    sameSite: "Lax",
    secure: false,
  });
  res.sendStatus(204);
});

//  Rota protegida para listar usuários
app.get("/users", authenticate, (req, res) => {
  const usersFilter = USERS.map(({ password, roles, ...user }) => user);
  res.json(usersFilter);
});

// Verifica se o refresh token ainda é válido e retorna dados do usuário
app.get("/auth/me", (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.sendStatus(401); // Não autenticado

  try {
    const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET);
    const user = USERS.find((u) => u.id === decoded.id);
    if (!user) return res.sendStatus(404);

    // Gera novo accessToken seguro
    const accessToken = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      ACCESS_TOKEN_SECRET,
      { expiresIn: "10m" }
    );

    const { id, username, email, roles } = user;
    res.json({ user: { id, username, email, roles }, accessToken });
  } catch (err) {
    return res.sendStatus(403);
  }
});

// Inicialização
app.listen(3001, () =>
  console.log("✅ Backend rodando em http://localhost:3001")
);
