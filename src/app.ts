import express, { type NextFunction, type Request, type Response } from "express";
import { Prisma } from "@prisma/client";
import { config } from "./config.js";
import { createAccessToken, createRefreshToken, hashPassword, hashToken, verifyAccessToken, verifyPassword } from "./auth.js";
import { openApiDocument } from "./openapi.js";
import { prisma } from "./prisma.js";

type AuthRequest = Request & { userId?: string };
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isObject = (body: unknown): body is Record<string, unknown> => typeof body === "object" && body !== null && !Array.isArray(body);
const userDto = (user: { id: string; name: string; email: string; createdAt: Date }) => ({ ...user, createdAt: user.createdAt.toISOString() });

const authenticate = (req: AuthRequest, res: Response, next: NextFunction) => {
  const [scheme, token] = req.header("authorization")?.split(" ") ?? [];
  const userId = scheme?.toLowerCase() === "bearer" && token ? verifyAccessToken(token) : null;
  if (!userId) return res.status(401).json({ error: "Não autenticado." });
  req.userId = userId;
  next();
};

async function createSession(user: { id: string; name: string; email: string; createdAt: Date }) {
  const refreshToken = createRefreshToken();
  await prisma.refreshSession.create({ data: { userId: user.id, tokenHash: hashToken(refreshToken), expiresAt: new Date(Date.now() + config.refreshTokenTtlDays * 86_400_000) } });
  return { user: userDto(user), accessToken: createAccessToken(user.id), refreshToken };
}

export const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "16kb" }));
app.get("/health", (_req, res) => res.json({ status: "ok" }));
app.get("/openapi.json", (_req, res) => res.json(openApiDocument));

app.post("/auth/register", async (req, res, next) => {
  try {
    const { name, email, password } = isObject(req.body) ? req.body : {};
    const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
    if (typeof name !== "string" || !name.trim() || !emailPattern.test(normalizedEmail) || typeof password !== "string" || password.length < 8) return res.status(400).json({ error: "Informe nome, e-mail válido e senha de ao menos 8 caracteres." });
    const user = await prisma.user.create({ data: { name: name.trim(), email: normalizedEmail, passwordHash: await hashPassword(password) } });
    return res.status(201).json(await createSession(user));
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") return res.status(409).json({ error: "E-mail já cadastrado." });
    return next(error);
  }
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const { email, password } = isObject(req.body) ? req.body : {};
    const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
    if (typeof password !== "string") return res.status(401).json({ error: "Credenciais inválidas." });
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (!user || !(await verifyPassword(password, user.passwordHash))) return res.status(401).json({ error: "Credenciais inválidas." });
    return res.json(await createSession(user));
  } catch (error) { return next(error); }
});

app.post("/auth/refresh", async (req, res, next) => {
  try {
    const refreshToken = isObject(req.body) && typeof req.body.refreshToken === "string" ? req.body.refreshToken : "";
    const session = await prisma.refreshSession.findUnique({ where: { tokenHash: hashToken(refreshToken) }, include: { user: true } });
    if (!session || session.revokedAt || session.expiresAt <= new Date()) return res.status(401).json({ error: "Refresh token inválido ou expirado." });
    await prisma.refreshSession.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
    return res.json(await createSession(session.user));
  } catch (error) { return next(error); }
});

app.post("/auth/logout", async (req, res, next) => {
  try {
    const refreshToken = isObject(req.body) && typeof req.body.refreshToken === "string" ? req.body.refreshToken : "";
    await prisma.refreshSession.updateMany({ where: { tokenHash: hashToken(refreshToken), revokedAt: null }, data: { revokedAt: new Date() } });
    return res.status(204).send();
  } catch (error) { return next(error); }
});

app.get("/users/me", authenticate, async (req: AuthRequest, res, next) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) return res.status(401).json({ error: "Não autenticado." });
    return res.json(userDto(user));
  } catch (error) { return next(error); }
});

app.use((_req, res) => res.status(404).json({ error: "Rota não encontrada." }));
app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error(error);
  res.status(500).json({ error: "Erro interno do servidor." });
});
