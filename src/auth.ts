import { createHash, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { config } from "./config.js";

const scrypt = promisify(scryptCallback);
const encoder = new TextEncoder();

const base64Url = (value: Buffer | string) => Buffer.from(value).toString("base64url");
const sign = (value: string) => createHmac("sha256", config.jwtSecret).update(value).digest("base64url");

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  return `${salt}:${derived.toString("hex")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  return timingSafeEqual(derived, Buffer.from(hash, "hex"));
}

export function createAccessToken(userId: string): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = base64Url(JSON.stringify({ sub: userId, iat: now, exp: now + config.accessTokenTtlSeconds }));
  const header = base64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const message = `${header}.${payload}`;
  return `${message}.${sign(message)}`;
}

export function verifyAccessToken(token: string): string | null {
  const [header, payload, signature] = token.split(".");
  if (!header || !payload || !signature) return null;
  const message = `${header}.${payload}`;
  const expected = sign(message);
  if (signature.length !== expected.length || !timingSafeEqual(encoder.encode(signature), encoder.encode(expected))) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { sub?: unknown; exp?: unknown };
    return typeof decoded.sub === "string" && typeof decoded.exp === "number" && decoded.exp > Date.now() / 1000 ? decoded.sub : null;
  } catch {
    return null;
  }
}

export const createRefreshToken = () => randomBytes(48).toString("base64url");
export const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");
