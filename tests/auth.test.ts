import { beforeAll, afterAll, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../src/app.js";
import { prisma } from "../src/prisma.js";

beforeAll(async () => {
  await prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "User" ("id" TEXT NOT NULL PRIMARY KEY, "name" TEXT NOT NULL, "email" TEXT NOT NULL UNIQUE, "passwordHash" TEXT NOT NULL, "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "updatedAt" DATETIME NOT NULL)`);
  await prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "RefreshSession" ("id" TEXT NOT NULL PRIMARY KEY, "tokenHash" TEXT NOT NULL UNIQUE, "expiresAt" DATETIME NOT NULL, "revokedAt" DATETIME, "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "userId" TEXT NOT NULL, FOREIGN KEY("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE)`);
  await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS "RefreshSession_userId_idx" ON "RefreshSession"("userId")`);
  await prisma.refreshSession.deleteMany();
  await prisma.user.deleteMany();
});
afterAll(async () => prisma.$disconnect());

describe("authentication API", () => {
  it("registers, authenticates, refreshes and revokes a user session", async () => {
    const registration = await request(app).post("/auth/register").send({ name: "Ana Silva", email: "ANA@example.com", password: "senha-segura" }).expect(201);
    expect(registration.body.user.email).toBe("ana@example.com");
    expect(registration.body.accessToken).toEqual(expect.any(String));

    await request(app).get("/users/me").set("Authorization", `Bearer ${registration.body.accessToken}`).expect(200).expect(({ body }) => expect(body.name).toBe("Ana Silva"));
    await request(app).post("/auth/login").send({ email: "ana@example.com", password: "errada" }).expect(401);

    const refreshed = await request(app).post("/auth/refresh").send({ refreshToken: registration.body.refreshToken }).expect(200);
    await request(app).post("/auth/refresh").send({ refreshToken: registration.body.refreshToken }).expect(401);
    await request(app).post("/auth/logout").send({ refreshToken: refreshed.body.refreshToken }).expect(204);
    await request(app).post("/auth/refresh").send({ refreshToken: refreshed.body.refreshToken }).expect(401);
  });

  it("protects profile routes and rejects duplicate emails", async () => {
    await request(app).get("/users/me").expect(401);
    await request(app).post("/auth/register").send({ name: "Outra Ana", email: "ana@example.com", password: "senha-segura" }).expect(409);
  });
});
