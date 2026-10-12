const positiveInteger = (value: string | undefined, fallback: number): number => {
  const parsed = Number(value ?? fallback);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
};

export const config = {
  port: positiveInteger(process.env.PORT, 3000),
  jwtSecret: process.env.JWT_ACCESS_SECRET ?? "development-only-secret-change-me",
  accessTokenTtlSeconds: positiveInteger(process.env.ACCESS_TOKEN_TTL_SECONDS, 900),
  refreshTokenTtlDays: positiveInteger(process.env.REFRESH_TOKEN_TTL_DAYS, 7),
};
