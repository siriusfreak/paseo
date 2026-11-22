import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import type { IncomingMessage } from "node:http";
import path from "node:path";
import type { Request, RequestHandler, Response } from "express";
import { createRemoteJWKSet, jwtVerify, SignJWT, type JWTPayload } from "jose";
import type { Logger } from "pino";
import { shouldBypassBearerAuth } from "./auth.js";

export interface KeycloakOidcConfig {
  issuer: string;
  clientId: string;
  redirectUrl: string;
  requiredRole?: string;
  cookieName?: string;
  cookieDomain?: string;
  cookieSecure?: boolean;
}

export interface KeycloakOidcPrincipal {
  sub: string;
  username: string;
  email?: string;
  roles: string[];
}

export interface KeycloakOidcRequest extends Request {
  oidcPrincipal?: KeycloakOidcPrincipal;
}

interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface TokenResponse {
  access_token?: string;
}

export interface KeycloakOidcRuntime {
  config: KeycloakOidcConfig;
  authenticate(request: IncomingMessage): Promise<KeycloakOidcPrincipal | null>;
  handleAuthStart: RequestHandler;
  handleAuthCallback: RequestHandler;
  handleLogout: RequestHandler;
  guard: RequestHandler;
}

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const STATE_TTL_SECONDS = 10 * 60;

function base64url(value: Buffer): string {
  return value.toString("base64url");
}

function normalizeIssuer(value: string): string {
  return value.replace(/\/+$/, "");
}

function sessionCookieName(config: KeycloakOidcConfig): string {
  return config.cookieName ?? "paseo_session";
}

function stateCookieName(config: KeycloakOidcConfig): string {
  return `${sessionCookieName(config)}_state`;
}

function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const name = part.slice(0, separator).trim();
    if (!name) continue;
    cookies.set(name, decodeURIComponent(part.slice(separator + 1).trim()));
  }
  return cookies;
}

function serializeCookie(
  config: KeycloakOidcConfig,
  name: string,
  value: string,
  maxAge: number,
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Lax"];
  if (maxAge > 0) parts.push(`Max-Age=${maxAge}`);
  if (maxAge === 0) parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  if (config.cookieSecure !== false) parts.push("Secure");
  if (config.cookieDomain) parts.push(`Domain=${config.cookieDomain}`);
  return parts.join("; ");
}

function appendCookie(
  config: KeycloakOidcConfig,
  res: Response,
  name: string,
  value: string,
  maxAge: number,
): void {
  const cookie = serializeCookie(config, name, value, maxAge);
  const current = res.getHeader("Set-Cookie");
  let cookies: string[] = [];
  if (Array.isArray(current)) {
    cookies = current;
  } else if (current !== undefined) {
    cookies = [String(current)];
  }
  res.setHeader("Set-Cookie", [...cookies, cookie]);
}

function safeReturnUrl(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.includes("\\")) return "/";
  return value.startsWith("//") ? "/" : value;
}

function wantsHtml(req: Request): boolean {
  return (req.method === "GET" || req.method === "HEAD") && req.accepts("html") !== false;
}

async function loadOrCreateSessionKey(paseoHome: string): Promise<Buffer> {
  const filename = path.join(paseoHome, "oidc-session.key");
  await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  try {
    const key = await readFile(filename);
    if (key.length < 32) throw new Error(`${filename} is too short to sign OIDC sessions`);
    await chmod(filename, 0o600);
    return key;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const key = randomBytes(32);
  await writeFile(filename, key, { mode: 0o600, flag: "wx" });
  return key;
}

export async function createKeycloakOidcRuntime(input: {
  config: KeycloakOidcConfig;
  paseoHome: string;
  logger: Pick<Logger, "warn" | "error">;
}): Promise<KeycloakOidcRuntime> {
  const config = {
    ...input.config,
    issuer: normalizeIssuer(input.config.issuer),
  };
  const sessionKey = await loadOrCreateSessionKey(input.paseoHome);
  let discoveryPromise: Promise<DiscoveryDocument> | null = null;
  let keySet: ReturnType<typeof createRemoteJWKSet> | null = null;

  async function discovery(): Promise<DiscoveryDocument> {
    discoveryPromise ??= (async () => {
      const url = `${config.issuer}/.well-known/openid-configuration`;
      const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      if (!response.ok) throw new Error(`OIDC discovery returned ${response.status}`);
      const document = (await response.json()) as DiscoveryDocument;
      if (normalizeIssuer(document.issuer) !== config.issuer) {
        throw new Error("OIDC discovery issuer does not match the configured issuer");
      }
      keySet = createRemoteJWKSet(new URL(document.jwks_uri));
      return document;
    })();
    try {
      return await discoveryPromise;
    } catch (error) {
      discoveryPromise = null;
      throw error;
    }
  }

  async function verifyAccessToken(token: string): Promise<JWTPayload> {
    await discovery();
    const { payload } = await jwtVerify(token, keySet!, {
      issuer: config.issuer,
      clockTolerance: 5,
    });
    if (payload.azp !== config.clientId)
      throw new Error("OIDC token has the wrong authorized party");
    const roles = Array.isArray((payload.realm_access as { roles?: unknown } | undefined)?.roles)
      ? ((payload.realm_access as { roles: unknown[] }).roles.filter(
          (role): role is string => typeof role === "string",
        ) as string[])
      : [];
    const requiredRole = config.requiredRole ?? "opencode";
    if (!roles.includes(requiredRole))
      throw new Error(`OIDC token is missing role ${requiredRole}`);
    return payload;
  }

  async function sign(claims: JWTPayload, expiresIn: number): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setIssuedAt()
      .setExpirationTime(`${expiresIn}s`)
      .sign(sessionKey);
  }

  async function authenticate(request: IncomingMessage): Promise<KeycloakOidcPrincipal | null> {
    const token = parseCookies(request.headers.cookie).get(sessionCookieName(config));
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, sessionKey, { clockTolerance: 5 });
      const roles = Array.isArray(payload.roles)
        ? payload.roles.filter((role): role is string => typeof role === "string")
        : [];
      if (typeof payload.sub !== "string" || !roles.includes(config.requiredRole ?? "opencode")) {
        return null;
      }
      return {
        sub: payload.sub,
        username: typeof payload.username === "string" ? payload.username : payload.sub,
        email: typeof payload.email === "string" ? payload.email : undefined,
        roles,
      };
    } catch {
      return null;
    }
  }

  const handleAuthStart: RequestHandler = (req, res, next) => {
    void (async () => {
      try {
        const document = await discovery();
        const verifier = base64url(randomBytes(64));
        const returnUrl = safeReturnUrl(req.query.rd);
        const state = await sign(
          { nonce: base64url(randomBytes(32)), verifier, rd: returnUrl },
          STATE_TTL_SECONDS,
        );
        appendCookie(config, res, stateCookieName(config), state, STATE_TTL_SECONDS);
        const challenge = base64url(createHash("sha256").update(verifier).digest());
        const query = new URLSearchParams({
          response_type: "code",
          client_id: config.clientId,
          redirect_uri: config.redirectUrl,
          scope: "openid email profile",
          state,
          code_challenge: challenge,
          code_challenge_method: "S256",
        });
        res.redirect(`${document.authorization_endpoint}?${query}`);
      } catch (error) {
        next(error);
      }
    })();
  };

  const handleAuthCallback: RequestHandler = (req, res) => {
    void (async () => {
      try {
        const cookies = parseCookies(req.headers.cookie);
        const state = typeof req.query.state === "string" ? req.query.state : "";
        if (!state || cookies.get(stateCookieName(config)) !== state) {
          res.status(400).send("Invalid OIDC state");
          return;
        }
        const { payload: stateClaims } = await jwtVerify(state, sessionKey, {
          clockTolerance: 5,
        });
        const verifier = typeof stateClaims.verifier === "string" ? stateClaims.verifier : "";
        if (!verifier) {
          res.status(400).send("Invalid OIDC verifier");
          return;
        }
        const code = typeof req.query.code === "string" ? req.query.code : "";
        if (!code) {
          res.status(400).send("Missing OIDC authorization code");
          return;
        }
        const document = await discovery();
        const tokenResponse = await fetch(document.token_endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: config.redirectUrl,
            client_id: config.clientId,
            code_verifier: verifier,
          }),
          signal: AbortSignal.timeout(10_000),
        });
        if (!tokenResponse.ok) {
          input.logger.warn({ status: tokenResponse.status }, "OIDC token exchange failed");
          res.status(502).send("OIDC token exchange failed");
          return;
        }
        const tokens = (await tokenResponse.json()) as TokenResponse;
        if (!tokens.access_token) {
          res.status(502).send("OIDC token response is missing an access token");
          return;
        }
        const claims = await verifyAccessToken(tokens.access_token);
        const session = await sign(
          {
            sub: claims.sub,
            username: claims.preferred_username,
            email: claims.email,
            roles: (claims.realm_access as { roles?: string[] } | undefined)?.roles ?? [],
          },
          SESSION_TTL_SECONDS,
        );
        appendCookie(config, res, sessionCookieName(config), session, SESSION_TTL_SECONDS);
        appendCookie(config, res, stateCookieName(config), "", 0);
        res.redirect(safeReturnUrl(stateClaims.rd));
      } catch (error) {
        input.logger.warn({ err: error }, "OIDC callback failed");
        res.status(403).send("OIDC authentication failed");
      }
    })();
  };

  const handleLogout: RequestHandler = (_req, res) => {
    appendCookie(config, res, sessionCookieName(config), "", 0);
    appendCookie(config, res, stateCookieName(config), "", 0);
    res.redirect("/");
  };

  const guard: RequestHandler = (req, res, next) => {
    if (shouldBypassBearerAuth(req.method, req.path)) {
      next();
      return;
    }
    void (async () => {
      try {
        const principal = await authenticate(req);
        if (principal) {
          (req as KeycloakOidcRequest).oidcPrincipal = principal;
          next();
          return;
        }
        if (req.path.startsWith("/api/") || req.path.startsWith("/mcp/")) {
          next();
          return;
        }
        if (wantsHtml(req)) {
          const returnUrl = safeReturnUrl(req.originalUrl);
          res.redirect(`/auth?rd=${encodeURIComponent(returnUrl)}`);
          return;
        }
        res.status(401).json({ error: "Unauthorized" });
      } catch (error) {
        next(error);
      }
    })();
  };

  return {
    config,
    authenticate,
    handleAuthStart,
    handleAuthCallback,
    handleLogout,
    guard,
  };
}
