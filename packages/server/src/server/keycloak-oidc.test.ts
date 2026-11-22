import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from "jose";
import { WebSocket } from "ws";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createTestPaseoDaemon } from "./test-utils/paseo-daemon.js";

const PASSWORD_HASH = "$2b$12$OLxyuuP9uLK30Uzc4wQX0O6liuU/Q1t5P2b0Ebf36mULvpVK3DRZW";
const originalEnv = { ...process.env };
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  vi.restoreAllMocks();
  process.env = { ...originalEnv };
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

interface MockKeycloak {
  issuer: string;
  close: () => Promise<void>;
}

async function startMockKeycloak(input: {
  privateKey: KeyLike;
  publicJwk: JWK;
  roles?: string[];
}): Promise<MockKeycloak> {
  let issuer = "";
  const server = createServer((req, res) => {
    void (async () => {
      if (req.url === "/auth/realms/master/.well-known/openid-configuration") {
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            issuer,
            authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
            token_endpoint: `${issuer}/protocol/openid-connect/token`,
            jwks_uri: `${issuer}/protocol/openid-connect/certs`,
          }),
        );
        return;
      }
      if (req.url === "/auth/realms/master/protocol/openid-connect/certs") {
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            keys: [{ ...input.publicJwk, kid: "test-key", alg: "RS256", use: "sig" }],
          }),
        );
        return;
      }
      if (
        req.url === "/auth/realms/master/protocol/openid-connect/token" &&
        req.method === "POST"
      ) {
        let body = "";
        for await (const chunk of req) body += chunk;
        const params = new URLSearchParams(body);
        if (params.get("code") !== "test-code" || !params.get("code_verifier")) {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        const accessToken = await new SignJWT({
          azp: "paseo",
          preferred_username: "test-user",
          email: "test@example.com",
          realm_access: { roles: input.roles ?? ["opencode"] },
        })
          .setProtectedHeader({ alg: "RS256", kid: "test-key", typ: "JWT" })
          .setIssuer(issuer)
          .setSubject("user-123")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(input.privateKey);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ access_token: accessToken, token_type: "Bearer" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    })().catch((error) => {
      res.statusCode = 500;
      res.end(String(error));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  issuer = `http://127.0.0.1:${address.port}/auth/realms/master`;
  return {
    issuer,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function cookiesFrom(response: Response): string[] {
  const headers = response.headers as unknown as { getSetCookie?: () => string[] };
  return headers.getSetCookie?.() ?? [];
}

function cookiePair(cookie: string): string {
  return cookie.split(";")[0];
}

async function connectWithCookie(port: number, cookie: string): Promise<WebSocket> {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers: { Cookie: cookie } });
  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  return ws;
}

describe("Keycloak OIDC", () => {
  test("runs PKCE login and accepts the session on HTML, HTTP and WebSocket", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(publicKey);
    const keycloak = await startMockKeycloak({ privateKey, publicJwk });
    cleanups.push(keycloak.close);
    const distDir = await mkdtemp(path.join(tmpdir(), "paseo-oidc-ui-"));
    cleanups.push(() => rm(distDir, { recursive: true, force: true }));
    await writeFile(path.join(distDir, "index.html"), "<html><body>Paseo</body></html>");
    const daemon = await createTestPaseoDaemon({
      auth: {
        password: PASSWORD_HASH,
        oidc: {
          issuer: keycloak.issuer,
          clientId: "paseo",
          redirectUrl: "https://paseo.i.siriusfrk.me/oauth2/callback",
          cookieSecure: false,
        },
      },
      webUi: { enabled: true, distDir },
    });
    cleanups.push(daemon.close);

    const missing = await fetch(`http://127.0.0.1:${daemon.port}/`, {
      headers: { Accept: "text/html" },
      redirect: "manual",
    });
    expect(missing.status).toBe(302);
    expect(missing.headers.get("location")).toBe("/auth?rd=%2F");

    const authStart = await fetch(
      `http://127.0.0.1:${daemon.port}${missing.headers.get("location")!}`,
      {
        redirect: "manual",
        headers: { Accept: "text/html" },
      },
    );
    expect(authStart.status).toBe(302);
    const authorizationUrl = new URL(authStart.headers.get("location")!);
    expect(authorizationUrl.searchParams.get("client_id")).toBe("paseo");
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
    const stateCookie = cookiesFrom(authStart).find((cookie) =>
      cookie.startsWith("paseo_session_state="),
    );
    expect(stateCookie).toBeDefined();
    const state = authorizationUrl.searchParams.get("state")!;

    const callback = await fetch(
      `http://127.0.0.1:${daemon.port}/oauth2/callback?code=test-code&state=${encodeURIComponent(state)}`,
      { headers: { Cookie: cookiePair(stateCookie!) }, redirect: "manual" },
    );
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe("/");
    const sessionCookie = cookiesFrom(callback).find((cookie) =>
      cookie.startsWith("paseo_session="),
    );
    expect(sessionCookie).toBeDefined();
    const session = cookiePair(sessionCookie!);

    const html = await fetch(`http://127.0.0.1:${daemon.port}/`, {
      headers: { Accept: "text/html", Cookie: session },
    });
    expect(html.status).toBe(200);
    expect(await html.text()).toContain("Paseo");

    const status = await fetch(`http://127.0.0.1:${daemon.port}/api/status`, {
      headers: { Cookie: session },
    });
    expect(status.status).toBe(200);

    const bearer = await fetch(`http://127.0.0.1:${daemon.port}/api/status`, {
      headers: { Authorization: "Bearer correct-password" },
    });
    expect(bearer.status).toBe(200);

    const ws = await connectWithCookie(daemon.port, session);
    const serverInfo = new Promise<unknown>((resolve, reject) => {
      ws.once("message", (data) => resolve(JSON.parse(data.toString())));
      ws.once("close", () => reject(new Error("closed before server_info")));
    });
    ws.send(
      JSON.stringify({
        type: "hello",
        clientId: "oidc-browser",
        clientType: "cli",
        protocolVersion: 1,
      }),
    );
    await expect(serverInfo).resolves.toMatchObject({
      type: "session",
      message: { payload: { status: "server_info" } },
    });
    ws.close();

    const sessionKey = await readFile(path.join(daemon.paseoHome, "oidc-session.key"));
    expect(sessionKey.length).toBe(32);
  });

  test("rejects a Keycloak token without the required role", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(publicKey);
    const keycloak = await startMockKeycloak({ privateKey, publicJwk, roles: ["other-role"] });
    cleanups.push(keycloak.close);
    const daemon = await createTestPaseoDaemon({
      auth: {
        password: PASSWORD_HASH,
        oidc: {
          issuer: keycloak.issuer,
          clientId: "paseo",
          redirectUrl: "https://paseo.i.siriusfrk.me/oauth2/callback",
          cookieSecure: false,
        },
      },
    });
    cleanups.push(daemon.close);

    const authStart = await fetch(`http://127.0.0.1:${daemon.port}/auth`, { redirect: "manual" });
    const stateCookie = cookiesFrom(authStart).find((cookie) =>
      cookie.startsWith("paseo_session_state="),
    )!;
    const state = new URL(authStart.headers.get("location")!).searchParams.get("state")!;
    const callback = await fetch(
      `http://127.0.0.1:${daemon.port}/oauth2/callback?code=test-code&state=${encodeURIComponent(state)}`,
      { headers: { Cookie: cookiePair(stateCookie) }, redirect: "manual" },
    );
    expect(callback.status).toBe(403);
    expect(cookiesFrom(callback).some((cookie) => cookie.startsWith("paseo_session="))).toBe(false);
  });
});
