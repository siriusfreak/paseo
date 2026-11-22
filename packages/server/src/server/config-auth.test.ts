import { mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { loadConfig } from "./config.js";
import { isBearerTokenValidAsync } from "./auth.js";

const roots: string[] = [];
const CONFIG_PASSWORD_HASH = "$2b$12$OLxyuuP9uLK30Uzc4wQX0O6liuU/Q1t5P2b0Ebf36mULvpVK3DRZW";

async function createPaseoHome(config: unknown): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "paseo-config-auth-"));
  roots.push(root);
  const paseoHome = path.join(root, ".paseo");
  await mkdir(paseoHome, { recursive: true });
  await writeFile(path.join(paseoHome, "config.json"), JSON.stringify(config, null, 2));
  return paseoHome;
}

describe("daemon auth config", () => {
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  });

  test("loads optional auth password hash from config.json", async () => {
    const paseoHome = await createPaseoHome({
      version: 1,
      daemon: {
        auth: { password: CONFIG_PASSWORD_HASH },
      },
    });

    const config = loadConfig(paseoHome, { env: {} });

    expect(config.auth?.password).toBe(CONFIG_PASSWORD_HASH);
    expect(
      await isBearerTokenValidAsync({ password: config.auth?.password, token: "correct-password" }),
    ).toBe(true);
  });

  test("loads Keycloak OIDC settings from the daemon environment", async () => {
    const paseoHome = await createPaseoHome({ version: 1 });

    const config = loadConfig(paseoHome, {
      env: {
        PASEO_OIDC_ISSUER: "https://keycloak.example/auth/realms/master",
        PASEO_OIDC_CLIENT_ID: "paseo",
        PASEO_OIDC_REDIRECT_URL: "https://paseo.example/oauth2/callback",
        PASEO_OIDC_REQUIRED_ROLE: "opencode",
        PASEO_OIDC_COOKIE_NAME: "paseo_session",
        PASEO_OIDC_COOKIE_DOMAIN: "paseo.example",
        PASEO_OIDC_COOKIE_SECURE: "true",
      },
    });

    expect(config.auth?.oidc).toEqual({
      issuer: "https://keycloak.example/auth/realms/master",
      clientId: "paseo",
      redirectUrl: "https://paseo.example/oauth2/callback",
      requiredRole: "opencode",
      cookieName: "paseo_session",
      cookieDomain: "paseo.example",
      cookieSecure: true,
    });
  });

  test("lets PASEO_PASSWORD override config.json auth password hash", async () => {
    const paseoHome = await createPaseoHome({
      version: 1,
      daemon: {
        auth: { password: CONFIG_PASSWORD_HASH },
      },
    });

    const config = loadConfig(paseoHome, {
      env: { PASEO_PASSWORD: "from-env" },
    });

    expect(config.auth?.password).not.toBe(CONFIG_PASSWORD_HASH);
    expect(config.auth?.password).toMatch(/^\$2[aby]\$12\$/);
    expect(
      await isBearerTokenValidAsync({ password: config.auth?.password, token: "from-env" }),
    ).toBe(true);
  });
});
