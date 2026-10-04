// Passkey ceremonies in the browser, via @simplewebauthn/browser.

import { browserSupportsWebAuthn, startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { ApiError, post } from "./api";

export const passkeysSupported = () => browserSupportsWebAuthn();

function deviceError(err: unknown): never {
  if (err instanceof ApiError) throw err;
  const name = err instanceof Error ? err.name : "";
  const message =
    name === "NotAllowedError"
      ? "The passkey request was cancelled or timed out. Try again when you're ready."
      : name === "InvalidStateError"
        ? "This device already has a passkey for your account."
        : "Your browser or device couldn't use a passkey. Try again, or use your authenticator app.";
  throw new ApiError(0, "passkey_device", message);
}

/** Second sign-in step with a passkey. */
export async function signInWithPasskey(): Promise<void> {
  const optionsJSON = await post<Parameters<typeof startAuthentication>[0]["optionsJSON"]>("/api/auth/passkey/options");
  let credential;
  try {
    credential = await startAuthentication({ optionsJSON });
  } catch (err) {
    deviceError(err);
  }
  await post("/api/auth/passkey/verify", { credential });
}

/** Add a passkey to the signed-in account (confirmed with password + code). */
export async function addPasskey(password: string, totpCode: string, name: string): Promise<void> {
  const optionsJSON = await post<Parameters<typeof startRegistration>[0]["optionsJSON"]>("/api/me/passkeys/options", {
    password,
    totp_code: totpCode,
  });
  let credential;
  try {
    credential = await startRegistration({ optionsJSON });
  } catch (err) {
    deviceError(err);
  }
  await post("/api/me/passkeys", { credential, name });
}
