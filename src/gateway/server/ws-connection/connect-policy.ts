import {
  validateOperatorScopeArray,
  type OperatorScopeArrayValidationResult,
} from "../../operator-scopes.js";
// `connect.params.scopes` is never authoritative on any branch. It is at most a
// hint that must be intersected with a server-derived baseline (paired-device
// approved scopes when paired or freshly approved during connect, or a
// bootstrap profile). When no such baseline exists, the cached scope set must
// be cleared to `[]` regardless of what the client requested. Authentication
// proves identity; pairing/bootstrap proves scope authority.
import type { ConnectParams } from "../../protocol/index.js";
import type { GatewayRole } from "../../role-policy.js";
import { roleCanSkipDeviceIdentity } from "../../role-policy.js";

export type ControlUiAuthPolicy = {
  isControlUi: boolean;
  allowInsecureAuthConfigured: boolean;
  dangerouslyDisableDeviceAuth: boolean;
  allowBypass: boolean;
  device: ConnectParams["device"] | null | undefined;
};

export function resolveControlUiAuthPolicy(params: {
  isControlUi: boolean;
  controlUiConfig:
    | {
        allowInsecureAuth?: boolean;
        dangerouslyDisableDeviceAuth?: boolean;
      }
    | undefined;
  deviceRaw: ConnectParams["device"] | null | undefined;
}): ControlUiAuthPolicy {
  const allowInsecureAuthConfigured =
    params.isControlUi && params.controlUiConfig?.allowInsecureAuth === true;
  const dangerouslyDisableDeviceAuth =
    params.isControlUi && params.controlUiConfig?.dangerouslyDisableDeviceAuth === true;
  return {
    isControlUi: params.isControlUi,
    allowInsecureAuthConfigured,
    dangerouslyDisableDeviceAuth,
    // `allowInsecureAuth` must not bypass secure-context/device-auth requirements.
    allowBypass: dangerouslyDisableDeviceAuth,
    device: dangerouslyDisableDeviceAuth ? null : params.deviceRaw,
  };
}

export function shouldSkipControlUiPairing(
  policy: ControlUiAuthPolicy,
  role: GatewayRole,
  trustedProxyAuthOk = false,
  authMode?: string,
  authMethod?: string,
): boolean {
  if (trustedProxyAuthOk) {
    return true;
  }
  if (policy.isControlUi && role === "operator" && authMethod === "tailscale" && policy.device) {
    return true;
  }
  // When auth is completely disabled (mode=none), there is no shared secret
  // or token to gate pairing. Requiring pairing in this configuration adds
  // friction without security value since any client can already connect
  // without credentials. Guard with policy.isControlUi because this function
  // is called for ALL clients (not just Control UI) at the call site.
  // Scope to operator role so node-role sessions still need device identity
  // (#43478 was reverted for skipping ALL clients).
  if (policy.isControlUi && role === "operator" && authMode === "none") {
    return true;
  }
  // dangerouslyDisableDeviceAuth is the break-glass path for Control UI
  // operators. Keep pairing aligned with the missing-device bypass, including
  // open-auth deployments where there is no shared token/password to prove.
  return role === "operator" && policy.allowBypass;
}

export function isTrustedProxyControlUiOperatorAuth(params: {
  isControlUi: boolean;
  role: GatewayRole;
  authMode: string;
  authOk: boolean;
  authMethod: string | undefined;
}): boolean {
  return (
    params.isControlUi &&
    params.role === "operator" &&
    params.authMode === "trusted-proxy" &&
    params.authOk &&
    params.authMethod === "trusted-proxy"
  );
}

export type MissingDeviceIdentityDecision =
  | { kind: "allow" }
  | { kind: "reject-control-ui-insecure-auth" }
  | { kind: "reject-unauthorized" }
  | { kind: "reject-device-required" };

function validateNodeScopeVocabulary(
  scopes: readonly unknown[],
): OperatorScopeArrayValidationResult {
  const unknownTokens: string[] = [];
  for (const value of scopes) {
    if (typeof value === "string" && value.startsWith("node.") && value.length > "node.".length) {
      continue;
    }
    unknownTokens.push(typeof value === "string" ? value : `<non-string:${typeof value}>`);
  }
  if (unknownTokens.length === 0) {
    return { ok: true };
  }
  return { ok: false, unknown: unknownTokens };
}

export function validateConnectScopeVocabulary(
  scopes: readonly unknown[],
  role?: string,
): OperatorScopeArrayValidationResult {
  if (typeof role === "string" && role.trim() === "node") {
    return validateNodeScopeVocabulary(scopes);
  }
  return validateOperatorScopeArray(scopes);
}

/**
 * Returns true when the WebSocket connection lacks a server-approved scope
 * baseline and is not covered by an existing explicit preserve/bypass
 * condition. The primary input is `hasApprovedScopeBaseline` — never raw
 * device presence, since an attacker-controlled keypair makes `device`
 * truthy without conferring any actual authority.
 */
export function shouldClampUnboundScopes(params: {
  hasApprovedScopeBaseline: boolean;
  decision: MissingDeviceIdentityDecision;
  controlUiAuthPolicy: ControlUiAuthPolicy;
  preserveInsecureLocalControlUiScopes: boolean;
  authMethod: string | undefined;
  trustedProxyAuthOk?: boolean;
}): boolean {
  if (params.decision.kind !== "allow") {
    return true;
  }
  if (params.hasApprovedScopeBaseline) {
    return false;
  }
  if (params.controlUiAuthPolicy.allowBypass && params.authMethod !== "trusted-proxy") {
    return false;
  }
  // Control UI deployments in open-auth and Tailscale-authenticated modes
  // intentionally bypass pairing for operator UI clients; keep their declared
  // scopes bound to that server-side auth mode. Trusted-proxy is excluded by
  // design because proxy identity alone must not reuse or mint device authority.
  if (
    params.controlUiAuthPolicy.isControlUi &&
    (params.authMethod === "none" || params.authMethod === "tailscale")
  ) {
    return false;
  }
  if (params.preserveInsecureLocalControlUiScopes) {
    return false;
  }
  return true;
}

export function evaluateMissingDeviceIdentity(params: {
  hasDeviceIdentity: boolean;
  role: GatewayRole;
  isControlUi: boolean;
  controlUiAuthPolicy: ControlUiAuthPolicy;
  trustedProxyAuthOk?: boolean;
  sharedAuthOk: boolean;
  authOk: boolean;
  hasSharedAuth: boolean;
  isLocalClient: boolean;
}): MissingDeviceIdentityDecision {
  if (params.hasDeviceIdentity) {
    return { kind: "allow" };
  }
  if (params.isControlUi && params.trustedProxyAuthOk) {
    return { kind: "allow" };
  }
  if (params.isControlUi && params.controlUiAuthPolicy.allowBypass && params.role === "operator") {
    // dangerouslyDisableDeviceAuth: true — operator has explicitly opted out of
    // device-identity enforcement for this Control UI.  Allow for operator-role
    // sessions only; node-role sessions must still satisfy device identity so
    // that the break-glass flag cannot be abused to admit device-less node
    // registrations (see #45405 review).
    return { kind: "allow" };
  }
  if (params.isControlUi && !params.controlUiAuthPolicy.allowBypass) {
    // Allow localhost Control UI connections when allowInsecureAuth is configured.
    // Localhost has no network interception risk, and browser SubtleCrypto
    // (needed for device identity) is unavailable in insecure HTTP contexts.
    // Remote connections are still rejected to preserve the MitM protection
    // that the security fix (#20684) intended.
    if (!params.controlUiAuthPolicy.allowInsecureAuthConfigured || !params.isLocalClient) {
      return { kind: "reject-control-ui-insecure-auth" };
    }
  }
  if (roleCanSkipDeviceIdentity(params.role, params.sharedAuthOk)) {
    return { kind: "allow" };
  }
  if (!params.authOk && params.hasSharedAuth) {
    return { kind: "reject-unauthorized" };
  }
  return { kind: "reject-device-required" };
}
