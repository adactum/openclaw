import type { PairedDevice } from "../../../infra/device-pairing.js";
import { hasEffectivePairedDeviceRole } from "../../../infra/device-pairing.js";
import { roleScopesAllow } from "../../../shared/operator-scope-compat.js";

/**
 * Returns true when the paired-device record cryptographically and
 * authoritatively admits the requested role + scopes. The public-key check is
 * load-bearing: an attacker-supplied keypair is rejected here even when the
 * caller signed the device frame correctly, because pairing — not signature
 * possession — is the source of authority.
 */
export function pairingStateAllowsRequestedAccess(params: {
  pairedCandidate: PairedDevice | null | undefined;
  devicePublicKey: string | null;
  role: string;
  scopes: readonly string[];
}): boolean {
  const { pairedCandidate, devicePublicKey, role, scopes } = params;
  if (!pairedCandidate || pairedCandidate.publicKey !== devicePublicKey) {
    return false;
  }
  if (!hasEffectivePairedDeviceRole(pairedCandidate, role)) {
    return false;
  }
  if (scopes.length === 0) {
    return true;
  }
  const pairedScopes = Array.isArray(pairedCandidate.approvedScopes)
    ? pairedCandidate.approvedScopes
    : Array.isArray(pairedCandidate.scopes)
      ? pairedCandidate.scopes
      : [];
  if (pairedScopes.length === 0) {
    return false;
  }
  return roleScopesAllow({
    role,
    requestedScopes: scopes,
    allowedScopes: pairedScopes,
  });
}

export type ScopeBaselineTracker = {
  has(): boolean;
  markApproved(): void;
  refreshAfterApproval(deviceId: string): Promise<void>;
};

/**
 * Tracks whether the connection has a server-approved scope baseline. After
 * every `requirePairing` call that returns true, call `refreshAfterApproval`
 * to re-read the pairing store; a freshly approved record (silent local,
 * bootstrap, trusted-CIDR node, metadata/role/scope upgrade, or concurrent
 * approval recovery) advances the baseline.
 *
 * `getDevicePublicKey`, `getRole`, and `getScopes` are read each time the
 * tracker is consulted, so the tracker stays correct as the connect flow
 * mutates these locals (scope clamp, role parsing, late publicKey resolution).
 */
export function createScopeBaselineTracker(params: {
  getPairedDevice: (deviceId: string) => Promise<PairedDevice | null | undefined>;
  getDevicePublicKey: () => string | null;
  getRole: () => string;
  getScopes: () => readonly string[];
}): ScopeBaselineTracker {
  let approved = false;
  return {
    has: () => approved,
    markApproved: () => {
      approved = true;
    },
    refreshAfterApproval: async (deviceId: string) => {
      const refreshed = await params.getPairedDevice(deviceId);
      if (
        pairingStateAllowsRequestedAccess({
          pairedCandidate: refreshed,
          devicePublicKey: params.getDevicePublicKey(),
          role: params.getRole(),
          scopes: params.getScopes(),
        })
      ) {
        approved = true;
      }
    },
  };
}
