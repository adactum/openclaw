import { isDeepStrictEqual } from "node:util";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { normalizeLowercaseStringOrEmpty } from "../shared/string-coerce.js";
import {
  evaluateCachedTrustedProxySession,
  type ResolvedGatewayAuthMode,
  type TrustedProxyAuthEvidence,
} from "./auth.js";

type TrustedProxyAuthModeOpts = {
  resolvedAuthMode?: ResolvedGatewayAuthMode;
  prevResolvedAuthMode?: ResolvedGatewayAuthMode;
  nextResolvedAuthMode?: ResolvedGatewayAuthMode;
};

export type TrustedProxyAuthClient = {
  socket: { close: (code: number, reason: string) => void };
  trustedProxyUser?: string;
  trustedProxyAuthEvidence?: TrustedProxyAuthEvidence;
};

export const TRUSTED_PROXY_REVOKED_CLOSE_REASON = "trusted-proxy auth revoked";

export type TrustedProxyAuthGenerationState = {
  get(): number;
  bump(): void;
};

export function createTrustedProxyAuthGenerationState(): TrustedProxyAuthGenerationState {
  const state = { current: 0 };
  return {
    get: () => state.current,
    bump: () => {
      state.current += 1;
    },
  };
}

function normalizedHeaderList(values: readonly string[] | undefined): string[] {
  if (!values) {
    return [];
  }
  return values.map((value) => normalizeLowercaseStringOrEmpty(value));
}

type TrustedProxyAuthFingerprintShape = {
  mode: string;
  userHeader: string;
  requiredHeaders: readonly string[];
  allowUsers: readonly string[];
  allowLoopback: boolean;
  trustedProxies: readonly string[];
};

function trustedProxyAuthFingerprint(
  cfg: OpenClawConfig,
  opts?: { resolvedAuthMode?: ResolvedGatewayAuthMode },
): TrustedProxyAuthFingerprintShape {
  const tp = cfg.gateway?.auth?.trustedProxy;
  return {
    mode: opts?.resolvedAuthMode ?? cfg.gateway?.auth?.mode ?? "",
    userHeader: normalizeLowercaseStringOrEmpty(tp?.userHeader ?? ""),
    requiredHeaders: normalizedHeaderList(tp?.requiredHeaders).toSorted(),
    allowUsers: (tp?.allowUsers ?? []).toSorted(),
    allowLoopback: tp?.allowLoopback === true,
    trustedProxies: (cfg.gateway?.trustedProxies ?? []).toSorted(),
  };
}

/**
 * Stable string fingerprint for trusted-proxy auth surface. Same fields
 * compared by `didTrustedProxyAuthChange`; a shared serialization prevents
 * the applicator's dedup state from drifting from the change-detection
 * predicate.
 */
export function computeTrustedProxyAuthFingerprint(
  cfg: OpenClawConfig,
  opts?: { resolvedAuthMode?: ResolvedGatewayAuthMode },
): string {
  return JSON.stringify(trustedProxyAuthFingerprint(cfg, opts));
}

export function didTrustedProxyAuthChange(
  prev: OpenClawConfig,
  next: OpenClawConfig,
  opts?: TrustedProxyAuthModeOpts,
): boolean {
  const prevResolvedAuthMode = opts?.prevResolvedAuthMode ?? opts?.resolvedAuthMode;
  const nextResolvedAuthMode = opts?.nextResolvedAuthMode ?? opts?.resolvedAuthMode;
  return !isDeepStrictEqual(
    trustedProxyAuthFingerprint(prev, { resolvedAuthMode: prevResolvedAuthMode }),
    trustedProxyAuthFingerprint(next, { resolvedAuthMode: nextResolvedAuthMode }),
  );
}

/**
 * Tightening here is scoped to header / source / loopback / mode policy.
 * `allowUsers` transitions are handled by the disconnect planner because
 * empty `allowUsers` means allow-all and is asymmetric with finite values.
 */
export function didTrustedProxyHeaderOrSourcePolicyTighten(
  prev: OpenClawConfig,
  next: OpenClawConfig,
  opts?: TrustedProxyAuthModeOpts,
): boolean {
  const prevTp = prev.gateway?.auth?.trustedProxy;
  const nextTp = next.gateway?.auth?.trustedProxy;
  const prevMode =
    opts?.prevResolvedAuthMode ?? opts?.resolvedAuthMode ?? prev.gateway?.auth?.mode ?? "";
  const nextMode =
    opts?.nextResolvedAuthMode ?? opts?.resolvedAuthMode ?? next.gateway?.auth?.mode ?? "";
  if (prevMode === "trusted-proxy" && nextMode !== "trusted-proxy") {
    return true;
  }
  const prevUserHeader = normalizeLowercaseStringOrEmpty(prevTp?.userHeader ?? "");
  const nextUserHeader = normalizeLowercaseStringOrEmpty(nextTp?.userHeader ?? "");
  if (prevUserHeader !== nextUserHeader) {
    return true;
  }
  const prevRequired = new Set(normalizedHeaderList(prevTp?.requiredHeaders));
  const nextRequired = normalizedHeaderList(nextTp?.requiredHeaders);
  for (const name of nextRequired) {
    if (!prevRequired.has(name)) {
      return true;
    }
  }
  if (prevTp?.allowLoopback === true && nextTp?.allowLoopback !== true) {
    return true;
  }
  const prevTrustedProxies = new Set(prev.gateway?.trustedProxies ?? []);
  const nextTrustedProxies = new Set(next.gateway?.trustedProxies ?? []);
  for (const proxy of prevTrustedProxies) {
    if (!nextTrustedProxies.has(proxy)) {
      return true;
    }
  }
  return false;
}

export type TrustedProxyAuthDisconnectPlan =
  | { kind: "none" }
  | { kind: "revalidate"; reason: string }
  | { kind: "users"; users: readonly string[] }
  | { kind: "bulk"; reason: string };

/**
 * Maps a (prev, next) config delta to the proactive eviction action for live
 * trusted-proxy clients. Empty `allowUsers` means allow-all, so transitions
 * are asymmetric:
 *
 *   empty   -> empty   : none
 *   empty   -> finite  : revalidate (selective close via cached evaluation)
 *   finite  -> empty   : none (loosen)
 *   finite  -> finite, removed-set non-empty : per-user close removed users
 *   finite  -> finite, removed-set empty     : none (same/grow)
 *
 * Header / source / loopback / mode tightening takes precedence and produces
 * `bulk` because evidence-shape comparison cannot help.
 */
export function resolveTrustedProxyAuthDisconnectPlan(
  prev: OpenClawConfig,
  next: OpenClawConfig,
  opts?: TrustedProxyAuthModeOpts,
): TrustedProxyAuthDisconnectPlan {
  if (didTrustedProxyHeaderOrSourcePolicyTighten(prev, next, opts)) {
    return { kind: "bulk", reason: "trusted-proxy header/source policy changed" };
  }
  const prevAllowUsers = prev.gateway?.auth?.trustedProxy?.allowUsers ?? [];
  const nextAllowUsers = next.gateway?.auth?.trustedProxy?.allowUsers ?? [];
  if (prevAllowUsers.length === 0 && nextAllowUsers.length === 0) {
    return { kind: "none" };
  }
  if (prevAllowUsers.length === 0 && nextAllowUsers.length > 0) {
    return { kind: "revalidate", reason: "trusted-proxy allowUsers narrowed from allow-all" };
  }
  if (prevAllowUsers.length > 0 && nextAllowUsers.length === 0) {
    return { kind: "none" };
  }
  const nextSet = new Set(nextAllowUsers);
  const removed: string[] = [];
  for (const user of prevAllowUsers) {
    if (!nextSet.has(user)) {
      removed.push(user);
    }
  }
  if (removed.length === 0) {
    return { kind: "none" };
  }
  return { kind: "users", users: removed };
}

export function closeTrustedProxyClient(
  client: { socket: { close: (code: number, reason: string) => void } },
  reason: string,
): void {
  try {
    client.socket.close(4001, reason);
  } catch {
    /* ignore */
  }
}

/**
 * Iterates trusted-proxy clients and closes any whose cached evidence + user
 * fail to satisfy `nextConfig`. Used after a config write to evict sessions
 * whose policy changed without bulk-closing allowlisted ones.
 */
export function disconnectStaleTrustedProxyClients(
  clients: Iterable<TrustedProxyAuthClient>,
  nextConfig: OpenClawConfig,
  opts?: { resolvedAuthMode?: ResolvedGatewayAuthMode },
): void {
  const trustedProxyConfig = nextConfig.gateway?.auth?.trustedProxy;
  const trustedProxies = nextConfig.gateway?.trustedProxies;
  const gatewayAuthMode = opts?.resolvedAuthMode ?? nextConfig.gateway?.auth?.mode;
  for (const gatewayClient of clients) {
    const user = gatewayClient.trustedProxyUser;
    if (!user) {
      continue;
    }
    const verdict = evaluateCachedTrustedProxySession({
      user,
      evidence: gatewayClient.trustedProxyAuthEvidence,
      trustedProxyConfig,
      trustedProxies,
      gatewayAuthMode,
    });
    if (verdict.ok) {
      continue;
    }
    closeTrustedProxyClient(gatewayClient, TRUSTED_PROXY_REVOKED_CLOSE_REASON);
  }
}

export function disconnectAllTrustedProxyClients(
  clients: Iterable<TrustedProxyAuthClient>,
  opts?: { reason?: string },
): void {
  const reason = opts?.reason ?? TRUSTED_PROXY_REVOKED_CLOSE_REASON;
  for (const gatewayClient of clients) {
    if (!gatewayClient.trustedProxyUser) {
      continue;
    }
    closeTrustedProxyClient(gatewayClient, reason);
  }
}

export type TrustedProxyAuthApplicatorActions = {
  bumpTrustedProxyAuthGeneration: () => void;
  disconnectAllTrustedProxyClients: (opts: { reason: string }) => void;
  disconnectRevokedTrustedProxyClients: (next: OpenClawConfig) => void;
  disconnectClientsForTrustedProxyUser: (user: string, opts?: { reason?: string }) => void;
};

export type TrustedProxyAuthApplicator = {
  apply(
    prev: OpenClawConfig,
    next: OpenClawConfig,
    actions: TrustedProxyAuthApplicatorActions,
    opts?: TrustedProxyAuthModeOpts,
  ): void;
};

/**
 * Per-Gateway-instance applicator. Closes over the last-applied trusted-proxy
 * auth fingerprint so a (prev -> next) transition observed by both the
 * in-process config-write trigger and the reloader trigger bumps and
 * dispatches exactly once. State is closure-scoped — never module-global —
 * so concurrent test gateways don't share dedup state.
 */
export function createTrustedProxyAuthApplicator(
  initialConfig: OpenClawConfig,
  opts?: { resolvedAuthMode?: ResolvedGatewayAuthMode },
): TrustedProxyAuthApplicator {
  let lastAppliedFingerprint = computeTrustedProxyAuthFingerprint(initialConfig, opts);
  return {
    apply(prev, next, actions, applyOpts) {
      const hasResolvedModeOpt = Boolean(
        applyOpts?.resolvedAuthMode ??
        applyOpts?.prevResolvedAuthMode ??
        applyOpts?.nextResolvedAuthMode,
      );
      const modeOpts = hasResolvedModeOpt ? applyOpts : undefined;
      if (!didTrustedProxyAuthChange(prev, next, modeOpts)) {
        return;
      }
      const fingerprint = computeTrustedProxyAuthFingerprint(next, {
        resolvedAuthMode: modeOpts?.nextResolvedAuthMode ?? modeOpts?.resolvedAuthMode,
      });
      if (fingerprint === lastAppliedFingerprint) {
        return;
      }
      lastAppliedFingerprint = fingerprint;
      actions.bumpTrustedProxyAuthGeneration();
      const plan = resolveTrustedProxyAuthDisconnectPlan(prev, next, modeOpts);
      switch (plan.kind) {
        case "none":
          return;
        case "bulk":
          actions.disconnectAllTrustedProxyClients({ reason: plan.reason });
          return;
        case "revalidate":
          actions.disconnectRevokedTrustedProxyClients(next);
          return;
        case "users":
          for (const user of plan.users) {
            actions.disconnectClientsForTrustedProxyUser(user, {
              reason: TRUSTED_PROXY_REVOKED_CLOSE_REASON,
            });
          }
          return;
      }
    },
  };
}
