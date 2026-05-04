import type { OpenClawConfig } from "../../../config/types.openclaw.js";
import type { TrustedProxyAuthEvidence } from "../../auth.js";
import { evaluateCachedTrustedProxySession } from "../../auth.js";

export type RevalidatableFrameClient = {
  usesSharedGatewayAuth?: boolean;
  sharedGatewaySessionGeneration?: string;
  trustedProxyUser?: string;
  trustedProxyAuthGeneration?: number;
  trustedProxyAuthEvidence?: TrustedProxyAuthEvidence;
};

export type RevalidateFrameAuthVerdict =
  | { ok: true }
  | {
      ok: false;
      closeCode: number;
      closeReason: string;
      causeReason: string;
      causeMeta: Record<string, unknown>;
    };

/**
 * Combined per-frame auth-rotation guard for shared-secret and trusted-proxy
 * sessions. On a successful trusted-proxy revalidation the caller's cached
 * generation is advanced in place. Order: shared-auth first, trusted-proxy
 * second.
 */
export function revalidateFrameAuth(params: {
  client: RevalidatableFrameClient;
  method: string;
  getRequiredSharedGatewaySessionGeneration?: () => string | undefined;
  getTrustedProxyAuthGeneration?: () => number;
  getRuntimeConfig: () => OpenClawConfig;
  getResolvedAuthMode?: () => string | undefined;
}): RevalidateFrameAuthVerdict {
  const { client, method } = params;
  if (client.usesSharedGatewayAuth) {
    const requiredSharedGatewaySessionGeneration =
      params.getRequiredSharedGatewaySessionGeneration?.();
    if (
      requiredSharedGatewaySessionGeneration !== undefined &&
      client.sharedGatewaySessionGeneration !== requiredSharedGatewaySessionGeneration
    ) {
      return {
        ok: false,
        closeCode: 4001,
        closeReason: "gateway auth changed",
        causeReason: "gateway-auth-rotated",
        causeMeta: { authGenerationStale: true, method },
      };
    }
  }
  if (client.trustedProxyUser !== undefined) {
    const currentTrustedProxyGeneration = params.getTrustedProxyAuthGeneration?.() ?? 0;
    if (client.trustedProxyAuthGeneration !== currentTrustedProxyGeneration) {
      const cfg = params.getRuntimeConfig();
      const verdict = evaluateCachedTrustedProxySession({
        user: client.trustedProxyUser,
        evidence: client.trustedProxyAuthEvidence,
        trustedProxyConfig: cfg.gateway?.auth?.trustedProxy,
        trustedProxies: cfg.gateway?.trustedProxies,
        gatewayAuthMode: params.getResolvedAuthMode?.() ?? cfg.gateway?.auth?.mode,
      });
      if (!verdict.ok) {
        return {
          ok: false,
          closeCode: 4001,
          closeReason: "trusted-proxy auth revoked",
          causeReason: "gateway-auth-rotated",
          causeMeta: {
            authGenerationStale: true,
            method,
            trustedProxyRevocation: verdict.reason,
          },
        };
      }
      client.trustedProxyAuthGeneration = currentTrustedProxyGeneration;
    }
  }
  return { ok: true };
}
