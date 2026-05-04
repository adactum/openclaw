import { describe, expect, test } from "vitest";
import type { OpenClawConfig } from "../../../config/types.openclaw.js";
import type { TrustedProxyAuthEvidence } from "../../auth.js";
import { revalidateFrameAuth, type RevalidatableFrameClient } from "./revalidate-frame-auth.js";

const evidence: TrustedProxyAuthEvidence = {
  remoteAddr: "10.0.0.5",
  isLoopback: false,
  requiredHeadersPresented: ["x-forwarded-proto"],
  userHeaderName: "x-forwarded-user",
};

function trustedProxyRuntimeConfig(opts?: { allowUsers?: string[] }): OpenClawConfig {
  return {
    gateway: {
      auth: {
        mode: "trusted-proxy",
        trustedProxy: {
          userHeader: "x-forwarded-user",
          requiredHeaders: ["x-forwarded-proto"],
          ...(opts?.allowUsers ? { allowUsers: opts.allowUsers } : {}),
        },
      },
      trustedProxies: ["10.0.0.0/8"],
    },
  } as unknown as OpenClawConfig;
}

describe("revalidateFrameAuth", () => {
  test("shared-auth precedence: stale shared-auth gen closes before trusted-proxy is evaluated", () => {
    const client: RevalidatableFrameClient = {
      usesSharedGatewayAuth: true,
      sharedGatewaySessionGeneration: "old",
      trustedProxyUser: "alice",
      trustedProxyAuthGeneration: 0,
      trustedProxyAuthEvidence: evidence,
    };
    let runtimeConfigCalls = 0;
    const verdict = revalidateFrameAuth({
      client,
      method: "ping",
      getRequiredSharedGatewaySessionGeneration: () => "new",
      getTrustedProxyAuthGeneration: () => 5,
      getRuntimeConfig: () => {
        runtimeConfigCalls += 1;
        return trustedProxyRuntimeConfig();
      },
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.closeCode).toBe(4001);
      expect(verdict.closeReason).toBe("gateway auth changed");
      expect(verdict.causeReason).toBe("gateway-auth-rotated");
      expect(verdict.causeMeta).toMatchObject({ authGenerationStale: true, method: "ping" });
    }
    // Trusted-proxy branch must not have run.
    expect(runtimeConfigCalls).toBe(0);
    expect(client.trustedProxyAuthGeneration).toBe(0);
  });

  test("trusted-proxy in-place generation advancement when evidence still passes", () => {
    const client: RevalidatableFrameClient = {
      trustedProxyUser: "alice",
      trustedProxyAuthGeneration: 3,
      trustedProxyAuthEvidence: evidence,
    };
    const verdict = revalidateFrameAuth({
      client,
      method: "ping",
      getTrustedProxyAuthGeneration: () => 7,
      getRuntimeConfig: () => trustedProxyRuntimeConfig({ allowUsers: ["alice"] }),
    });
    expect(verdict.ok).toBe(true);
    expect(client.trustedProxyAuthGeneration).toBe(7);
  });

  test("trusted-proxy verdict-fail closes with revoked reason and preserves generation", () => {
    const client: RevalidatableFrameClient = {
      trustedProxyUser: "alice",
      trustedProxyAuthGeneration: 3,
      trustedProxyAuthEvidence: evidence,
    };
    const verdict = revalidateFrameAuth({
      client,
      method: "ping",
      getTrustedProxyAuthGeneration: () => 7,
      // Alice is no longer in allowUsers
      getRuntimeConfig: () => trustedProxyRuntimeConfig({ allowUsers: ["bob"] }),
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.closeCode).toBe(4001);
      expect(verdict.closeReason).toBe("trusted-proxy auth revoked");
      expect(verdict.causeReason).toBe("gateway-auth-rotated");
      expect(verdict.causeMeta).toMatchObject({ authGenerationStale: true, method: "ping" });
      expect(typeof verdict.causeMeta.trustedProxyRevocation).toBe("string");
    }
    // Generation must not advance on a fail verdict.
    expect(client.trustedProxyAuthGeneration).toBe(3);
  });

  test("ok when neither shared-auth nor trusted-proxy is present", () => {
    const client: RevalidatableFrameClient = {};
    const verdict = revalidateFrameAuth({
      client,
      method: "ping",
      getRuntimeConfig: () => trustedProxyRuntimeConfig(),
    });
    expect(verdict.ok).toBe(true);
  });
});
