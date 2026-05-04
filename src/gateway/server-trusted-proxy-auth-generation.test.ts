import { describe, expect, test } from "vitest";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import {
  closeTrustedProxyClient,
  computeTrustedProxyAuthFingerprint,
  createTrustedProxyAuthApplicator,
  createTrustedProxyAuthGenerationState,
  didTrustedProxyAuthChange,
  didTrustedProxyHeaderOrSourcePolicyTighten,
  disconnectAllTrustedProxyClients,
  disconnectStaleTrustedProxyClients,
  resolveTrustedProxyAuthDisconnectPlan,
  type TrustedProxyAuthApplicatorActions,
  type TrustedProxyAuthClient,
} from "./server-trusted-proxy-auth-generation.js";

function tpConfig(opts: {
  mode?: string;
  userHeader?: string;
  requiredHeaders?: string[];
  allowUsers?: string[];
  allowLoopback?: boolean;
  trustedProxies?: string[];
}): OpenClawConfig {
  return {
    gateway: {
      auth: {
        mode: opts.mode ?? "trusted-proxy",
        trustedProxy: {
          userHeader: opts.userHeader ?? "x-forwarded-user",
          requiredHeaders: opts.requiredHeaders ?? ["x-forwarded-proto"],
          ...(opts.allowUsers !== undefined ? { allowUsers: opts.allowUsers } : {}),
          ...(opts.allowLoopback !== undefined ? { allowLoopback: opts.allowLoopback } : {}),
        },
      },
      trustedProxies: opts.trustedProxies ?? ["127.0.0.1", "10.0.0.0/8"],
    },
  } as OpenClawConfig;
}

describe("createTrustedProxyAuthGenerationState", () => {
  test("starts at 0 and bumps monotonically", () => {
    const state = createTrustedProxyAuthGenerationState();
    expect(state.get()).toBe(0);
    state.bump();
    expect(state.get()).toBe(1);
    state.bump();
    state.bump();
    expect(state.get()).toBe(3);
  });
});

describe("didTrustedProxyAuthChange", () => {
  test("stable under header/proxy/user reorders", () => {
    const a = tpConfig({
      requiredHeaders: ["x-forwarded-proto", "x-forwarded-user"],
      allowUsers: ["alice", "bob"],
      trustedProxies: ["127.0.0.1", "10.0.0.1"],
    });
    const b = tpConfig({
      requiredHeaders: ["x-forwarded-user", "x-forwarded-proto"],
      allowUsers: ["bob", "alice"],
      trustedProxies: ["10.0.0.1", "127.0.0.1"],
    });
    expect(didTrustedProxyAuthChange(a, b)).toBe(false);
  });

  test("detects user-header rename", () => {
    expect(
      didTrustedProxyAuthChange(
        tpConfig({ userHeader: "x-forwarded-user" }),
        tpConfig({ userHeader: "x-other-user" }),
      ),
    ).toBe(true);
  });

  test("detects effective auth-mode transition even when raw config mode is unchanged", () => {
    expect(
      didTrustedProxyAuthChange(
        tpConfig({ mode: "trusted-proxy" }),
        tpConfig({ mode: "trusted-proxy" }),
        {
          prevResolvedAuthMode: "trusted-proxy",
          nextResolvedAuthMode: "token",
        },
      ),
    ).toBe(true);
  });
});

describe("didTrustedProxyHeaderOrSourcePolicyTighten", () => {
  test("user-header rename tightens", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ userHeader: "x-forwarded-user" }),
        tpConfig({ userHeader: "x-other-user" }),
      ),
    ).toBe(true);
  });

  test("requiredHeaders add tightens", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ requiredHeaders: ["x-forwarded-proto"] }),
        tpConfig({ requiredHeaders: ["x-forwarded-proto", "x-tenant"] }),
      ),
    ).toBe(true);
  });

  test("requiredHeaders remove does not tighten", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ requiredHeaders: ["x-forwarded-proto", "x-tenant"] }),
        tpConfig({ requiredHeaders: ["x-forwarded-proto"] }),
      ),
    ).toBe(false);
  });

  test("allowLoopback true->false tightens", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ allowLoopback: true }),
        tpConfig({ allowLoopback: false }),
      ),
    ).toBe(true);
  });

  test("allowLoopback false->true does not tighten", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ allowLoopback: false }),
        tpConfig({ allowLoopback: true }),
      ),
    ).toBe(false);
  });

  test("trustedProxy CIDR removal tightens", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ trustedProxies: ["127.0.0.1", "10.0.0.1"] }),
        tpConfig({ trustedProxies: ["127.0.0.1"] }),
      ),
    ).toBe(true);
  });

  test("trustedProxy CIDR add does not tighten", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ trustedProxies: ["127.0.0.1"] }),
        tpConfig({ trustedProxies: ["127.0.0.1", "10.0.0.1"] }),
      ),
    ).toBe(false);
  });

  test("mode trusted-proxy -> off tightens", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ mode: "trusted-proxy" }),
        tpConfig({ mode: "off" }),
      ),
    ).toBe(true);
  });

  test("effective mode trusted-proxy -> token tightens when raw config mode is unchanged", () => {
    expect(
      didTrustedProxyHeaderOrSourcePolicyTighten(
        tpConfig({ mode: "trusted-proxy" }),
        tpConfig({ mode: "trusted-proxy" }),
        {
          prevResolvedAuthMode: "trusted-proxy",
          nextResolvedAuthMode: "token",
        },
      ),
    ).toBe(true);
  });
});

describe("resolveTrustedProxyAuthDisconnectPlan", () => {
  test("empty -> empty: none", () => {
    expect(
      resolveTrustedProxyAuthDisconnectPlan(
        tpConfig({ allowUsers: [] }),
        tpConfig({ allowUsers: [] }),
      ),
    ).toEqual({ kind: "none" });
  });

  test("empty -> finite: revalidate", () => {
    const plan = resolveTrustedProxyAuthDisconnectPlan(
      tpConfig({ allowUsers: [] }),
      tpConfig({ allowUsers: ["alice"] }),
    );
    expect(plan.kind).toBe("revalidate");
  });

  test("finite -> empty: none (loosen)", () => {
    expect(
      resolveTrustedProxyAuthDisconnectPlan(
        tpConfig({ allowUsers: ["alice"] }),
        tpConfig({ allowUsers: [] }),
      ),
    ).toEqual({ kind: "none" });
  });

  test('replacement ["alice"] -> ["bob"]: users ["alice"]', () => {
    expect(
      resolveTrustedProxyAuthDisconnectPlan(
        tpConfig({ allowUsers: ["alice"] }),
        tpConfig({ allowUsers: ["bob"] }),
      ),
    ).toEqual({ kind: "users", users: ["alice"] });
  });

  test('shrink ["alice","bob"] -> ["alice"]: users ["bob"]', () => {
    expect(
      resolveTrustedProxyAuthDisconnectPlan(
        tpConfig({ allowUsers: ["alice", "bob"] }),
        tpConfig({ allowUsers: ["alice"] }),
      ),
    ).toEqual({ kind: "users", users: ["bob"] });
  });

  test("mixed replace + grow: users contains only the removed user", () => {
    expect(
      resolveTrustedProxyAuthDisconnectPlan(
        tpConfig({ allowUsers: ["alice", "carol"] }),
        tpConfig({ allowUsers: ["bob", "carol", "dave"] }),
      ),
    ).toEqual({ kind: "users", users: ["alice"] });
  });

  test("grow only: none", () => {
    expect(
      resolveTrustedProxyAuthDisconnectPlan(
        tpConfig({ allowUsers: ["alice"] }),
        tpConfig({ allowUsers: ["alice", "bob"] }),
      ),
    ).toEqual({ kind: "none" });
  });

  test("user-header rename + finite-to-finite no-removal: bulk (orthogonal precedence)", () => {
    const plan = resolveTrustedProxyAuthDisconnectPlan(
      tpConfig({ userHeader: "x-forwarded-user", allowUsers: ["alice"] }),
      tpConfig({ userHeader: "x-other", allowUsers: ["alice"] }),
    );
    expect(plan.kind).toBe("bulk");
  });

  test("requiredHeader add + grow: bulk (orthogonal precedence)", () => {
    const plan = resolveTrustedProxyAuthDisconnectPlan(
      tpConfig({ requiredHeaders: ["x-forwarded-proto"], allowUsers: ["alice"] }),
      tpConfig({
        requiredHeaders: ["x-forwarded-proto", "x-tenant"],
        allowUsers: ["alice", "bob"],
      }),
    );
    expect(plan.kind).toBe("bulk");
  });

  test("source CIDR removal: bulk regardless of allowUsers shape", () => {
    const plan = resolveTrustedProxyAuthDisconnectPlan(
      tpConfig({ trustedProxies: ["127.0.0.1", "10.0.0.1"], allowUsers: [] }),
      tpConfig({ trustedProxies: ["127.0.0.1"], allowUsers: [] }),
    );
    expect(plan.kind).toBe("bulk");
  });

  test("allowLoopback true->false: bulk", () => {
    const plan = resolveTrustedProxyAuthDisconnectPlan(
      tpConfig({ allowLoopback: true, allowUsers: ["alice"] }),
      tpConfig({ allowLoopback: false, allowUsers: ["alice"] }),
    );
    expect(plan.kind).toBe("bulk");
  });
});

function makeTrustedProxyClient(
  user: string,
  requiredHeadersPresented: string[] = ["x-forwarded-proto"],
): TrustedProxyAuthClient & { closed?: { code: number; reason: string } } {
  const client = {
    socket: {
      close(code: number, reason: string) {
        client.closed = { code, reason };
      },
    },
    trustedProxyUser: user,
    trustedProxyAuthEvidence: {
      remoteAddr: "10.0.0.5",
      isLoopback: false,
      requiredHeadersPresented,
      userHeaderName: "x-forwarded-user",
    },
    closed: undefined as { code: number; reason: string } | undefined,
  };
  return client;
}

describe("disconnectStaleTrustedProxyClients", () => {
  test("closes clients whose user is no longer allowed; keeps allowlisted ones", () => {
    const alice = makeTrustedProxyClient("alice");
    const bob = makeTrustedProxyClient("bob");
    const next = tpConfig({ allowUsers: ["alice"] });
    disconnectStaleTrustedProxyClients([alice, bob], next);
    expect(alice.closed).toBeUndefined();
    expect(bob.closed).toEqual({ code: 4001, reason: "trusted-proxy auth revoked" });
  });

  test("closes clients when source CIDR is removed", () => {
    const carol = makeTrustedProxyClient("carol");
    const next = tpConfig({ trustedProxies: ["10.0.0.99"], allowUsers: [] });
    disconnectStaleTrustedProxyClients([carol], next);
    expect(carol.closed).toEqual({ code: 4001, reason: "trusted-proxy auth revoked" });
  });

  test("ignores non-trusted-proxy clients (no trustedProxyUser)", () => {
    const stranger = {
      socket: {
        close: () => {
          throw new Error("must not close");
        },
      },
    } as TrustedProxyAuthClient;
    disconnectStaleTrustedProxyClients([stranger], tpConfig({ allowUsers: ["alice"] }));
  });
});

describe("disconnectAllTrustedProxyClients", () => {
  test("closes only trusted-proxy clients with the supplied reason", () => {
    const alice = makeTrustedProxyClient("alice");
    const stranger = {
      closed: undefined as { code: number; reason: string } | undefined,
      socket: {
        close(code: number, reason: string) {
          (stranger as { closed?: unknown }).closed = { code, reason };
        },
      },
    } as TrustedProxyAuthClient & { closed?: { code: number; reason: string } };
    disconnectAllTrustedProxyClients([alice, stranger], { reason: "policy tightened" });
    expect(alice.closed).toEqual({ code: 4001, reason: "policy tightened" });
    expect(stranger.closed).toBeUndefined();
  });
});

describe("closeTrustedProxyClient", () => {
  test("swallows close errors", () => {
    expect(() =>
      closeTrustedProxyClient(
        {
          socket: {
            close() {
              throw new Error("boom");
            },
          },
        },
        "x",
      ),
    ).not.toThrow();
  });
});

type ApplicatorCallLog = {
  bumps: number;
  bulk: Array<{ reason: string }>;
  revalidate: number;
  users: string[];
};

function trackingActions(): {
  log: ApplicatorCallLog;
  actions: TrustedProxyAuthApplicatorActions;
} {
  const log: ApplicatorCallLog = { bumps: 0, bulk: [], revalidate: 0, users: [] };
  const actions: TrustedProxyAuthApplicatorActions = {
    bumpTrustedProxyAuthGeneration: () => {
      log.bumps += 1;
    },
    disconnectAllTrustedProxyClients: (opts) => {
      log.bulk.push({ reason: opts.reason });
    },
    disconnectRevokedTrustedProxyClients: () => {
      log.revalidate += 1;
    },
    disconnectClientsForTrustedProxyUser: (user) => {
      log.users.push(user);
    },
  };
  return { log, actions };
}

describe("createTrustedProxyAuthApplicator", () => {
  test("dedups (prev -> next) transition across two calls (in-process + reloader)", () => {
    const prev = tpConfig({ allowUsers: ["alice", "bob"] });
    const next = tpConfig({ allowUsers: ["alice"] });
    const applicator = createTrustedProxyAuthApplicator(prev);
    const { log, actions } = trackingActions();

    applicator.apply(prev, next, actions);
    applicator.apply(prev, next, actions);

    expect(log.bumps).toBe(1);
    expect(log.users).toEqual(["bob"]);
  });

  test("a fresh transition after a deduped one bumps again", () => {
    const a = tpConfig({ allowUsers: ["alice", "bob"] });
    const b = tpConfig({ allowUsers: ["alice"] });
    const c = tpConfig({ allowUsers: [] });
    const applicator = createTrustedProxyAuthApplicator(a);
    const { log, actions } = trackingActions();

    applicator.apply(a, b, actions);
    applicator.apply(a, b, actions);
    expect(log.bumps).toBe(1);

    applicator.apply(b, c, actions);
    expect(log.bumps).toBe(2);
  });

  test("does not bump when transition matches the startup-primed fingerprint", () => {
    const initial = tpConfig({ allowUsers: ["alice"] });
    const applicator = createTrustedProxyAuthApplicator(initial);
    const { log, actions } = trackingActions();

    // The reloader sees a (prev, next) where next == initial (e.g. dryrun reload that
    // computed the same shape as startup). The applicator must dedup: nothing to do.
    const prev = tpConfig({ allowUsers: ["alice", "bob"] });
    applicator.apply(prev, initial, actions);

    expect(log.bumps).toBe(0);
    expect(log.users).toEqual([]);
  });

  test("two independent applicator instances applying the same next fingerprint each bump once", () => {
    const prev = tpConfig({ allowUsers: ["alice", "bob"] });
    const next = tpConfig({ allowUsers: ["alice"] });
    const applicatorA = createTrustedProxyAuthApplicator(prev);
    const applicatorB = createTrustedProxyAuthApplicator(prev);
    const a = trackingActions();
    const b = trackingActions();

    applicatorA.apply(prev, next, a.actions);
    applicatorB.apply(prev, next, b.actions);

    expect(a.log.bumps).toBe(1);
    expect(b.log.bumps).toBe(1);
    // Each instance's dedup state is private — re-running the same transition is
    // idempotent per instance, not across instances.
    applicatorA.apply(prev, next, a.actions);
    expect(a.log.bumps).toBe(1);
  });

  test("noop when prev/next have identical trusted-proxy fingerprint", () => {
    const cfg = tpConfig({ allowUsers: ["alice"] });
    const applicator = createTrustedProxyAuthApplicator(cfg);
    const { log, actions } = trackingActions();

    applicator.apply(cfg, cfg, actions);

    expect(log.bumps).toBe(0);
  });

  test("dispatches bulk disconnect on header/source/loopback/mode tightening", () => {
    const prev = tpConfig({ allowLoopback: true });
    const next = tpConfig({ allowLoopback: false });
    const applicator = createTrustedProxyAuthApplicator(prev);
    const { log, actions } = trackingActions();

    applicator.apply(prev, next, actions);

    expect(log.bumps).toBe(1);
    expect(log.bulk).toEqual([{ reason: "trusted-proxy header/source policy changed" }]);
  });

  test("dispatches bulk disconnect on effective mode tightening with unchanged raw config mode", () => {
    const prev = tpConfig({ mode: "trusted-proxy" });
    const next = tpConfig({ mode: "trusted-proxy" });
    const applicator = createTrustedProxyAuthApplicator(prev, {
      resolvedAuthMode: "trusted-proxy",
    });
    const { log, actions } = trackingActions();

    applicator.apply(prev, next, actions, {
      prevResolvedAuthMode: "trusted-proxy",
      nextResolvedAuthMode: "token",
    });

    expect(log.bumps).toBe(1);
    expect(log.bulk).toEqual([{ reason: "trusted-proxy header/source policy changed" }]);
  });

  test("dispatches revalidate on allowUsers narrowing from allow-all", () => {
    const prev = tpConfig({});
    const next = tpConfig({ allowUsers: ["alice"] });
    const applicator = createTrustedProxyAuthApplicator(prev);
    const { log, actions } = trackingActions();

    applicator.apply(prev, next, actions);

    expect(log.revalidate).toBe(1);
  });
});

describe("computeTrustedProxyAuthFingerprint", () => {
  test("stable across reordering of header/proxy/user lists", () => {
    const a = computeTrustedProxyAuthFingerprint(
      tpConfig({
        requiredHeaders: ["x-forwarded-proto", "x-forwarded-user"],
        allowUsers: ["alice", "bob"],
        trustedProxies: ["127.0.0.1", "10.0.0.1"],
      }),
    );
    const b = computeTrustedProxyAuthFingerprint(
      tpConfig({
        requiredHeaders: ["x-forwarded-user", "x-forwarded-proto"],
        allowUsers: ["bob", "alice"],
        trustedProxies: ["10.0.0.1", "127.0.0.1"],
      }),
    );
    expect(a).toBe(b);
  });

  test("differs when allowUsers content changes", () => {
    expect(computeTrustedProxyAuthFingerprint(tpConfig({ allowUsers: ["alice"] }))).not.toBe(
      computeTrustedProxyAuthFingerprint(tpConfig({ allowUsers: ["bob"] })),
    );
  });
});
