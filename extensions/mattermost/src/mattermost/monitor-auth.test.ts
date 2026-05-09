import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const evaluateSenderGroupAccessForPolicy = vi.hoisted(() => vi.fn());
const isDangerousNameMatchingEnabled = vi.hoisted(() => vi.fn());
const resolveAllowlistMatchSimple = vi.hoisted(() => vi.fn());
const resolveControlCommandGate = vi.hoisted(() => vi.fn());
const resolveEffectiveAllowFromLists = vi.hoisted(() => vi.fn());

vi.mock("./runtime-api.js", () => ({
  evaluateSenderGroupAccessForPolicy,
  isDangerousNameMatchingEnabled,
  resolveAllowlistMatchSimple,
  resolveControlCommandGate,
  resolveEffectiveAllowFromLists,
}));

describe("mattermost monitor auth", () => {
  let authorizeMattermostCommandInvocation: typeof import("./monitor-auth.js").authorizeMattermostCommandInvocation;
  let isMattermostSenderAllowed: typeof import("./monitor-auth.js").isMattermostSenderAllowed;
  let normalizeMattermostAllowEntry: typeof import("./monitor-auth.js").normalizeMattermostAllowEntry;
  let normalizeMattermostAllowList: typeof import("./monitor-auth.js").normalizeMattermostAllowList;
  let resolveMattermostEffectiveAllowFromLists: typeof import("./monitor-auth.js").resolveMattermostEffectiveAllowFromLists;

  beforeAll(async () => {
    ({
      authorizeMattermostCommandInvocation,
      isMattermostSenderAllowed,
      normalizeMattermostAllowEntry,
      normalizeMattermostAllowList,
      resolveMattermostEffectiveAllowFromLists,
    } = await import("./monitor-auth.js"));
  });

  beforeEach(() => {
    evaluateSenderGroupAccessForPolicy.mockReset();
    isDangerousNameMatchingEnabled.mockReset();
    resolveAllowlistMatchSimple.mockReset();
    resolveControlCommandGate.mockReset();
    resolveEffectiveAllowFromLists.mockReset();
  });

  it("normalizes allowlist entries and resolves effective lists", () => {
    resolveEffectiveAllowFromLists.mockReturnValue({
      effectiveAllowFrom: ["alice"],
      effectiveGroupAllowFrom: ["team"],
    });

    expect(normalizeMattermostAllowEntry(" @Alice ")).toBe("alice");
    expect(normalizeMattermostAllowEntry("mattermost:Bob")).toBe("bob");
    expect(normalizeMattermostAllowEntry("*")).toBe("*");
    expect(normalizeMattermostAllowList([" Alice ", "user:alice", "ALICE", "*"])).toEqual([
      "alice",
      "*",
    ]);
    expect(
      resolveMattermostEffectiveAllowFromLists({
        allowFrom: [" Alice "],
        groupAllowFrom: [" Team "],
        storeAllowFrom: ["Store"],
        dmPolicy: "pairing",
      }),
    ).toEqual({
      effectiveAllowFrom: ["alice"],
      effectiveGroupAllowFrom: ["team"],
    });
    expect(resolveEffectiveAllowFromLists).toHaveBeenCalledWith({
      allowFrom: ["alice"],
      groupAllowFrom: ["team"],
      storeAllowFrom: ["store"],
      dmPolicy: "pairing",
    });
  });

  it("checks sender allowlists against normalized ids and names", () => {
    resolveAllowlistMatchSimple.mockReturnValue({ allowed: true });
    expect(
      isMattermostSenderAllowed({
        senderId: "@Alice",
        senderName: "Alice",
        allowFrom: [" mattermost:alice "],
        allowNameMatching: true,
      }),
    ).toBe(true);
    expect(resolveAllowlistMatchSimple).toHaveBeenCalledWith({
      allowFrom: ["alice"],
      senderId: "alice",
      senderName: "alice",
      allowNameMatching: true,
    });
  });

  it("requires open direct messages to match the effective allowlist", () => {
    isDangerousNameMatchingEnabled.mockReturnValue(false);
    resolveEffectiveAllowFromLists.mockReturnValue({
      effectiveAllowFrom: [],
      effectiveGroupAllowFrom: [],
    });
    resolveControlCommandGate.mockReturnValue({
      commandAuthorized: false,
      shouldBlock: false,
    });
    evaluateSenderGroupAccessForPolicy.mockReturnValue({
      allowed: false,
      reason: "empty_allowlist",
    });
    resolveAllowlistMatchSimple.mockReturnValue({ allowed: false });

    expect(
      authorizeMattermostCommandInvocation({
        account: {
          config: { dmPolicy: "open" },
        } as never,
        cfg: {} as never,
        senderId: "alice",
        senderName: "Alice",
        channelId: "dm-1",
        channelInfo: { type: "D", name: "alice", display_name: "Alice" } as never,
        allowTextCommands: false,
        hasControlCommand: false,
      }),
    ).toMatchObject({
      ok: false,
      denyReason: "unauthorized",
      kind: "direct",
    });

    resolveEffectiveAllowFromLists.mockReturnValue({
      effectiveAllowFrom: ["*"],
      effectiveGroupAllowFrom: [],
    });
    resolveAllowlistMatchSimple.mockReturnValue({ allowed: true });

    expect(
      authorizeMattermostCommandInvocation({
        account: {
          config: { dmPolicy: "open", allowFrom: ["*"] },
        } as never,
        cfg: {} as never,
        senderId: "alice",
        senderName: "Alice",
        channelId: "dm-1",
        channelInfo: { type: "D", name: "alice", display_name: "Alice" } as never,
        allowTextCommands: false,
        hasControlCommand: false,
      }),
    ).toMatchObject({
      ok: true,
      commandAuthorized: true,
      kind: "direct",
    });

    expect(
      authorizeMattermostCommandInvocation({
        account: {
          config: { dmPolicy: "disabled" },
        } as never,
        cfg: {} as never,
        senderId: "alice",
        senderName: "Alice",
        channelId: "dm-1",
        channelInfo: { type: "D", name: "alice", display_name: "Alice" } as never,
        allowTextCommands: false,
        hasControlCommand: false,
      }),
    ).toMatchObject({
      ok: false,
      denyReason: "dm-disabled",
    });

    expect(
      authorizeMattermostCommandInvocation({
        account: {
          config: { groupPolicy: "allowlist" },
        } as never,
        cfg: {} as never,
        senderId: "alice",
        senderName: "Alice",
        channelId: "chan-1",
        channelInfo: { type: "O", name: "town-square", display_name: "Town Square" } as never,
        allowTextCommands: true,
        hasControlCommand: false,
      }),
    ).toMatchObject({
      ok: false,
      denyReason: "channel-no-allowlist",
      kind: "channel",
    });
  });
});

describe("resolveButtonClickChannelAuthorization", () => {
  // resolveButtonClickChannelAuthorization does not use runtime-api.js; import directly.
  let resolveButtonClickChannelAuthorization: typeof import("./monitor-auth.js").resolveButtonClickChannelAuthorization;

  beforeAll(async () => {
    ({ resolveButtonClickChannelAuthorization } = await import("./monitor-auth.js"));
  });

  const baseAccount = {
    accountId: "default",
    enabled: true,
    botToken: "bot-token",
    baseUrl: "https://chat.example.com",
    botTokenSource: "config",
    baseUrlSource: "config",
    streamingMode: "partial",
    config: {},
  } as never;

  const channelInfo = {
    id: "chan-1",
    type: "O",
    name: "general",
    display_name: "General",
  } as never;
  const dmChannelInfo = { id: "dm-1", type: "D", name: "", display_name: "" } as never;

  it("allows a public channel when groupPolicy is open", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo,
        account: baseAccount,
        groupPolicy: "open",
        context: {} as Record<string, unknown>,
      }),
    ).toEqual({ ok: true });
  });

  it("allows a public channel when groupPolicy is allowlist and entries are configured", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo,
        account: { ...baseAccount, config: { allowFrom: ["trusted-user"] } } as never,
        groupPolicy: "allowlist",
        context: {} as Record<string, unknown>,
      }),
    ).toEqual({ ok: true });
  });

  it("denies a public channel when groupPolicy is disabled", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo,
        account: baseAccount,
        groupPolicy: "disabled",
        context: {} as Record<string, unknown>,
      }),
    ).toMatchObject({ ok: false });
  });

  it("denies a public channel when groupPolicy is allowlist with no entries configured", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo,
        account: baseAccount,
        groupPolicy: "allowlist",
        context: {} as Record<string, unknown>,
      }),
    ).toMatchObject({ ok: false });
  });

  it("allows a picker DM click when dmPolicy is pairing", () => {
    // Picker contexts carry an HMAC-sealed owner identity, so DM picker clicks are
    // allowed even though the clicker is not authenticated.
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo: dmChannelInfo,
        account: { ...baseAccount, config: { dmPolicy: "pairing" } } as never,
        groupPolicy: "allowlist",
        context: { oc_model_picker: true, ownerUserId: "u-1", action: "providers" } as Record<
          string,
          unknown
        >,
      }),
    ).toEqual({ ok: true });
  });

  it("denies a non-picker DM click even when dmPolicy permits DMs", () => {
    // Generic (non-picker) button clicks in DMs are denied because the clicker
    // cannot be authenticated and dispatch is skipped downstream — proceeding
    // would write a trusted system event and post update with no agent action
    // (a silent false-success).
    const result = resolveButtonClickChannelAuthorization({
      channelInfo: dmChannelInfo,
      account: { ...baseAccount, config: { dmPolicy: "pairing" } } as never,
      groupPolicy: "allowlist",
      context: {} as Record<string, unknown>,
    });
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) {
      expect(result.ephemeralText).toMatch(/direct message/i);
    }
  });

  it("denies any DM click (picker or not) when dmPolicy is disabled", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo: dmChannelInfo,
        account: { ...baseAccount, config: { dmPolicy: "disabled" } } as never,
        groupPolicy: "open",
        context: { oc_model_picker: true, ownerUserId: "u-1", action: "providers" } as Record<
          string,
          unknown
        >,
      }),
    ).toMatchObject({ ok: false });
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo: dmChannelInfo,
        account: { ...baseAccount, config: { dmPolicy: "disabled" } } as never,
        groupPolicy: "open",
        context: {} as Record<string, unknown>,
      }),
    ).toMatchObject({ ok: false });
  });

  it("allows button clicks even when text commands are disabled (native slash-command picker flows)", () => {
    // Button callbacks can originate from native slash commands (e.g. /models) that remain
    // active even when commands.text=false. The guard must not block these.
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo,
        account: { ...baseAccount, config: { allowFrom: ["trusted-user"] } } as never,
        groupPolicy: "open",
        context: {} as Record<string, unknown>,
      }),
    ).toEqual({ ok: true });
  });

  it("denies when channelInfo is null (unknown channel type)", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo: null,
        account: baseAccount,
        groupPolicy: "open",
        context: {} as Record<string, unknown>,
      }),
    ).toMatchObject({ ok: false });
  });

  it("uses groupAllowFrom when configured instead of allowFrom", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo,
        account: {
          ...baseAccount,
          config: { groupAllowFrom: ["group-member"], allowFrom: [] },
        } as never,
        groupPolicy: "allowlist",
        context: {} as Record<string, unknown>,
      }),
    ).toEqual({ ok: true });
  });
  // ── Full-parser classification (Tests E–G) ──────────────────────────

  it("denies a malformed signed picker DM (tag set, ownerUserId missing)", () => {
    // Even an HMAC-valid context tagged oc_model_picker:true is denied at the auth
    // boundary when it does not parse as picker state (no ownerUserId / no valid action).
    const malformed = { action_id: "approve", oc_model_picker: true } as Record<string, unknown>;
    const result = resolveButtonClickChannelAuthorization({
      channelInfo: dmChannelInfo,
      account: { ...baseAccount, config: { dmPolicy: "pairing" } } as never,
      groupPolicy: "open",
      context: malformed,
    });
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) {
      expect(result.ephemeralText).toMatch(/direct message/i);
    }
  });

  it("allows a valid picker DM (parseable picker state with ownerUserId + valid action)", () => {
    const valid = {
      ownerUserId: "u-1",
      action: "providers",
      oc_model_picker: true,
    } as Record<string, unknown>;
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo: dmChannelInfo,
        account: { ...baseAccount, config: { dmPolicy: "pairing" } } as never,
        groupPolicy: "open",
        context: valid,
      }),
    ).toEqual({ ok: true });
  });

  it("allows a generic public-channel click (compat: channel-policy gate still passes)", () => {
    expect(
      resolveButtonClickChannelAuthorization({
        channelInfo,
        account: { ...baseAccount, config: { allowFrom: ["trusted-user"] } } as never,
        groupPolicy: "allowlist",
        context: {} as Record<string, unknown>,
      }),
    ).toEqual({ ok: true });
  });
});
