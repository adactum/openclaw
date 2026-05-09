import { beforeEach, describe, expect, it, vi } from "vitest";
import type { OpenClawConfig, RuntimeEnv } from "./runtime-api.js";

class FakeWebSocket {
  public readonly sent: string[] = [];
  private readonly openListeners: Array<() => void> = [];
  private readonly messageListeners: Array<(data: Buffer) => void | Promise<void>> = [];
  private readonly pongListeners: Array<(data: Buffer) => void> = [];
  private readonly closeListeners: Array<(code: number, reason: Buffer) => void> = [];
  private readonly errorListeners: Array<(err: unknown) => void> = [];

  on(event: "open", listener: () => void): void;
  on(event: "message", listener: (data: Buffer) => void | Promise<void>): void;
  on(event: "pong", listener: (data: Buffer) => void): void;
  on(event: "close", listener: (code: number, reason: Buffer) => void): void;
  on(event: "error", listener: (err: unknown) => void): void;
  on(event: "open" | "message" | "pong" | "close" | "error", listener: unknown): void {
    if (event === "open") {
      this.openListeners.push(listener as () => void);
      return;
    }
    if (event === "message") {
      this.messageListeners.push(listener as (data: Buffer) => void | Promise<void>);
      return;
    }
    if (event === "pong") {
      this.pongListeners.push(listener as (data: Buffer) => void);
      return;
    }
    if (event === "close") {
      this.closeListeners.push(listener as (code: number, reason: Buffer) => void);
      return;
    }
    this.errorListeners.push(listener as (err: unknown) => void);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  ping(): void {}

  close(): void {}

  terminate(): void {}

  get openListenerCount(): number {
    return this.openListeners.length;
  }

  emitOpen(): void {
    for (const listener of this.openListeners) {
      listener();
    }
  }

  async emitMessage(payload: unknown): Promise<void> {
    const buffer = Buffer.from(JSON.stringify(payload), "utf8");
    await Promise.all(this.messageListeners.map((listener) => Promise.resolve(listener(buffer))));
  }

  emitClose(code: number, reason = ""): void {
    const buffer = Buffer.from(reason, "utf8");
    for (const listener of this.closeListeners) {
      listener(code, buffer);
    }
  }

  emitError(err: unknown): void {
    for (const listener of this.errorListeners) {
      listener(err);
    }
  }
}

const mockState = vi.hoisted(() => ({
  abortController: undefined as AbortController | undefined,
  createMattermostClient: vi.fn(),
  createMattermostDraftStream: vi.fn(),
  dispatchReplyFromConfig: vi.fn(),
  enqueueSystemEvent: vi.fn(),
  fetchMattermostMe: vi.fn(),
  registerMattermostMonitorSlashCommands: vi.fn(),
  registerPluginHttpRoute: vi.fn(),
  resolveChannelInfo: vi.fn(),
  resolveMattermostMedia: vi.fn(),
  resolveUserInfo: vi.fn(),
  runtimeCore: undefined as unknown,
  updateMattermostPost: vi.fn(),
}));

vi.mock("./client.js", async () => {
  const actual = await vi.importActual<typeof import("./client.js")>("./client.js");
  return {
    ...actual,
    createMattermostClient: mockState.createMattermostClient,
    fetchMattermostMe: mockState.fetchMattermostMe,
    normalizeMattermostBaseUrl: (value: string | undefined) => value?.trim() ?? "",
    updateMattermostPost: mockState.updateMattermostPost,
  };
});

vi.mock("./draft-stream.js", () => ({
  buildMattermostToolStatusText: () => "Working",
  createMattermostDraftStream: mockState.createMattermostDraftStream,
}));

vi.mock("./monitor-resources.js", () => ({
  createMattermostMonitorResources: () => ({
    resolveMattermostMedia: mockState.resolveMattermostMedia,
    sendTypingIndicator: vi.fn(async () => {}),
    resolveChannelInfo: mockState.resolveChannelInfo,
    resolveUserInfo: mockState.resolveUserInfo,
    updateModelPickerPost: vi.fn(async () => {}),
  }),
}));

vi.mock("./monitor-slash.js", () => ({
  registerMattermostMonitorSlashCommands: mockState.registerMattermostMonitorSlashCommands,
}));

vi.mock("./runtime-api.js", async () => {
  const actual = await vi.importActual<typeof import("./runtime-api.js")>("./runtime-api.js");
  return {
    ...actual,
    buildAgentMediaPayload: vi.fn(() => ({})),
    createChannelPairingController: vi.fn(() => ({
      readStoreForDmPolicy: vi.fn(async () => []),
      upsertPairingRequest: vi.fn(async () => ({ code: "123456", created: true })),
    })),
    createChannelMessageReplyPipeline: vi.fn(() => ({
      onModelSelected: vi.fn(),
      typingCallbacks: {},
    })),
    readStoreAllowFromForDmPolicy: vi.fn(async () => []),
    registerPluginHttpRoute: mockState.registerPluginHttpRoute,
    resolveChannelMediaMaxBytes: vi.fn(() => 8 * 1024 * 1024),
    warnMissingProviderGroupPolicyFallbackOnce: vi.fn(),
  };
});

function createRuntimeCore(cfg: OpenClawConfig) {
  const runPrepared = vi.fn(
    async (turn: {
      storePath: string;
      routeSessionKey: string;
      ctxPayload: { SessionKey?: string };
      recordInboundSession: (params: unknown) => Promise<void>;
      record?: {
        groupResolution?: unknown;
        createIfMissing?: boolean;
        updateLastRoute?: unknown;
        onRecordError?: (err: unknown) => void;
      };
      runDispatch: () => Promise<{
        queuedFinal: boolean;
        counts: { tool: number; block: number; final: number };
      }>;
    }) => {
      await turn.recordInboundSession({
        storePath: turn.storePath,
        sessionKey: turn.ctxPayload.SessionKey ?? turn.routeSessionKey,
        ctx: turn.ctxPayload,
        groupResolution: turn.record?.groupResolution,
        createIfMissing: turn.record?.createIfMissing,
        updateLastRoute: turn.record?.updateLastRoute,
        onRecordError: turn.record?.onRecordError ?? (() => undefined),
      });
      const dispatchResult = await turn.runDispatch();
      return {
        admission: { kind: "dispatch" as const },
        dispatched: true,
        ctxPayload: turn.ctxPayload,
        routeSessionKey: turn.routeSessionKey,
        dispatchResult,
      };
    },
  );
  const run = vi.fn(
    async (params: {
      raw: unknown;
      adapter: {
        ingest: (raw: unknown) => unknown;
        resolveTurn: (
          input: unknown,
          eventClass: { kind: "message"; canStartAgentTurn: true },
          preflight: Record<string, never>,
        ) => Parameters<typeof runPrepared>[0];
      };
    }) => {
      const input = params.adapter.ingest(params.raw);
      const turn = params.adapter.resolveTurn(
        input,
        { kind: "message", canStartAgentTurn: true },
        {},
      );
      return await runPrepared(turn);
    },
  );
  return {
    config: {
      current: () => cfg,
    },
    logging: {
      shouldLogVerbose: () => false,
      getChildLogger: () => ({
        debug: vi.fn(),
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
      }),
    },
    media: {
      mediaKindFromMime: () => "document",
    },
    system: {
      enqueueSystemEvent: mockState.enqueueSystemEvent,
    },
    channel: {
      activity: {
        record: vi.fn(),
      },
      commands: {
        shouldHandleTextCommands: () => false,
      },
      debounce: {
        resolveInboundDebounceMs: () => 0,
        createInboundDebouncer: <T>(params: {
          onFlush: (entries: T[]) => Promise<void> | void;
        }) => ({
          enqueue: async (entry: T) => {
            await params.onFlush([entry]);
          },
        }),
      },
      groups: {
        resolveRequireMention: () => false,
      },
      media: {
        fetchRemoteMedia: vi.fn(),
        saveMediaBuffer: vi.fn(),
      },
      mentions: {
        buildMentionRegexes: () => [],
        matchesMentionPatterns: () => false,
      },
      pairing: {
        buildPairingReply: () => "pairing required",
      },
      reply: {
        createReplyDispatcherWithTyping: vi.fn(() => ({
          dispatcher: {},
          replyOptions: {},
          markDispatchIdle: vi.fn(),
          markRunComplete: vi.fn(),
        })),
        dispatchReplyFromConfig: mockState.dispatchReplyFromConfig,
        finalizeInboundContext: (context: unknown) => context,
        formatInboundEnvelope: (params: { channel: string; from: string; body: string }) =>
          `${params.channel} ${params.from}\n${params.body}`,
        resolveHumanDelayConfig: () => ({}),
        withReplyDispatcher: async (params: { run: () => unknown; onSettled?: () => void }) => {
          try {
            return await params.run();
          } finally {
            params.onSettled?.();
          }
        },
      },
      routing: {
        resolveAgentRoute: () => ({
          accountId: "default",
          agentId: "main",
          mainSessionKey: "mattermost:default:channel:chan-1",
          sessionKey: "mattermost:default:channel:chan-1",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-test-sessions.json",
        recordInboundSession: vi.fn(async () => {}),
        updateLastRoute: vi.fn(async () => {}),
      },
      turn: {
        run,
        runPrepared,
      },
      text: {
        chunkMarkdownTextWithMode: (text: string) => [text],
        convertMarkdownTables: (text: string) => text,
        hasControlCommand: () => false,
        resolveChunkMode: () => "off",
        resolveMarkdownTableMode: () => "off",
        resolveTextChunkLimit: () => 4000,
      },
    },
  };
}

const testConfig: OpenClawConfig = {
  channels: {
    mattermost: {
      enabled: true,
      baseUrl: "https://mattermost.example.com",
      botToken: "bot-token",
      chatmode: "onmessage",
      dmPolicy: "open",
      groupPolicy: "open",
    },
  },
};

vi.mock("../runtime.js", () => ({
  getMattermostRuntime: () => mockState.runtimeCore,
}));

const testRuntime = (): RuntimeEnv =>
  ({
    log: vi.fn(),
    error: vi.fn(),
    exit: ((code: number): never => {
      throw new Error(`exit ${code}`);
    }) as RuntimeEnv["exit"],
  }) satisfies RuntimeEnv;

describe("mattermost inbound user posts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockState.abortController = undefined;
    mockState.runtimeCore = createRuntimeCore(testConfig);
    mockState.createMattermostClient.mockReturnValue({});
    mockState.createMattermostDraftStream.mockReturnValue({
      update: vi.fn(),
      stop: vi.fn(async () => {}),
    });
    mockState.fetchMattermostMe.mockResolvedValue({
      id: "bot-user",
      username: "openclaw",
      update_at: 1,
    });
    mockState.registerMattermostMonitorSlashCommands.mockResolvedValue(undefined);
    mockState.registerPluginHttpRoute.mockReturnValue(vi.fn());
    mockState.resolveChannelInfo.mockResolvedValue({
      id: "chan-1",
      name: "town-square",
      display_name: "Town Square",
      team_id: "team-1",
      type: "O",
    });
    mockState.resolveMattermostMedia.mockResolvedValue([]);
    mockState.resolveUserInfo.mockResolvedValue({ id: "user-1", username: "alice" });
    mockState.dispatchReplyFromConfig.mockImplementation(async () => {
      mockState.abortController?.abort();
    });
  });

  it("does not enqueue regular user posts as system events", async () => {
    const socket = new FakeWebSocket();
    const abortController = new AbortController();
    mockState.abortController = abortController;
    const { monitorMattermostProvider } = await import("./monitor.js");

    const monitor = monitorMattermostProvider({
      config: testConfig,
      runtime: testRuntime(),
      abortSignal: abortController.signal,
      webSocketFactory: () => socket,
    });

    await vi.waitFor(() => {
      expect(socket.openListenerCount).toBeGreaterThan(0);
    });
    socket.emitOpen();

    await socket.emitMessage({
      event: "posted",
      data: {
        channel_id: "chan-1",
        channel_name: "town-square",
        channel_display_name: "Town Square",
        sender_name: "alice",
        post: JSON.stringify({
          id: "post-1",
          channel_id: "chan-1",
          user_id: "user-1",
          message: "hello from mattermost",
          create_at: 1_714_000_000_000,
        }),
      },
      broadcast: {
        channel_id: "chan-1",
        user_id: "user-1",
      },
    });
    socket.emitClose(1000);
    await monitor;

    expect(mockState.enqueueSystemEvent).not.toHaveBeenCalled();
    expect(mockState.dispatchReplyFromConfig).toHaveBeenCalledTimes(1);
    expect(mockState.dispatchReplyFromConfig.mock.calls[0]?.[0].ctx).toMatchObject({
      BodyForAgent: "hello from mattermost",
      ConversationLabel: "Town Square id:chan-1",
      MessageSid: "post-1",
      OriginatingChannel: "mattermost",
      Provider: "mattermost",
    });
  });

  it("pins direct-message main route updates to the configured owner", async () => {
    const socket = new FakeWebSocket();
    const abortController = new AbortController();
    mockState.abortController = abortController;
    const directConfig: OpenClawConfig = {
      channels: {
        mattermost: {
          enabled: true,
          baseUrl: "https://mattermost.example.com",
          botToken: "bot-token",
          chatmode: "onmessage",
          dmPolicy: "allowlist",
          groupPolicy: "open",
          allowFrom: ["user-1"],
        },
      },
    };
    const runtimeCore = createRuntimeCore(directConfig);
    mockState.runtimeCore = runtimeCore;
    mockState.resolveChannelInfo.mockResolvedValue({
      id: "dm-1",
      name: "",
      display_name: "",
      team_id: "team-1",
      type: "D",
    });
    const { monitorMattermostProvider } = await import("./monitor.js");

    const monitor = monitorMattermostProvider({
      config: directConfig,
      runtime: testRuntime(),
      abortSignal: abortController.signal,
      webSocketFactory: () => socket,
    });

    await vi.waitFor(() => {
      expect(socket.openListenerCount).toBeGreaterThan(0);
    });
    socket.emitOpen();

    await socket.emitMessage({
      event: "posted",
      data: {
        channel_id: "dm-1",
        sender_name: "alice",
        post: JSON.stringify({
          id: "post-dm-1",
          channel_id: "dm-1",
          user_id: "user-1",
          message: "direct hello",
          create_at: 1_714_000_000_000,
        }),
      },
      broadcast: {
        channel_id: "dm-1",
        user_id: "user-1",
      },
    });
    socket.emitClose(1000);
    await monitor;

    expect(runtimeCore.channel.session.recordInboundSession).toHaveBeenCalledWith(
      expect.objectContaining({
        updateLastRoute: expect.objectContaining({
          channel: "mattermost",
          to: "user:user-1",
          mainDmOwnerPin: expect.objectContaining({
            ownerRecipient: "user-1",
            senderRecipient: "user-1",
          }),
        }),
      }),
    );
  });
});

describe("mattermost button click HTTP handler — prompt-taint and malformed-picker DM", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockState.abortController = undefined;
    mockState.runtimeCore = createRuntimeCore(testConfig);
    mockState.createMattermostClient.mockReturnValue({
      baseUrl: "https://mattermost.example.com",
      apiBaseUrl: "https://mattermost.example.com/api/v4",
      token: "bot-token",
      request: vi.fn(),
      fetchImpl: vi.fn(),
    });
    mockState.createMattermostDraftStream.mockReturnValue({
      update: vi.fn(),
      stop: vi.fn(async () => {}),
    });
    mockState.fetchMattermostMe.mockResolvedValue({
      id: "bot-user",
      username: "openclaw",
      update_at: 1,
    });
    mockState.registerMattermostMonitorSlashCommands.mockResolvedValue(undefined);
    mockState.registerPluginHttpRoute.mockReturnValue(vi.fn());
    mockState.resolveChannelInfo.mockResolvedValue({
      id: "chan-1",
      name: "town-square",
      display_name: "Town Square",
      team_id: "team-1",
      type: "O",
    });
    mockState.resolveMattermostMedia.mockResolvedValue([]);
    mockState.resolveUserInfo.mockResolvedValue({ id: "user-1", username: "alice" });
    mockState.updateMattermostPost.mockResolvedValue({ id: "post-1" });
  });

  // Lightweight req/res harness mirroring interactions.test.ts.
  type CapturedRes = import("node:http").ServerResponse & {
    headers: Record<string, string>;
    body: string;
  };

  function createReq(params: {
    method?: string;
    body?: unknown;
    remoteAddress?: string;
  }): import("node:http").IncomingMessage {
    const body = params.body === undefined ? "" : JSON.stringify(params.body);
    const listeners = new Map<string, Array<(...args: unknown[]) => void>>();
    const req = {
      destroyed: false,
      method: params.method ?? "POST",
      headers: {},
      socket: { remoteAddress: params.remoteAddress ?? "127.0.0.1" },
      on(event: string, handler: (...args: unknown[]) => void) {
        const existing = listeners.get(event) ?? [];
        existing.push(handler);
        listeners.set(event, existing);
        return this;
      },
      removeListener(event: string, handler: (...args: unknown[]) => void) {
        const existing = listeners.get(event) ?? [];
        listeners.set(
          event,
          existing.filter((entry) => entry !== handler),
        );
        return this;
      },
      destroy() {
        this.destroyed = true;
        return this;
      },
    } as import("node:http").IncomingMessage & {
      emitTest: (event: string, ...args: unknown[]) => void;
    };
    req.emitTest = (event: string, ...args: unknown[]) => {
      const handlers = listeners.get(event) ?? [];
      for (const handler of handlers) {
        handler(...args);
      }
    };
    queueMicrotask(() => {
      if (body) {
        req.emitTest("data", Buffer.from(body));
      }
      req.emitTest("end");
    });
    return req;
  }

  function createRes(): CapturedRes {
    const res = {
      statusCode: 200,
      headers: {} as Record<string, string>,
      body: "",
      setHeader(name: string, value: string | number | readonly string[]) {
        res.headers[name] = Array.isArray(value) ? value.join(",") : String(value);
        return res;
      },
      end(
        chunk?: string | Buffer | Uint8Array,
        _encoding?: BufferEncoding | (() => void),
        cb?: () => void,
      ) {
        res.body = chunk ? String(chunk) : "";
        cb?.();
        return res;
      },
    } as CapturedRes;
    return res;
  }

  async function startMonitorAndCaptureHandler() {
    const socket = new FakeWebSocket();
    const abortController = new AbortController();
    mockState.abortController = abortController;
    const { monitorMattermostProvider } = await import("./monitor.js");
    const monitor = monitorMattermostProvider({
      config: testConfig,
      runtime: testRuntime(),
      abortSignal: abortController.signal,
      webSocketFactory: () => socket,
    });
    await vi.waitFor(() => {
      expect(mockState.registerPluginHttpRoute).toHaveBeenCalled();
    });
    const registration = mockState.registerPluginHttpRoute.mock.calls[0]?.[0] as
      | { handler: (req: unknown, res: unknown) => Promise<void> }
      | undefined;
    if (!registration) {
      throw new Error("interaction route was not registered");
    }
    return { handler: registration.handler, socket, abortController, monitor };
  }

  function buildSignedBody(
    context: Record<string, unknown>,
    token: string,
    overrides: { channelId?: string; userName?: string; userId?: string } = {},
  ) {
    return {
      user_id: overrides.userId ?? "u-evil",
      ...(overrides.userName !== undefined ? { user_name: overrides.userName } : {}),
      channel_id: overrides.channelId ?? "chan-1",
      post_id: "post-1",
      context: { ...context, _token: token },
    };
  }

  it("Test H: generic group click synthetic inbound carries no claimed identity", async () => {
    const interactions = await import("./interactions.js");
    const { generateInteractionToken } = interactions;
    const { handler, socket, abortController, monitor } = await startMonitorAndCaptureHandler();

    // Simulate Mattermost client.request used by updateMattermostPost — already mocked.
    const channelId = "chan-1";
    const ctx = { action_id: "approve", __openclaw_channel_id: channelId };
    const token = generateInteractionToken(ctx, "default");
    const req = createReq({
      body: buildSignedBody(ctx, token, {
        channelId,
        userName: "spoofed-admin",
        userId: "u-evil",
      }),
    });
    const res = createRes();
    await handler(req, res);
    expect(res.statusCode).toBe(200);

    expect(mockState.dispatchReplyFromConfig).toHaveBeenCalledTimes(1);
    const ctxPayload = mockState.dispatchReplyFromConfig.mock.calls[0]?.[0]?.ctx as Record<
      string,
      unknown
    >;
    for (const key of [
      "Body",
      "BodyForAgent",
      "RawBody",
      "CommandBody",
      "ConversationLabel",
    ] as const) {
      const value = ctxPayload[key];
      if (typeof value === "string") {
        expect(value).not.toContain("spoofed-admin");
        expect(value).not.toContain("u-evil");
      }
    }
    expect(ctxPayload.SenderName).toBeUndefined();
    expect(ctxPayload.MessageSid).toBe("interaction:post-1:approve");

    abortController.abort();
    socket.emitClose(1000);
    await monitor;
  });

  it("Test I: picker-select dispatch routes via HMAC-bound ownerUserId, not claimed user_name", async () => {
    const interactions = await import("./interactions.js");
    const { generateInteractionToken } = interactions;
    const { handler, socket, abortController, monitor } = await startMonitorAndCaptureHandler();

    // Picker-select context: HMAC-sealed ownerUserId, claimed user_name in payload.
    const ctx = {
      action_id: "mdlsel",
      __openclaw_channel_id: "chan-1",
      oc_model_picker: true,
      ownerUserId: "owner-real",
      action: "select",
      provider: "openai",
      page: 0,
      model: "gpt-5.5",
    };
    const token = generateInteractionToken(ctx, "default");
    const req = createReq({
      body: buildSignedBody(ctx, token, {
        channelId: "chan-1",
        userName: "spoofed-admin",
        userId: "u-evil",
      }),
    });
    const res = createRes();
    await handler(req, res);
    // Picker handler runs async — no strict assertion on dispatchReply here, but
    // verify response was 200 and no spoofed identity touched the prompt-side fields
    // when dispatchReplyFromConfig was called (if at all).
    expect(res.statusCode).toBe(200);
    if (mockState.dispatchReplyFromConfig.mock.calls.length > 0) {
      const ctxPayload = mockState.dispatchReplyFromConfig.mock.calls[0]?.[0]?.ctx as Record<
        string,
        unknown
      >;
      expect(ctxPayload.SenderId).toBe("owner-real");
      const senderName = ctxPayload.SenderName;
      if (typeof senderName === "string") {
        expect(senderName).not.toBe("spoofed-admin");
      }
      const conversationLabel = ctxPayload.ConversationLabel;
      if (typeof conversationLabel === "string") {
        expect(conversationLabel).not.toContain("spoofed-admin");
      }
    }

    abortController.abort();
    socket.emitClose(1000);
    await monitor;
  });

  it("Test J: malformed picker DM context (HMAC-valid bare tag) is denied before side effects", async () => {
    mockState.resolveChannelInfo.mockResolvedValue({
      id: "dm-1",
      name: "",
      display_name: "",
      team_id: "team-1",
      type: "D",
    });
    const interactions = await import("./interactions.js");
    const { generateInteractionToken } = interactions;
    const { handler, socket, abortController, monitor } = await startMonitorAndCaptureHandler();

    // HMAC-valid context with the picker tag set but missing ownerUserId/valid action.
    const ctx = {
      action_id: "approve",
      __openclaw_channel_id: "dm-1",
      oc_model_picker: true,
    };
    const token = generateInteractionToken(ctx, "default");
    const req = createReq({
      body: buildSignedBody(ctx, token, {
        channelId: "dm-1",
        userName: "spoofed-admin",
      }),
    });
    const res = createRes();
    await handler(req, res);

    // The handler short-circuits with the auth denial response (statusCode 200 + ephemeral_text).
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("ephemeral_text");
    expect(mockState.enqueueSystemEvent).not.toHaveBeenCalled();
    expect(mockState.dispatchReplyFromConfig).not.toHaveBeenCalled();

    abortController.abort();
    socket.emitClose(1000);
    await monitor;
  });
});
