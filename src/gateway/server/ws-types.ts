import type { WebSocket } from "ws";
import type { TrustedProxyAuthEvidence } from "../auth.js";
import type { ConnectParams } from "../protocol/index.js";

export type { TrustedProxyAuthEvidence };

export type GatewayWsClient = {
  socket: WebSocket;
  connect: ConnectParams;
  connId: string;
  isDeviceTokenAuth?: boolean;
  usesSharedGatewayAuth: boolean;
  sharedGatewaySessionGeneration?: string;
  presenceKey?: string;
  clientIp?: string;
  canvasHostUrl?: string;
  canvasCapability?: string;
  canvasCapabilityExpiresAtMs?: number;
  /** Resolved trusted-proxy user identity. Present only for trusted-proxy sessions. */
  trustedProxyUser?: string;
  /** Snapshot of trusted-proxy auth generation at connect (or last successful revalidation). */
  trustedProxyAuthGeneration?: number;
  /** Non-secret evidence used to re-evaluate trusted-proxy authorization after policy changes. */
  trustedProxyAuthEvidence?: TrustedProxyAuthEvidence;
};
