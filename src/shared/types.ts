export type SubscriptionTarget = "raw" | "mihomo" | "singbox" | "json";

export interface NormalizedNode {
  id?: string;
  sourceId?: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
  config: Record<string, unknown>;
  tags: string[];
  enabled: boolean;
  fingerprint: string;
  rawUri?: string;
}

export interface SubscriptionRules {
  protocols?: string[];
  tags?: string[];
  includeName?: string;
  excludeName?: string;
  sortBy?: "name" | "protocol" | "source";
  rename?: Array<{ pattern: string; replacement: string }>;
}
