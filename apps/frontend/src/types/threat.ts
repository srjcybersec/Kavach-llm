export type ThreatFeedEvent = {
  time: string;
  category: string;
  riskScore: number;
  actionTaken: string;
  redactedInputSnippet: string;
};

