type Role = "ADMIN" | "ANALYST" | "VIEWER";

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        role: Role;
      };
    }

    interface Locals {
      scan?: {
        flags: string[];
        riskScore: number;
        piiFound: string[];
      };
      threatClassification?: {
        category: string;
        confidence: number;
        subCategories: string[];
      };
      contextTracker?: {
        sessionRiskScore: number;
        escalationDetected: boolean;
        patternName?: string;
      };
      outputFilter?: {
        filtered: boolean;
        redactions: string[];
        warningFlags: string[];
      };
      llmResponseFiltered?: string;
      outputFingerprint?: string;
      honeypotCanaryPhrase?: string;
    }
  }
}

export {};

