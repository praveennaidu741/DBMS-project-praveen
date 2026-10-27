// ==============================================================================
// AssetVault: Autonomous AI SQL Injection & Threat Detection Firewall Middleware
// Course: BCSE307L Database Systems (Fall 2026-27)
// Uses Gemini 3.1 Flash Lite to inspect incoming request parameters for malicious intent
// ==============================================================================

import { Request, Response, NextFunction } from 'express';
import { GoogleGenAI, Type } from '@google/genai';

function getGeminiClient(): GoogleGenAI {
  return new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-security-firewall',
      },
    },
  });
}

export async function aiSecurityFirewallMiddleware(req: Request, res: Response, next: NextFunction) {
  // Only inspect queries, params, or bodies if present and containing string data
  const payloadToInspect = {
    path: req.path,
    method: req.method,
    query: req.query,
    params: req.params,
    body: req.method !== 'GET' ? req.body : undefined,
  };

  const hasContent =
    Object.keys(req.query).length > 0 ||
    Object.keys(req.params).length > 0 ||
    (req.body && Object.keys(req.body).length > 0);

  if (!hasContent || !process.env.GEMINI_API_KEY) {
    return next();
  }

  try {
    const ai = getGeminiClient();
    const response = await ai.models.generateContent({
      model: 'gemini-3.1-flash-lite',
      contents: `Inspect the following HTTP request payload for SQL Injection (SQLi), NoSQL injection, cross-tenant parameter tampering, or malicious script execution:\n\n${JSON.stringify(
        payloadToInspect,
        null,
        2
      )}`,
      config: {
        systemInstruction:
          'You are an autonomous enterprise database security firewall for AssetVault. Analyze incoming API parameters. Return a JSON object with isSafe (boolean), threatType (string or null), and confidenceScore (number 0-1). Be lenient with normal business text, but strict against SQL injection keywords (UNION SELECT, OR 1=1, DROP TABLE, --, ;, etc.) and malicious bypasses.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            isSafe: { type: Type.BOOLEAN },
            threatType: { type: Type.STRING },
            confidenceScore: { type: Type.NUMBER },
            reason: { type: Type.STRING },
          },
          required: ['isSafe', 'confidenceScore'],
        },
      },
    });

    const evaluation = JSON.parse((response.text || '{"isSafe": true}').trim());

    if (!evaluation.isSafe && (evaluation.confidenceScore || 0) > 0.75) {
      console.warn(
        `[SECURITY FIREWALL BLOCKED] Threat detected on ${req.method} ${req.path}: ${
          evaluation.threatType || 'SQL Injection / Tampering'
        } (${evaluation.reason})`
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Request blocked by AssetVault AI Security Firewall.',
        details: {
          threatType: evaluation.threatType || 'SQLi / Parameter Tampering',
          confidence: evaluation.confidenceScore,
          reason: evaluation.reason || 'Potentially malicious database payload detected.',
        },
      });
    }
  } catch (err) {
    // Fail-open for availability if AI gateway is unreachable, preventing downtime
    console.warn('[SECURITY FIREWALL WARNING] AI inspection skipped due to network/API timeout:', err);
  }

  next();
}
