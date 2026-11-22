import { DEFAULT_HINTS } from './hints.js';

export type ErrCode =
  | 'AUTH_FAILED'
  | 'HOST_UNREACHABLE'
  | 'CAPABILITY_UNAVAILABLE'
  | 'TRANSPORT_SEVERED_RISK'
  | 'TIMEOUT'
  | 'SESSION_GONE'
  | 'BAD_ARGS'
  | 'REMOTE_ERROR'
  | 'INTERNAL';

export function toolError(
  code: ErrCode,
  message: string,
  detail?: Record<string, unknown>,
  hint?: string,
) {
  const structured: { code: ErrCode; message: string; detail?: Record<string, unknown>; hint?: string } = { code, message };
  if (detail) structured.detail = detail;
  // Every refusal carries an actionable next step so a calling AI can recover on
  // its own. A call site may pass a specific hint; otherwise the per-code table
  // is the safety net. It rides on the text line so even single-block clients see
  // it, and on structuredContent for programmatic callers.
  const guidance = hint ?? DEFAULT_HINTS[code];
  if (guidance) structured.hint = guidance;
  return {
    isError: true as const,
    content: [{ type: 'text' as const, text: guidance ? `[${code}] ${message}\n→ ${guidance}` : `[${code}] ${message}` }],
    structuredContent: structured,
  };
}

export function toolText(text: string, extra?: Record<string, unknown>) {
  return {
    content: [{ type: 'text' as const, text }],
    ...(extra ? { structuredContent: extra } : {}),
  };
}

export class ControlError extends Error {
  readonly code: ErrCode;
  readonly detail?: Record<string, unknown>;
  readonly hint?: string;
  constructor(code: ErrCode, message: string, detail?: Record<string, unknown>, hint?: string) {
    super(message);
    this.name = 'ControlError';
    this.code = code;
    this.detail = detail;
    this.hint = hint;
  }
}
