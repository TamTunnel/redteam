/**
 * LLM provider abstraction for the Redteam attack-agent pass.
 *
 * Plain `fetch` only — no SDK dependencies, keeping the dep tree light.
 * API keys come from the environment and are never logged.
 */

export interface LlmProvider {
  /** Human-readable provider name, e.g. "anthropic". */
  name: string;
  /** Send a prompt, resolve with the model's text response. */
  complete(prompt: string): Promise<string>;
}

export interface ProviderOptions {
  apiKey: string;
  baseUrl?: string;
  model?: string;
  maxTokens?: number;
}

const REQUEST_TIMEOUT_MS = 60_000;
const MAX_ERROR_BODY_CHARS = 500;

const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5";

const DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1";
const DEFAULT_OPENAI_MODEL = "gpt-4o-mini";

const DEFAULT_MAX_TOKENS = 1024;

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

async function readErrorBody(res: Response): Promise<string> {
  try {
    const text = await res.text();
    return text ? truncate(text, MAX_ERROR_BODY_CHARS) : "";
  } catch {
    return "";
  }
}

async function throwForHttpError(providerName: string, res: Response): Promise<never> {
  const body = await readErrorBody(res);
  const status = res.statusText ? `${res.status} ${res.statusText}` : `${res.status}`;
  throw new Error(
    `${providerName}: request failed (HTTP ${status})${body ? `: ${body}` : ""}`,
  );
}

function requireApiKey(providerName: string, apiKey: string): void {
  if (!apiKey || !apiKey.trim()) {
    throw new Error(`${providerName}: apiKey is required`);
  }
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, "");
}

/** Anthropic Messages API provider. */
export class AnthropicProvider implements LlmProvider {
  readonly name: string = "anthropic";
  protected readonly apiKey: string;
  protected readonly model: string;
  protected readonly maxTokens: number;

  constructor(opts: ProviderOptions) {
    requireApiKey("anthropic", opts.apiKey);
    this.apiKey = opts.apiKey;
    this.model = opts.model?.trim() || DEFAULT_ANTHROPIC_MODEL;
    this.maxTokens = opts.maxTokens ?? DEFAULT_MAX_TOKENS;
  }

  async complete(prompt: string): Promise<string> {
    const res = await fetch(ANTHROPIC_API_URL, {
      method: "POST",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: this.maxTokens,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    if (!res.ok) await throwForHttpError(this.name, res);
    const data = (await res.json()) as { content?: Array<{ text?: string }> };
    const text = data?.content?.[0]?.text;
    if (typeof text !== "string") {
      throw new Error("anthropic: unexpected response shape (missing content[0].text)");
    }
    return text;
  }
}

/** OpenAI Chat Completions provider (also the base for OpenAI-compatible endpoints). */
export class OpenAIProvider implements LlmProvider {
  readonly name: string = "openai";
  protected readonly apiKey: string;
  protected readonly baseUrl: string;
  protected readonly model: string;
  protected readonly maxTokens: number;

  constructor(opts: ProviderOptions) {
    requireApiKey("openai", opts.apiKey);
    this.apiKey = opts.apiKey;
    this.baseUrl = normalizeBaseUrl(opts.baseUrl?.trim() || DEFAULT_OPENAI_BASE_URL);
    this.model = opts.model?.trim() || DEFAULT_OPENAI_MODEL;
    this.maxTokens = opts.maxTokens ?? DEFAULT_MAX_TOKENS;
  }

  async complete(prompt: string): Promise<string> {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        messages: [{ role: "user", content: prompt }],
        max_tokens: this.maxTokens,
      }),
    });
    if (!res.ok) await throwForHttpError(this.name, res);
    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== "string") {
      throw new Error("openai: unexpected response shape (missing choices[0].message.content)");
    }
    return content;
  }
}

export interface OpenAICompatibleOptions extends ProviderOptions {
  /** Required: the OpenAI-compatible endpoint base URL (e.g. https://host/v1). */
  baseUrl: string;
}

/**
 * OpenAI-compatible provider for third-party endpoints
 * (REDTEAM_LLM_API_KEY + REDTEAM_LLM_BASE_URL).
 */
export class OpenAICompatibleProvider extends OpenAIProvider {
  override readonly name: string = "openai-compatible";

  constructor(opts: OpenAICompatibleOptions) {
    if (!opts.baseUrl || !opts.baseUrl.trim()) {
      throw new Error("openai-compatible: baseUrl is required (set REDTEAM_LLM_BASE_URL)");
    }
    super(opts);
  }
}

export type ExplicitProviderName = "anthropic" | "openai" | "openai-compatible";

function fromExplicitName(
  name: ExplicitProviderName,
  env: NodeJS.ProcessEnv,
): LlmProvider | null {
  switch (name) {
    case "anthropic":
      return env.ANTHROPIC_API_KEY?.trim()
        ? new AnthropicProvider({ apiKey: env.ANTHROPIC_API_KEY, model: env.REDTEAM_LLM_MODEL })
        : null;
    case "openai":
      return env.OPENAI_API_KEY?.trim()
        ? new OpenAIProvider({ apiKey: env.OPENAI_API_KEY, model: env.REDTEAM_LLM_MODEL })
        : null;
    case "openai-compatible":
      return env.REDTEAM_LLM_API_KEY?.trim()
        ? new OpenAICompatibleProvider({
            apiKey: env.REDTEAM_LLM_API_KEY,
            baseUrl: env.REDTEAM_LLM_BASE_URL?.trim() || DEFAULT_OPENAI_BASE_URL,
            model: env.REDTEAM_LLM_MODEL,
          })
        : null;
  }
}

/**
 * Resolve an LLM provider from the environment.
 *
 * Precedence: explicit `REDTEAM_LLM_PROVIDER` ("anthropic" | "openai" |
 * "openai-compatible") wins; otherwise auto-detect: ANTHROPIC_API_KEY →
 * anthropic, OPENAI_API_KEY → openai, REDTEAM_LLM_API_KEY (+ optional
 * REDTEAM_LLM_BASE_URL / REDTEAM_LLM_MODEL) → openai-compatible.
 *
 * Returns null when no key is configured (the zero-config skip path).
 * Never logs keys.
 */
export function resolveProvider(env: NodeJS.ProcessEnv = process.env): LlmProvider | null {
  const explicit = env.REDTEAM_LLM_PROVIDER?.trim().toLowerCase();
  if (explicit === "anthropic" || explicit === "openai" || explicit === "openai-compatible") {
    return fromExplicitName(explicit, env);
  }
  if (explicit) {
    // Unknown explicit value: fail closed rather than guessing a provider.
    return null;
  }
  if (env.ANTHROPIC_API_KEY?.trim()) {
    return new AnthropicProvider({
      apiKey: env.ANTHROPIC_API_KEY,
      model: env.REDTEAM_LLM_MODEL,
    });
  }
  if (env.OPENAI_API_KEY?.trim()) {
    return new OpenAIProvider({ apiKey: env.OPENAI_API_KEY, model: env.REDTEAM_LLM_MODEL });
  }
  if (env.REDTEAM_LLM_API_KEY?.trim()) {
    return new OpenAICompatibleProvider({
      apiKey: env.REDTEAM_LLM_API_KEY,
      baseUrl: env.REDTEAM_LLM_BASE_URL?.trim() || DEFAULT_OPENAI_BASE_URL,
      model: env.REDTEAM_LLM_MODEL,
    });
  }
  return null;
}
