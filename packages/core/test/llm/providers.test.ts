import { describe, it, expect, vi, afterEach } from "vitest";
import {
  AnthropicProvider,
  OpenAIProvider,
  OpenAICompatibleProvider,
  resolveProvider,
} from "../../src/llm/providers.js";

interface MockResponseSpec {
  ok: boolean;
  status: number;
  statusText?: string;
  body: unknown;
}

function mockFetchOnce(spec: MockResponseSpec) {
  const textBody =
    typeof spec.body === "string" ? spec.body : JSON.stringify(spec.body);
  const fetchMock = vi.fn().mockResolvedValue({
    ok: spec.ok,
    status: spec.status,
    statusText: spec.statusText ?? "",
    json: async () => (typeof spec.body === "string" ? JSON.parse(spec.body) : spec.body),
    text: async () => textBody,
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AnthropicProvider", () => {
  it("posts to the messages endpoint with the right headers and body", async () => {
    const fetchMock = mockFetchOnce({
      ok: true,
      status: 200,
      body: { content: [{ type: "text", text: "looks bad" }] },
    });
    const provider = new AnthropicProvider({ apiKey: "sk-ant-test" });
    expect(provider.name).toBe("anthropic");

    const out = await provider.complete("audit this");
    expect(out).toBe("looks bad");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.anthropic.com/v1/messages");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("sk-ant-test");
    expect(headers["anthropic-version"]).toBe("2023-06-01");
    expect(headers["content-type"]).toBe("application/json");
    const body = JSON.parse(init.body as string) as {
      model: string;
      max_tokens: number;
      messages: Array<{ role: string; content: string }>;
    };
    expect(body.model).toBe("claude-sonnet-4-5");
    expect(body.max_tokens).toBe(1024);
    expect(body.messages).toEqual([{ role: "user", content: "audit this" }]);
    expect(init.signal).toBeDefined();
  });

  it("allows model and maxTokens overrides", async () => {
    const fetchMock = mockFetchOnce({
      ok: true,
      status: 200,
      body: { content: [{ type: "text", text: "ok" }] },
    });
    const provider = new AnthropicProvider({
      apiKey: "k",
      model: "claude-opus-4-1",
      maxTokens: 2048,
    });
    await provider.complete("hi");
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as { model: string; max_tokens: number };
    expect(body.model).toBe("claude-opus-4-1");
    expect(body.max_tokens).toBe(2048);
  });

  it("surfaces the provider error body on HTTP errors", async () => {
    mockFetchOnce({ ok: false, status: 401, body: '{"error":{"message":"invalid x-api-key"}}' });
    const provider = new AnthropicProvider({ apiKey: "bad" });
    await expect(provider.complete("hi")).rejects.toThrow(
      /anthropic: request failed \(HTTP 401\): \{"error":\{"message":"invalid x-api-key"\}\}/,
    );
  });

  it("rejects an unexpected response shape", async () => {
    mockFetchOnce({ ok: true, status: 200, body: { content: [] } });
    const provider = new AnthropicProvider({ apiKey: "k" });
    await expect(provider.complete("hi")).rejects.toThrow(/unexpected response shape/);
  });

  it("requires an apiKey", () => {
    expect(() => new AnthropicProvider({ apiKey: "" })).toThrow(/apiKey is required/);
  });
});

describe("OpenAIProvider", () => {
  it("posts to {baseUrl}/chat/completions with bearer auth", async () => {
    const fetchMock = mockFetchOnce({
      ok: true,
      status: 200,
      body: { choices: [{ message: { content: "fine" } }] },
    });
    const provider = new OpenAIProvider({ apiKey: "sk-test" });
    expect(provider.name).toBe("openai");

    const out = await provider.complete("audit this");
    expect(out).toBe("fine");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.openai.com/v1/chat/completions");
    const headers = init.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer sk-test");
    const body = JSON.parse(init.body as string) as {
      model: string;
      messages: Array<{ role: string; content: string }>;
      max_tokens: number;
    };
    expect(body.model).toBe("gpt-4o-mini");
    expect(body.messages).toEqual([{ role: "user", content: "audit this" }]);
    expect(body.max_tokens).toBe(1024);
  });

  it("uses a custom baseUrl and trims trailing slashes", async () => {
    const fetchMock = mockFetchOnce({
      ok: true,
      status: 200,
      body: { choices: [{ message: { content: "ok" } }] },
    });
    const provider = new OpenAIProvider({
      apiKey: "k",
      baseUrl: "https://proxy.example.com/v1/",
      model: "gpt-4o",
    });
    await provider.complete("hi");
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://proxy.example.com/v1/chat/completions");
  });

  it("surfaces the provider error body on HTTP errors", async () => {
    mockFetchOnce({ ok: false, status: 429, body: '{"error":{"message":"rate limited"}}' });
    const provider = new OpenAIProvider({ apiKey: "k" });
    await expect(provider.complete("hi")).rejects.toThrow(/HTTP 429.*rate limited/);
  });
});

describe("OpenAICompatibleProvider", () => {
  it("extends OpenAIProvider with a required baseUrl", async () => {
    const fetchMock = mockFetchOnce({
      ok: true,
      status: 200,
      body: { choices: [{ message: { content: "ok" } }] },
    });
    const provider = new OpenAICompatibleProvider({
      apiKey: "k",
      baseUrl: "https://llm.local/v1",
      model: "qwen3",
    });
    expect(provider.name).toBe("openai-compatible");
    expect(provider).toBeInstanceOf(OpenAIProvider);
    await provider.complete("hi");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://llm.local/v1/chat/completions");
    const body = JSON.parse(init.body as string) as { model: string };
    expect(body.model).toBe("qwen3");
  });

  it("throws without a baseUrl", () => {
    expect(
      () => new OpenAICompatibleProvider({ apiKey: "k", baseUrl: "  " }),
    ).toThrow(/baseUrl is required/);
  });
});

describe("resolveProvider", () => {
  it("auto-detects anthropic first", () => {
    const p = resolveProvider({ ANTHROPIC_API_KEY: "a", OPENAI_API_KEY: "o" });
    expect(p?.name).toBe("anthropic");
  });

  it("falls back to openai", () => {
    const p = resolveProvider({ OPENAI_API_KEY: "o" });
    expect(p?.name).toBe("openai");
  });

  it("uses openai-compatible for REDTEAM_LLM_API_KEY", () => {
    const p = resolveProvider({
      REDTEAM_LLM_API_KEY: "k",
      REDTEAM_LLM_BASE_URL: "https://llm.local/v1",
      REDTEAM_LLM_MODEL: "qwen3",
    });
    expect(p?.name).toBe("openai-compatible");
  });

  it("honors an explicit REDTEAM_LLM_PROVIDER over auto-detect order", () => {
    const p = resolveProvider({
      REDTEAM_LLM_PROVIDER: "openai",
      ANTHROPIC_API_KEY: "a",
      OPENAI_API_KEY: "o",
    });
    expect(p?.name).toBe("openai");
  });

  it("returns null for an explicit provider whose key is missing", () => {
    expect(resolveProvider({ REDTEAM_LLM_PROVIDER: "anthropic" })).toBeNull();
  });

  it("returns null for an unknown explicit provider (fail closed)", () => {
    expect(
      resolveProvider({ REDTEAM_LLM_PROVIDER: "gemini", OPENAI_API_KEY: "o" }),
    ).toBeNull();
  });

  it("returns null when no key is configured", () => {
    expect(resolveProvider({})).toBeNull();
    expect(resolveProvider({ REDTEAM_LLM_PROVIDER: "" })).toBeNull();
  });
});
