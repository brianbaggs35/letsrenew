import { mount, flushPromises } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.vue";

const providers = [
  { id: 1, name: "IONOS", plugin: "ionos", package: "certbot-dns-ionos", has_credentials: true },
  { id: 2, name: "No credentials", plugin: "test", package: "certbot-dns-test", has_credentials: false },
];
const certificate = {
  id: 1,
  name: "example.com",
  domains: ["example.com"],
  cert_path: "/cert/example.pem",
  expires_at: "2026-12-01T00:00:00Z",
  days_left: 45,
  expired: false,
  available: true,
  managed: true,
  deploy_path: "/deploy",
};
const catalog = [
  { name: "IONOS", plugin: "ionos", package: "certbot-dns-ionos" },
  { name: "Cloudflare", plugin: "cloudflare", package: "certbot-dns-cloudflare" },
];

function response(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  };
}

function installFetch(overrides: Record<string, unknown> = {}) {
  const handlers: Record<string, unknown> = {
    "/api/certificates": [],
    "/api/providers": [],
    "/api/providers/catalog": catalog,
    "/api/login": { token: "test-token" },
    ...overrides,
  };
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const method = init?.method ?? "GET";
    const result = handlers[`${method} ${url.pathname}`] ?? handlers[url.pathname];
    if (result instanceof Error) throw result;
    if (typeof result === "function") return (result as () => unknown)();
    if (
      result &&
      typeof result === "object" &&
      "ok" in result &&
      "status" in result &&
      "json" in result
    ) {
      return result;
    }
    return response(result);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, handlers };
}

async function mountApp(token?: string) {
  if (token) sessionStorage.setItem("letsrenew-token", token);
  const wrapper = mount(App);
  await flushPromises();
  return wrapper;
}

async function login(wrapper: ReturnType<typeof mount>) {
  await wrapper.get('input[type="password"]').setValue("correct");
  await wrapper.get("form").trigger("submit");
  await flushPromises();
}

describe("LetsRenew app", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("shows sign-in, reports invalid credentials, and logs in", async () => {
    const { handlers } = installFetch();
    handlers["/api/login"] = response({ detail: "Incorrect password" }, 401);
    const wrapper = await mountApp();
    expect(wrapper.text()).toContain("Welcome back");
    expect(wrapper.text()).toContain("make up");
    await login(wrapper);
    await flushPromises();
    expect(wrapper.text()).toContain("Incorrect password");

    handlers["/api/login"] = { token: "test-token" };
    await login(wrapper);
    expect(wrapper.text()).toContain("Your certificates");
    expect(sessionStorage.getItem("letsrenew-token")).toBe("test-token");
    expect(wrapper.text()).toContain("No certificates tracked yet.");
  });

  it("loads certificates, shows expiration states, and supports renew and delete", async () => {
    installFetch({
      "/api/certificates": [
        certificate,
        { ...certificate, id: 2, name: "expired", days_left: 0, expired: true, managed: false },
        {
          ...certificate,
          id: 3,
          name: "missing",
          expires_at: null,
          days_left: null,
          expired: null,
          available: false,
        },
        { ...certificate, id: 4, name: "monitor", managed: false, days_left: 31 },
        { ...certificate, id: 5, name: "no domains", domains: [] },
      ],
      "/api/providers": providers,
    });
    const wrapper = await mountApp("test-token");
    expect(wrapper.text()).toContain("45 days");
    expect(wrapper.text()).toContain("Expired");
    expect(wrapper.text()).toContain("Unavailable");
    expect(wrapper.text()).toContain("Monitor only");
    expect(wrapper.findAll("button").some((button) => button.text() === "Renew")).toBe(true);

    const actions = wrapper.findAll("button").filter((button) => button.text() === "Renew");
    await actions[0].trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("Renewal completed and files deployed.");
    expect(wrapper.text()).toContain("Expires");

    const removeButtons = wrapper.findAll('button[title="Remove from tracking"]');
    await removeButtons[0].trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("Certificate removed from tracking.");
  });

  it("handles expired sessions and API error bodies that cannot be parsed", async () => {
    const { handlers } = installFetch({
      "/api/certificates": () => ({
        ok: false,
        status: 401,
        json: async () => {
          throw new Error("not json");
        },
      }),
    });
    const wrapper = await mountApp("stale-token");
    await flushPromises();
    expect(sessionStorage.getItem("letsrenew-token")).toBeNull();
    expect(wrapper.text()).toContain("Request failed (401)");
    expect(handlers["/api/providers"]).toBeDefined();
  });

  it("configures a preset provider and reports invalid JSON", async () => {
    installFetch();
    const wrapper = await mountApp("test-token");
    const providersTab = wrapper.findAll("button").find((button) => button.text() === "DNS providers");
    await providersTab?.trigger("click");
    await flushPromises();
    const selector = wrapper.find("select");
    await selector.setValue("ionos");
    expect((wrapper.findAll("input")[0].element as HTMLInputElement).value).toBe("IONOS");
    await selector.setValue("");

    const credentials = wrapper.findAll("textarea")[0];
    await credentials.setValue("{invalid");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("JSON");
  });

  it("saves a provider, issues a certificate, and imports one", async () => {
    const { fetchMock } = installFetch({ "/api/providers": providers });
    const wrapper = await mountApp("test-token");
    await wrapper.findAll("button").find((button) => button.text() === "DNS providers")?.trigger("click");
    await flushPromises();
    await wrapper.findAll("textarea")[0].setValue('{"dns_ionos_secret":"secret"}');
    await wrapper.findAll("textarea")[1].setValue("{}");
    const providerInputs = wrapper.findAll("input");
    await providerInputs[0].setValue("Test IONOS");
    await providerInputs[1].setValue("custom-ionos");
    await providerInputs[2].setValue("certbot-dns-custom-ionos");
    await wrapper.findAll("form")[0].trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("DNS provider saved.");
    expect(fetchMock.mock.calls.some((call) => String(call[0]) === "/api/providers")).toBe(true);

    await wrapper.findAll("button").find((button) => button.text() === "Certificates")?.trigger("click");
    await flushPromises();
    const inputs = wrapper.findAll("input");
    await inputs[0].setValue("example.com");
    await wrapper.find("textarea").setValue("example.com, www.example.com");
    await inputs[1].setValue("admin@example.com");
    await wrapper.find("select").setValue("1");
    await inputs[2].setValue("/deploy/example.com");
    const issueForm = wrapper.findAll("form")[0];
    await issueForm.trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("Certificate issued and deployed.");

    const importForm = wrapper.findAll("form")[1];
    const importInputs = importForm.findAll("input");
    await importInputs[0].setValue("Imported");
    await importInputs[1].setValue("/certs/fullchain.pem");
    await importInputs[2].setValue("/certs/privkey.pem");
    await importForm.trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("Certificate added for expiration monitoring.");
    const importRequest = fetchMock.mock.calls.find((call) => String(call[0]) === "/api/certificates/import");
    expect(JSON.parse(String(importRequest?.[1]?.body))).toEqual({
      name: "Imported",
      cert_path: "/certs/fullchain.pem",
      key_path: "/certs/privkey.pem",
    });
  });

  it("reports issue, import, provider, and action failures", async () => {
    const { handlers } = installFetch({ "/api/providers": providers });
    const wrapper = await mountApp("test-token");
    const failNext = (method: string, path: string, detail: string) => {
      handlers[`${method} ${path}`] = () => Promise.reject(detail);
    };

    const providerTab = wrapper.findAll("button").find((button) => button.text() === "DNS providers");
    await providerTab?.trigger("click");
    await flushPromises();
    failNext("POST", "/api/providers", "provider failed");
    await wrapper.findAll("form")[0].trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("provider failed");

    const certificatesTab = wrapper.findAll("button").find((button) => button.text() === "Certificates");
    await certificatesTab?.trigger("click");
    await flushPromises();
    failNext("POST", "/api/certificates/issue", "issue failed");
    await wrapper.findAll("form")[0].trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("issue failed");

    handlers["POST /api/certificates/issue"] = response({ detail: "issue error" }, 502);
    await wrapper.findAll("form")[0].trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("issue error");

    failNext("POST", "/api/certificates/import", "import failed");
    await wrapper.findAll("form")[1].trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("import failed");

    handlers["POST /api/certificates/import"] = response({ detail: "import error" }, 502);
    await wrapper.findAll("form")[1].trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("import error");

    await wrapper.findAll("button").find((button) => button.text() === "DNS providers")?.trigger("click");
    await flushPromises();
    handlers["/api/providers"] = providers;
    handlers["DELETE /api/providers/1"] = () => Promise.reject("delete failed");
    await wrapper.findAll('button[title="Delete provider"]')[0].trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("delete failed");
    handlers["DELETE /api/providers/1"] = response({ detail: "delete error" }, 502);
    await wrapper.findAll('button[title="Delete provider"]')[0].trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("delete error");
  });

  it("handles non-Error login and loading failures, provider lists, and sign out", async () => {
    const { handlers } = installFetch();
    handlers["/api/login"] = () => Promise.reject("login failed");
    const wrapper = await mountApp();
    await login(wrapper);
    expect(wrapper.text()).toContain("login failed");

    handlers["/api/certificates"] = () => Promise.reject("load failed");
    const authenticated = await mountApp("test-token");
    expect(authenticated.text()).toContain("load failed");
    handlers["/api/certificates"] = [];
    handlers["/api/providers"] = providers;
    const providerView = await mountApp("test-token");
    expect(providerView.text()).toContain("IONOS");
    expect(providerView.text()).toContain("No credentials");
    await providerView.findAll("button").find((button) => button.text() === "Sign out")?.trigger("click");
    expect(sessionStorage.getItem("letsrenew-token")).toBeNull();
    expect(providerView.text()).toContain("Welcome back");
  });

  it("mounts the production entry point", async () => {
    installFetch();
    document.body.innerHTML = '<div id="app"></div>';
    await import("./main");
    await flushPromises();
    expect(document.querySelector("#app")?.textContent).toContain("Welcome back");
  });
});
