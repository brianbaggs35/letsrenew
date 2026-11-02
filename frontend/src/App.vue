<script setup lang="ts">
import { computed, onMounted, ref } from "vue";

type Certificate = {
  id: number;
  name: string;
  domains: string[];
  cert_path: string;
  expires_at: string | null;
  days_left: number | null;
  expired: boolean | null;
  available: boolean;
  managed: boolean;
  deploy_path: string | null;
};
type Provider = { id: number; name: string; plugin: string; package: string; has_credentials: boolean };
type CatalogItem = { name: string; plugin: string; package: string };

const token = ref(sessionStorage.getItem("letsrenew-token") || "");
const password = ref("");
const certificates = ref<Certificate[]>([]);
const providers = ref<Provider[]>([]);
const catalog = ref<CatalogItem[]>([]);
const message = ref("");
const error = ref("");
const busy = ref(false);
const tab = ref<"certificates" | "providers">("certificates");
const issueForm = ref({ name: "", domains: "", email: "", provider_id: 0, deploy_path: "/deploy" });
const providerForm = ref({
  name: "IONOS",
  plugin: "ionos",
  package: "certbot-dns-ionos",
  credentials: "{}",
  options: "{}",
});
const importForm = ref({ name: "", cert_path: "", key_path: "" });
const authenticated = computed(() => Boolean(token.value));

async function api<T>(url: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token.value ? { Authorization: `Bearer ${token.value}` } : {}),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (response.status === 401) {
      token.value = "";
      sessionStorage.removeItem("letsrenew-token");
    }
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

async function login() {
  error.value = "";
  try {
    const result = await api<{ token: string }>("/api/login", {
      method: "POST",
      body: JSON.stringify({ password: password.value }),
    });
    token.value = result.token;
    sessionStorage.setItem("letsrenew-token", result.token);
    await load();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  }
}

async function load() {
  if (!token.value) return;
  try {
    [certificates.value, providers.value, catalog.value] = await Promise.all([
      api<Certificate[]>("/api/certificates"),
      api<Provider[]>("/api/providers"),
      api<CatalogItem[]>("/api/providers/catalog"),
    ]);
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  }
}

function chooseProvider(event: Event) {
  const provider = catalog.value.find((item) => item.plugin === (event.target as HTMLSelectElement).value);
  if (provider) Object.assign(providerForm.value, provider);
}

async function saveProvider() {
  error.value = message.value = "";
  try {
    const credentials = JSON.parse(providerForm.value.credentials);
    const options = JSON.parse(providerForm.value.options);
    await api("/api/providers", {
      method: "POST",
      body: JSON.stringify({ ...providerForm.value, credentials, options }),
    });
    message.value = "DNS provider saved. Credentials are encrypted in the database.";
    await load();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  }
}

async function issueCertificate() {
  busy.value = true;
  error.value = message.value = "";
  try {
    await api("/api/certificates/issue", {
      method: "POST",
      body: JSON.stringify({
        ...issueForm.value,
        domains: issueForm.value.domains.split(/[,\s]+/).filter(Boolean),
        provider_id: Number(issueForm.value.provider_id),
      }),
    });
    message.value = "Certificate issued and deployed.";
    await load();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  } finally {
    busy.value = false;
  }
}

async function importCertificate() {
  error.value = message.value = "";
  try {
    await api("/api/certificates/import", {
      method: "POST",
      body: JSON.stringify({
        ...importForm.value,
        key_path: importForm.value.key_path || null,
      }),
    });
    message.value = "Certificate added for expiration monitoring.";
    await load();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  }
}

async function action(url: string, method: string, success: string) {
  error.value = message.value = "";
  try {
    await api(url, { method });
    message.value = success;
    await load();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  }
}

function formattedDate(value: string | null) {
  return value ? new Date(value).toLocaleDateString() : "Unavailable";
}

function logout() {
  token.value = "";
  sessionStorage.removeItem("letsrenew-token");
}

onMounted(load);
</script>

<template>
  <main class="shell">
    <header class="topbar">
      <a class="brand" href="/">LetsRenew<span>.</span></a>
      <span class="subtitle">Certificate operations</span>
      <button v-if="authenticated" class="button subtle" @click="logout">Sign out</button>
    </header>

    <section v-if="!authenticated" class="login-panel panel">
      <p class="eyebrow">PRIVATE CERTIFICATE MANAGER</p>
      <h1>Welcome back</h1>
      <p>Enter the admin password printed when you first ran <code>make up</code>.</p>
      <form @submit.prevent="login">
        <label>Admin password<input v-model="password" type="password" autocomplete="current-password" required /></label>
        <button class="button primary" type="submit">Sign in</button>
      </form>
      <p v-if="error" class="alert error">{{ error }}</p>
    </section>

    <template v-else>
      <section class="hero">
        <div>
          <p class="eyebrow">CERTIFICATE CONTROL CENTER</p>
          <h1>Keep every certificate<br />ready for renewal.</h1>
          <p>Monitor expiration, issue Let's Encrypt certificates, and deploy renewed files automatically.</p>
        </div>
        <div class="summary panel">
          <span class="summary-number">{{ certificates.length }}</span>
          <span>Tracked certificates</span>
          <span class="summary-caption">Renewal check runs every 6 hours</span>
        </div>
      </section>

      <p v-if="message" class="alert success">{{ message }}</p>
      <p v-if="error" class="alert error">{{ error }}</p>

      <nav class="tabs">
        <button :class="{ selected: tab === 'certificates' }" @click="tab = 'certificates'">Certificates</button>
        <button :class="{ selected: tab === 'providers' }" @click="tab = 'providers'">DNS providers</button>
      </nav>

      <section v-if="tab === 'certificates'" class="content-grid">
        <div class="panel">
          <div class="section-heading"><div><p class="eyebrow">TRACKING</p><h2>Your certificates</h2></div></div>
          <div v-if="!certificates.length" class="empty">No certificates tracked yet. Import one to monitor it or issue a new Let's Encrypt certificate.</div>
          <article v-for="cert in certificates" :key="cert.id" class="certificate-row">
            <div class="status-dot" :class="{ warning: cert.days_left !== null && cert.days_left <= 30, missing: !cert.available }"></div>
            <div class="cert-main">
              <strong>{{ cert.name }}</strong>
              <span>{{ cert.domains.join(", ") || cert.cert_path }}</span>
            </div>
            <div class="expiry">
              <strong>{{ cert.days_left === null ? "Unavailable" : cert.expired ? "Expired" : `${cert.days_left} days` }}</strong>
              <span>Expires {{ formattedDate(cert.expires_at) }}</span>
            </div>
            <span class="badge" :class="{ managed: cert.managed }">{{ cert.managed ? "Auto-renew" : "Monitor only" }}</span>
            <button v-if="cert.managed" class="button small" @click="action(`/api/certificates/${cert.id}/renew`, 'POST', 'Renewal completed and files deployed.')">Renew</button>
            <button class="icon-button" title="Remove from tracking" @click="action(`/api/certificates/${cert.id}`, 'DELETE', 'Certificate removed from tracking.')">×</button>
          </article>
        </div>

        <div class="panel form-panel">
          <p class="eyebrow">NEW CERTIFICATE</p><h2>Issue with Let's Encrypt</h2>
          <form @submit.prevent="issueCertificate">
            <label>Certificate name<input v-model="issueForm.name" placeholder="example.com" required /></label>
            <label>Domains<textarea v-model="issueForm.domains" placeholder="example.com, www.example.com" required rows="2"></textarea></label>
            <label>Account email<input v-model="issueForm.email" type="email" required /></label>
            <label>DNS provider<select v-model.number="issueForm.provider_id" required><option :value="0" disabled>Select provider</option><option v-for="provider in providers" :key="provider.id" :value="provider.id">{{ provider.name }}</option></select></label>
            <label>Deployment directory<input v-model="issueForm.deploy_path" placeholder="/deploy/example.com" /></label>
            <button class="button primary full" :disabled="busy || !providers.length">{{ busy ? "Issuing certificate…" : "Issue certificate" }}</button>
            <small v-if="!providers.length">Add DNS credentials in the DNS providers tab first.</small>
          </form>
        </div>

        <div class="panel form-panel import-panel">
          <p class="eyebrow">EXISTING CERTIFICATE</p><h2>Add an existing certificate</h2>
          <form @submit.prevent="importCertificate">
            <label>Label<input v-model="importForm.name" placeholder="Internal API" required /></label>
            <label>Certificate file path<input v-model="importForm.cert_path" placeholder="/certificates/live/example.com/fullchain.pem" required /></label>
            <label>Private key file path <span class="muted">(optional for monitoring)</span><input v-model="importForm.key_path" placeholder="/certificates/live/example.com/privkey.pem" /></label>
            <button class="button secondary full" type="submit">Add certificate</button>
            <small>Imported certificates are monitored only. To renew one with LetsRenew, issue a certificate using the same label and set its deployment directory to this certificate's directory.</small>
          </form>
        </div>
      </section>

      <section v-else class="content-grid providers-grid">
        <div class="panel form-panel">
          <p class="eyebrow">DNS-01 CHALLENGE</p><h2>Configure a DNS provider</h2>
          <p class="muted">Provider plugins are installed from PyPI into the container when you install or issue a certificate.</p>
          <form @submit.prevent="saveProvider">
            <label>Provider preset<select @change="chooseProvider"><option value="">Custom plugin…</option><option v-for="item in catalog" :key="item.plugin" :value="item.plugin">{{ item.name }}</option></select></label>
            <label>Configuration name<input v-model="providerForm.name" required /></label>
            <label>Plugin identifier<input v-model="providerForm.plugin" placeholder="ionos" required /></label>
            <label>Python package<input v-model="providerForm.package" placeholder="certbot-dns-ionos" required /></label>
            <label>Credentials JSON<textarea v-model="providerForm.credentials" rows="4" placeholder="{&quot;dns_ionos_prefix&quot;:&quot;…&quot;,&quot;dns_ionos_secret&quot;:&quot;…&quot;}"></textarea></label>
            <label>Plugin options JSON <span class="muted">(optional)</span><textarea v-model="providerForm.options" rows="3" placeholder="{&quot;propagation-seconds&quot;:&quot;60&quot;}"></textarea></label>
            <button class="button primary full">Save encrypted credentials</button>
          </form>
        </div>
        <div class="panel">
          <div class="section-heading"><div><p class="eyebrow">SAVED CONFIGURATIONS</p><h2>DNS providers</h2></div></div>
          <p v-if="!providers.length" class="empty">No DNS providers configured.</p>
          <article v-for="provider in providers" :key="provider.id" class="provider-row">
            <div><strong>{{ provider.name }}</strong><span>{{ provider.package }} · dns-{{ provider.plugin }}</span></div>
            <span class="badge managed">{{ provider.has_credentials ? "Credentials encrypted" : "No credentials" }}</span>
            <button class="icon-button" title="Delete provider" @click="action(`/api/providers/${provider.id}`, 'DELETE', 'Provider removed.')">×</button>
          </article>
          <aside class="notice"><strong>Plugin security</strong><br />DNS plugins are third-party Python packages and execute inside this container. Only configure packages you trust. Secret values are encrypted in SQLite; keep your encryption key safe.</aside>
        </div>
      </section>
      <footer>Files deployed to the configured directory as <code>fullchain.pem</code> and <code>privkey.pem</code>.</footer>
    </template>
  </main>
</template>
