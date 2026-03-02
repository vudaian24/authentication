import { useState, useCallback } from "react";
import type { ApiResponse, AuthResponse } from "@auth-labs/shared";
import "./App.css";
import { digestAuthFetch, type DigestStep } from "./utils/digestClient";

// ─── Types ─────────────────────────────────────────────────────────────────────

type Tab = "basic" | "digest";
type Status = "idle" | "loading" | "success" | "error";

interface RequestState {
  status: Status;
  data: ApiResponse<AuthResponse> | null;
  error: string | null;
  rawHeader: string | null;
  digestSteps: DigestStep[];
  duration: number | null;
}

const INITIAL_STATE: RequestState = {
  status: "idle",
  data: null,
  error: null,
  rawHeader: null,
  digestSteps: [],
  duration: null,
};

const SERVER = "/api";

// ─── Component ────────────────────────────────────────────────────────────────

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("basic");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("secret123");
  const [showPassword, setShowPassword] = useState(false);
  const [endpoint, setEndpoint] = useState<"protected" | "profile">(
    "protected",
  );
  const [state, setState] = useState<RequestState>(INITIAL_STATE);

  // ─── Basic Auth Handler ──────────────────────────────────────────────────────

  const handleBasicAuth = useCallback(async () => {
    setState({ ...INITIAL_STATE, status: "loading" });
    const t0 = performance.now();

    try {
      const credentials = btoa(`${username}:${password}`);
      const rawHeader = `Authorization: Basic ${credentials}`;

      const res = await fetch(`${SERVER}/basic/${endpoint}`, {
        headers: { Authorization: `Basic ${credentials}` },
      });

      const data: ApiResponse<AuthResponse> = await res.json();
      const duration = Math.round(performance.now() - t0);

      if (res.ok) {
        setState({
          status: "success",
          data,
          error: null,
          rawHeader,
          digestSteps: [],
          duration,
        });
      } else {
        setState({
          status: "error",
          data: null,
          error: data.error || "Authentication failed",
          rawHeader,
          digestSteps: [],
          duration,
        });
      }
    } catch (err) {
      setState({
        ...INITIAL_STATE,
        status: "error",
        error: err instanceof Error ? err.message : "Network error",
        duration: Math.round(performance.now() - t0),
      });
    }
  }, [username, password, endpoint]);

  // ─── Digest Auth Handler ─────────────────────────────────────────────────────

  const handleDigestAuth = useCallback(async () => {
    setState({ ...INITIAL_STATE, status: "loading" });
    const t0 = performance.now();

    try {
      const result = await digestAuthFetch(
        `${SERVER}/digest/${endpoint}`,
        username,
        password,
      );

      const duration = Math.round(performance.now() - t0);

      if (result.ok) {
        setState({
          status: "success",
          data: result.data as ApiResponse<AuthResponse>,
          error: null,
          rawHeader: null,
          digestSteps: result.steps,
          duration,
        });
      } else {
        const errData = result.data as ApiResponse<never>;
        setState({
          status: "error",
          data: null,
          error: errData?.error || "Authentication failed",
          rawHeader: null,
          digestSteps: result.steps,
          duration,
        });
      }
    } catch (err) {
      setState({
        ...INITIAL_STATE,
        status: "error",
        error: err instanceof Error ? err.message : "Network error",
        duration: Math.round(performance.now() - t0),
      });
    }
  }, [username, password, endpoint]);

  const handleSubmit =
    activeTab === "basic" ? handleBasicAuth : handleDigestAuth;

  const fillCredentials = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-badge">LAB 01</div>
        <h1 className="header-title">HTTP Authentication</h1>
        <p className="header-subtitle">
          Basic Auth & Digest Auth — RFC 7617 / RFC 7616
        </p>
      </header>

      {/* ── Main Content ── */}
      <main className="main">
        <div className="layout">
          {/* ── Left Panel — Controls ── */}
          <section className="panel panel--controls">
            {/* Tab Switcher */}
            <div className="tab-switcher">
              <button
                className={`tab-btn tab-btn--basic ${activeTab === "basic" ? "active" : ""}`}
                onClick={() => {
                  setActiveTab("basic");
                  setState(INITIAL_STATE);
                }}
              >
                <span className="tab-icon">⬡</span>
                Basic Auth
              </button>
              <button
                className={`tab-btn tab-btn--digest ${activeTab === "digest" ? "active" : ""}`}
                onClick={() => {
                  setActiveTab("digest");
                  setState(INITIAL_STATE);
                }}
              >
                <span className="tab-icon">◈</span>
                Digest Auth
              </button>
            </div>

            {/* Method Info */}
            <div className={`method-info method-info--${activeTab}`}>
              {activeTab === "basic" ? (
                <>
                  <div className="method-info__title">Basic Authentication</div>
                  <div className="method-info__desc">
                    Sends credentials as <code>Base64(user:pass)</code> in the
                    Authorization header. Simple but{" "}
                    <strong>requires HTTPS</strong> — Base64 is NOT encryption.
                  </div>
                  <div className="method-info__flow">
                    <span className="flow-step">Request</span>
                    <span className="flow-arrow">→</span>
                    <span className="flow-step flow-step--highlight">
                      401 + Realm
                    </span>
                    <span className="flow-arrow">→</span>
                    <span className="flow-step">Base64 Header</span>
                    <span className="flow-arrow">→</span>
                    <span className="flow-step flow-step--success">200 OK</span>
                  </div>
                </>
              ) : (
                <>
                  <div className="method-info__title">
                    Digest Authentication
                  </div>
                  <div className="method-info__desc">
                    Uses MD5 challenge-response. Password{" "}
                    <strong>never travels</strong> over the wire — only a hash
                    of <code>HA1:nonce:HA2</code> is sent.
                  </div>
                  <div className="method-info__flow">
                    <span className="flow-step">Request</span>
                    <span className="flow-arrow">→</span>
                    <span className="flow-step flow-step--highlight">
                      401 + Nonce
                    </span>
                    <span className="flow-arrow">→</span>
                    <span className="flow-step">MD5 Hash</span>
                    <span className="flow-arrow">→</span>
                    <span className="flow-step flow-step--success">200 OK</span>
                  </div>
                </>
              )}
            </div>

            {/* Credentials Form */}
            <div className="form">
              <div className="form-group">
                <label className="form-label">Username</label>
                <input
                  className="form-input"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="username"
                  autoComplete="off"
                />
              </div>
              <div className="form-group">
                <label className="form-label">Password</label>
                <div className="input-row">
                  <input
                    className="form-input"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="password"
                    autoComplete="off"
                  />
                  <button
                    className="btn-icon"
                    onClick={() => setShowPassword((s) => !s)}
                    title={showPassword ? "Hide" : "Show"}
                  >
                    {showPassword ? "○" : "●"}
                  </button>
                </div>
              </div>

              {/* Quick fill */}
              <div className="quick-fill">
                <span className="quick-fill__label">Quick fill:</span>
                <button
                  className="chip chip--admin"
                  onClick={() => fillCredentials("admin", "secret123")}
                >
                  admin / secret123
                </button>
                <button
                  className="chip"
                  onClick={() => fillCredentials("user", "password456")}
                >
                  user / password456
                </button>
                <button
                  className="chip chip--wrong"
                  onClick={() => fillCredentials("hacker", "wrong")}
                >
                  wrong creds
                </button>
              </div>

              {/* Endpoint selector */}
              <div className="form-group">
                <label className="form-label">Endpoint</label>
                <div className="segment-control">
                  <button
                    className={`segment-btn ${endpoint === "protected" ? "active" : ""}`}
                    onClick={() => setEndpoint("protected")}
                  >
                    /protected
                  </button>
                  <button
                    className={`segment-btn ${endpoint === "profile" ? "active" : ""}`}
                    onClick={() => setEndpoint("profile")}
                  >
                    /profile
                  </button>
                </div>
              </div>

              {/* Submit */}
              <button
                className={`submit-btn submit-btn--${activeTab} ${state.status === "loading" ? "loading" : ""}`}
                onClick={handleSubmit}
                disabled={state.status === "loading"}
              >
                {state.status === "loading" ? (
                  <>
                    <span className="spinner" />
                    Authenticating...
                  </>
                ) : (
                  <>
                    <span>▶</span>
                    Authenticate with{" "}
                    {activeTab === "basic" ? "Basic" : "Digest"} Auth
                  </>
                )}
              </button>

              {/* cURL hint */}
              <div className="curl-hint">
                <span className="curl-hint__label">$ curl</span>
                {activeTab === "basic" ? (
                  <code>
                    curl -u {username}:{password}{" "}
                    http://localhost:3001/api/basic/{endpoint}
                  </code>
                ) : (
                  <code>
                    curl --digest -u {username}:{password}{" "}
                    http://localhost:3001/api/digest/{endpoint}
                  </code>
                )}
              </div>
            </div>
          </section>

          {/* ── Right Panel — Response ── */}
          <section className="panel panel--response">
            <div className="panel-header">
              <span className="panel-title">Response</span>
              {state.duration !== null && (
                <span className="duration-badge">{state.duration}ms</span>
              )}
              {state.status !== "idle" && (
                <button
                  className="clear-btn"
                  onClick={() => setState(INITIAL_STATE)}
                >
                  clear
                </button>
              )}
            </div>

            {/* Idle State */}
            {state.status === "idle" && (
              <div className="response-idle">
                <div className="idle-icon">
                  {activeTab === "basic" ? "⬡" : "◈"}
                </div>
                <p>
                  Hit <strong>Authenticate</strong> to send a request
                </p>
                <p className="idle-hint">
                  {activeTab === "basic"
                    ? "Watch the Authorization: Basic header in DevTools"
                    : "Digest performs 2 requests automatically"}
                </p>
              </div>
            )}

            {/* Loading State */}
            {state.status === "loading" && (
              <div className="response-idle">
                <div className="loading-dots">
                  <span />
                  <span />
                  <span />
                </div>
                <p>
                  Sending request
                  {activeTab === "digest" ? "s (2 round trips)" : ""}...
                </p>
              </div>
            )}

            {/* Digest Steps Visualization */}
            {state.digestSteps.length > 0 && (
              <div className="digest-steps">
                <div className="digest-steps__title">Digest Auth Flow</div>
                {state.digestSteps.map((step, i) => (
                  <div
                    key={i}
                    className={`digest-step digest-step--${step.type}`}
                  >
                    <div className="digest-step__num">{i + 1}</div>
                    <div className="digest-step__content">
                      <div className="digest-step__label">{step.label}</div>
                      <div className="digest-step__detail">{step.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Basic Auth Header Visualization */}
            {activeTab === "basic" && state.rawHeader && (
              <div className="header-visual">
                <div className="header-visual__title">HTTP Header Sent</div>
                <div className="header-visual__code">
                  <span className="hv-key">Authorization: </span>
                  <span className="hv-type">Basic </span>
                  <span
                    className="hv-value"
                    title={`Decoded: ${username}:${password}`}
                  >
                    {btoa(`${username}:${password}`)}
                  </span>
                </div>
                <div className="header-visual__note">
                  ⚠ Base64 decoded ={" "}
                  <code>
                    {username}:{password}
                  </code>{" "}
                  — use HTTPS!
                </div>
              </div>
            )}

            {/* Success Response */}
            {state.status === "success" && state.data && (
              <div className="response-success">
                <div className="response-status">
                  <span className="status-dot status-dot--success" />
                  <span className="status-text">200 OK</span>
                </div>
                {state.data.data && (
                  <div className="response-cards">
                    <div className="response-card">
                      <span className="rc-label">User</span>
                      <span className="rc-value">
                        {state.data.data.user.username}
                      </span>
                    </div>
                    <div className="response-card">
                      <span className="rc-label">Role</span>
                      <span
                        className={`rc-value role-badge role-badge--${state.data.data.user.role}`}
                      >
                        {state.data.data.user.role}
                      </span>
                    </div>
                    <div className="response-card">
                      <span className="rc-label">Method</span>
                      <span className="rc-value">{state.data.data.method}</span>
                    </div>
                    <div className="response-card rc-full">
                      <span className="rc-label">Message</span>
                      <span className="rc-value">
                        {state.data.data.message}
                      </span>
                    </div>
                  </div>
                )}
                <details className="json-details">
                  <summary>View full JSON response</summary>
                  <pre className="json-body">
                    {JSON.stringify(state.data, null, 2)}
                  </pre>
                </details>
              </div>
            )}

            {/* Error Response */}
            {state.status === "error" && (
              <div className="response-error">
                <div className="response-status">
                  <span className="status-dot status-dot--error" />
                  <span className="status-text">Authentication Failed</span>
                </div>
                <div className="error-message">{state.error}</div>
                <div className="error-hint">
                  {state.error?.includes("Network")
                    ? "⚠ Make sure the server is running on port 3001"
                    : "💡 Try using the quick-fill buttons with correct credentials"}
                </div>
              </div>
            )}
          </section>
        </div>

        {/* ── Comparison Table ── */}
        <section className="comparison">
          <h2 className="comparison__title">
            Basic vs Digest — Quick Comparison
          </h2>
          <div className="comparison__grid">
            <div className="comp-header">Feature</div>
            <div className="comp-header comp-header--basic">Basic Auth</div>
            <div className="comp-header comp-header--digest">Digest Auth</div>

            <div className="comp-row__label">Password transmission</div>
            <div className="comp-cell comp-cell--warn">Base64 (plaintext)</div>
            <div className="comp-cell comp-cell--good">Never sent (hashed)</div>

            <div className="comp-row__label">Replay attack protection</div>
            <div className="comp-cell comp-cell--bad">None</div>
            <div className="comp-cell comp-cell--good">Nonce + nc counter</div>

            <div className="comp-row__label">Requires HTTPS</div>
            <div className="comp-cell comp-cell--bad">Mandatory</div>
            <div className="comp-cell comp-cell--warn">
              Strongly recommended
            </div>

            <div className="comp-row__label">Implementation complexity</div>
            <div className="comp-cell comp-cell--good">Very simple</div>
            <div className="comp-cell comp-cell--warn">
              Medium (2 round-trips)
            </div>

            <div className="comp-row__label">Browser support</div>
            <div className="comp-cell comp-cell--good">Universal</div>
            <div className="comp-cell comp-cell--good">Universal</div>

            <div className="comp-row__label">Mutual authentication</div>
            <div className="comp-cell comp-cell--bad">No</div>
            <div className="comp-cell comp-cell--warn">Partial</div>

            <div className="comp-row__label">Modern usage</div>
            <div className="comp-cell comp-cell--warn">Internal APIs only</div>
            <div className="comp-cell comp-cell--bad">Mostly legacy</div>
          </div>
        </section>
      </main>
    </div>
  );
}
