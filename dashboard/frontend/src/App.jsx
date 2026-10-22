import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Bot,
  Brain,
  CheckCircle,
  ChevronRight,
  Clock,
  FileText,
  Flame,
  Lock,
  LogOut,
  Menu,
  MessageSquare,
  Network,
  RefreshCw,
  Search,
  Send,
  Shield,
  ShieldAlert,
  Terminal,
  User,
  X,
  Zap,
} from "lucide-react";

import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

const api = axios.create({
  baseURL: API_BASE,
});

function authHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
  };
}

function formatDate(value) {
  if (!value) return "—";

  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatNumber(value, digits = 2) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "—";
  }

  return Number(value).toFixed(digits);
}

function riskClass(state) {
  switch ((state || "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    default:
      return "low";
  }
}

function RiskBadge({ state }) {
  return (
    <span className={`risk-badge ${riskClass(state)}`}>
      <span className="risk-dot" />
      {state || "LOW"}
    </span>
  );
}

function StatCard({ icon: Icon, title, value, subtitle, danger }) {
  return (
    <div className={`stat-card ${danger ? "danger-card" : ""}`}>
      <div className="stat-icon">
        <Icon size={20} />
      </div>

      <div className="stat-content">
        <span className="stat-title">{title}</span>
        <strong>{value}</strong>
        {subtitle && <small>{subtitle}</small>}
      </div>
    </div>
  );
}

function Login({ onLogin }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();

    setError("");
    setLoading(true);

    try {
      const response = await axios.post(`${API_BASE}/auth/login`, {
        username,
        password,
      });

      localStorage.setItem("honeypot_token", response.data.access_token);

      onLogin(response.data.access_token);
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        "Login failed. Check your username and password."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-grid" />

      <div className="login-card">
        <div className="login-logo">
          <div className="logo-mark">
            <Shield size={28} />
          </div>

          <div>
            <h1>ADAPTIVE<span>HONEY</span></h1>
            <p>INTELLIGENT THREAT DEFENSE</p>
          </div>
        </div>

        <div className="login-title">
          <span className="terminal-label">&gt; SECURE_ACCESS</span>
          <h2>Dashboard Login</h2>
          <p>Authorized personnel only.</p>
        </div>

        <form onSubmit={submit}>
          <label>
            Username
            <div className="input-wrapper">
              <User size={17} />
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                autoComplete="username"
              />
            </div>
          </label>

          <label>
            Password
            <div className="input-wrapper">
              <Lock size={17} />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                autoComplete="current-password"
              />
            </div>
          </label>

          {error && (
            <div className="login-error">
              <AlertTriangle size={16} />
              {error}
            </div>
          )}

          <button className="login-button" disabled={loading}>
            {loading ? (
              <>
                <RefreshCw className="spin" size={18} />
                AUTHENTICATING...
              </>
            ) : (
              <>
                <Shield size={18} />
                ENTER DASHBOARD
              </>
            )}
          </button>
        </form>

        <div className="login-footer">
          <span>
            <span className="status-online" /> SYSTEM ONLINE
          </span>
          <span>JWT PROTECTED</span>
        </div>
      </div>
    </div>
  );
}

function App() {
  const [token, setToken] = useState(
    localStorage.getItem("honeypot_token") || ""
  );

  const [user, setUser] = useState(null);
  const [summary, setSummary] = useState(null);
  const [sessions, setSessions] = useState([]);

  const [selectedId, setSelectedId] = useState(null);
  const [sessionDetails, setSessionDetails] = useState(null);
  const [threatProfile, setThreatProfile] = useState(null);

  const [loading, setLoading] = useState(false);
  const [detailsLoading, setDetailsLoading] = useState(false);

  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [decoyContent, setDecoyContent] = useState(null);
  const [decoyLoading, setDecoyLoading] = useState(false);

  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState([
    {
      role: "assistant",
      content:
        "Security assistant online. Ask me about attacks, severity, risk, behaviors, SHAP explanations, or the selected session.",
    },
  ]);
  const [chatLoading, setChatLoading] = useState(false);

  const isLoggedIn = Boolean(token);

  async function loadCurrentUser() {
    try {
      const response = await api.get("/auth/me", {
        headers: authHeaders(token),
      });

      setUser(response.data);
    } catch {
      logout();
    }
  }

  async function loadDashboard() {
    setLoading(true);

    try {
      const [summaryResponse, sessionsResponse] = await Promise.all([
        api.get("/dashboard/summary", {
          headers: authHeaders(token),
        }),
        api.get("/sessions?limit=100", {
          headers: authHeaders(token),
        }),
      ]);

      setSummary(summaryResponse.data);

      // /sessions returns { sessions: [...] }. Keep sessions as an array.
      const sessionPayload = sessionsResponse.data;
      const normalizedSessions = Array.isArray(sessionPayload)
        ? sessionPayload
        : Array.isArray(sessionPayload?.sessions)
          ? sessionPayload.sessions
          : Array.isArray(sessionPayload?.items)
            ? sessionPayload.items
            : [];

      setSessions(normalizedSessions);
    } catch (err) {
      if (err?.response?.status === 401) {
        logout();
      }
    } finally {
      setLoading(false);
    }
  }

  async function loadSession(sessionId) {
    setSelectedId(sessionId);
    setDetailsLoading(true);
    setThreatProfile(null);
    setSessionDetails(null);

    try {
      const [detailsResponse, profileResponse] = await Promise.all([
        api.get(`/sessions/${sessionId}`, {
          headers: authHeaders(token),
        }),
        api.get(`/sessions/${sessionId}/threat-profile`, {
          headers: authHeaders(token),
        }),
      ]);

      setSessionDetails(detailsResponse.data);
      setThreatProfile(profileResponse.data);
    } catch (err) {
      console.error(err);
    } finally {
      setDetailsLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem("honeypot_token");

    setToken("");
    setUser(null);
    setSummary(null);
    setSessions([]);
    setSelectedId(null);
    setSessionDetails(null);
    setThreatProfile(null);
  }

  async function viewDecoy(decoyId) {
    setDecoyLoading(true);

    try {
      const response = await api.get(`/decoys/${decoyId}`, {
        headers: authHeaders(token),
      });

      setDecoyContent(response.data);
    } catch (err) {
      alert(
        err?.response?.data?.detail || "Unable to retrieve decoy content."
      );
    } finally {
      setDecoyLoading(false);
    }
  }

  async function sendChat(event) {
    event?.preventDefault();

    const message = chatInput.trim();

    if (!message || chatLoading) return;

    setChatInput("");

    setChatMessages((previous) => [
      ...previous,
      {
        role: "user",
        content: message,
      },
    ]);

    setChatLoading(true);

    try {
      const response = await api.post(
        "/chat",
        {
          message,
          session_id: selectedId,
        },
        {
          headers: authHeaders(token),
        }
      );

      setChatMessages((previous) => [
        ...previous,
        {
          role: "assistant",
          content:
            response.data.answer ||
            response.data.response ||
            "No response received.",
        },
      ]);
    } catch (err) {
      setChatMessages((previous) => [
        ...previous,
        {
          role: "assistant",
          content:
            err?.response?.data?.detail ||
            "The security assistant could not process the request.",
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  }

  useEffect(() => {
    if (!token) return;

    loadCurrentUser();
    loadDashboard();

    const interval = setInterval(() => {
      loadDashboard();
    }, 15000);

    return () => clearInterval(interval);
  }, [token]);

  const selectedSession = useMemo(
    () => (Array.isArray(sessions) ? sessions : []).find((session) => session.session_id === selectedId),
    [sessions, selectedId]
  );

  if (!isLoggedIn) {
    return <Login onLogin={setToken} />;
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <button
          className="mobile-menu"
          onClick={() => setSidebarOpen((value) => !value)}
        >
          <Menu size={21} />
        </button>

        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>

          <div>
            <h1>
              ADAPTIVE<span>HONEY</span>
            </h1>
            <small>AI-POWERED ADAPTIVE HONEYPOT</small>
          </div>
        </div>

        <div className="topbar-right">
          <div className="system-status">
            <span className="status-online" />
            SYSTEM ONLINE
          </div>

          <div className="user-info">
            <User size={16} />
            {user?.username || "admin"}
          </div>

          <button className="logout-button" onClick={logout}>
            <LogOut size={16} />
            Logout
          </button>
        </div>
      </header>

      <aside className={`sidebar ${sidebarOpen ? "open" : ""}`}>
        <div className="sidebar-section">
          <span className="sidebar-label">COMMAND CENTER</span>

          <button
            className={`nav-item ${!selectedId ? "active" : ""}`}
            onClick={() => {
              setSelectedId(null);
              setSessionDetails(null);
              setThreatProfile(null);
              setSidebarOpen(false);
            }}
          >
            <Activity size={18} />
            Overview
          </button>

          <button
            className={`nav-item ${selectedId ? "active" : ""}`}
            onClick={() => setSidebarOpen(false)}
          >
            <Terminal size={18} />
            Sessions
          </button>
        </div>

        <div className="sidebar-section">
          <span className="sidebar-label">SECURITY MODULES</span>

          <div className="sidebar-info">
            <Brain size={17} />
            <span>ML Classifier</span>
            <span className="module-dot" />
          </div>

          <div className="sidebar-info">
            <ShieldAlert size={17} />
            <span>Risk Engine</span>
            <span className="module-dot" />
          </div>

          <div className="sidebar-info">
            <Zap size={17} />
            <span>Adaptive Response</span>
            <span className="module-dot" />
          </div>

          <div className="sidebar-info">
            <Bot size={17} />
            <span>Groq Assistant</span>
            <span className="module-dot" />
          </div>
        </div>

        <div className="sidebar-bottom">
          <div className="architecture-mini">
            <span>PIPELINE</span>
            <p>COWRIE</p>
            <ChevronRight size={13} />
            <p>ANALYZER</p>
            <ChevronRight size={13} />
            <p>ML</p>
            <ChevronRight size={13} />
            <p>RISK</p>
            <ChevronRight size={13} />
            <p>ADAPT</p>
          </div>
        </div>
      </aside>

      <main className="main-content">
        {!selectedId ? (
          <DashboardHome
            summary={summary}
            sessions={sessions}
            loading={loading}
            onSelectSession={loadSession}
            onRefresh={loadDashboard}
          />
        ) : (
          <SessionView
            selectedSession={selectedSession}
            sessionDetails={sessionDetails}
            threatProfile={threatProfile}
            loading={detailsLoading}
            onBack={() => {
              setSelectedId(null);
              setSessionDetails(null);
              setThreatProfile(null);
            }}
            onViewDecoy={viewDecoy}
            decoyLoading={decoyLoading}
          />
        )}
      </main>

      <button
        className="chat-fab"
        onClick={() => setChatOpen((value) => !value)}
        title="Security Assistant"
      >
        {chatOpen ? <X size={23} /> : <Bot size={23} />}
        {!chatOpen && <span className="chat-pulse" />}
      </button>

      {chatOpen && (
        <ChatPanel
          messages={chatMessages}
          input={chatInput}
          setInput={setChatInput}
          loading={chatLoading}
          onSend={sendChat}
          selectedId={selectedId}
          onClose={() => setChatOpen(false)}
        />
      )}

      {decoyContent && (
        <DecoyModal
          content={decoyContent}
          onClose={() => setDecoyContent(null)}
        />
      )}
    </div>
  );
}

function DashboardHome({
  summary,
  sessions,
  loading,
  onSelectSession,
  onRefresh,
}) {
  const safeSessions = Array.isArray(sessions) ? sessions : [];

  const totalSessions =
    summary?.total_sessions ??
    (typeof summary?.sessions === "number" ? summary.sessions : undefined) ??
    safeSessions.length;

  const highRisk =
    summary?.high_risk_sessions ??
    summary?.high_risk ??
    0;

  const critical =
    summary?.critical_sessions ??
    summary?.critical ??
    0;

  const totalCommands =
    summary?.total_commands ??
    safeSessions.reduce(
      (sum, session) => sum + Number(session.command_count || 0),
      0
    );

  return (
    <>
      <div className="page-header">
        <div>
          <span className="eyebrow">
            <span className="orange-line" />
            SECURITY OPERATIONS CENTER
          </span>

          <h2>Threat Overview</h2>
          <p>
            Monitor attacker activity, machine-learning predictions and
            adaptive honeypot responses.
          </p>
        </div>

        <button className="refresh-button" onClick={onRefresh}>
          <RefreshCw size={17} className={loading ? "spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="stats-grid">
        <StatCard
          icon={Activity}
          title="Total Sessions"
          value={totalSessions}
          subtitle="Observed by Cowrie"
        />

        <StatCard
          icon={Terminal}
          title="Commands"
          value={totalCommands}
          subtitle="Captured activities"
        />

        <StatCard
          icon={AlertTriangle}
          title="High Risk"
          value={highRisk}
          subtitle="HIGH + CRITICAL"
          danger
        />

        <StatCard
          icon={Flame}
          title="Critical"
          value={critical}
          subtitle="Immediate attention"
          danger
        />
      </div>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-kicker">LIVE TELEMETRY</span>
            <h3>Recent Sessions</h3>
          </div>

          <span className="live-indicator">
            <span className="status-online" />
            LIVE
          </span>
        </div>

        {loading && sessions.length === 0 ? (
          <LoadingState text="Loading session telemetry..." />
        ) : sessions.length === 0 ? (
          <EmptyState text="No honeypot sessions recorded yet." />
        ) : (
          <SessionTable
            sessions={safeSessions}
            onSelect={onSelectSession}
          />
        )}
      </section>
    </>
  );
}

function SessionTable({ sessions, onSelect }) {
  const safeSessions = Array.isArray(sessions) ? sessions : [];

  return (
    <div className="table-wrapper">
      <table className="session-table">
        <thead>
          <tr>
            <th>SESSION</th>
            <th>SOURCE</th>
            <th>USER</th>
            <th>COMMANDS</th>
            <th>RISK</th>
            <th>TIME</th>
            <th />
          </tr>
        </thead>

        <tbody>
          {safeSessions.map((session) => (
            <tr
              key={session.session_id}
              onClick={() => onSelect(session.session_id)}
            >
              <td>
                <div className="session-id">
                  <span className="session-live-dot" />
                  {session.session_id}
                </div>
              </td>

              <td>
                <div className="source-cell">
                  <Network size={15} />
                  {session.source_ip || "—"}
                </div>
              </td>

              <td>{session.username || "—"}</td>

              <td>
                <span className="command-count">
                  {session.command_count ??
                    session.commands?.length ??
                    0}
                </span>
              </td>

              <td>
                <RiskBadge state={session.risk_state} />
              </td>

              <td className="time-cell">
                {formatDate(session.created_at || session.start_time)}
              </td>

              <td>
                <ChevronRight size={18} className="table-arrow" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SessionView({
  selectedSession,
  sessionDetails,
  threatProfile,
  loading,
  onBack,
  onViewDecoy,
  decoyLoading,
}) {
  const details = sessionDetails || selectedSession;

  const commands = sessionDetails?.commands || [];
  const behaviors = sessionDetails?.behaviors || [];
  const actions = sessionDetails?.adaptive_actions || [];
  const decoys = sessionDetails?.decoys || [];

  const risk =
    threatProfile?.risk ||
    sessionDetails?.risk ||
    selectedSession?.risk ||
    {};

  return (
    <>
      <div className="page-header session-page-header">
        <div>
          <button className="back-button" onClick={onBack}>
            <ArrowLeft size={17} />
            All Sessions
          </button>

          <span className="eyebrow">
            <span className="orange-line" />
            SESSION ANALYSIS
          </span>

          <h2 className="session-title">
            {selectedSession?.session_id || "Session"}
          </h2>

          <p>
            Full telemetry, ML classification, risk assessment and adaptive
            response history.
          </p>
        </div>

        <RiskBadge state={risk.state || selectedSession?.risk_state} />
      </div>

      {loading ? (
        <LoadingState text="Analyzing session..." />
      ) : (
        <>
          <div className="session-overview-grid">
            <div className="panel overview-card">
              <div className="panel-header">
                <div>
                  <span className="panel-kicker">SESSION</span>
                  <h3>Connection Details</h3>
                </div>
                <Network size={20} />
              </div>

              <InfoGrid
                items={[
                  ["Source IP", details?.source_ip || "—"],
                  ["Source Port", details?.source_port || "—"],
                  ["Destination", details?.destination_ip || "—"],
                  ["Username", details?.username || "—"],
                  ["Protocol", details?.protocol || "SSH"],
                  [
                    "Authentication",
                    details?.successful_auth === true
                      ? "Successful"
                      : details?.successful_auth === false
                        ? "Failed"
                        : "Unknown",
                  ],
                ]}
              />
            </div>

            <div className="panel risk-panel">
              <div className="panel-header">
                <div>
                  <span className="panel-kicker">RISK ENGINE</span>
                  <h3>Threat Severity</h3>
                </div>

                <ShieldAlert size={21} />
              </div>

              <div className="risk-score">
                <strong>{risk.score ?? 0}</strong>
                <span>/100</span>
              </div>

              <RiskBadge state={risk.state || "LOW"} />

              <div className="risk-progress">
                <div
                  style={{
                    width: `${Math.min(
                      Number(risk.score || 0),
                      100
                    )}%`,
                  }}
                />
              </div>

              <div className="risk-breakdown">
                <div>
                  <span>Behavior</span>
                  <strong>{risk.behavior_score ?? 0}</strong>
                </div>

                <div>
                  <span>Progression</span>
                  <strong>{risk.progression_score ?? 0}</strong>
                </div>

                <div>
                  <span>Authentication</span>
                  <strong>{risk.authentication_score ?? 0}</strong>
                </div>
              </div>
            </div>
          </div>

          <div className="content-grid">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <span className="panel-kicker">AI CLASSIFIER</span>
                  <h3>Threat Profile</h3>
                </div>

                <Brain size={20} />
              </div>

              {threatProfile ? (
                <>
                  <div className="prediction-box">
                    <div>
                      <span>Predicted Attack Class</span>
                      <strong>
                        {threatProfile.predicted_class || "Unknown"}
                      </strong>
                    </div>

                    <div className="confidence">
                      <span>Confidence</span>
                      <strong>
                        {(
                          Number(threatProfile.prediction_confidence || 0) *
                          100
                        ).toFixed(1)}
                        %
                      </strong>
                    </div>
                  </div>

                  <ProbabilityList
                    probabilities={threatProfile.class_probabilities}
                  />
                </>
              ) : (
                <EmptyState text="Threat profile unavailable." />
              )}
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <span className="panel-kicker">EXPLAINABILITY</span>
                  <h3>Top SHAP Features</h3>
                </div>

                <Zap size={20} />
              </div>

              {threatProfile?.top_shap_features?.length ? (
                <ShapList features={threatProfile.top_shap_features} />
              ) : (
                <EmptyState text="No SHAP explanation available." />
              )}
            </section>
          </div>

          <div className="content-grid">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <span className="panel-kicker">BEHAVIOR ANALYSIS</span>
                  <h3>Observed Behaviors</h3>
                </div>

                <Activity size={20} />
              </div>

              <div className="behavior-list">
                {(
                  threatProfile?.observed_behaviors ||
                  behaviors.map((item) => item.behavior)
                ).map((behavior, index) => (
                  <div className="behavior-tag" key={`${behavior}-${index}`}>
                    <span />
                    {behavior}
                  </div>
                ))}

                {!(
                  threatProfile?.observed_behaviors?.length ||
                  behaviors.length
                ) && <EmptyState text="No behaviors detected." />}
              </div>

              {risk.reasons?.length > 0 && (
                <div className="risk-reasons">
                  <h4>Risk Reasons</h4>

                  {risk.reasons.map((reason, index) => (
                    <div key={index}>
                      <AlertTriangle size={14} />
                      {reason}
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <span className="panel-kicker">ADAPTIVE DEFENSE</span>
                  <h3>Response Actions</h3>
                </div>

                <Shield size={20} />
              </div>

              <ActionTimeline actions={actions} />
            </section>
          </div>

          <section className="panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">DECEPTION LAYER</span>
                <h3>Created Decoy Files</h3>
              </div>

              <FileText size={20} />
            </div>

            {decoys.length === 0 ? (
              <EmptyState text="No decoy files created for this session." />
            ) : (
              <div className="decoy-grid">
                {decoys.map((decoy) => (
                  <div className="decoy-card" key={decoy.id}>
                    <div className="decoy-icon">
                      <FileText size={20} />
                    </div>

                    <div className="decoy-info">
                      <strong>{decoy.virtual_path}</strong>
                      <span>{decoy.decoy_type || "decoy"}</span>
                      <small>{formatDate(decoy.created_at)}</small>
                    </div>

                    <button
                      className="view-decoy-button"
                      onClick={() => onViewDecoy(decoy.id)}
                      disabled={decoyLoading}
                    >
                      <Search size={15} />
                      View Content
                    </button>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">ATTACK ACTIVITY</span>
                <h3>Captured Commands</h3>
              </div>

              <Terminal size={20} />
            </div>

            <CommandList commands={commands} />
          </section>
        </>
      )}
    </>
  );
}

function InfoGrid({ items }) {
  return (
    <div className="info-grid">
      {items.map(([label, value]) => (
        <div className="info-item" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function ProbabilityList({ probabilities }) {
  if (!probabilities) {
    return <EmptyState text="No class probabilities available." />;
  }

  const entries = Object.entries(probabilities).sort(
    ([, a], [, b]) => Number(b) - Number(a)
  );

  return (
    <div className="probability-list">
      {entries.map(([name, probability]) => {
        const percent = Number(probability) * 100;

        return (
          <div className="probability-row" key={name}>
            <div className="probability-label">
              <span>{name}</span>
              <strong>{percent.toFixed(1)}%</strong>
            </div>

            <div className="probability-bar">
              <div style={{ width: `${percent}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ShapList({ features }) {
  return (
    <div className="shap-list">
      {features.slice(0, 10).map((feature, index) => {
        const value = Number(
          feature.shap_value ??
          feature.value ??
          feature.importance ??
          0
        );

        return (
          <div className="shap-row" key={`${feature.feature}-${index}`}>
            <div className="shap-name">
              <span>{index + 1}</span>
              {feature.feature || feature.name || "Feature"}
            </div>

            <strong className={value >= 0 ? "positive" : "negative"}>
              {value >= 0 ? "+" : ""}
              {value.toFixed(4)}
            </strong>
          </div>
        );
      })}
    </div>
  );
}

function ActionTimeline({ actions }) {
  if (!actions.length) {
    return <EmptyState text="No adaptive actions recorded." />;
  }

  return (
    <div className="action-timeline">
      {actions.map((action, index) => (
        <div className="timeline-item" key={action.id || index}>
          <div className="timeline-marker">
            <Zap size={12} />
          </div>

          <div className="timeline-content">
            <strong>{action.action}</strong>

            <span>
              {action.target || "Adaptive defense"}{" "}
              {action.risk_state && `• ${action.risk_state}`}
            </span>

            <small>{formatDate(action.created_at)}</small>
          </div>
        </div>
      ))}
    </div>
  );
}

function CommandList({ commands }) {
  if (!commands.length) {
    return <EmptyState text="No commands captured." />;
  }

  return (
    <div className="command-list">
      {commands.map((command, index) => (
        <div className="command-row" key={command.id || index}>
          <span className="command-number">
            {String(index + 1).padStart(2, "0")}
          </span>

          <Terminal size={15} />

          <code>{command.command || "—"}</code>

          <span className="command-time">
            {formatDate(command.timestamp)}
          </span>
        </div>
      ))}
    </div>
  );
}

function ChatPanel({
  messages,
  input,
  setInput,
  loading,
  onSend,
  selectedId,
  onClose,
}) {
  return (
    <div className="chat-panel">
      <div className="chat-header">
        <div className="chat-title">
          <div className="chat-icon">
            <Bot size={19} />
          </div>

          <div>
            <strong>Security Assistant</strong>
            <span>
              {selectedId
                ? `Context: ${selectedId}`
                : "General threat intelligence"}
            </span>
          </div>
        </div>

        <button onClick={onClose}>
          <X size={18} />
        </button>
      </div>

      <div className="chat-messages">
        {messages.map((message, index) => (
          <div
            className={`chat-message ${message.role === "user" ? "user-message" : "bot-message"
              }`}
            key={index}
          >
            <div className="chat-avatar">
              {message.role === "user" ? (
                <User size={14} />
              ) : (
                <Bot size={14} />
              )}
            </div>

            <div className="chat-bubble">
              {message.content}
            </div>
          </div>
        ))}

        {loading && (
          <div className="chat-message bot-message">
            <div className="chat-avatar">
              <Bot size={14} />
            </div>

            <div className="chat-bubble typing">
              <span />
              <span />
              <span />
            </div>
          </div>
        )}
      </div>

      <form className="chat-input-area" onSubmit={onSend}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about the attack..."
          disabled={loading}
        />

        <button disabled={loading || !input.trim()}>
          <Send size={17} />
        </button>
      </form>
    </div>
  );
}

function DecoyModal({ content, onClose }) {
  const path = content?.virtual_path || content?.path || "Decoy File";

  const body =
    content?.content ??
    content?.file_content ??
    content?.text ??
    "No content available.";

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="decoy-modal"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-header">
          <div>
            <span className="panel-kicker">DECOY CONTENT</span>
            <h3>{path}</h3>
          </div>

          <button onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        <div className="decoy-meta">
          <span>
            <FileText size={14} />
            {content?.decoy_type || "Safe deception file"}
          </span>

          <span>
            <Shield size={14} />
            Honeypot generated
          </span>
        </div>

        <pre className="decoy-content">{body}</pre>

        <div className="modal-footer">
          <span>
            <CheckCircle size={14} />
            Safe simulated content
          </span>

          <button className="close-modal-button" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function LoadingState({ text }) {
  return (
    <div className="loading-state">
      <RefreshCw className="spin" size={22} />
      <span>{text}</span>
    </div>
  );
}

function EmptyState({ text }) {
  return (
    <div className="empty-state">
      <Shield size={22} />
      <span>{text}</span>
    </div>
  );
}

export default App;