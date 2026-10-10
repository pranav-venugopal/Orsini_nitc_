import { useEffect, useRef, useState } from "react";
import Lenis from "lenis";
import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import WorkspaceNav from "../components/AppSidebar";
import HomePage from "../pages/HomePage";
import LoginPage from "../pages/LoginPage";
import SignupPage from "../pages/SignupPage";
import ChatPage from "../pages/ChatPage";
import AgentToolsPage from "../pages/AgentToolsPage";
import RedTeamPage from "../pages/RedTeamPage";
import SecurityDashboardPage from "../pages/SecurityDashboardPage";
import { api, clearSession, hasSession } from "../services/api";
import { resetChatCache } from "../hooks/useChat";
import type { SessionUser } from "../types/api";

type Theme = "light" | "dark";

function getInitialTheme(): Theme {
  const saved = window.localStorage.getItem("secure-ai-theme");
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function SessionLoading() {
  return <div className="grid min-h-screen place-items-center text-sm text-mute"><p role="status" className="flex items-center gap-3"><span className="size-2 animate-pulse rounded-full bg-accent" /> Restoring secure session</p></div>;
}

function WorkspaceLayout({ theme, onToggleTheme, user, onSignOut }: {
  theme: Theme;
  onToggleTheme: () => void;
  user: SessionUser;
  onSignOut: () => void;
}) {
  const [mock, setMock] = useState(false);
  const [modelMode, setModelMode] = useState<string>("groq");
  const scrollWrapper = useRef<HTMLDivElement>(null);
  const scrollContent = useRef<HTMLDivElement>(null);

  useEffect(() => { 
    api.health().then((health) => {
      setMock(health.mock_models);
      setModelMode(health.model_mode);
    }).catch(() => {}); 
  }, []);
  
  const handleToggleMode = async () => {
    if (user.role !== "admin") return;
    const newMode = modelMode === "local" ? "groq" : "local";
    try {
      await api.configMode(newMode);
      setModelMode(newMode);
      setMock(newMode === "mock");
    } catch (e) {
      console.error("Failed to change mode", e);
    }
  };
  
  useEffect(() => {
    const wrapper = scrollWrapper.current;
    const content = scrollContent.current;
    if (!wrapper || !content) return;
    const lenis = new Lenis({ wrapper, content, eventsTarget: wrapper, autoRaf: true, lerp: 0.14, allowNestedScroll: true, respectReducedMotion: true });
    return () => lenis.destroy();
  }, []);

  return (
    <div className="relative z-10 flex h-screen flex-col overflow-hidden">
      <WorkspaceNav theme={theme} role={user.role} username={user.username} onToggleTheme={onToggleTheme} onSignOut={onSignOut} modelMode={modelMode} onToggleModelMode={handleToggleMode} />
      {mock && <p role="note" className="model-banner flex items-center justify-center gap-2 border-b border-edge px-4 py-2 text-center text-xs backdrop-blur"><span className="size-1.5 shrink-0 rounded-full bg-cyan-600" /> Stand-in models are active. Answers and safety labels are placeholders until Qwen and Llama Guard are connected.</p>}
      <main className="flex min-h-0 min-w-0 flex-1 flex-col">
        <div ref={scrollWrapper} className="min-h-0 flex-1 overflow-y-auto">
          <div ref={scrollContent} className="h-full min-h-full"><Outlet context={{ user }} /></div>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  const [mock, setMock] = useState(false);
  const [theme, setTheme] = useState<Theme>(getInitialTheme);
  const [sessionReady, setSessionReady] = useState(false);
  const [user, setUser] = useState<SessionUser | null>(null);
  useEffect(() => {
    if (!hasSession()) { setSessionReady(true); return; }
    let active = true;
    api.me().then((currentUser) => { if (active) setUser(currentUser); })
      .catch(() => clearSession())
      .finally(() => { if (active) setSessionReady(true); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("secure-ai-theme", theme);
  }, [theme]);

  const signIn = async (username: string, password: string) => {
    const signedInUser = await api.login(username, password);
    setUser(signedInUser);
    return signedInUser;
  };
  const signUp = async (username: string, password: string) => {
    const signedUpUser = await api.register(username, password);
    setUser(signedUpUser);
    return signedUpUser;
  };
  const signOut = () => { clearSession(); resetChatCache(); setUser(null); };
  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");

  return (
    <Routes>
      <Route path="/" element={!sessionReady ? <SessionLoading /> : user ? <Navigate to="/chat" replace /> : <HomePage theme={theme} onToggleTheme={toggleTheme} />} />
      <Route path="/login" element={!sessionReady ? <SessionLoading /> : user ? <Navigate to="/chat" replace /> : <LoginPage theme={theme} onToggleTheme={toggleTheme} onLogin={signIn} />} />
      <Route path="/signup" element={!sessionReady ? <SessionLoading /> : user ? <Navigate to="/chat" replace /> : <SignupPage theme={theme} onToggleTheme={toggleTheme} onSignUp={signUp} />} />
      <Route element={!sessionReady ? <SessionLoading /> : user ? <WorkspaceLayout theme={theme} onToggleTheme={toggleTheme} user={user} onSignOut={signOut} /> : <Navigate to="/login" replace />}>
        <Route path="chat" element={<ChatPage />} />
        <Route path="tools" element={user?.role === "admin" ? <AgentToolsPage /> : <Navigate to="/chat" replace />} />
        <Route path="dashboard" element={user?.role === "admin" ? <SecurityDashboardPage /> : <Navigate to="/chat" replace />} />
        <Route path="red-team" element={user?.role === "admin" ? <RedTeamPage /> : <Navigate to="/chat" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
