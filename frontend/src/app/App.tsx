import { useEffect, useRef, useState } from "react";
import Lenis from "lenis";
import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import AppSidebar from "../components/AppSidebar";
import ThemeToggle from "../components/ThemeToggle";
import HomePage from "../pages/HomePage";
import LoginPage from "../pages/LoginPage";
import ChatPage from "../pages/ChatPage";
import RedTeamPage from "../pages/RedTeamPage";
import SecurityDashboardPage from "../pages/SecurityDashboardPage";
import { api, clearSession, hasSession } from "../services/api";
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
  const scrollWrapper = useRef<HTMLDivElement>(null);
  const scrollContent = useRef<HTMLDivElement>(null);

  useEffect(() => { api.health().then((health) => setMock(health.mock_models)).catch(() => {}); }, []);
  useEffect(() => {
    const wrapper = scrollWrapper.current;
    const content = scrollContent.current;
    if (!wrapper || !content) return;
    const lenis = new Lenis({ wrapper, content, eventsTarget: wrapper, autoRaf: true, lerp: 0.14, allowNestedScroll: true, respectReducedMotion: true });
    return () => lenis.destroy();
  }, []);

  return (
    <div className="relative z-10 flex h-screen flex-col overflow-hidden md:flex-row">
      <AppSidebar theme={theme} role={user.role} username={user.username} onToggleTheme={onToggleTheme} onSignOut={onSignOut} />
      <main className="flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="hidden h-14 shrink-0 items-center justify-end border-b border-edge/60 bg-panel/55 px-6 md:flex">
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        </header>
        {mock && <p role="note" className="model-banner flex items-center gap-2 border-b border-edge px-4 py-2 text-xs backdrop-blur"><span className="size-1.5 bg-cyan-600" /> Stand-in models are active. Answers and safety labels are placeholders until Qwen and Llama Guard are connected.</p>}
        <div ref={scrollWrapper} className="min-h-0 flex-1 overflow-y-auto">
          <div ref={scrollContent} className="h-full min-h-full"><Outlet /></div>
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
  const signOut = () => { clearSession(); setUser(null); };
  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");

  return (
    <Routes>
      <Route path="/" element={!sessionReady ? <SessionLoading /> : user ? <Navigate to="/chat" replace /> : <HomePage theme={theme} onToggleTheme={toggleTheme} />} />
      <Route path="/login" element={!sessionReady ? <SessionLoading /> : user ? <Navigate to="/chat" replace /> : <LoginPage theme={theme} onToggleTheme={toggleTheme} onLogin={signIn} />} />
      <Route element={!sessionReady ? <SessionLoading /> : user ? <WorkspaceLayout theme={theme} onToggleTheme={toggleTheme} user={user} onSignOut={signOut} /> : <Navigate to="/login" replace />}>
        <Route path="chat" element={<ChatPage />} />
        <Route path="dashboard" element={user?.role === "admin" ? <SecurityDashboardPage /> : <Navigate to="/chat" replace />} />
        <Route path="red-team" element={user?.role === "admin" ? <RedTeamPage /> : <Navigate to="/chat" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
