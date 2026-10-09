import { useEffect, useRef, useState } from "react";
import Lenis from "lenis";
import { Route, Routes } from "react-router-dom";
import AppSidebar from "../components/AppSidebar";
import ThemeToggle from "../components/ThemeToggle";
import { api } from "../services/api";
import ChatPage from "../pages/ChatPage";
import RedTeamPage from "../pages/RedTeamPage";
import SecurityDashboardPage from "../pages/SecurityDashboardPage";

type Theme = "light" | "dark";

function getInitialTheme(): Theme {
  const saved = window.localStorage.getItem("secure-ai-theme");
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export default function App() {
  const [mock, setMock] = useState(false);
  const [theme, setTheme] = useState<Theme>(getInitialTheme);
  const scrollWrapper = useRef<HTMLDivElement>(null);
  const scrollContent = useRef<HTMLDivElement>(null);
  useEffect(() => { api.health().then((h) => setMock(h.mock_models)).catch(() => {}); }, []);
  useEffect(() => {
    const wrapper = scrollWrapper.current;
    const content = scrollContent.current;
    if (!wrapper || !content) return;
    const lenis = new Lenis({
      wrapper,
      content,
      eventsTarget: wrapper,
      autoRaf: true,
      lerp: 0.14,
      allowNestedScroll: true,
      respectReducedMotion: true,
    });
    return () => lenis.destroy();
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("secure-ai-theme", theme);
  }, [theme]);
  return (
    <div className="relative z-10 flex h-screen flex-col overflow-hidden md:flex-row">
      <AppSidebar theme={theme} onToggleTheme={() => setTheme((current) => current === "dark" ? "light" : "dark")} />
      <main className="flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="hidden h-14 shrink-0 items-center justify-end border-b border-edge/60 bg-panel/55 px-6 md:flex">
          <ThemeToggle theme={theme} onToggle={() => setTheme((current) => current === "dark" ? "light" : "dark")} />
        </header>
        {mock && (
          <p role="note" className="model-banner flex items-center gap-2 border-b border-edge px-4 py-2 text-xs backdrop-blur">
            <span className="size-1.5 bg-cyan-600" />
            Stand-in models are active. Answers and safety labels are placeholders until Qwen and Llama Guard are connected.
          </p>
        )}
        <div ref={scrollWrapper} className="min-h-0 flex-1 overflow-y-auto">
          <div ref={scrollContent} className="h-full min-h-full">
            <Routes>
              <Route path="/" element={<ChatPage />} />
              <Route path="/dashboard" element={<SecurityDashboardPage />} />
              <Route path="/red-team" element={<RedTeamPage />} />
            </Routes>
          </div>
        </div>
      </main>
    </div>
  );
}
