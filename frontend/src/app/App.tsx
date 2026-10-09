import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import AppSidebar from "../components/AppSidebar";
import { api } from "../services/api";
import ChatPage from "../pages/ChatPage";
import RedTeamPage from "../pages/RedTeamPage";
import SecurityDashboardPage from "../pages/SecurityDashboardPage";

export default function App() {
  const [mock, setMock] = useState(false);
  useEffect(() => { api.health().then((h) => setMock(h.mock_models)).catch(() => {}); }, []);
  return (
    <div className="flex h-full flex-col md:flex-row">
      <AppSidebar />
      <main className="flex min-h-0 flex-1 flex-col">
        {mock && (
          <p role="note" className="border-b border-edge bg-node px-4 py-2 text-xs text-mute">
            Stand-in models are active. Answers and safety labels are placeholders until Qwen and Llama Guard are connected.
          </p>
        )}
        <div className="min-h-0 flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<ChatPage />} />
            <Route path="/dashboard" element={<SecurityDashboardPage />} />
            <Route path="/red-team" element={<RedTeamPage />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
