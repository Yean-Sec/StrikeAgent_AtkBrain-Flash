import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { ProjectsPage } from "./pages/ProjectsPage";
import { ProjectPage } from "./pages/ProjectPage";
import { SettingsPage } from "./pages/SettingsPage";

export default function App() {
  return (
    <AppShell>
        <Routes>
          <Route path="/" element={<ProjectsPage />} />
          <Route path="/project/:id" element={<ProjectPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/replay" element={<Navigate to="/" replace />} />
        </Routes>
    </AppShell>
  );
}
