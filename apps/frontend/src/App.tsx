import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "./components/layout/Shell";
import Dashboard from "./pages/Dashboard";
import Playground from "./pages/Playground";
import Policies from "./pages/Policies";
import Audit from "./pages/Audit";
import Settings from "./pages/Settings";

export default function App(): React.ReactElement {
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/playground" element={<Playground />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}

