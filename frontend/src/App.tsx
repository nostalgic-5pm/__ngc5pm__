// frontend/src/App.tsx

import { Outlet } from "react-router-dom";
import { PowGate } from "./features/pow/components/PowGate";

export default function App() {
  return (
    <PowGate>
      <Outlet />
    </PowGate>
  );
}
