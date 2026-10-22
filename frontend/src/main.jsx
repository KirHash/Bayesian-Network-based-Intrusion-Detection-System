import React from "react";
import { createRoot } from "react-dom/client";

import App from "./App.jsx";
import CrashScreen from "./components/CrashScreen.jsx";
import ConnectGate from "./components/ConnectGate.jsx";
import LoginGate from "./components/LoginGate.jsx";
import "@fontsource-variable/public-sans";
import "./styles.css";
import "./console.css";
import "./auth.css";
import "./taste.css";

createRoot(document.getElementById("root")).render(
  <CrashScreen>
    <ConnectGate>
      <LoginGate>
        <App />
      </LoginGate>
    </ConnectGate>
  </CrashScreen>
);
