import React from "react";
import ReactDOM from "react-dom/client";
import "@/index.css";
import App from "@/App";

// Chrome/Radix/ResizeObserver dev-overlay noise:
// "ResizeObserver loop limit exceeded" or
// "ResizeObserver loop completed with undelivered notifications."
// This is typically non-fatal but can spam the CRA error overlay.
window.addEventListener(
  "error",
  (e) => {
    const msg = String(e?.message || "");
    if (msg.includes("ResizeObserver loop")) {
      e.stopImmediatePropagation();
    }
  },
  true,
);

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
