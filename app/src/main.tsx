import { createRoot } from "react-dom/client";
import { ErrorWrapper, setFallbackIconProvider } from "@flanksource/clicky-ui";
import { clickyIconProvider } from "@flanksource/clicky-ui/icons";
import { App } from "./App";
import "@flanksource/clicky-ui/styles.css";
import "./index.css";

// Schema-driven icons carried as runtime name strings resolve through this set.
setFallbackIconProvider(clickyIconProvider());

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");
createRoot(root).render(
  <ErrorWrapper>
    <App />
  </ErrorWrapper>,
);
