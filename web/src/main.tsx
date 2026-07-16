import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import "./index.css"
import App from "./App.tsx"
import { ThemeProvider } from "@/components/theme-provider.tsx"
import { consumeAuthMiniCallback } from "@/lib/auth-redirect.ts"

const authRedirectError = consumeAuthMiniCallback()

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <App startupError={authRedirectError} />
    </ThemeProvider>
  </StrictMode>
)
