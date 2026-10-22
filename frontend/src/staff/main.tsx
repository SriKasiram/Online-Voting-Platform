// SR-06: entry point for the staff sign-in page (staff.html), separate from the voter app
import "@fontsource-variable/atkinson-hyperlegible-next";
import "@fontsource-variable/atkinson-hyperlegible-mono";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../styles.css";
import StaffApp from "./StaffApp";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <StaffApp />
  </StrictMode>,
);
