import type { Metadata } from "next";
import "./globals.css";
import "@xyflow/react/dist/style.css";

export const metadata: Metadata = {
  title: "SnowImpact",
  description: "Snowflake change intelligence and policy firewall",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <aside className="sidebar">
            <div className="brand"><span className="brandMark">S</span><div><strong>SnowImpact</strong><small>Change Intelligence</small></div></div>
            <nav>
              <a className="active" href="#overview">Overview</a>
              <a href="#analysis">Analyze change</a>
              <a href="#findings">Findings</a>
              <a href="#security">Security</a>
              <a href="#finops">FinOps</a>
              <a href="#policies">Policies</a>
            </nav>
            <div className="sidebarFoot">v1.0.0 · Community</div>
          </aside>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
