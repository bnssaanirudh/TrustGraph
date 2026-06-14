import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TrustGraph — Agentic Third-Party Risk & Threat Hunting",
  description: "Enterprise-grade agentic security platform combining Splunk MCP, Neo4j graph semantics, PyTorch GAT risk propagation, and LangGraph CARAG for real-time third-party risk intelligence.",
  keywords: ["threat hunting", "third-party risk", "supply chain security", "graph neural network", "AI security"],
  authors: [{ name: "TrustGraph Security" }],
  openGraph: {
    title: "TrustGraph — Agentic Third-Party Risk & Threat Hunting",
    description: "Real-time supply chain threat intelligence powered by Graph Attention Networks and Corrective Agentic RAG.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=Inter:wght@300;400;450;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
