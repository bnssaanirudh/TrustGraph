"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { motion, useScroll, useTransform, useInView, AnimatePresence } from "framer-motion";

// ─── Animated Counter ─────────────────────────────────────────────────────────
function AnimatedCounter({ target, suffix = "", prefix = "" }: { target: number; suffix?: string; prefix?: string }) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });

  useEffect(() => {
    if (!inView) return;
    const duration = 1800;
    const startTime = Date.now();
    const tick = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.floor(eased * target));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [inView, target]);

  return (
    <div ref={ref} className="stat-value">
      {prefix}{count.toLocaleString()}{suffix}
    </div>
  );
}

// ─── Abstract Data Graph Background ──────────────────────────────────────────
function DataGraphBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;
    
    const resize = () => {
      canvas.width = canvas.offsetWidth * window.devicePixelRatio;
      canvas.height = canvas.offsetHeight * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    };
    resize();
    window.addEventListener("resize", resize);
    
    const nodes: { x: number; y: number; vx: number; vy: number; r: number; opacity: number }[] = [];
    const count = 60;
    
    for (let i = 0; i < count; i++) {
      nodes.push({
        x: Math.random() * canvas.offsetWidth,
        y: Math.random() * canvas.offsetHeight,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: Math.random() * 2 + 1,
        opacity: Math.random() * 0.4 + 0.1,
      });
    }
    
    let raf: number;
    const animate = () => {
      ctx.clearRect(0, 0, canvas.offsetWidth, canvas.offsetHeight);
      
      nodes.forEach(n => {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > canvas.offsetWidth) n.vx *= -1;
        if (n.y < 0 || n.y > canvas.offsetHeight) n.vy *= -1;
      });
      
      // Draw edges
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.strokeStyle = `rgba(10, 9, 8, ${0.04 * (1 - dist / 120)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }
      
      // Draw nodes
      nodes.forEach(n => {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(10, 9, 8, ${n.opacity * 0.3})`;
        ctx.fill();
      });
      
      raf = requestAnimationFrame(animate);
    };
    animate();
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);
  
  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none"
      style={{ opacity: 0.6 }}
    />
  );
}

// ─── Scroll Reveal Wrapper ────────────────────────────────────────────────────
function Reveal({ children, delay = 0, className = "" }: { children: React.ReactNode; delay?: number; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });
  
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 48 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.9, delay, ease: [0.25, 0.46, 0.45, 0.94] }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

// ─── Architecture Feature Row ─────────────────────────────────────────────────
function FeatureRow({ index, label, title, description, tag }: {
  index: string; label: string; title: string; description: string; tag: string;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <Reveal>
      <div
        className="grid grid-cols-12 gap-12 py-16 border-t border-[rgba(10,9,8,0.1)] cursor-default"
        style={{ transition: "background 0.2s ease" }}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      >
        <div className="col-span-1">
          <span className="text-label" style={{ color: hovered ? "var(--color-accent-red)" : undefined }}>
            {index}
          </span>
        </div>
        <div className="col-span-3">
          <span className="text-label">{label}</span>
        </div>
        <div className="col-span-5">
          <h3 style={{ fontFamily: "var(--font-display)", fontSize: "clamp(1.5rem, 3vw, 2.5rem)", lineHeight: 1.2, color: "var(--color-ink)", marginBottom: "1rem" }}>
            {title}
          </h3>
          <p style={{ fontSize: "1rem", color: "var(--color-ink-soft)", lineHeight: 1.8 }}>{description}</p>
        </div>
        <div className="col-span-3 flex items-start justify-end">
          <motion.span
            animate={{ x: hovered ? 8 : 0 }}
            transition={{ duration: 0.2 }}
            className="text-label px-3 py-1.5"
            style={{ border: "1px solid rgba(10,9,8,0.15)", color: "var(--color-ink-muted)" }}
          >
            {tag}
          </motion.span>
        </div>
      </div>
    </Reveal>
  );
}

// ─── Landing Page ─────────────────────────────────────────────────────────────
export default function LandingPage() {
  const { scrollY } = useScroll();
  const heroParallax = useTransform(scrollY, [0, 600], [0, -120]);
  const heroOpacity = useTransform(scrollY, [0, 400], [1, 0]);

  return (
    <main style={{ background: "var(--color-paper)", color: "var(--color-ink)", overflowX: "hidden" }}>
      
      {/* ── Navigation ─────────────────────────────────────────────────────── */}
      <nav className="landing-nav">
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <div style={{ width: "20px", height: "20px", background: "var(--color-ink)", clipPath: "polygon(50% 0%, 100% 100%, 0% 100%)" }} />
          <span style={{ fontWeight: 700, fontSize: "0.875rem", letterSpacing: "0.08em", textTransform: "uppercase" }}>
            TrustGraph
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "2.5rem" }}>
          {["Platform", "Architecture", "Intelligence", "Compliance", "About"].map(item => (
            <a key={item} href={`#${item.toLowerCase()}`} className="landing-nav-link">{item}</a>
          ))}
        </div>

        <Link href="/dashboard" className="cta-primary" style={{ padding: "0.6rem 1.5rem" }}>
          <span>Enter Operations</span>
          <span>→</span>
        </Link>
      </nav>

      {/* ── Hero Section ───────────────────────────────────────────────────── */}
      <section
        id="platform"
        style={{ minHeight: "100svh", display: "grid", gridTemplateColumns: "1fr", position: "relative", paddingTop: "4.5rem", overflow: "hidden" }}
      >
        <DataGraphBackground />
        
        {/* Oversize background text */}
        <motion.div
          style={{ y: heroParallax, opacity: heroOpacity, position: "absolute", inset: 0, display: "flex", alignItems: "flex-end", paddingLeft: "4vw", paddingBottom: "2rem", pointerEvents: "none" }}
        >
          <div
            style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(6rem, 18vw, 22rem)",
              lineHeight: 0.78,
              color: "var(--color-ink)",
              opacity: 0.035,
              letterSpacing: "-0.03em",
              userSelect: "none",
              whiteSpace: "nowrap",
            }}
          >
            TRUST
          </div>
        </motion.div>

        {/* Main hero content */}
        <div style={{ position: "relative", zIndex: 1, padding: "12vh 6rem 8rem", display: "grid", gridTemplateColumns: "7fr 5fr", alignItems: "end", gap: "6rem", maxWidth: "100%" }}>
          
          {/* Left: Headline */}
          <div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="text-label mb-8"
              style={{ color: "var(--color-accent-red)" }}
            >
              Agentic Third-Party Risk & Threat Hunting
            </motion.div>
            
            <motion.h1
              className="display-hero"
              initial={{ opacity: 0, y: 60 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 1.1, delay: 0.3, ease: [0.25, 0.46, 0.45, 0.94] }}
            >
              Trust
              <br />
              <em style={{ fontStyle: "italic", color: "var(--color-accent-red)" }}>Graph.</em>
            </motion.h1>
          </div>

          {/* Right: Description + CTA */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.7, ease: [0.25, 0.46, 0.45, 0.94] }}
            style={{ paddingBottom: "1rem" }}
          >
            <p className="text-body-landing" style={{ marginBottom: "3rem", fontSize: "1.25rem", lineHeight: 1.8 }}>
              Enterprise supply chain threat intelligence combining Graph Attention Networks, Splunk MCP log aggregation, 
              and Corrective Agentic RAG — to identify, contain, and quantify third-party breach exposure in real time.
            </p>
            
            <div style={{ display: "flex", gap: "2rem", alignItems: "center", flexWrap: "wrap" }}>
              <Link href="/dashboard" className="cta-primary" style={{ padding: "1rem 2.5rem", fontSize: "1.0625rem" }}>
                <span>Enter TrustGraph Operations</span>
                <motion.span animate={{ x: [0, 6, 0] }} transition={{ duration: 1.5, repeat: Infinity, ease: "easeInOut" }}>→</motion.span>
              </Link>
              <a href="#architecture" className="cta-ghost" style={{ fontSize: "1rem" }}>
                View Architecture
              </a>
            </div>
            
            <div className="text-label mt-8" style={{ color: "var(--color-ink-muted)" }}>Scroll ↓</div>
          </motion.div>
        </div>
      </section>

      {/* ── Stats Strip ────────────────────────────────────────────────────── */}
      <div className="divider" />
      <section style={{ background: "var(--color-paper)", padding: "5rem 4rem" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1px", background: "rgba(10,9,8,0.1)" }}>
          {[
            { value: 21150000, prefix: "$", suffix: "", label: "Financial Exposure Quantified", decimals: false },
            { value: 127, prefix: "", suffix: "min", label: "Mean Time to Containment" },
            { value: 34, prefix: "", suffix: "%", label: "Global Trust Index Drop" },
            { value: 91, prefix: "", suffix: "%", label: "GAT Breach Probability" },
          ].map((stat, i) => (
            <Reveal key={i} delay={i * 0.1}>
              <div className="bento-cell" style={{ textAlign: i === 0 ? "left" : "center" }}>
                <AnimatedCounter target={stat.value / (stat.prefix === "$" ? 1000000 : 1)} prefix={stat.prefix} suffix={stat.prefix === "$" ? "M+" : stat.suffix} />
                <div className="stat-label">{stat.label}</div>
              </div>
            </Reveal>
          ))}
        </div>
      </section>
      <div className="divider" />

      {/* ── Architecture Features ───────────────────────────────────────────── */}
      <section id="architecture" style={{ padding: "8rem 4rem", background: "var(--color-paper)" }}>
        <div style={{ maxWidth: "100%" }}>
          <Reveal>
            <div className="grid grid-cols-12 gap-12 mb-20">
              <div className="col-span-1">
                <span className="text-label" style={{ color: "var(--color-accent-red)" }}>02</span>
              </div>
              <div className="col-span-5">
                <h2 className="display-section">Architecture<br /><em>Components.</em></h2>
              </div>
              <div className="col-span-5 col-start-8" style={{ display: "flex", alignItems: "flex-end" }}>
                <p className="text-body-landing">
                  Five production-grade intelligence layers operating in concert — each engineered 
                  for enterprise scalability, observable execution, and deterministic threat containment.
                </p>
              </div>
            </div>
          </Reveal>

          {[
            { index: "01", label: "Data Aggregation", title: "Splunk MCP Native Integration", description: "Real-time log aggregation via the Model Context Protocol server. Intent-to-SPL translation engine with automatic query refinement, generating optimized Splunk Processing Language from natural language security hunting objectives.", tag: "Splunk · MCP · SPL" },
            { index: "02", label: "Graph Intelligence", title: "Neo4j Enterprise Graph Topology", description: "Full entity relationship graph — Vendor → Service → Container → Database — with MERGE-safe idempotent write operations, structural blast radius modeling, and Cypher-native containment mutations.", tag: "Neo4j · Cypher · Graph" },
            { index: "03", label: "Risk Propagation", title: "PyTorch Geometric GAT Engine", description: "Dual-layer Graph Attention Network computing node-level compromise probability scores [0.0→1.0] across the full topology. Multi-head attention learns which neighbor nodes amplify breach propagation.", tag: "PyG · GATConv · CUDA" },
            { index: "04", label: "Agentic Pipeline", title: "LangGraph CARAG Workflow", description: "Corrective Agentic RAG executing iterative Planner→Retriever→Evaluator→Refiner→Mitigator loops. Confidence threshold routing forces autonomous SPL reformulation until precision exceeds configurable floor.", tag: "LangGraph · RAG · Agent" },
            { index: "05", label: "Threat Intelligence", title: "Executive Blast Radius Quantification", description: "Risk(N) = β·Σ(wᵢ·Severity) + (1-β)·log(DownstreamDegree) — real-time financial exposure calculation bridging graph topology and operational impact for board-level risk communication.", tag: "Risk · Finance · Graph" },
          ].map((f, i) => (
            <FeatureRow key={i} {...f} />
          ))}
        </div>
      </section>

      {/* ── Red Accent Full-Width Block (Tresmares-style) ───────────────────── */}
      <section style={{ background: "var(--color-accent-red)", padding: "8rem 4rem", position: "relative", overflow: "hidden" }}>
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ duration: 1, ease: [0.25, 0.46, 0.45, 0.94] }}
          viewport={{ once: true }}
        >
          <div style={{ display: "grid", gridTemplateColumns: "6fr 6fr", gap: "8rem", alignItems: "center" }}>
            <div>
              <div className="text-label mb-6" style={{ color: "rgba(245, 243, 239, 0.5)" }}>CARAG Pipeline</div>
              <h2 style={{ fontFamily: "var(--font-display)", fontSize: "clamp(2.5rem, 7vw, 8rem)", lineHeight: 0.88, color: "var(--color-paper)", letterSpacing: "-0.02em" }}>
                Corrective
                <br />
                Agentic
                <br />
                <em>RAG.</em>
              </h2>
            </div>
            <div>
              <div style={{ display: "flex", flexDirection: "column", gap: "3rem" }}>
                {[
                  { step: "PLAN", detail: "PlannerNode identifies root compromise entry coordinates from threat intent vector." },
                  { step: "RETRIEVE", detail: "RetrieverNode dispatches dynamically-constructed SPL to Splunk MCP server." },
                  { step: "EVALUATE", detail: "EvaluatorNode grades context relevance — scores below 0.85 trigger refinement loop." },
                  { step: "REFINE", detail: "RefinerNode autonomously rewrites SPL parameters, shifts time horizons, adds exclusion filters." },
                  { step: "MITIGATE", detail: "MitigatorNode assembles containment plan: IAM revocations, container isolation, VPC rules." },
                ].map(({ step, detail }) => (
                  <div key={step} style={{ display: "flex", gap: "1.5rem", alignItems: "flex-start" }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", fontWeight: 600, color: "rgba(245, 243, 239, 0.5)", minWidth: "4rem", paddingTop: "2px" }}>{step}</span>
                    <p style={{ fontSize: "0.9375rem", color: "rgba(245, 243, 239, 0.9)", lineHeight: 1.6 }}>{detail}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </section>

      {/* ── Intelligence Metrics ────────────────────────────────────────────── */}
      <section id="intelligence" style={{ background: "var(--color-paper)", padding: "8rem 4rem" }}>
        <Reveal>
          <div className="text-label mb-4" style={{ color: "var(--color-accent-red)" }}>03 / Threat Intelligence</div>
          <h2 className="display-section mb-16">
            Blast Radius<br />
            <em>Quantification.</em>
          </h2>
        </Reveal>
        
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1px", background: "rgba(10,9,8,0.1)" }}>
          {[
            { title: "Graph Attention Network", body: "Dual-layer GATConv with 8-head and 4-head multi-head attention. Processes 5-dimensional node feature vectors: failed_logins, api_volume, privilege_level, historical_trust_score, degree_centrality.", stat: "512", statLabel: "Hidden Dimensions" },
            { title: "Blast Radius Formula", body: "Risk(N) = β·Σ(wᵢ·AnomalySeverity) + (1-β)·log(DownstreamDegree+1) — tensor-native computation balancing local anomaly signals against structural network exposure.", stat: "0.89", statLabel: "VendorX GAT Score" },
            { title: "MITRE ATT&CK Coverage", body: "Full kill chain coverage from Initial Access through Exfiltration. Automated technique tagging: T1190, T1550.001, T1611, T1530 mapped to graph topology mutations.", stat: "47+", statLabel: "Techniques Tracked" },
          ].map((card, i) => (
            <Reveal key={i} delay={i * 0.12}>
              <div className="bento-cell" style={{ minHeight: "280px", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ fontFamily: "var(--font-display)", fontSize: "1.5rem", marginBottom: "1rem", color: "var(--color-ink)" }}>{card.title}</h3>
                  <p style={{ fontSize: "0.9rem", color: "var(--color-ink-soft)", lineHeight: 1.7 }}>{card.body}</p>
                </div>
                <div style={{ marginTop: "2rem", paddingTop: "1.5rem", borderTop: "1px solid rgba(10,9,8,0.1)" }}>
                  <div className="stat-value" style={{ fontSize: "2.5rem" }}>{card.stat}</div>
                  <div className="stat-label">{card.statLabel}</div>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ── Final CTA ───────────────────────────────────────────────────────── */}
      <section style={{ background: "var(--color-ink)", padding: "10rem 4rem", textAlign: "center" }}>
        <Reveal>
          <div className="text-label mb-8" style={{ color: "rgba(245, 243, 239, 0.35)" }}>
            Production-Ready Security Intelligence
          </div>
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: "clamp(3rem, 8vw, 9rem)", lineHeight: 0.88, color: "var(--color-paper)", marginBottom: "3rem", letterSpacing: "-0.02em" }}>
            Secure Your
            <br />
            <em style={{ color: "var(--color-accent-red)" }}>Supply Chain.</em>
          </h2>
          <p style={{ fontSize: "1.125rem", color: "rgba(245, 243, 239, 0.65)", marginBottom: "3rem", maxWidth: "500px", margin: "0 auto 3rem" }}>
            Deploy enterprise-grade agentic threat hunting across your entire third-party ecosystem.
          </p>
          <Link href="/dashboard" className="cta-primary" style={{ background: "var(--color-paper)", color: "var(--color-ink)", fontSize: "1rem", padding: "1rem 2.5rem" }}>
            <span>Enter TrustGraph Operations</span>
            <span>→</span>
          </Link>
        </Reveal>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────────── */}
      <footer style={{ background: "var(--color-ink)", padding: "2rem 4rem", borderTop: "1px solid rgba(245, 243, 239, 0.08)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <div style={{ width: "16px", height: "16px", background: "var(--color-paper)", clipPath: "polygon(50% 0%, 100% 100%, 0% 100%)" }} />
            <span style={{ fontWeight: 700, fontSize: "0.8125rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-paper)" }}>TrustGraph</span>
          </div>
          <span style={{ fontSize: "0.8125rem", color: "rgba(245, 243, 239, 0.35)" }}>
            © 2024 TrustGraph Security — Enterprise Agentic Threat Intelligence
          </span>
        </div>
      </footer>
    </main>
  );
}
