export function LogoMark({ className = "size-7" }: { className?: string }) {
  return (
    <span
      className={`flex items-center justify-center rounded-[7px] bg-ink ${className}`}
      aria-hidden="true"
    >
      <svg viewBox="0 0 24 24" className="size-[62%]" fill="none">
        {/* lens */}
        <rect x="3" y="3" width="18" height="18" rx="5" className="stroke-skyfield" strokeWidth="1.6" />
        {/* pilcrow: the markdown artifact under the lamp */}
        <path
          d="M15.2 7.4H11.4a2.4 2.4 0 0 0 0 4.8h1.1M13.6 7.4v9.2M15.9 7.4v9.2"
          className="stroke-skyfield"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
        {/* scan bar */}
        <path d="M5.8 12h1.9" className="stroke-signal" strokeWidth="1.8" strokeLinecap="round" />
      </svg>
    </span>
  );
}

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <LogoMark />
      <span className="font-display text-[16px] font-semibold tracking-tight">PARAGRAPH</span>
      {!compact && (
        <span className="ml-1 hidden font-mono text-[10px] uppercase tracking-[0.18em] text-muted sm:inline">
          skill forensics
        </span>
      )}
    </span>
  );
}
