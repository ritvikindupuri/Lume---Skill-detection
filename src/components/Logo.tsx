export function LogoMark({ className = "size-7" }: { className?: string }) {
  return (
    <span
      className={`relative flex items-center justify-center rounded-[9px] bg-foreground ${className}`}
      aria-hidden="true"
    >
      <svg viewBox="0 0 24 24" className="size-[58%]" fill="none">
        <path
          d="M6.5 7.5 12 4l5.5 3.5v4.8c0 3.2-2.1 5.9-5.5 7.7-3.4-1.8-5.5-4.5-5.5-7.7V7.5Z"
          className="stroke-background"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path d="m9.2 12 1.8 1.8 3.9-4" className="stroke-primary" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

export function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <LogoMark />
      <span className="font-display text-[17px] font-semibold">Attest</span>
    </span>
  );
}