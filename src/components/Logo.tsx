export function LogoMark({ className = "size-7" }: { className?: string }) {
  return (
    <span className={`aperture-mark relative flex items-center justify-center ${className}`} aria-hidden="true">
      <svg viewBox="0 0 42 42" className="size-full overflow-visible" fill="none">
        <path d="M21 3.5 38 37h-7.4L21 17.4 11.4 37H4L21 3.5Z" className="fill-foreground" />
        <path d="M10.5 24h21" className="aperture-beam stroke-primary" strokeWidth="3.2" strokeLinecap="round" />
        <rect x="17.7" y="20.7" width="6.6" height="6.6" rx="1.25" className="fill-background" />
        <rect x="19.5" y="22.5" width="3" height="3" rx="0.5" className="fill-primary" />
      </svg>
    </span>
  );
}

export function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <LogoMark className="size-8" />
      <span className="flex flex-col leading-none">
        <span className="font-display text-[17px] font-semibold uppercase">Aperture</span>
        <span className="mt-1 font-mono text-[7px] uppercase tracking-[0.18em] text-primary">AI Security</span>
      </span>
    </span>
  );
}