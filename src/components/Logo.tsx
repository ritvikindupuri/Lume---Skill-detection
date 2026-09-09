export function LogoMark({ className = "size-7" }: { className?: string }) {
  return (
    <span className={`relative flex items-center justify-center ${className}`} aria-hidden="true">
      <svg viewBox="0 0 48 48" className="lume-prism size-full overflow-visible" fill="none">
        <path d="M24 4 43 37 24 44 5 37 24 4Z" className="fill-primary" />
        <path d="m24 4 19 33-19-7V4Z" className="fill-prism-violet" />
        <path d="M24 44 5 37l19-7 19 7-19 7Z" className="fill-prism-pink" />
        <circle cx="24" cy="28" r="6.5" className="fill-primary-foreground/90" />
        <circle cx="24" cy="28" r="2.4" className="fill-foreground" />
      </svg>
    </span>
  );
}

export function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <LogoMark className="size-8" />
      <span className="font-display text-xl font-semibold">Lume</span>
    </span>
  );
}