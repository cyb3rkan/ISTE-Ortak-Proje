import type { ReactNode } from "react";

interface ExternalLinkProps {
  href: string;
  children: ReactNode;
  className?: string;
}

/**
 * Harici bağlantı: yeni sekmede açılır; `noopener noreferrer` ile açılan
 * sayfanın `window.opener`'a erişmesi ve referrer sızıntısı engellenir.
 */
export function ExternalLink({ href, children, className = "" }: ExternalLinkProps) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={`text-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent ${className}`}
    >
      {children}
      <span aria-hidden> ↗</span>
      <span className="sr-only"> (yeni sekmede açılır)</span>
    </a>
  );
}
