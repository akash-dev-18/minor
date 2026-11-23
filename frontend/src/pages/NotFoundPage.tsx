import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <div className="py-20 text-center">
      <p className="font-mono text-xs uppercase tracking-widest text-ink-faint">404</p>
      <h1 className="mt-3 text-lg font-semibold text-ink">Page not found</h1>
      <p className="mt-1 text-sm text-ink-muted">The requested view does not exist.</p>
      <Link to="/" className="mt-5 inline-block text-sm text-accent hover:underline">
        Return to dashboard
      </Link>
    </div>
  )
}
