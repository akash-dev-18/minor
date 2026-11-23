import {
  BrainCircuit,
  History,
  LayoutDashboard,
  ScanLine,
  Settings,
  ShieldCheck,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'

import { useHealth } from '../../hooks/queries'
import { cn } from '../../lib/utils'
import { Badge } from '../ui/badge'

const navigation = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/analyze', label: 'Analyze', icon: ScanLine },
  { to: '/history', label: 'History', icon: History },
  { to: '/model', label: 'Model', icon: BrainCircuit },
  { to: '/settings', label: 'Settings', icon: Settings },
]

function SystemStatus() {
  const { data, isError } = useHealth()

  if (isError || data?.status === 'degraded') {
    return (
      <div className="flex items-center justify-between px-3 py-2">
        <span className="text-xs text-ink-faint">System</span>
        <Badge tone="critical">degraded</Badge>
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between px-3 py-2">
      <span className="text-xs text-ink-faint">System</span>
      <Badge tone="ok">
        <span className="h-1.5 w-1.5 rounded-full bg-ok" />
        operational
      </Badge>
    </div>
  )
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-line bg-surface">
        <div className="flex h-14 items-center gap-2.5 border-b border-line px-5">
          <ShieldCheck className="h-5 w-5 text-accent" strokeWidth={2} />
          <span className="text-sm font-semibold tracking-[0.18em] text-ink">SENTINEL</span>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-4" aria-label="Primary">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-raised text-ink'
                    : 'text-ink-muted hover:bg-raised/60 hover:text-ink',
                )
              }
            >
              {({ isActive }) => (
                <>
                  <item.icon
                    className={cn('h-4 w-4', isActive ? 'text-accent' : 'text-ink-faint')}
                    strokeWidth={1.75}
                  />
                  {item.label}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-line py-2">
          <SystemStatus />
        </div>
      </aside>

      <div className="ml-60 flex min-h-screen w-full flex-col">
        <main className="flex-1 px-8 py-8">
          <div className="mx-auto w-full max-w-6xl">{children}</div>
        </main>
      </div>
    </div>
  )
}
