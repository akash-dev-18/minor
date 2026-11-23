import { cva, type VariantProps } from 'class-variance-authority'
import type { HTMLAttributes } from 'react'

import { cn } from '../../lib/utils'

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium tracking-wide',
  {
    variants: {
      tone: {
        neutral: 'border-line-strong bg-raised text-ink-muted',
        ok: 'border-ok/25 bg-ok/10 text-ok',
        warn: 'border-warn/25 bg-warn/10 text-warn',
        critical: 'border-critical/25 bg-critical/10 text-critical',
        accent: 'border-accent/30 bg-accent-soft text-accent',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
)

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />
}
