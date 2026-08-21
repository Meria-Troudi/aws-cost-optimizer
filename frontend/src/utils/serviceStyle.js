// Single source of truth for "what color is this AWS service" across
// the whole app (dashboard donuts, cost-driver rows, findings,
// recommendations). Colors are derived from the app's own design
// tokens (--red/--ink/--muted/--amber/--green in styles.css) so a
// given service renders the same color everywhere, and stays stable
// across reloads since it's hashed from the name, not from rank
// position in whatever list happens to be showing it.
export const PALETTE = [
  '#e8394b',
  '#12141a',
  '#414a5b',
  '#d98a17',
  '#1fae64',
  '#8a93a3',
  '#b23a4f',
]

export const OTHER_COLOR = '#dfe2e8'

export function colorForService(name) {
  const label = name || 'Other'

  let hash = 0

  for (let i = 0; i < label.length; i += 1) {
    hash = (hash * 31 + label.charCodeAt(i)) >>> 0
  }

  return PALETTE[hash % PALETTE.length]
}

export function serviceStyle(name) {
  const label = name || 'Other'

  const color = colorForService(label)

  const icon =
    label.replace(/[^A-Za-z0-9]/g, '').charAt(0).toUpperCase() || '•'

  return {
    color,
    icon,
  }
}