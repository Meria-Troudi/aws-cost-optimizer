const PALETTE = ['#2E4CF6', '#414A5B', '#1FAE64', '#D98A17', '#E0453B', '#8C9CFF']

export function serviceStyle(name) {
  const label = name || 'Other'
  let hash = 0
  for (let i = 0; i < label.length; i += 1) {
    hash = (hash * 31 + label.charCodeAt(i)) >>> 0
  }
  const color = PALETTE[hash % PALETTE.length]
  const icon = label.replace(/[^A-Za-z0-9]/g, '').charAt(0).toUpperCase() || '•'
  return { color, icon }
}
