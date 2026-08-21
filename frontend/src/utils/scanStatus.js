const RUNNING_STATUSES = [
  'running',
  'pending',
  'queued',
  'analyzing',
]

const DONE_STATUSES = [
  'completed',
  'completed_with_errors',
]

const FAILED_STATUSES = [
  'failed',
  'cancelled',
]

function normalize(status) {
  return String(status || '').toLowerCase()
}

export function isRunningStatus(status) {
  return RUNNING_STATUSES.includes(normalize(status))
}

export function isDoneStatus(status) {
  return DONE_STATUSES.includes(normalize(status))
}

export function isFailedStatus(status) {
  return FAILED_STATUSES.includes(normalize(status))
}

export function isTerminalStatus(status) {
  return isDoneStatus(status) || isFailedStatus(status)
}
