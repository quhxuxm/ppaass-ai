import { ApiError } from './types'
import { asRecord, stringValue } from './values'

let csrfToken = ''

export function clearClientSession(): void {
  csrfToken = ''
}

export async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')

  if (init.body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }
  if (csrfToken && isMutation(init.method)) {
    headers.set('X-CSRF-Token', csrfToken)
  }

  const response = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers,
  })

  const body = await parseResponse(response)
  adoptCsrf(body)

  if (!response.ok) {
    const record = asRecord(body)
    const nested = asRecord(record?.error)
    const message =
      stringValue(record?.message) ??
      stringValue(nested?.message) ??
      stringValue(record?.detail) ??
      stringValue(record?.error) ??
      `请求失败（HTTP ${response.status}）`
    const code = stringValue(record?.code) ?? stringValue(nested?.code)
    throw new ApiError(message, response.status, code)
  }

  return body as T
}

async function parseResponse(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return undefined
  }

  const text = await response.text()
  if (!text) {
    return undefined
  }

  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(text) as unknown
    } catch {
      throw new ApiError('服务器返回了无效的 JSON', 502)
    }
  }
  return text
}

function isMutation(method?: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes(
    (method ?? 'GET').toUpperCase(),
  )
}

function adoptCsrf(value: unknown): void {
  const record = asRecord(value)
  const session = asRecord(record?.session)
  const token =
    stringValue(record?.csrf_token) ??
    stringValue(record?.csrfToken) ??
    stringValue(session?.csrf_token)
  if (token) {
    csrfToken = token
  }
}
