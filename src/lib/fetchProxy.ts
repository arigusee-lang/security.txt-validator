import type { FetchMetadata } from './types';

export interface FetchProxyResult {
  content: string;
  metadata: FetchMetadata;
}

export interface FetchProxyError {
  error: string;
  message: string;
  httpStatus?: number;
}

const DEFAULT_PROXY_URL = '/api/fetch';

/**
 * Strips protocol prefix from a domain string.
 * e.g. "https://example.com/path" ? "example.com"
 */
function stripProtocol(input: string): string {
  let domain = input.trim();
  // Remove protocol prefix if present
  domain = domain.replace(/^https?:\/\//, '');
  // Remove any other scheme
  domain = domain.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  // Remove trailing path/slash
  domain = domain.split('/')[0];
  return domain;
}

/**
 * Fetches a security.txt file via the proxy server.
 *
 * @param domain - Domain name or full URL to fetch from
 * @param proxyUrl - Base URL for the proxy endpoint (default: /api/fetch)
 * @throws {FetchProxyError} on proxy or network errors
 */
export async function fetchSecurityTxt(
  domain: string,
  proxyUrl: string = DEFAULT_PROXY_URL,
): Promise<FetchProxyResult> {
  const cleanDomain = stripProtocol(domain);

  let response: Response;
  try {
    response = await fetch(`${proxyUrl}?domain=${encodeURIComponent(cleanDomain)}`);
  } catch {
    throw {
      error: 'network_error',
      message: 'Unable to reach the validation service. Please try again later.',
    } satisfies FetchProxyError;
  }

  let data: any;
  try {
    const text = await response.text();
    data = text ? JSON.parse(text) : null;
  } catch {
    throw {
      error: 'network_error',
      message: 'The validation service returned an invalid response. Please try again later.',
    } satisfies FetchProxyError;
  }

  if (!data || !data.success) {
    throw {
      error: data?.error ?? 'unknown',
      message: data?.message ?? 'An unknown error occurred.',
      httpStatus: data?.httpStatus,
    } satisfies FetchProxyError;
  }

  return {
    content: data.content,
    metadata: {
      contentType: data.contentType ?? '',
      fetchedFrom: data.fetchedFrom ?? '',
      redirectChain: data.redirectChain ?? [],
      wellKnownFound: data.wellKnownFound ?? false,
      fallbackUsed: data.fallbackUsed ?? false,
      usedHttps: true,
    },
  };
}
