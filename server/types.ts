/** Response from the proxy fetch endpoint on success */
export interface ProxyFetchResponse {
  success: true;
  content: string;
  contentType: string;
  fetchedFrom: string;
  redirectChain: string[];
  wellKnownFound: boolean;
  fallbackUsed: boolean;
}

/** Error response from the proxy */
export interface ProxyFetchError {
  success: false;
  error:
    | "timeout"
    | "size_limit"
    | "dns_failure"
    | "http_error"
    | "ssrf_blocked"
    | "invalid_content_type"
    | "not_found"
    | "too_many_redirects"
    | "invalid_request"
    | "internal";
  message: string;
  httpStatus?: number;
}

export type ProxyResponse = ProxyFetchResponse | ProxyFetchError;
