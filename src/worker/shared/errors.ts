export class AppError extends Error {
  constructor(
    public readonly status: 400 | 401 | 403 | 404 | 409 | 413 | 422 | 429 | 500 | 502 | 503,
    message: string,
    public readonly code = "request_failed",
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export function publicErrorMessage(error: unknown): string {
  if (error instanceof AppError) return error.message;
  return "请求处理失败";
}
