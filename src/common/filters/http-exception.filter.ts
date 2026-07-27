import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
import { Response } from 'express';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const isHttp = exception instanceof HttpException;
    const status = isHttp ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    const payload = isHttp ? exception.getResponse() : null;

    // Normaliza a { error, code, details? }
    const error =
      typeof payload === 'object' && payload !== null && 'message' in payload
        ? String((payload as Record<string, unknown>).message)
        : isHttp
          ? exception.message
          : 'Internal server error';
    const code =
      typeof payload === 'object' && payload !== null && 'code' in payload
        ? String((payload as Record<string, unknown>).code)
        : isHttp
          ? exception.constructor.name.replace('Exception', '').toUpperCase()
          : 'INTERNAL_ERROR';

    res.status(status).json({ error, code });
  }
}
