import { NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { LogService } from './logger.service';
export declare class LoggingInterceptor implements NestInterceptor {
    private logService;
    constructor(logService: LogService);
    intercept(ctx: ExecutionContext, next: CallHandler): Observable<void>;
}
