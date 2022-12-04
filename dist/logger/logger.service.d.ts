import { LoggerService } from '@nestjs/common';
export declare class LogService implements LoggerService {
    log(obj: unknown): void;
    error(obj: unknown): void;
    warn(obj: unknown): void;
    debug?(obj: unknown): void;
    verbose?(obj: unknown): void;
}
