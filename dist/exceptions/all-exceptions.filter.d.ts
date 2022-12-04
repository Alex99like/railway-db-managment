import { ArgumentsHost, HttpException } from '@nestjs/common';
import { BaseExceptionFilter, AbstractHttpAdapter } from '@nestjs/core';
import { LogService } from '../logger/logger.service';
export declare class AllExceptionsFilter extends BaseExceptionFilter {
    private httpAdapter;
    private logService;
    constructor(httpAdapter: AbstractHttpAdapter, logService: LogService);
    catch(exception: HttpException, host: ArgumentsHost): void;
}
