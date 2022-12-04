import { StreamableFile } from '@nestjs/common';
export declare class LogsController {
    getErrors(): StreamableFile;
    getInfo(): StreamableFile;
}
