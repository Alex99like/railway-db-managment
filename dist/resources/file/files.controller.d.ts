/// <reference types="multer" />
import { StreamableFile } from '@nestjs/common';
import { FileService } from './files.service';
import { SaveFileDto } from './dto/save-file.dto';
export declare class FileController {
    private fileService;
    constructor(fileService: FileService);
    upload(file: Express.Multer.File, body: SaveFileDto): Promise<string>;
    download(reqTaskId: string, reqFilename: string): Promise<StreamableFile>;
}
