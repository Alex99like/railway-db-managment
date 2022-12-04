import { Repository } from 'typeorm';
import { File } from './files.entity';
export declare class FileService {
    private fileRepository;
    constructor(fileRepository: Repository<File>);
    checkExistFileInDB(taskId: UUIDType, filename: string): Promise<boolean>;
    saveFilename(filename: string, fileId: UUIDType, fileSize: number, taskId: UUIDType): Promise<string>;
    findFileId(taskId: string, filename: string): Promise<string>;
}
