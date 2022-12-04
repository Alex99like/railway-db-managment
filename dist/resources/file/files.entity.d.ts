import { BaseEntity } from 'typeorm';
import { Task } from '../tasks/tasks.entity';
export declare class File extends BaseEntity {
    filename: string;
    fileId: UUIDType;
    fileSize: number;
    taskId: UUIDType;
    task: Task;
}
