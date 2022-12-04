import { BaseEntity } from 'typeorm';
import { File } from '../file/files.entity';
export interface ITask {
    id: UUIDType;
    title: string;
    order: number;
    description: string;
    userId: string | null;
    board: string;
    boardId: string | null;
    columnId: string | null;
}
export declare class Task extends BaseEntity {
    id: UUIDType;
    title: string;
    order: number;
    description: string;
    user: string;
    userId: string | null;
    board: string;
    boardId: string | null;
    column: string;
    columnId: string;
    files: File[];
}
