import { BaseEntity } from 'typeorm';
import { Task } from '../tasks/tasks.entity';
import { Board } from '../boards/boards.entity';
export interface IColumn {
    id: UUIDType;
    title: string;
    order: number;
}
export declare class Column extends BaseEntity {
    id: UUIDType;
    title: string;
    order: number;
    board: Board;
    boardId: string | null;
    tasks: Task[];
}
