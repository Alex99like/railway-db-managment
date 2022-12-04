import { BaseEntity } from 'typeorm';
import { Task } from '../tasks/tasks.entity';
import { CreateColumnDto } from '../columns/dto/create-column.dto';
export interface IColumn {
    id: UUIDType;
    title: string;
    order: number;
}
export interface IBoard {
    id: UUIDType;
    title: string;
    description: string;
}
export declare class Board extends BaseEntity {
    id: UUIDType;
    title: string;
    description: string;
    columns: CreateColumnDto[];
    tasks: Task[];
}
