import { Repository } from 'typeorm';
import { CreateTaskDto } from './dto/create-tasks.dto';
import { UpdateTaskDto } from './dto/update-tasks.dto';
import { UsersService } from '../users/users.service';
import { BoardsService } from '../boards/boards.service';
import { ColumnsService } from '../columns/columns.service';
import { Task, ITask } from './tasks.entity';
export declare class TasksService {
    private tasksRepository;
    private columnRepository;
    private boardRepository;
    private userRepository;
    constructor(tasksRepository: Repository<Task>, columnRepository: ColumnsService, boardRepository: BoardsService, userRepository: UsersService);
    getAll(boardId: UUIDType, columnId: UUIDType): Promise<ITask[]>;
    getById(boardId: UUIDType, columnId: UUIDType, taskId: UUIDType): Promise<ITask>;
    create(boardId: UUIDType, columnId: UUIDType, taskDto: CreateTaskDto): Promise<ITask>;
    remove(boardId: UUIDType, columnId: UUIDType, taskId: UUIDType): Promise<void>;
    update(boardId: UUIDType, columnId: UUIDType, taskId: UUIDType, body: UpdateTaskDto): Promise<ITask>;
}
