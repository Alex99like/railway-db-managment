import { CreateTaskDto } from './dto/create-tasks.dto';
import { UpdateTaskDto } from './dto/update-tasks.dto';
import { TasksService } from './tasks.service';
import { ITask } from './tasks.entity';
export declare class TasksController {
    private readonly taskService;
    constructor(taskService: TasksService);
    getAll(boardId: UUIDType, columnId: UUIDType): Promise<ITask[]>;
    getOne(boardId: UUIDType, columnId: UUIDType, taskId: UUIDType): Promise<ITask>;
    create(boardId: UUIDType, columnId: UUIDType, createTaskDto: CreateTaskDto): Promise<ITask>;
    remove(boardId: UUIDType, columnId: UUIDType, taskId: UUIDType): Promise<void>;
    update(boardId: UUIDType, columnId: UUIDType, taskId: UUIDType, updateTaskDto: UpdateTaskDto): Promise<ITask>;
}
