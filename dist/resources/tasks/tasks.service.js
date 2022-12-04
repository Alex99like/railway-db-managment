"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TasksService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const users_service_1 = require("../users/users.service");
const boards_service_1 = require("../boards/boards.service");
const columns_service_1 = require("../columns/columns.service");
const tasks_entity_1 = require("./tasks.entity");
let TasksService = class TasksService {
    constructor(tasksRepository, columnRepository, boardRepository, userRepository) {
        this.tasksRepository = tasksRepository;
        this.columnRepository = columnRepository;
        this.boardRepository = boardRepository;
        this.userRepository = userRepository;
    }
    async getAll(boardId, columnId) {
        await this.boardRepository.isExist(boardId);
        await this.columnRepository.isExist(columnId);
        const resp = await this.tasksRepository
            .createQueryBuilder('tasks')
            .where({ boardId, columnId })
            .select([
            'tasks.id',
            'tasks.title',
            'tasks.order',
            'tasks.description',
            'tasks.userId',
            'tasks.boardId',
            'tasks.columnId',
            'files.filename',
            'files.fileSize',
        ])
            .leftJoin('tasks.files', 'files')
            .getMany();
        return resp;
    }
    async getById(boardId, columnId, taskId) {
        await this.boardRepository.isExist(boardId);
        await this.columnRepository.isExist(columnId);
        const task = await this.tasksRepository
            .createQueryBuilder('tasks')
            .where({ boardId, columnId, id: taskId })
            .select([
            'tasks.id',
            'tasks.title',
            'tasks.order',
            'tasks.description',
            'tasks.userId',
            'tasks.boardId',
            'tasks.columnId',
            'files.filename',
            'files.fileSize',
        ])
            .leftJoin('tasks.files', 'files')
            .getOne();
        if (!task) {
            throw new common_1.HttpException('Task was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        return task;
    }
    async create(boardId, columnId, taskDto) {
        await this.boardRepository.isExist(boardId);
        await this.columnRepository.isExist(columnId);
        await this.userRepository.getById(taskDto.userId);
        const task = (await this.tasksRepository.find({
            where: { boardId, columnId },
            order: { order: 'DESC' },
            take: 1,
        }));
        const autoOrder = task.length ? task[0].order + 1 : 1;
        const modelTask = await this.tasksRepository.create({ ...taskDto, columnId, order: autoOrder, boardId }).save();
        return modelTask;
    }
    async remove(boardId, columnId, taskId) {
        await this.boardRepository.isExist(boardId);
        await this.columnRepository.isExist(columnId);
        const tasks = (await this.tasksRepository.find({
            where: { boardId, columnId },
            order: { order: 'ASC' },
        }));
        const currentTask = tasks.find((task) => task.id === taskId);
        if (!currentTask) {
            throw new common_1.HttpException('Task was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        const arrayTasksToSort = tasks.filter((task) => task.order > currentTask.order);
        this.tasksRepository.manager.transaction(async (transact) => {
            await currentTask.remove();
            arrayTasksToSort.forEach(async (task) => {
                task.order -= 1;
                await transact.save(task);
            });
        });
    }
    async update(boardId, columnId, taskId, body) {
        await this.boardRepository.isExist(boardId);
        await this.columnRepository.isExist(columnId);
        const tasks = (await this.tasksRepository.find({
            where: { boardId, columnId },
            order: { order: 'ASC' },
        }));
        const currentTask = tasks.find((task) => task.id === taskId);
        if (!currentTask) {
            throw new common_1.HttpException('Task was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        if (body.order < 1) {
            throw new common_1.HttpException('The task order number cannot be less than 1!', common_1.HttpStatus.BAD_REQUEST);
        }
        currentTask.title = body.title;
        currentTask.description = body.description;
        currentTask.userId = body.userId;
        currentTask.boardId = body.boardId;
        if (currentTask.columnId !== body.columnId) {
            const tasksInOtherColumn = (await this.tasksRepository.find({
                where: { boardId, columnId: body.columnId },
                order: { order: 'ASC' },
            }));
            if (tasksInOtherColumn.length + 1 < body.order) {
                throw new common_1.HttpException('The task order number cannot be greater than the total number of tasks!', common_1.HttpStatus.BAD_REQUEST);
            }
            tasksInOtherColumn.forEach((task) => {
                if (body.order <= task.order) {
                    task.order += 1;
                }
            });
            tasks.forEach((task) => {
                if (currentTask.order < task.order) {
                    task.order -= 1;
                }
            });
            currentTask.columnId = body.columnId;
            currentTask.order = body.order;
            this.tasksRepository.manager.transaction(async (transact) => {
                [...tasks, ...tasksInOtherColumn].forEach(async (record) => {
                    await transact.save(record);
                });
            });
            return {
                id: taskId,
                title: body.title,
                order: body.order,
                description: body.description,
                userId: body.userId,
                boardId: body.boardId,
                columnId: body.columnId,
            };
        }
        if (currentTask.order !== body.order) {
            if (tasks.length + 1 < body.order) {
                throw new common_1.HttpException('The task order number cannot be greater than the total number of tasks!', common_1.HttpStatus.BAD_REQUEST);
            }
            this.columnRepository.transactSortingRecords(this.tasksRepository, tasks, currentTask, body.order);
            return {
                id: taskId,
                title: body.title,
                order: body.order,
                description: body.description,
                userId: body.userId,
                boardId: body.boardId,
                columnId: body.columnId,
            };
        }
        const data = await currentTask.save();
        return data;
    }
};
TasksService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(tasks_entity_1.Task)),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        columns_service_1.ColumnsService,
        boards_service_1.BoardsService,
        users_service_1.UsersService])
], TasksService);
exports.TasksService = TasksService;
