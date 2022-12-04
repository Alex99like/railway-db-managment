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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TasksController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const create_tasks_dto_1 = require("./dto/create-tasks.dto");
const update_tasks_dto_1 = require("./dto/update-tasks.dto");
const tasks_service_1 = require("./tasks.service");
const tasks_entity_1 = require("./tasks.entity");
const controller_create_1 = __importDefault(require("./schema/controller.create"));
const controller_update_1 = __importDefault(require("./schema/controller.update"));
const jwt_auth_guard_1 = require("../auth/jwt-auth.guard");
let TasksController = class TasksController {
    constructor(taskService) {
        this.taskService = taskService;
    }
    getAll(boardId, columnId) {
        return this.taskService.getAll(boardId, columnId);
    }
    getOne(boardId, columnId, taskId) {
        return this.taskService.getById(boardId, columnId, taskId);
    }
    create(boardId, columnId, createTaskDto) {
        return this.taskService.create(boardId, columnId, createTaskDto);
    }
    remove(boardId, columnId, taskId) {
        return this.taskService.remove(boardId, columnId, taskId);
    }
    update(boardId, columnId, taskId, updateTaskDto) {
        return this.taskService.update(boardId, columnId, taskId, updateTaskDto);
    }
};
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Get all tasks' }),
    (0, swagger_1.ApiResponse)({ status: 200, type: [tasks_entity_1.Task] }),
    (0, swagger_1.ApiParam)({ name: 'boardId', description: 'ID Board' }),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, common_1.Get)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", Promise)
], TasksController.prototype, "getAll", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Get the task by id' }),
    (0, swagger_1.ApiResponse)({ status: 200, type: tasks_entity_1.Task }),
    (0, swagger_1.ApiParam)({ name: 'boardId', description: 'ID Board' }),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, swagger_1.ApiParam)({ name: 'taskId', description: 'ID Task' }),
    (0, common_1.Get)(':taskId'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __param(2, (0, common_1.Param)('taskId', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, String]),
    __metadata("design:returntype", Promise)
], TasksController.prototype, "getOne", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Create task' }),
    (0, swagger_1.ApiResponse)({ status: 201, schema: controller_create_1.default }),
    (0, swagger_1.ApiParam)({ name: 'boardId', description: 'ID Board' }),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, common_1.Post)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.CREATED),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, create_tasks_dto_1.CreateTaskDto]),
    __metadata("design:returntype", Promise)
], TasksController.prototype, "create", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Delete task' }),
    (0, swagger_1.ApiResponse)({ status: 204 }),
    (0, swagger_1.ApiParam)({ name: 'boardId', description: 'ID Board' }),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, swagger_1.ApiParam)({ name: 'taskId', description: 'ID Task' }),
    (0, common_1.Delete)(':taskId'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __param(2, (0, common_1.Param)('taskId', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, String]),
    __metadata("design:returntype", Promise)
], TasksController.prototype, "remove", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Update task' }),
    (0, swagger_1.ApiResponse)({ status: 200, schema: controller_update_1.default }),
    (0, swagger_1.ApiParam)({ name: 'boardId', description: 'ID Board' }),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, swagger_1.ApiParam)({ name: 'taskId', description: 'ID Task' }),
    (0, common_1.Put)(':taskId'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __param(2, (0, common_1.Param)('taskId', common_1.ParseUUIDPipe)),
    __param(3, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, String, update_tasks_dto_1.UpdateTaskDto]),
    __metadata("design:returntype", Promise)
], TasksController.prototype, "update", null);
TasksController = __decorate([
    (0, swagger_1.ApiTags)('Tasks'),
    (0, swagger_1.ApiBearerAuth)('token'),
    (0, common_1.Controller)('/boards/:boardId/columns/:columnId/tasks/'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.AuthGuard),
    __metadata("design:paramtypes", [tasks_service_1.TasksService])
], TasksController);
exports.TasksController = TasksController;
