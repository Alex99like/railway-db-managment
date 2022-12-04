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
Object.defineProperty(exports, "__esModule", { value: true });
exports.Task = void 0;
const swagger_1 = require("@nestjs/swagger");
const typeorm_1 = require("typeorm");
const columns_entity_1 = require("../columns/columns.entity");
const boards_entity_1 = require("../boards/boards.entity");
const users_entity_1 = require("../users/users.entity");
const files_entity_1 = require("../file/files.entity");
let Task = class Task extends typeorm_1.BaseEntity {
};
__decorate([
    (0, swagger_1.ApiProperty)({ example: '40af606c-c0bb-47d1-bc20-a2857242cde3', description: 'Unique task ID' }),
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], Task.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Task: pet the cat', description: 'Task title' }),
    (0, typeorm_1.Column)(),
    __metadata("design:type", String)
], Task.prototype, "title", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: '1', description: 'Task order' }),
    (0, typeorm_1.Column)(),
    __metadata("design:type", Number)
], Task.prototype, "order", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Domestic cat needs to be stroked gently', description: 'Task description' }),
    (0, typeorm_1.Column)(),
    __metadata("design:type", String)
], Task.prototype, "description", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => users_entity_1.User, (user) => user.tasks, { onDelete: 'SET NULL', onUpdate: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'userId' }),
    __metadata("design:type", String)
], Task.prototype, "user", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: '40af606c-c0bb-47d1-bc20-a2857242cde3', description: 'ID of the User who owns the Task' }),
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", Object)
], Task.prototype, "userId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => boards_entity_1.Board, (board) => board.tasks, { onDelete: 'CASCADE', onUpdate: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'boardId' }),
    __metadata("design:type", String)
], Task.prototype, "board", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        example: '8d3bad56-ad8a-495d-9500-18ae4d1de8dc',
        description: 'ID of the Board to which the belongs Task',
    }),
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", Object)
], Task.prototype, "boardId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => columns_entity_1.Column, (column) => column.tasks, { onDelete: 'CASCADE', onUpdate: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'columnId' }),
    __metadata("design:type", String)
], Task.prototype, "column", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        example: '41344d09-b995-451f-93dc-2f17ae13a4a9',
        description: 'ID of the Column to which the belongs Task',
    }),
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], Task.prototype, "columnId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        example: [
            {
                filename: 'foto.jpg',
                fileSize: 6105000,
            },
        ],
        description: 'Array of files associated with the task',
    }),
    (0, typeorm_1.OneToMany)(() => files_entity_1.File, (file) => file.task, { onDelete: 'CASCADE', onUpdate: 'CASCADE' }),
    __metadata("design:type", Array)
], Task.prototype, "files", void 0);
Task = __decorate([
    (0, typeorm_1.Entity)('tasks')
], Task);
exports.Task = Task;
