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
exports.Column = void 0;
const swagger_1 = require("@nestjs/swagger");
const typeorm_1 = require("typeorm");
const tasks_entity_1 = require("../tasks/tasks.entity");
const boards_entity_1 = require("../boards/boards.entity");
let Column = class Column extends typeorm_1.BaseEntity {
};
__decorate([
    (0, swagger_1.ApiProperty)({ example: '08cc10f4-1aeb-4cce-9793-9fea8313b592', description: 'ID Column' }),
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], Column.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Done', description: 'Column title' }),
    (0, typeorm_1.Column)(),
    __metadata("design:type", String)
], Column.prototype, "title", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: '1', description: 'Column order' }),
    (0, typeorm_1.Column)(),
    __metadata("design:type", Number)
], Column.prototype, "order", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => boards_entity_1.Board, (board) => board.columns, { onDelete: 'CASCADE', onUpdate: 'CASCADE' }),
    __metadata("design:type", boards_entity_1.Board)
], Column.prototype, "board", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true, select: false }),
    __metadata("design:type", Object)
], Column.prototype, "boardId", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => tasks_entity_1.Task, (task) => task.column, { onDelete: 'CASCADE', onUpdate: 'CASCADE' }),
    __metadata("design:type", Array)
], Column.prototype, "tasks", void 0);
Column = __decorate([
    (0, typeorm_1.Entity)('columns')
], Column);
exports.Column = Column;
