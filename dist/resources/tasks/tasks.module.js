"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TasksModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const auth_module_1 = require("../auth/auth.module");
const tasks_entity_1 = require("./tasks.entity");
const tasks_service_1 = require("./tasks.service");
const tasks_controller_1 = require("./tasks.controller");
const boards_module_1 = require("../boards/boards.module");
const columns_module_1 = require("../columns/columns.module");
const users_module_1 = require("../users/users.module");
let TasksModule = class TasksModule {
};
TasksModule = __decorate([
    (0, common_1.Module)({
        providers: [tasks_service_1.TasksService],
        controllers: [tasks_controller_1.TasksController],
        imports: [auth_module_1.AuthModule, boards_module_1.BoardsModule, columns_module_1.ColumnsModule, users_module_1.UsersModule, typeorm_1.TypeOrmModule.forFeature([tasks_entity_1.Task])],
    })
], TasksModule);
exports.TasksModule = TasksModule;
