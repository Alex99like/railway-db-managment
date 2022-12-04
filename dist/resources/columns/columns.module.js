"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ColumnsModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const auth_module_1 = require("../auth/auth.module");
const columns_entity_1 = require("./columns.entity");
const columns_service_1 = require("./columns.service");
const columns_controller_1 = require("./columns.controller");
const boards_module_1 = require("../boards/boards.module");
let ColumnsModule = class ColumnsModule {
};
ColumnsModule = __decorate([
    (0, common_1.Module)({
        providers: [columns_service_1.ColumnsService],
        controllers: [columns_controller_1.ColumnsController],
        imports: [auth_module_1.AuthModule, boards_module_1.BoardsModule, typeorm_1.TypeOrmModule.forFeature([columns_entity_1.Column])],
        exports: [columns_service_1.ColumnsService],
    })
], ColumnsModule);
exports.ColumnsModule = ColumnsModule;
