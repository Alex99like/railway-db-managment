"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const auth_module_1 = require("../auth/auth.module");
const files_entity_1 = require("./files.entity");
const files_controller_1 = require("./files.controller");
const files_service_1 = require("./files.service");
let FileModule = class FileModule {
};
FileModule = __decorate([
    (0, common_1.Module)({
        controllers: [files_controller_1.FileController],
        providers: [files_service_1.FileService],
        imports: [auth_module_1.AuthModule, typeorm_1.TypeOrmModule.forFeature([files_entity_1.File])],
        exports: [files_service_1.FileService],
    })
], FileModule);
exports.FileModule = FileModule;
