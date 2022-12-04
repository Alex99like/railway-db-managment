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
exports.LogsController = void 0;
const path_1 = require("path");
const fs_1 = require("fs");
const common_1 = require("@nestjs/common");
let LogsController = class LogsController {
    getErrors() {
        const filepath = (0, path_1.join)(process.cwd(), `/logs/error.log`);
        if ((0, fs_1.existsSync)(filepath)) {
            const stream = (0, fs_1.createReadStream)(filepath);
            return new common_1.StreamableFile(stream);
        }
        throw new common_1.HttpException('File was not founded!', common_1.HttpStatus.NOT_FOUND);
    }
    getInfo() {
        const filepath = (0, path_1.join)(process.cwd(), `/logs/info.log`);
        if ((0, fs_1.existsSync)(filepath)) {
            const stream = (0, fs_1.createReadStream)(filepath);
            return new common_1.StreamableFile(stream);
        }
        throw new common_1.HttpException('File was not founded!', common_1.HttpStatus.NOT_FOUND);
    }
};
__decorate([
    (0, common_1.Get)('/error'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", common_1.StreamableFile)
], LogsController.prototype, "getErrors", null);
__decorate([
    (0, common_1.Get)('/info'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", common_1.StreamableFile)
], LogsController.prototype, "getInfo", null);
LogsController = __decorate([
    (0, common_1.Controller)('/logs')
], LogsController);
exports.LogsController = LogsController;
