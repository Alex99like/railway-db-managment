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
exports.FileService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const files_entity_1 = require("./files.entity");
let FileService = class FileService {
    constructor(fileRepository) {
        this.fileRepository = fileRepository;
    }
    async checkExistFileInDB(taskId, filename) {
        const isExist = await this.fileRepository.findOne({ select: ['fileId'], where: { taskId, filename } });
        return !!isExist;
    }
    async saveFilename(filename, fileId, fileSize, taskId) {
        try {
            await this.fileRepository.create({ filename, fileId, fileSize, taskId }).save();
        }
        catch (e) {
            throw new common_1.HttpException('File already exists!', common_1.HttpStatus.CONFLICT);
        }
        return 'File uploaded!';
    }
    async findFileId(taskId, filename) {
        const modelFile = await this.fileRepository.findOne({ select: ['fileId'], where: { filename } });
        if (!modelFile) {
            throw new common_1.HttpException('File was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        return modelFile.fileId;
    }
};
FileService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(files_entity_1.File)),
    __metadata("design:paramtypes", [typeorm_2.Repository])
], FileService);
exports.FileService = FileService;
