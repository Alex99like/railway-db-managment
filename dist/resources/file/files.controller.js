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
exports.FileController = void 0;
const uuid_1 = require("uuid");
const common_1 = require("@nestjs/common");
const fs_1 = require("fs");
const path_1 = require("path");
const swagger_1 = require("@nestjs/swagger");
const multer_1 = require("multer");
const jwt_auth_guard_1 = require("../auth/jwt-auth.guard");
const files_interceptor_1 = require("./files.interceptor");
const files_service_1 = require("./files.service");
const save_file_dto_1 = require("./dto/save-file.dto");
let FileController = class FileController {
    constructor(fileService) {
        this.fileService = fileService;
    }
    upload(file, body) {
        const { taskId } = body;
        const { originalname, filename, size } = file;
        return this.fileService.saveFilename(originalname, filename, size, taskId);
    }
    async download(reqTaskId, reqFilename) {
        const fileId = await this.fileService.findFileId(reqTaskId, reqFilename);
        const filepath = (0, path_1.join)(process.cwd(), `/uploads/${fileId}`);
        if ((0, fs_1.existsSync)(filepath)) {
            const stream = (0, fs_1.createReadStream)(filepath);
            return new common_1.StreamableFile(stream);
        }
        throw new common_1.HttpException('File was not founded!', common_1.HttpStatus.NOT_FOUND);
    }
};
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Upload file' }),
    (0, swagger_1.ApiConsumes)('multipart/form-data'),
    (0, swagger_1.ApiBody)({
        schema: {
            type: 'object',
            properties: {
                taskId: {
                    type: 'string',
                },
                file: {
                    type: 'string',
                    format: 'binary',
                },
            },
        },
    }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'File uploaded' }),
    (0, common_1.Post)('/file'),
    (0, common_1.UseInterceptors)((0, files_interceptor_1.FileFastifyInterceptor)('file', {
        storage: (0, multer_1.diskStorage)({
            destination: './uploads',
            filename: (req, file, cb) => cb(null, (0, uuid_1.v4)()),
        }),
    })),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.UploadedFile)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, save_file_dto_1.SaveFileDto]),
    __metadata("design:returntype", Promise)
], FileController.prototype, "upload", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Download file' }),
    (0, swagger_1.ApiResponse)({ status: 200 }),
    (0, swagger_1.ApiParam)({ name: 'taskid', description: 'Task id associated with the file' }),
    (0, swagger_1.ApiParam)({ name: 'filename', description: 'Filename to download' }),
    (0, common_1.Get)('/file/:taskid/:filename'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('taskid')),
    __param(1, (0, common_1.Param)('filename')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", Promise)
], FileController.prototype, "download", null);
FileController = __decorate([
    (0, swagger_1.ApiTags)('Upload/Download file'),
    (0, swagger_1.ApiBearerAuth)('token'),
    (0, common_1.Controller)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.AuthGuard),
    __metadata("design:paramtypes", [files_service_1.FileService])
], FileController);
exports.FileController = FileController;
