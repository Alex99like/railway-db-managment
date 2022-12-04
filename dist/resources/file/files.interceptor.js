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
exports.FileFastifyInterceptor = void 0;
const common_1 = require("@nestjs/common");
const fastify_multer_1 = __importDefault(require("fastify-multer"));
const files_service_1 = require("./files.service");
const multerExceptions = {
    LIMIT_PART_COUNT: 'Too many parts',
    LIMIT_FILE_SIZE: 'File too large',
    LIMIT_FILE_COUNT: 'Too many files',
    LIMIT_FIELD_KEY: 'Field name too long',
    LIMIT_FIELD_VALUE: 'Field value too long',
    LIMIT_FIELD_COUNT: 'Too many fields',
    LIMIT_UNEXPECTED_FILE: 'Unexpected field',
};
function transformException(error) {
    if (!error || error instanceof common_1.HttpException) {
        return error;
    }
    switch (error.message) {
        case multerExceptions.LIMIT_FILE_SIZE:
            return new common_1.PayloadTooLargeException(error.message);
        case multerExceptions.LIMIT_FILE_COUNT:
        case multerExceptions.LIMIT_FIELD_KEY:
        case multerExceptions.LIMIT_FIELD_VALUE:
        case multerExceptions.LIMIT_FIELD_COUNT:
        case multerExceptions.LIMIT_UNEXPECTED_FILE:
        case multerExceptions.LIMIT_PART_COUNT:
            return new common_1.BadRequestException(error.message);
        default:
            return new common_1.BadRequestException(error.message);
    }
}
function FileFastifyInterceptor(fieldName, localOptions) {
    let FileInterceptor = class FileInterceptor {
        constructor(fileService, options) {
            this.fileService = fileService;
            this.options = options;
        }
        async intercept(context, next) {
            const ctx = context.switchToHttp();
            const req = ctx.getRequest();
            const fileFilter = async (_, file, next) => {
                const isExistInDB = await this.fileService.checkExistFileInDB(req.body.taskId, file.originalname);
                if (isExistInDB) {
                    return next(new common_1.HttpException('File already exists!', common_1.HttpStatus.CONFLICT), false);
                }
                if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
                    return next(new common_1.HttpException('Only image files are allowed!', common_1.HttpStatus.CONFLICT), false);
                }
                next(null, true);
            };
            this.multer = fastify_multer_1.default({ ...this.options, ...localOptions, fileFilter });
            await new Promise((resolve, reject) => this.multer.single(fieldName)(req, ctx.getResponse(), (err) => {
                if (err) {
                    const error = transformException(err);
                    return reject(error);
                }
                resolve();
            }));
            return next.handle();
        }
    };
    FileInterceptor = __decorate([
        (0, common_1.Injectable)(),
        __param(1, (0, common_1.Optional)()),
        __param(1, (0, common_1.Inject)('MULTER_MODULE_OPTIONS')),
        __metadata("design:paramtypes", [files_service_1.FileService, Object])
    ], FileInterceptor);
    return FileInterceptor;
}
exports.FileFastifyInterceptor = FileFastifyInterceptor;
