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
exports.ColumnsController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const controller_getOne_1 = __importDefault(require("./schema/controller.getOne"));
const create_column_dto_1 = require("./dto/create-column.dto");
const update_column_dto_1 = require("./dto/update-column.dto");
const columns_service_1 = require("./columns.service");
const columns_entity_1 = require("./columns.entity");
const controller_404_1 = __importDefault(require("../boards/schema/controller.404"));
const controller_404_2 = __importDefault(require("./schema/controller.404"));
const jwt_auth_guard_1 = require("../auth/jwt-auth.guard");
let ColumnsController = class ColumnsController {
    constructor(columnService) {
        this.columnService = columnService;
    }
    getAll(boardId) {
        return this.columnService.getAll(boardId);
    }
    getOne(boardId, columnId) {
        return this.columnService.getById(boardId, columnId);
    }
    create(boardId, createColumnDto) {
        return this.columnService.create(boardId, createColumnDto);
    }
    remove(boardId, columnId) {
        return this.columnService.remove(boardId, columnId);
    }
    update(boardId, columnId, updateColumnDto) {
        return this.columnService.update(boardId, columnId, updateColumnDto);
    }
};
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Get all columns' }),
    (0, swagger_1.ApiResponse)({ status: 200, type: [columns_entity_1.Column] }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiResponse)(controller_404_2.default),
    (0, common_1.Get)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], ColumnsController.prototype, "getAll", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Get the column by id' }),
    (0, swagger_1.ApiResponse)({ status: 200, schema: controller_getOne_1.default }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiResponse)(controller_404_2.default),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, common_1.Get)(':columnId'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", Promise)
], ColumnsController.prototype, "getOne", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Create column' }),
    (0, swagger_1.ApiResponse)({ status: 201, type: columns_entity_1.Column }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiResponse)(controller_404_2.default),
    (0, common_1.Post)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.CREATED),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, create_column_dto_1.CreateColumnDto]),
    __metadata("design:returntype", Promise)
], ColumnsController.prototype, "create", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Delete column' }),
    (0, swagger_1.ApiResponse)({ status: 204 }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiResponse)(controller_404_2.default),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, common_1.Delete)(':columnId'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", Promise)
], ColumnsController.prototype, "remove", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Update column' }),
    (0, swagger_1.ApiResponse)({ status: 200, type: columns_entity_1.Column }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiResponse)(controller_404_2.default),
    (0, swagger_1.ApiParam)({ name: 'columnId', description: 'ID Column' }),
    (0, common_1.Put)(':columnId'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('boardId', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Param)('columnId', common_1.ParseUUIDPipe)),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, update_column_dto_1.UpdateColumnDto]),
    __metadata("design:returntype", Promise)
], ColumnsController.prototype, "update", null);
ColumnsController = __decorate([
    (0, swagger_1.ApiTags)('Columns'),
    (0, swagger_1.ApiBearerAuth)('token'),
    (0, common_1.Controller)('/boards/:boardId/columns'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.AuthGuard),
    __metadata("design:paramtypes", [columns_service_1.ColumnsService])
], ColumnsController);
exports.ColumnsController = ColumnsController;
