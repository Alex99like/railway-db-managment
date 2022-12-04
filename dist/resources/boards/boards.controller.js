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
exports.BoardsController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const create_board_dto_1 = require("./dto/create-board.dto");
const update_board_dto_1 = require("./dto/update-board.dto");
const boards_service_1 = require("./boards.service");
const boards_entity_1 = require("./boards.entity");
const controller_getOne_1 = __importDefault(require("./schema/controller.getOne"));
const controller_404_1 = __importDefault(require("./schema/controller.404"));
const jwt_auth_guard_1 = require("../auth/jwt-auth.guard");
let BoardsController = class BoardsController {
    constructor(boardService) {
        this.boardService = boardService;
    }
    getAll() {
        return this.boardService.getAll();
    }
    getOne(id) {
        return this.boardService.getById(id);
    }
    create(createBoardDto) {
        return this.boardService.create(createBoardDto);
    }
    remove(id) {
        return this.boardService.remove(id);
    }
    update(id, updateBoardDto) {
        return this.boardService.update(id, updateBoardDto);
    }
};
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Get all boards' }),
    (0, swagger_1.ApiResponse)({ status: 200, type: [boards_entity_1.Board] }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, common_1.Get)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], BoardsController.prototype, "getAll", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Get the board by id' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        schema: controller_getOne_1.default,
    }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'ID Board' }),
    (0, common_1.Get)(':id'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], BoardsController.prototype, "getOne", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Create board' }),
    (0, swagger_1.ApiResponse)({ status: 201, type: boards_entity_1.Board }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, common_1.Post)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.CREATED),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [create_board_dto_1.CreateBoardDto]),
    __metadata("design:returntype", Promise)
], BoardsController.prototype, "create", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Delete board' }),
    (0, swagger_1.ApiResponse)({ status: 204 }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'ID Board' }),
    (0, common_1.Delete)(':id'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], BoardsController.prototype, "remove", null);
__decorate([
    (0, swagger_1.ApiOperation)({ summary: 'Update board' }),
    (0, swagger_1.ApiResponse)({ status: 200, type: boards_entity_1.Board }),
    (0, swagger_1.ApiResponse)(controller_404_1.default),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'ID Board' }),
    (0, common_1.Put)(':id'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, update_board_dto_1.UpdateBoardDto]),
    __metadata("design:returntype", Promise)
], BoardsController.prototype, "update", null);
BoardsController = __decorate([
    (0, swagger_1.ApiTags)('Boards'),
    (0, swagger_1.ApiBearerAuth)('token'),
    (0, common_1.Controller)('boards'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.AuthGuard),
    __metadata("design:paramtypes", [boards_service_1.BoardsService])
], BoardsController);
exports.BoardsController = BoardsController;
