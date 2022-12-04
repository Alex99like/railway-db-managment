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
exports.BoardsService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const boards_entity_1 = require("./boards.entity");
let BoardsService = class BoardsService {
    constructor(boardsRepository) {
        this.boardsRepository = boardsRepository;
    }
    async isExist(id) {
        const resp = await this.boardsRepository.findOne({ where: { id } });
        if (!resp) {
            throw new common_1.HttpException('Board was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        return !!resp;
    }
    async getAll() {
        const resp = await this.boardsRepository.find();
        return resp;
    }
    async getById(id) {
        const board = await this.boardsRepository
            .createQueryBuilder('boards')
            .where({ id })
            .select([
            'boards.id',
            'boards.title',
            'boards.description',
            'columns.id',
            'columns.title',
            'columns.order',
            'tasks.id',
            'tasks.title',
            'tasks.order',
            'tasks.description',
            'tasks.userId',
            'files.filename',
            'files.fileSize',
        ])
            .leftJoin('boards.columns', 'columns')
            .leftJoin('columns.tasks', 'tasks')
            .leftJoin('tasks.files', 'files')
            .getOne();
        if (!board) {
            throw new common_1.HttpException('Board was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        return board;
    }
    async create(boardDto) {
        const board = new boards_entity_1.Board();
        board.title = boardDto.title;
        board.description = boardDto.description;
        const modelBoard = await this.boardsRepository.save(board);
        return modelBoard;
    }
    async remove(id) {
        const board = (await this.boardsRepository.findOne({ where: { id } }));
        if (!board) {
            throw new common_1.HttpException('Board was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        await board.remove();
    }
    async update(id, body) {
        const board = (await this.boardsRepository.findOne({ where: { id } }));
        if (!board) {
            throw new common_1.HttpException('Board was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        board.title = body.title;
        board.description = body.description;
        const data = await board.save();
        return data;
    }
};
BoardsService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(boards_entity_1.Board)),
    __metadata("design:paramtypes", [typeorm_2.Repository])
], BoardsService);
exports.BoardsService = BoardsService;
