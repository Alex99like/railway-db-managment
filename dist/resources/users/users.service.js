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
exports.UsersService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const users_entity_1 = require("./users.entity");
const genHashPassword_1 = require("../../helpers/genHashPassword");
let UsersService = class UsersService {
    constructor(usersRepository) {
        this.usersRepository = usersRepository;
    }
    async getAll() {
        const resp = await this.usersRepository.find({ select: ['id', 'name', 'login'] });
        return resp;
    }
    async getById(id) {
        const user = await this.usersRepository.findOne({ select: ['id', 'name', 'login'], where: { id } });
        if (!user) {
            throw new common_1.HttpException('User was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        return user;
    }
    async create(userDto) {
        try {
            const { name, login, password } = userDto;
            const hash = await (0, genHashPassword_1.genHashPassword)(password);
            const modelUser = await this.usersRepository.create({ name, login, password: hash }).save();
            const token = jsonwebtoken_1.default.sign({ userId: modelUser.id, login: modelUser.login }, process.env.JWT_SECRET_KEY);
            return { id: modelUser.id, name: modelUser.name, login: modelUser.login, token };
        }
        catch (e) {
            throw new common_1.HttpException('User login already exists!', common_1.HttpStatus.CONFLICT);
        }
    }
    async remove(id) {
        const user = (await this.usersRepository.findOne({ where: { id } }));
        if (!user) {
            throw new common_1.HttpException('User was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        await user.remove();
    }
    async update(id, body) {
        const user = (await this.usersRepository.findOne({ where: { id } }));
        if (!user) {
            throw new common_1.HttpException('User was not founded!', common_1.HttpStatus.NOT_FOUND);
        }
        const password = await (0, genHashPassword_1.genHashPassword)(body.password);
        user.name = body.name;
        user.login = body.login;
        user.password = password;
        const data = await user.save();
        return { id: data.id, name: data.name, login: data.login };
    }
};
UsersService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(users_entity_1.User)),
    __metadata("design:paramtypes", [typeorm_2.Repository])
], UsersService);
exports.UsersService = UsersService;
