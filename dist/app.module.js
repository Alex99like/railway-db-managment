"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const config_1 = require("@nestjs/config");
const app_controller_1 = require("./app.controller");
const logger_module_1 = require("./logger/logger.module");
const users_module_1 = require("./resources/users/users.module");
const boards_module_1 = require("./resources/boards/boards.module");
const tasks_module_1 = require("./resources/tasks/tasks.module");
const columns_module_1 = require("./resources/columns/columns.module");
const files_module_1 = require("./resources/file/files.module");
const logs_module_1 = require("./resources/logs/logs.module");
const ormconfig_1 = __importDefault(require("./ormconfig"));
let AppModule = class AppModule {
};
AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                isGlobal: true,
                envFilePath: '.env',
            }),
            typeorm_1.TypeOrmModule.forRoot({
                ...ormconfig_1.default,
                autoLoadEntities: true,
                synchronize: true,
                entities: [`${__dirname}/resources/**/**.entity{.ts,.js}`],
                migrations: [`${__dirname}/migrations/*.ts`],
            }),
            logger_module_1.LoggerModule,
            users_module_1.UsersModule,
            boards_module_1.BoardsModule,
            columns_module_1.ColumnsModule,
            tasks_module_1.TasksModule,
            files_module_1.FileModule,
            logs_module_1.LogsModule,
        ],
        controllers: [app_controller_1.AppController],
    })
], AppModule);
exports.AppModule = AppModule;
