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
exports.LoggingInterceptor = void 0;
const common_1 = require("@nestjs/common");
const operators_1 = require("rxjs/operators");
const logger_service_1 = require("./logger.service");
let LoggingInterceptor = class LoggingInterceptor {
    constructor(logService) {
        this.logService = logService;
    }
    intercept(ctx, next) {
        const [req, res] = ctx.getArgs();
        const { method, url, query, body } = req;
        const { statusCode } = res;
        const now = Date.now();
        return next
            .handle()
            .pipe((0, operators_1.tap)(() => this.logService.log({ method, url, query, body, statusCode, responseTime: `${Date.now() - now}ms` })));
    }
};
LoggingInterceptor = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [logger_service_1.LogService])
], LoggingInterceptor);
exports.LoggingInterceptor = LoggingInterceptor;
