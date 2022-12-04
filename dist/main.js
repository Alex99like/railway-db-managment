"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const platform_fastify_1 = require("@nestjs/platform-fastify");
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const swagger_1 = require("@nestjs/swagger");
const fastify_file_interceptor_1 = require("fastify-file-interceptor");
const app_module_1 = require("./app.module");
const all_exceptions_filter_1 = require("./exceptions/all-exceptions.filter");
const logger_service_1 = require("./logger/logger.service");
const logging_interceptor_1 = require("./logger/logging.interceptor");
const USE_FASTIFY = JSON.parse(process.env.USE_FASTIFY);
const LOG_CONSOLE = JSON.parse(process.env.LOG_CONSOLE);
async function _initApp(isFastify, isLogger) {
    if (isFastify) {
        const app = await core_1.NestFactory.create(app_module_1.AppModule, new platform_fastify_1.FastifyAdapter({ logger: isLogger }), {
            cors: true,
        });
        app.register(fastify_file_interceptor_1.contentParser);
        return app;
    }
    const app = await core_1.NestFactory.create(app_module_1.AppModule, { logger: isLogger ? ['verbose'] : false });
    return app;
}
async function bootstrap() {
    const app = await _initApp(USE_FASTIFY, LOG_CONSOLE);
    const logger = app.get(logger_service_1.LogService);
    app.useLogger(logger);
    const { httpAdapter } = app.get(core_1.HttpAdapterHost);
    app.useGlobalFilters(new all_exceptions_filter_1.AllExceptionsFilter(httpAdapter, logger));
    app.useGlobalInterceptors(new logging_interceptor_1.LoggingInterceptor(logger));
    app.useGlobalPipes(new common_1.ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
    const PORT = app.get(config_1.ConfigService).get('PORT');
    const config = new swagger_1.DocumentBuilder()
        .setTitle('Kanban service')
        .setDescription('The kanban service API description')
        .setVersion('1.0')
        .addBearerAuth({
        in: 'header',
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'JWT',
        description: 'Enter JWT token',
    }, 'token')
        .build();
    const document = swagger_1.SwaggerModule.createDocument(app, config);
    swagger_1.SwaggerModule.setup('/docs', app, document);
    await app.listen(4200, '0.0.0.0');
    process.on('unhandledRejection', () => {
        logger.error({ msg: 'unhandledRejection event' });
        process.exit(1);
    });
}
bootstrap();
