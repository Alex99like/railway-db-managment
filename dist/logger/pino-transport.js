"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const pino_1 = __importDefault(require("pino"));
const { LOG_ERR_LEVEL, LOG_INFO_LEVEL } = process.env;
const transport = pino_1.default.transport({
    targets: [
        {
            level: LOG_ERR_LEVEL,
            target: 'pino/file',
            options: { destination: './logs/error.log' },
        },
        {
            level: LOG_INFO_LEVEL,
            target: 'pino/file',
            options: { destination: './logs/info.log' },
        },
    ],
});
exports.default = (0, pino_1.default)(transport);
