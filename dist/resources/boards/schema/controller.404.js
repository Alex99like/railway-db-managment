"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    status: 404,
    schema: {
        type: 'object',
        properties: {
            statusCode: { example: 404 },
            message: { example: 'Board was not founded!' },
        },
    },
};
