"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.genHashPassword = void 0;
const bcrypt = require("bcryptjs");
const genHashPassword = async (password) => {
    const salt = await bcrypt.genSalt(parseInt(process.env.SALT_SIZE, 10));
    const out = await bcrypt.hash(password, salt);
    return out;
};
exports.genHashPassword = genHashPassword;
