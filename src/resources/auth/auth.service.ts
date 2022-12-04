import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import jwt from 'jsonwebtoken'
import bcrypt = require('bcryptjs');

import { User } from '../users/users.entity';
import { SigninUserDto } from './dto/signin-user.dto';

@Injectable()
export class AuthService {
  constructor(@InjectRepository(User) private usersRepository: Repository<User>) {}

  async signin(body: SigninUserDto): Promise<{ token: string; name: string, id: string; login: string }> {
    const user = await this.usersRepository.findOne({ select: ['id', 'password', 'login'], where: { login: body.login } });
    if (!user) {
      throw new HttpException('User was not founded!', HttpStatus.FORBIDDEN);
    }

    const match = await bcrypt.compare(body.password, user.password);
    if (!match) {
      throw new HttpException('User was not founded!', HttpStatus.FORBIDDEN);
    }

    const token = jwt.sign({ userId: user.id, login: body.login }, process.env.JWT_SECRET_KEY as string);
    return { token, name: user.login, id: user.id, login: user.login };
  }
}
