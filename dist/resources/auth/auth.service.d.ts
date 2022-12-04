import { Repository } from 'typeorm';
import { User } from '../users/users.entity';
import { SigninUserDto } from './dto/signin-user.dto';
export declare class AuthService {
    private usersRepository;
    constructor(usersRepository: Repository<User>);
    signin(body: SigninUserDto): Promise<{
        token: string;
        name: string;
        id: string;
        login: string;
    }>;
}
