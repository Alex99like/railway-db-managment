import { SigninUserDto } from './dto/signin-user.dto';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
export declare class AuthController {
    private authService;
    private usersService;
    constructor(authService: AuthService, usersService: UsersService);
    signin(signinDto: SigninUserDto): Promise<{
        token: string;
        name: string;
        id: string;
        login: string;
    }>;
    signup(signupDto: CreateUserDto): Promise<import("../users/users.entity").IUserNoId & {
        token: string;
    }>;
}
