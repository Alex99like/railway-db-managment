import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';
import { IUserNoId } from './users.entity';
export declare class UsersController {
    private readonly userService;
    constructor(userService: UsersService);
    getAll(): Promise<IUserNoId[]>;
    getOne(id: UUIDType): Promise<IUserNoId>;
    remove(id: UUIDType): Promise<void>;
    update(id: UUIDType, updateUserDto: UpdateUserDto): Promise<IUserNoId>;
}
