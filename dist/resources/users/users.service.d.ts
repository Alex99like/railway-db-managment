import { Repository } from 'typeorm';
import { User, IUserNoId, IUser } from './users.entity';
export declare class UsersService {
    private usersRepository;
    constructor(usersRepository: Repository<User>);
    getAll(): Promise<IUserNoId[]>;
    getById(id: UUIDType): Promise<IUserNoId>;
    create(userDto: IUser): Promise<IUserNoId & {
        token: string;
    }>;
    remove(id: UUIDType): Promise<void>;
    update(id: UUIDType, body: IUser): Promise<IUserNoId>;
}
