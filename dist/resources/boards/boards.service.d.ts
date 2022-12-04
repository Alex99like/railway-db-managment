import { Repository } from 'typeorm';
import { CreateBoardDto } from './dto/create-board.dto';
import { UpdateBoardDto } from './dto/update-board.dto';
import { Board, IBoard } from './boards.entity';
export declare class BoardsService {
    private boardsRepository;
    constructor(boardsRepository: Repository<Board>);
    isExist(id: UUIDType): Promise<boolean>;
    getAll(): Promise<IBoard[]>;
    getById(id: UUIDType): Promise<IBoard>;
    create(boardDto: CreateBoardDto): Promise<IBoard>;
    remove(id: UUIDType): Promise<void>;
    update(id: UUIDType, body: UpdateBoardDto): Promise<IBoard>;
}
