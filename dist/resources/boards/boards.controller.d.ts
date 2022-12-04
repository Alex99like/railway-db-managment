import { CreateBoardDto } from './dto/create-board.dto';
import { UpdateBoardDto } from './dto/update-board.dto';
import { BoardsService } from './boards.service';
import { IBoard } from './boards.entity';
export declare class BoardsController {
    private readonly boardService;
    constructor(boardService: BoardsService);
    getAll(): Promise<IBoard[]>;
    getOne(id: UUIDType): Promise<IBoard>;
    create(createBoardDto: CreateBoardDto): Promise<IBoard>;
    remove(id: UUIDType): Promise<void>;
    update(id: UUIDType, updateBoardDto: UpdateBoardDto): Promise<IBoard>;
}
