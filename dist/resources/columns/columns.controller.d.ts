import { CreateColumnDto } from './dto/create-column.dto';
import { UpdateColumnDto } from './dto/update-column.dto';
import { ColumnsService } from './columns.service';
import { IColumn } from './columns.entity';
export declare class ColumnsController {
    private readonly columnService;
    constructor(columnService: ColumnsService);
    getAll(boardId: UUIDType): Promise<IColumn[]>;
    getOne(boardId: UUIDType, columnId: UUIDType): Promise<IColumn>;
    create(boardId: UUIDType, createColumnDto: CreateColumnDto): Promise<IColumn>;
    remove(boardId: UUIDType, columnId: UUIDType): Promise<void>;
    update(boardId: UUIDType, columnId: UUIDType, updateColumnDto: UpdateColumnDto): Promise<IColumn>;
}
