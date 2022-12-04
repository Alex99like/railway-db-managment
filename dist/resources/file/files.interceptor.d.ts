import { NestInterceptor, Type } from '@nestjs/common';
import { Options } from 'multer';
export declare function FileFastifyInterceptor(fieldName: string, localOptions?: Options): Type<NestInterceptor>;
