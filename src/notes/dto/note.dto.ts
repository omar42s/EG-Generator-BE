import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsBoolean,
  IsArray,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class NoteDto {
  @ApiProperty({
    description: 'The content of the note',
    example: 'This is a new note',
  })
  @IsString()
  @IsNotEmpty()
  note: string;

  @ApiProperty({
    description: 'Indicates whether the note is pinned',
    required: false,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  pinned?: boolean;

  @ApiProperty({
    description: 'List of tags associated with the note',
    required: false,
    type: [String],
    example: ['tag1', 'tag2'],
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  tags?: string[];
}
