import { IsOptional, IsString, IsBoolean, IsArray } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateNoteDto {
  @ApiProperty({
    description: 'The note content that can be updated',
    required: false,
    example: 'Updated note text',
  })
  @IsOptional()
  @IsString()
  note?: string;

  @ApiProperty({
    description: 'Tags associated with the note',
    required: false,
    type: [String],
    example: ['tag1', 'tag2'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];
}
