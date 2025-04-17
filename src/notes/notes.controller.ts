import {
  Controller,
  Post,
  Body,
  Put,
  Delete,
  NotFoundException,
  Patch,
  Param,
  Get,
} from '@nestjs/common';
import { NotesService } from './notes.service';
import { NoteDto } from './dto/note.dto';
import { UpdateNoteDto } from './dto/update-note.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { UseGuards } from '@nestjs/common';
import { CurrentUser } from '../auth/current-user.decorator';
import { Note } from './schemas/note.schema';

@Controller('notes')
@UseGuards(JwtAuthGuard)
export class NotesController {
  constructor(private readonly notesService: NotesService) {}

  @Post()
  async createNote(
    @Body() noteDto: NoteDto,
    @CurrentUser() user: any,
  ): Promise<Note> {
    return this.notesService.createNote(noteDto, user.sub);
  }

  @Get()
  async getAllNotes(@CurrentUser() user: any): Promise<Note[]> {
    return this.notesService.getAllNotes(user.sub);
  }

  @Put(':id')
  async updateNote(
    @Param('id') id: string,
    @Body() noteDto: UpdateNoteDto,
    @CurrentUser() user: any,
  ): Promise<Note> {
    const updated = await this.notesService.updateNote(id, noteDto, user.sub);
    if (!updated)
      throw new NotFoundException('Note not found or not authorized');
    return updated;
  }

  @Delete(':id')
  async deleteNote(
    @Param('id') id: string,
    @CurrentUser() user: any,
  ): Promise<{ deleted: boolean }> {
    const result = await this.notesService.deleteNote(id, user.sub);
    if (!result.deleted)
      throw new NotFoundException('Note not found or not authorized');
    return result;
  }

  @Patch(':id/pin')
  async pinNote(
    @Param('id') id: string,
    @CurrentUser() user: any,
  ): Promise<Note> {
    const updatedNote = await this.notesService.updateNote(
      id,
      {
        pinned: true,
      },
      user.sub,
    );
    if (!updatedNote)
      throw new NotFoundException('Note not found or not authorized');
    return updatedNote;
  }

  @Patch(':id/unpin')
  async unpinNote(
    @Param('id') id: string,
    @CurrentUser() user: any,
  ): Promise<Note> {
    const updatedNote = await this.notesService.updateNote(
      id,
      {
        pinned: false,
      },
      user.sub,
    );
    if (!updatedNote)
      throw new NotFoundException('Note not found or not authorized');
    return updatedNote;
  }
}
