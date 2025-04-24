import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Note } from './schemas/note.schema';
import { NoteDto } from './dto/note.dto';

@Injectable()
export class NotesService {
  constructor(@InjectModel('Note') private noteModel: Model<Note>) {}

  async createNote(noteDto: NoteDto, userId: string): Promise<Note> {
    const newNote = new this.noteModel({
      ...noteDto,
      user: userId,
    });
    return newNote.save();
  }

  async getAllNotes(userId: string): Promise<Note[]> {
    return this.noteModel.find({ user: userId }).sort({ pinned: -1 }).exec();
  }

  async getNoteById(noteId: string, userId: string): Promise<Note> {
    return this.noteModel.findOne({ _id: noteId, user: userId }).exec();
  }

  async updateNote(
    noteId: string,
    updateData: Partial<Note>,
    userId: string,
  ): Promise<Note | null> {
    return this.noteModel
      .findOneAndUpdate(
        { _id: noteId, user: userId },
        { $set: updateData },
        { new: true },
      )
      .exec();
  }

  async deleteNote(
    noteId: string,
    userId: string,
  ): Promise<{ deleted: boolean }> {
    const result = await this.noteModel
      .deleteOne({ _id: noteId, user: userId })
      .exec();
    return { deleted: result.deletedCount > 0 };
  }

  async pinNote(noteId: string, userId: string): Promise<Note | null> {
    await this.noteModel
      .updateOne({ user: userId, pinned: true }, { pinned: false })
      .exec();

    return this.noteModel
      .findOneAndUpdate(
        { _id: noteId, user: userId },
        { pinned: true },
        { new: true },
      )
      .exec();
  }

  async unpinNote(noteId: string, userId: string): Promise<Note | null> {
    return this.noteModel
      .findOneAndUpdate(
        { _id: noteId, user: userId },
        { pinned: false },
        { new: true },
      )
      .exec();
  }
}
