import { Schema, Document, Types } from 'mongoose';

export interface Note extends Document {
  user: Types.ObjectId;
  note: string;
  pinned?: boolean;
  tags?: string[];
  createdAt: Date;
  updatedAt: Date;
}

export const NoteSchema = new Schema<Note>(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    note: { type: String, required: true },
    pinned: { type: Boolean, default: false },
    tags: [{ type: String }],
  },
  {
    timestamps: true,
  },
);
