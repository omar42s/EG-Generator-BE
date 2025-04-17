import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as bcrypt from 'bcryptjs';
import { Document } from 'mongoose';

// User schema definition
@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true, minlength: 3 })
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true, minlength: 6 })
  password: string;

  @Prop()
  salt: string;

  // Marking lastLogin as optional
  @Prop({ required: false })
  lastLogin?: Date;


  @Prop({ required: false })
  address?: string;

  @Prop()
  refreshToken?: string;

  @Prop({ type: Date, default: Date.now }) // Setting default for refresh token expiry
  refreshTokenExpiry?: Date;

  @Prop({ default: false })
  isVerified: boolean;

  // Marking verificationToken as optional in the schema
  @Prop({ required: false }) // Make verificationToken optional here
  verificationToken?: string; // Ensure it is optional
}

// Now you can create the schema using SchemaFactory.createForClass(User)
export const UserSchema = SchemaFactory.createForClass(User);


// User interface definition
export interface User extends Document {
  email: string;
  password: string;
  salt: string;
  name: string;
  isVerified: boolean;
  verificationToken?: string;
  lastLogin?: Date;
  refreshToken?: string;
  refreshTokenExpiry?: Date;
}
