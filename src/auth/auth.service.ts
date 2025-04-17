import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { MailService } from '../mail/mail.service';
import { HttpException, HttpStatus } from '@nestjs/common';

interface DecodedToken {
  email: string;
  iat: number;
  exp: number;
}
@Injectable()
export class AuthService {
  constructor(
    @InjectModel('User') private userModel: Model<User>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
  ) {}

  async signUp(signUpDto: SignUpDto): Promise<{ message: string }> {
    const { email, password, name } = signUpDto;

    const userExists = await this.userModel.findOne({ email });
    if (userExists) {
      throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);
    }
    if (password.length < 6) {
      throw new HttpException(
        'Password must be at least 6 characters long',
        HttpStatus.BAD_REQUEST,
      );
    }

    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*]).{6,}$/;
    if (!passwordRegex.test(password)) {
      throw new HttpException(
        'Password must contain at least one number, one letter, and one special character',
        HttpStatus.BAD_REQUEST,
      );
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new this.userModel({
      email,
      password: hashedPassword,
      salt,
      name,
      verificationToken: this.createVerificationToken(email),
    });
    await newUser.save();
    await this.mailService.sendVerificationEmail(
      email,
      newUser.verificationToken,
    );

    return {
      message:
        'Signup successful. Please check your email to verify your account.',
    };
  }
  createVerificationToken(email: string): string {
    return jwt.sign({ email }, this.configService.get<string>('JWT_SECRET'), {
      expiresIn: '1d',
    });
  }
  async verifyEmail(token: string): Promise<void> {
    try {
      token = token.trim();
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      console.log('JWT Secret:', jwtSecret);

      const decoded = this.jwtService.verify(token, {
        secret: jwtSecret,
      }) as DecodedToken;

      if (!decoded?.email) {
        throw new HttpException(
          'Token is missing email',
          HttpStatus.BAD_REQUEST,
        );
      }

      const email = decoded.email.toLowerCase();
      console.log('Decoded email:', email);

      const user = await this.userModel.findOne({ email });
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      user.isVerified = true;
      await user.save();
    } catch (error) {
      console.error('Error verifying token:', error);

      if (error instanceof jwt.TokenExpiredError) {
        throw new HttpException('Token has expired', HttpStatus.BAD_REQUEST);
      }

      throw new HttpException(
        'Invalid or expired token',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async login(
    loginDto: LoginDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new HttpException(
        'Invalid email or password',
        HttpStatus.BAD_REQUEST,
      );
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new HttpException(
        'Invalid email or password',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!user.isVerified) {
      throw new HttpException('Email not verified', HttpStatus.FORBIDDEN);
    }


    const accessToken = this.createAccessToken(user);
    const refreshToken = this.createRefreshToken(user);

    const updatedUser = await this.userModel.updateOne(
      { email: user.email },
      {
        $set: {
          lastLogin: new Date(),
          refreshToken: refreshToken,
        },
      },
    );

    if (updatedUser.modifiedCount === 0) {
      throw new HttpException(
        'Error encountered, please try again',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    return { accessToken, refreshToken };
  }

  createAccessToken(user: User): string {
    const payload: JwtPayload = { email: user.email, sub: user._id.toString() };
    const expiresIn = this.configService.get<string>('JWT_EXPIRES') || '1h';
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn,
    });
  }

  createRefreshToken(user: User): string {
    const refreshToken = this.jwtService.sign(
      { email: user.email },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES'),
      },
    );

    user.refreshToken = refreshToken;
    user.refreshTokenExpiry = new Date(Date.now() + 3600 * 1000 * 24);
    user.save();

    return refreshToken;
  }

  async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ accessToken: string }> {
    try {
      const decoded = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      const user = await this.userModel.findOne({ email: decoded.email });

      if (!user || user.refreshToken !== refreshToken) {
        throw new HttpException(
          'Invalid refresh token',
          HttpStatus.UNAUTHORIZED,
        );
      }

      const accessToken = this.createAccessToken(user);
      return { accessToken };
    } catch (error) {
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
    }
  }
}
