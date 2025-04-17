import {
  Query,
  Res,
  Controller,
  Post,
  Body,
  Get,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LoginDto } from './dto/login.dto';
import * as jwt from 'jsonwebtoken';
import { Response } from 'express';

import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  @Post('/signup')
  @ApiOperation({ summary: 'User signup' })
  @ApiBody({ type: SignUpDto })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 400, description: 'Validation failed or user exists' })
  signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @Post('/login')
  @ApiOperation({ summary: 'User login' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Login successful, returns tokens' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('refresh-token')
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        refreshToken: { type: 'string', example: 'your-refresh-token' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'New access token issued' })
  @ApiResponse({ status: 400, description: 'Invalid or expired refresh token' })
  async refreshAccessToken(@Body() refreshTokenDto: { refreshToken: string }) {
    const { refreshToken } = refreshTokenDto;
    return this.authService.refreshAccessToken(refreshToken);
  }

  @Get('verify')
  @ApiOperation({ summary: 'Verify email via token' })
  @ApiQuery({
    name: 'token',
    required: true,
    description: 'Email verification token',
  })
  @ApiResponse({ status: 302, description: 'Redirects to frontend login page' })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired verification token',
  })
  async verifyEmail(@Query('token') token: string, @Res() res: Response) {
    try {
      await this.authService.verifyEmail(token);
      const baseUrl = this.configService.get<string>('FRONTEND_URL');
      const redirectUrl = `${baseUrl}/auth/login`;
      return res.redirect(redirectUrl);
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new HttpException('Token has expired', HttpStatus.BAD_REQUEST);
      }

      throw new HttpException(
        'Invalid or expired verification token',
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
