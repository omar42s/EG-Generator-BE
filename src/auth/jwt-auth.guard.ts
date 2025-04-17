import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
  CanActivate,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AuthService } from './auth.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const accessToken = this.extractAccessToken(request);

    if (!accessToken) {
      throw new UnauthorizedException('Access token is missing');
    }

    try {
      const decoded = await this.jwtService.verifyAsync(accessToken);
      console.log('Decoded Token:', decoded);
      request.user = decoded;
      return true;
    } catch (error) {
      console.log('JWT Verification Error:', error);
      if (error.name === 'TokenExpiredError') {
        const refreshToken = this.extractRefreshToken(request);
        if (!refreshToken) {
          throw new UnauthorizedException('Refresh token is missing');
        }
        const newAccessToken = await this.authService.refreshAccessToken(
          refreshToken,
        );
        request.user = newAccessToken;
        return true;
      }
      throw new UnauthorizedException('Invalid access token');
    }
  }

  private extractAccessToken(request: Request): string | undefined {
    const authorizationHeader = request.headers['authorization'];
    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
      return authorizationHeader.substring(7, authorizationHeader.length);
    }
    return undefined;
  }

  private extractRefreshToken(request: Request): string | undefined {
    return request.body.refreshToken || request.headers['x-refresh-token'];
  }
}
