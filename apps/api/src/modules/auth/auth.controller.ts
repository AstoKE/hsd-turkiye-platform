import {
  Body,
  Controller,
  Get,
  Headers,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('refresh')
  refresh(@Headers('authorization') authorization?: string) {
    const refreshToken = authorization?.replace(/^Bearer\s+/i, '');

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    return this.authService.refresh(refreshToken);
  }

  @Post('logout')
  logout(@Headers('authorization') authorization?: string) {
    const refreshToken = authorization?.replace(/^Bearer\s+/i, '');

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    return this.authService.logout(refreshToken);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('me')
  me(@Req() req: Request & { user: { userId: string } }) {
    return this.authService.me(req.user.userId);
  }
}