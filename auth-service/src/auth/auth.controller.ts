import { Controller, Post, Body, UseGuards, Req, Get, Param, Ip } from '@nestjs/common'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { AuthService } from './auth.service'
import { LoginDto } from './dto/login.dto'
import { RegisterDto } from './dto/register.dto'
import { RefreshTokenDto } from './dto/refresh-token.dto'
import { ValidateTokenDto } from './dto/validate-token.dto'
import { Request } from 'express'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto, @Req() req: Request, @Ip() ip: string) {
    const userAgent = req.headers['user-agent'] || 'unknown'
    return this.authService.register(registerDto, userAgent, ip)
  }

  @Post('login')
  public async login(@Body() loginDto: LoginDto, @Req() req: Request, @Ip() ip: string) {
    const userAgent = req.headers['user-agent'] || 'Unknown'
    return this.authService.login(loginDto, userAgent, ip)
  }

  @Post('refresh')
  async refresh(@Body() refreshTokenDto: RefreshTokenDto, @Req() req: Request, @Ip() ip: string) {
    const userAgent = req.headers['user-agent'] || 'unknown'
    return this.authService.refreshTokens(refreshTokenDto.refreshToken, userAgent, ip)
  }

  @Post('logout')
  async logout(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.logout(refreshTokenDto.refreshToken)
  }

  @Post('validate')
  async validateToken(@Body() validateTokenDto: ValidateTokenDto) {
    return this.authService.validateToken(validateTokenDto.token)
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getCurrentUser(@Req() req: any) {
    return {
      userId: req.user.userId,
      email: req.user.email,
    }
  }
}
