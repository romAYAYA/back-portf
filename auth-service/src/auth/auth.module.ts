import { Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { PassportModule } from '@nestjs/passport'
import { TypeOrmModule } from '@nestjs/typeorm'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { AuthUser } from './entities/auth-user.entity'
import { JwtStrategy } from './strategies/jwt.strategy'
import { RefreshJwtStrategy } from './strategies/refresh-jwt.strategy'
import { RedisModule } from '../redis/redis.module'

@Module({
  imports: [TypeOrmModule.forFeature([AuthUser]), PassportModule, JwtModule.register({}), RedisModule],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, RefreshJwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
