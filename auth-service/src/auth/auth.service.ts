import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { ConfigService } from '@nestjs/config'
import { InjectRepository } from '@nestjs/typeorm'
import { InjectRedis } from '@nestjs-modules/ioredis'
import { Repository } from 'typeorm'
import Redis from 'ioredis'
import { AuthUser } from './entities/auth-user.entity'
import { Role } from './entities/role.entity'
import { LoginDto } from './dto/login.dto'
import { RegisterDto } from './dto/register.dto'
import { JwtPayload } from './interfaces/jwt-payload.interface'
import { RefreshTokenData } from './interfaces/refresh-token-data.interface'
import * as crypto from 'crypto'
import * as bcrypt from 'bcrypt'

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(AuthUser)
    private authUserRepository: Repository<AuthUser>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRedis()
    private readonly redis: Redis,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  public async register(registerDto: RegisterDto, userAgent: string, ipAddress: string) {
    const emailExists = await this.authUserRepository.findOne({ where: { email: registerDto.email } })
    if (emailExists) {
      throw new ConflictException('Email already exists')
    }

    let defaultRole = await this.roleRepository.findOne({ where: { name: 'user' } })
    if (!defaultRole) {
      defaultRole = this.roleRepository.create({ name: 'user' })
      await this.roleRepository.save(defaultRole)
    }

    const usernameExists = await this.authUserRepository.findOne({ where: { username: registerDto.username } })
    if (usernameExists) {
      throw new ConflictException('Username already exists')
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10)

    const user = this.authUserRepository.create({
      email: registerDto.email,
      username: registerDto.username,
      password: hashedPassword,
      roles: [defaultRole],
    })

    const savedUser = await this.authUserRepository.save(user)

    const tokens = await this.generateTokens(
      savedUser.id,
      savedUser.email,
      savedUser.username,
      [defaultRole.name],
      userAgent,
      ipAddress,
    )

    return {
      user: { id: savedUser.id, email: savedUser.email, username: savedUser.username },
      ...tokens,
    }
  }

  public async login(loginDto: LoginDto, userAgent: string, ipAddress: string) {
    const user = await this.authUserRepository.findOne({
      where: [{ email: loginDto.email }, { username: loginDto.username }],
      relations: ['roles'],
    })
    if (!user) {
      throw new UnauthorizedException('Invalid credentials')
    }
    const roles = user.roles.map((role) => role.name)

    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password)
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials')
    }

    const tokens = await this.generateTokens(user.id, user.email, user.username, roles, userAgent, ipAddress)

    return {
      user: { id: user.id, email: user.email, username: user.username },
      ...tokens,
    }
  }

  public async refreshTokens(refreshToken: string, userAgent: string, ipAddress: string) {
    const hmacKey = this.configService.get('REFRESH_TOKEN_HMAC_KEY')
    const tokenHash = crypto.createHmac('sha256', hmacKey).update(refreshToken).digest('hex')

    const redisKey = `refresh:${tokenHash}`
    const data = await this.redis.get(redisKey)
    if (!data) {
      throw new UnauthorizedException('Invalid refresh token')
    }

    const tokenData: RefreshTokenData = JSON.parse(data)

    const user = await this.authUserRepository.findOne({
      where: { id: tokenData.userId, isActive: true },
      relations: ['roles'],
    })
    if (!user) {
      throw new UnauthorizedException('User not found')
    }
    const roles = user.roles.map((role) => role.name)

    await this.redis.del(redisKey)
    await this.removeFromUserSessions(tokenData.userId, tokenHash)

    return this.generateTokens(tokenData.userId, tokenData.email, tokenData.username, roles, userAgent, ipAddress)
  }

  public async logout(refreshToken: string) {
    const hmacKey = this.configService.get('REFRESH_TOKEN_HMAC_KEY')
    const tokenHash = crypto.createHmac('sha256', hmacKey).update(refreshToken).digest('hex')

    const redisKey = `refresh:${tokenHash}`
    const data = await this.redis.get(redisKey)

    if (data) {
      const tokenData: RefreshTokenData = JSON.parse(data)
      await this.redis.del(redisKey)
      await this.removeFromUserSessions(tokenData.userId, tokenHash)
    }

    return { message: 'Logged out successfully' }
  }

  public async validateToken(token: string): Promise<JwtPayload> {
    try {
      const payload = this.jwtService.verify(token, { secret: this.configService.get('JWT_SECRET') })

      const user = await this.authUserRepository.findOne({
        where: { id: payload.sub, isActive: true },
        relations: ['roles'],
      })
      if (!user) {
        throw new UnauthorizedException('User not found')
      }
      const roles = user.roles.map((role) => role.name)

      return {
        sub: payload.sub,
        email: payload.email,
        roles,
      }
    } catch (error) {
      throw new UnauthorizedException('Invalid token')
    }
  }

  private async generateTokens(
    userId: string,
    email: string,
    username: string,
    roles: string[],
    userAgent: string,
    ipAddress: string,
  ) {
    const payload: JwtPayload = { email, sub: userId, roles }

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: this.configService.get('JWT_EXPIRATION_TIME', '15m'),
    })

    const refreshToken = crypto.randomBytes(64).toString('hex')

    const hmacKey = this.configService.get('REFRESH_TOKEN_HMAC_KEY')
    const tokenHash = crypto.createHmac('sha256', hmacKey).update(refreshToken).digest('hex')

    const tokenData: RefreshTokenData = {
      userId,
      email,
      username,
      roles,
      userAgent,
      ipAddress,
      createdAt: Date.now(),
    }

    const redisKey = `refresh:${tokenHash}`
    const ttl = 7 * 24 * 60 * 60

    await this.redis.setex(redisKey, ttl, JSON.stringify(tokenData))
    await this.addToUserSessions(userId, tokenHash, ttl)

    return { accessToken, refreshToken }
  }

  private async addToUserSessions(userId: string, tokenHash: string, ttl: number) {
    const sessionsKey = `user_sessions:${userId}`
    await this.redis.sadd(sessionsKey, tokenHash)
    await this.redis.expire(sessionsKey, ttl)
  }

  private async removeFromUserSessions(userId: string, tokenHash: string) {
    const sessionsKey = `user_sessions:${userId}`
    await this.redis.srem(sessionsKey, tokenHash)
  }
}
