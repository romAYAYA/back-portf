import { Module } from '@nestjs/common'
import { RedisModule as IORedisModule } from '@nestjs-modules/ioredis'
import { ConfigService } from '@nestjs/config'

@Module({
  imports: [
    IORedisModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        type: 'single',
        host: configService.get('REDIS_HOST', 'localhost'),
        port: configService.get('REDIS_PORT', 6379),
        password: configService.get('REDIS_PASSWORD'),
        db: configService.get('REDIS_DB', 0),
      }),
      inject: [ConfigService],
    }),
  ],
  exports: [IORedisModule],
})
export class RedisModule {}
