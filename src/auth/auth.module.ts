import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RefreshToken } from 'src/user/entities/refresh-token.entity';
import { ResetToken } from 'src/user/entities/reset-token.entity';
import { MailService } from 'src/services/mail.service';

@Module({
  imports: [TypeOrmModule.forFeature([User,RefreshToken,ResetToken]),

  JwtModule.registerAsync({
    imports: [ConfigModule],
    useFactory: async (configService: ConfigService) => ({
      secret: configService.get('JWT_SECRET'),
      signOptions: { expiresIn: '1h' },
    }),
    inject: [ConfigService],
  }),
], // Import User repository

  controllers: [AuthController],
  providers: [AuthService,MailService],
})
export class AuthModule {}
