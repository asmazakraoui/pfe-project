import { Module } from '@nestjs/common';
import { AppService } from './app.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user/entities/user.entity';
import * as dotenv from 'dotenv'
import { AuthModule } from './auth/auth.module';
import { Auth } from './auth/entities/auth.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { config } from './config/config';
import { RefreshToken } from './user/entities/refresh-token.entity';
import { ResetToken } from './user/entities/reset-token.entity';
import { AppController } from './app.controller';

dotenv.config();

@Module({
  imports: [ 
    ConfigModule.forRoot({
      isGlobal: true, // Permet d'accéder aux variables dans toute l'application
    }),

    // Authentification JWT
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'), // Récupération de la clé secrète depuis `.env`
        signOptions: { expiresIn: '1h' }, // Expiration du token après 1 heure
      }),
      inject: [ConfigService],
    }),



    AuthModule, 

    TypeOrmModule.forRoot({ 
      type: 'mysql', 
    
     host: process.env.DB_HOST, 
    
     port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306, 
    
    username: process.env.DB_USERNAME, 
    
    password: process.env.DB_PASSWORD, 
    
    database: process.env.DB_NAME, 
    
    entities: [User,RefreshToken, ResetToken], 
    
    synchronize: true,
    logging: true, 
    

})
],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
