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
import { AppController } from './app.controller';

dotenv.config();

@Module({
  imports: [ // Chargement des variables d'environnement
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
      type: 'mysql', // Spécifie que la base de données utilisée est MySQL. TypeORM supporte plusieurs bases de données comme PostgreSQL, SQLite, etc.
    
     host: process.env.DB_HOST, // Récupère l'adresse de l'hôte de la base de données depuis les variables d'environnement (fichier .env).
    
     port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306, // Vérification ajoutée ici
    
    username: process.env.DB_USERNAME, // Récupère le nom d'utilisateur pour la connexion à la base de données depuis les variables d'environnement.
    
    password: process.env.DB_PASSWORD, // Récupère le mot de passe pour la connexion à la base de données depuis les variables d'environnement.
    
    database: process.env.DB_NAME, // Spécifie le nom de la base de données à utiliser. Cette valeur doit être définie dans le fichier .env.
    
    entities: [User,RefreshToken], // Liste des entités que TypeORM doit utiliser pour créer les tables dans la base de données. Ici, Payment et User sont des entités.
    
    synchronize: false, // Si à `true`, TypeORM va automatiquement synchroniser les entités avec la base de données à chaque démarrage de l'application. C'est utile pour le développement, mais risqué en production (peut effacer des données).
    logging: true, // Active les logs pour voir les requêtes SQL
    

})
],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
