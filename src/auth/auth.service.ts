import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { MoreThanOrEqual, Repository } from 'typeorm';
import { User } from 'src/user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { RefreshToken } from 'src/user/entities/refresh-token.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(RefreshToken) 
    private refreshTokenRepository: Repository<RefreshToken>,
    private jwtService: JwtService
  ) { }

  async SignUp(signUpData: SignUpDto) {
    const { email, password, name } = signUpData;

    const emailInUse = await this.userRepository.findOne({ where: { email } });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    await this.userRepository.save({
      name,
      email,
      password: hashedPassword,
    });
    console.log('User created:', User);
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('wrong credentials');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('wrong credentials');
    }


    //generate JWT tokens 
    const tokens= await this.generateUserTokens(user.id);
    return {
      tokens,
      userId : user.id,
    }
  }

  async refreshTokens(refreshToken: string){
    const token = await this.refreshTokenRepository.findOne({ where: {
      token: refreshToken,
      expiryDate: MoreThanOrEqual(new Date())
,
    }
    });
    if(!token){
      throw new UnauthorizedException("Refresh Token is invalid  ");
    }
     // Supprimer le token après utilisation
  await this.refreshTokenRepository.delete(token.id);
    return this.generateUserTokens(token.userId);
  }

  async generateUserTokens(userId: number) {
    const accessToken = this.jwtService.sign({  userId });///Cela crée un token contenant l'ID de l'utilisateur.
    const refreshToken = uuidv4(); //génère un refreshToken avec uuidv4()
    await this.storeRefreshToken(refreshToken, userId);
    return {
    
      accessToken,
      refreshToken,
    };
  }
  
/*async storeRefreshToken(token : string, userId){

  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + 3);

  await this.refreshTokenRepository.save({
    token, userId, expiryDate});
}*/

async storeRefreshToken(token: string, userId: number) {
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + 3);

  // Trouver l'utilisateur d'abord
  const user = await this.userRepository.findOne({ where: { id: userId } });
  if (!user) {
    throw new UnauthorizedException('User not found');
  }
  // Vérifier si un refresh token existe déjà pour cet utilisateur
  const existingToken = await this.refreshTokenRepository.findOne({
    where: { user: { id: userId } }
  });

  if (existingToken) {
    // Mettre à jour le token existant au lieu d'en créer un nouveau
    existingToken.token = token;
    existingToken.expiryDate = expiryDate;
    await this.refreshTokenRepository.save(existingToken);
  } else {

  // Créer et sauvegarder le refresh token avec la relation user
  const refreshToken = this.refreshTokenRepository.create({
    token,
    user,  // Ceci établira la relation correctement
    expiryDate
  });

  await this.refreshTokenRepository.save(refreshToken);
}
}}
