import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { MoreThanOrEqual, Repository } from 'typeorm';
import { User } from 'src/user/entities/user.entity';
import { UserRole } from 'src/user/entities/role.entity';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { RefreshToken } from 'src/user/entities/refresh-token.entity';
import { nanoid } from 'nanoid';
import { ResetToken } from 'src/user/entities/reset-token.entity';
import { MailService } from 'src/services/mail.service';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(RefreshToken) 
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(ResetToken) 
    private resetTokenRepository: Repository<ResetToken>,
    private jwtService: JwtService,
    private mailService: MailService
  ) { }

  async SignUp(signUpData: SignUpDto) {
    const { email, password, name, role = UserRole.EMPLOYEE } = signUpData;

    const emailInUse = await this.userRepository.findOne({ where: { email } });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    await this.userRepository.save({
      name,
      email,
      password: hashedPassword,
      role
    });
    console.log('User created:', User);
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    //Find if user exists by email
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('wrong credentials');
    }
    //Compare entreted password with exixting 
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


async changePassword(userId, oldPassword: string, newPassword: string){
  //Find the user 
  const user = await this.userRepository.findOneBy({ id: userId });
  if(!user){
    throw new NotFoundException('user not found');
  }
  //compare the old password with the password in DB  
  const passwordMatch = await bcrypt.compare(oldPassword, user.password);
  if (!passwordMatch) {
    throw new UnauthorizedException('wrong credentials');
  }

  // Change user's password 

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
   ///Save the newPassword
user.password = newHashedPassword ;//remplace l’ancien mot de passe par le nouveau hashé 
await this.userRepository.save(user);


}


async forgotPassword(email: string) {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Generate reset token
    const token = nanoid(32);
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 1); // Token expires in 1 hour

    // Save reset token
    await this.resetTokenRepository.save({
      token,
      userId: user.id.toString(),
      expiryDate
    });

    // Send reset email
    await this.mailService.sendPasswordResetEmail(email, token);

    return { message: 'Password reset email sent successfully' };
  }

  async resetPassword(token: string, newPassword: string) {
    const resetToken = await this.resetTokenRepository.findOne({
      where: { 
        token,
        expiryDate: MoreThanOrEqual(new Date())
      },
      relations: ['user']
    });

    if (!resetToken) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    await this.userRepository.update(
      resetToken.userId,
      { password: hashedPassword }
    );

    // Delete used reset token
    await this.resetTokenRepository.remove(resetToken);

    return { message: 'Password reset successful' };
  }

  async refreshTokens(refreshToken: string){
    //Cherche le token dans BD + verfie si existe ou date expire 
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
  //Genere et retourne (access Token+ refresh token )
    return this.generateUserTokens(token.userId);
  }

  async generateUserTokens(userId: number) {
    //Chercher l'utlisateur dans la base de donnée 
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    //Sinon cree un access token
    const accessToken = this.jwtService.sign({ 
      userId, 
      role: user.role 
    });
    const refreshToken = uuidv4();
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

  // Trouver l'utilisateur dans la base d'abord
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

  // Si aucun token n'existe Créer et sauvegarder le refresh token 
  const refreshToken = this.refreshTokenRepository.create({
    token,
    user,  // Ceci établira la relation correctement
    expiryDate
  });

  await this.refreshTokenRepository.save(refreshToken);
}




}
///////////logout
async logout(userId: number, res: Response) {
  try {
    // Delete refresh tokens for the user
    await this.refreshTokenRepository.delete({ user: { id: userId } });

    // Clear cookies
    res.clearCookie('token');
    res.clearCookie('refreshToken');

    return res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    throw new BadRequestException('Logout failed');
  }
}
}
