import { Controller, Get, Post, Body, Patch, Param, Delete, Put, UseGuards, Req, Res, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '@nestjs/config';
import { RefreshTokenDto } from './dto/refresh-tokens.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService,
    private configService : ConfigService,
  ) {}

  @Post('signup')
  async signUp(@Body() signUpData: SignUpDto) {
    return this.authService.SignUp(signUpData);
  }

  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
  }


  @Post('refresh')
  async refreshTokens(@Body() refreshTokensDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokensDto.refreshToken);
  }
  //Change password 
  @UseGuards(AuthGuard)//pour verifier que ce user is with a valid access token 
  @Put('change-password')
  async changePassword (
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() req: Request & { userId: string }, 
  ){
    return this.authService.changePassword(
      req.userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword, 
     );
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto){
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword
    );
  }

  @Post('logout')
  @UseGuards(AuthGuard)
  async logout(@Req() req: any, @Res() res: Response) {
    const userId = req.userId;
    if (!userId) {
      throw new UnauthorizedException('User ID not found');
    }
    return this.authService.logout(userId, res);
  }
}
