import { Body, Controller, Get, Post, Query, Redirect } from '@nestjs/common';
import { AppService } from './app.service';
import { CognitoService } from './cognito.service';

export class SigInDto {
  email: string;
  password: string;
}

export class RespondToNewPasswordChalleneDto {
  email: string;
  newPassword: string;
  session: string;
}

export class SigUpDto {
  email: string;
  password: string;
}

export class SigUpConfirmationDto {
  email: string;
  confirmationCode: string;
}

export class ConfirmationCodeResendDto {
  email: string;
}

export class ForgotPasswordConfirmationDto {
  email: string;
  confirmationCode: string;
  newPassword: string;
}

export class ForgotPasswordDto {
  email: string;
}

export class PasswordChangeDto {
  accessToken: string;
  oldPassword: string;
  newPassword: string;
}

@Controller()
export class AppController {
  constructor(private readonly appService: AppService, private readonly cognitoService: CognitoService) { }

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Post('sign-in')
  signIn(@Body() { email, password }: SigInDto) {
    return this.cognitoService.signInCommand(email, password);
  }

  @Post('forgot-password')
  forgotPassword(@Body() { email }: ForgotPasswordDto) {
    return this.cognitoService.forgotPasswordCommand(email);
  }

  @Post('forgot-password-confirmation')
  forgotPasswordConfirmation(@Body() { email, confirmationCode, newPassword }: ForgotPasswordConfirmationDto) {
    return this.cognitoService.confirmForgotPasswordCommand(email, confirmationCode, newPassword);
  }

  @Post('sign-up')
  signUp(@Body() { email, password }: SigInDto) {
    return this.cognitoService.signUpCommand(email, password);
  }

  @Post('respond-to-new-password-challenge')
  respondToChallenge(@Body() { email, newPassword, session }: RespondToNewPasswordChalleneDto) {
    return this.cognitoService.respondToNewPasswordChallenge(email, newPassword, session);
  }

  @Post('sign-up-confirmation')
  confirmSignUp(@Body() { email, confirmationCode }: SigUpConfirmationDto) {
    return this.cognitoService.confirmSignUpCommand(email, confirmationCode);
  }

  @Post('confirmation-code-resend')
  resendConfirmationCode(@Body() { email }: ConfirmationCodeResendDto) {
    return this.cognitoService.resendConfirmationCodeCommand(email);
  }

  @Post('password-change')
  passwordChange(@Body() { accessToken, oldPassword, newPassword }: PasswordChangeDto) {
    return this.cognitoService.changePasswordCommand(accessToken, oldPassword, newPassword);
  }

  @Get('identity-providers')
  listIdentityProviders(@Query('clientId') clientId: string) {
    return this.cognitoService.listIdentityProvidersForClient(clientId);
  }

  @Get('auth-methods')
  getAuthMethods(@Query('clientId') clientId: string) {
      return this.cognitoService.getAvailableAuthMethods(clientId);
  }

  @Get('get-provider-url')
  async getProviderUrl(@Query('provider') identityProvider: string, @Query('clientId') clientId: string) {
    if(!identityProvider) {
      throw new Error('Provider not found!');
    }
    return this.cognitoService.getProviderUrl(identityProvider, clientId);
  }

  @Get('callback')
  async handleCallback(@Query('code') code: string, @Query('state') state: string) {
    const result = await this.cognitoService.handleCallback(code, state);
    return { message: 'Authentication successful', data: result };
  }
}
