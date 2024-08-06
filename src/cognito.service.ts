import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';
import {
    CognitoIdentityProviderClient,
    ConfirmSignUpCommand,
    ResendConfirmationCodeCommand,
    ForgotPasswordCommand,
    ConfirmForgotPasswordCommand,
    ChangePasswordCommand,
    SignUpCommand,
    SignUpCommandInput,
    ConfirmSignUpCommandInput,
    ResendConfirmationCodeCommandInput,
    ForgotPasswordCommandInput,
    ConfirmForgotPasswordCommandInput,
    ChangePasswordCommandInput,
    InitiateAuthCommandInput,
    InitiateAuthCommand,
    ListIdentityProvidersCommand,
    ListIdentityProvidersCommandInput,
    DescribeUserPoolClientCommand,
    DescribeUserPoolClientCommandInput,
    RespondToAuthChallengeCommandInput,
    RespondToAuthChallengeCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoClient } from './cognito.client';

export const REDIRECT_URI = 'http://localhost:3010/callback';

@Injectable()
export class CognitoService {
    private readonly cognitoClient: CognitoIdentityProviderClient;

    constructor() {
        this.cognitoClient = CognitoClient({
            region: process.env.AWS_COGNITO_REGION
        })
    }

    private getHashSecret(username: string): string {
        return crypto.createHmac('SHA256', process.env.AWS_COGNITO_CLIENT_SECRET)
        .update(username + process.env.AWS_COGNITO_CLIENT_ID)
        .digest('base64')  
      } 

    async signInCommand(email: string, password: string) {
        console.log(process.env.AWS_COGNITO_CLIENT_SECRET);
        const params: InitiateAuthCommandInput = {
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: process.env.AWS_COGNITO_CLIENT_ID,
            AuthParameters: {
                USERNAME: email,
                PASSWORD: password,
                SECRET_HASH: this.getHashSecret(email)
            },
        };

        return await this.cognitoClient.send(
            new InitiateAuthCommand(params),
        );
    }

    async signUpCommand(email: string, password: string) {
        const params: SignUpCommandInput = {
            ClientId: process.env.AWS_COGNITO_CLIENT_ID,
            Username: email,
            Password: password,
            UserAttributes: [
                {
                    Name: 'email',
                    Value: email,
                },
            ],
        };

        return await this.cognitoClient.send(new SignUpCommand(params));
    }

    async confirmSignUpCommand(email: string, confirmationCode: string) {
        const params: ConfirmSignUpCommandInput = {
            ClientId: process.env.AWS_COGNITO_CLIENT_ID,
            Username: email,
            ConfirmationCode: confirmationCode,
        };

        return await this.cognitoClient.send(new ConfirmSignUpCommand(params));
    }


    async resendConfirmationCodeCommand(email: string) {
        const params: ResendConfirmationCodeCommandInput = {
            ClientId: process.env.AWS_COGNITO_CLIENT_ID,
            Username: email,
        };

        return await this.cognitoClient.send(
            new ResendConfirmationCodeCommand(params),
        );
    }

    async forgotPasswordCommand(email: string) {
        const params: ForgotPasswordCommandInput = {
            ClientId: process.env.AWS_COGNITO_CLIENT_ID,
            Username: email,
        };

        return await this.cognitoClient.send(new ForgotPasswordCommand(params));
    }

    async confirmForgotPasswordCommand(email: string, confirmationCode: string, newPassword: string) {
        const params: ConfirmForgotPasswordCommandInput = {
            ClientId: process.env.AWS_COGNITO_CLIENT_ID,
            Username: email,
            ConfirmationCode: confirmationCode,
            Password: newPassword,
        };

        return await this.cognitoClient.send(
            new ConfirmForgotPasswordCommand(params),
        );
    }

    async changePasswordCommand(accessToken: string, oldPassword: string, newPassword: string) {
        const params: ChangePasswordCommandInput = {
            AccessToken: accessToken,
            PreviousPassword: oldPassword,
            ProposedPassword: newPassword,
        };

        return await this.cognitoClient.send(new ChangePasswordCommand(params));
    }

    async listIdentityProvidersCommand() {
        const params: ListIdentityProvidersCommandInput = {
            UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
        };

        return await this.cognitoClient.send(
            new ListIdentityProvidersCommand(params),
        );
    }

    async respondToNewPasswordChallenge(
        email: string,
        newPassword: string,
        session: string,
    ) {
        const params: RespondToAuthChallengeCommandInput = {
            ChallengeName: 'NEW_PASSWORD_REQUIRED',
            ClientId: process.env.AWS_COGNITO_CLIENT_ID,
            ChallengeResponses: {
                USERNAME: email,
                NEW_PASSWORD: newPassword,
                SECRET_HASH: this.getHashSecret(email)
            },
            Session: session,
        };

        try {
            const command = new RespondToAuthChallengeCommand(params);
            const response = await this.cognitoClient.send(command);
            return response;
        } catch (error) {
            throw new Error(error.message);
        }
    }

    async listIdentityProvidersForClient(clientId: string) {
        const allProvidersResponse = await this.listIdentityProvidersCommand();
        const allProviders = allProvidersResponse.Providers || [];

        const clientParams: DescribeUserPoolClientCommandInput = {
            UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
            ClientId: clientId,
        };

        const clientResponse = await this.cognitoClient.send(
            new DescribeUserPoolClientCommand(clientParams),
        );

        const clientConfig = clientResponse.UserPoolClient || {};
        const clientSupportedIdentityProviders = clientConfig.SupportedIdentityProviders || [];

        const clientIdentityProviders = allProviders.filter(provider =>
            clientSupportedIdentityProviders.includes(provider.ProviderName)
        );

        return clientIdentityProviders;
    }

    async getAvailableAuthMethods(clientId: string) {
        const params = {
            UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
            ClientId: clientId,
        };

        const command = new DescribeUserPoolClientCommand(params);
        const response = await this.cognitoClient.send(command);

        const flows = response.UserPoolClient?.ExplicitAuthFlows || [];

        return flows.map(flow => {
            switch (flow) {
                case 'ALLOW_ADMIN_USER_PASSWORD_AUTH':
                    return 'ADMIN_NO_SRP_AUTH';
                case 'ALLOW_USER_SRP_AUTH':
                    return 'USER_SRP_AUTH';
                case 'ALLOW_REFRESH_TOKEN_AUTH':
                    return 'REFRESH_TOKEN_AUTH';
                case 'ALLOW_CUSTOM_AUTH':
                    return 'CUSTOM_AUTH';
                case 'ALLOW_USER_PASSWORD_AUTH':
                    return 'USER_PASSWORD_AUTH';
                default:
                    return flow;
            }
        });
    }

    async getProviderUrl(identityProvider: string, clientId: string) {
        const baseUrl = `${process.env.AWS_COGNITO_DOMAIN}`;

        const params = new URLSearchParams();
        params.append('client_id', clientId);
        params.append('response_type', 'code');
        params.append('scope', 'profile email openid');
        params.append('redirect_uri', REDIRECT_URI);
        params.append('identity_provider', identityProvider);
        params.append('state', clientId); // Ensure this is a dynamic and secure value if used in production

        return `${baseUrl}/oauth2/authorize?${params.toString()}`;
    }

    async handleCallback(code: string, clientId: string) {
        const requestBody = new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: clientId,
            code: code,
            redirect_uri: REDIRECT_URI
        })

        const res = await fetch(`${process.env.AWS_COGNITO_DOMAIN}/oauth2/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: requestBody
        })

        const data = await res.json()

        return data;
    }
}   
