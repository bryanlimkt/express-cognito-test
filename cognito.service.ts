import AWS, { CognitoIdentityServiceProvider } from 'aws-sdk'
import {createHmac} from 'crypto'

class CognitoService{
    private config = {
        region: process.env.REGION,
    }
    private secretHash: string = process.env.SECRET_HASH
    private clientId: string = process.env.CLIENT_ID
    private cognitoIdentity: CognitoIdentityServiceProvider

    constructor(){
        this.cognitoIdentity = new AWS.CognitoIdentityServiceProvider(this.config)
    }

    public async signUpUser(username: string, password: string, userAttr: Array<any>): Promise<boolean> {
        const params = {
            ClientId: this.clientId,
            Password: password,
            Username: username,
            SecretHash: this.generateHash(username) ,
            UserAttributes: userAttr
        }
        try {
            const data = await this.cognitoIdentity.signUp(params).promise()
            console.log(data);
            return true
        } catch (err) {
            console.log(err);
            return false
            

        }
    }

    public async verifyAccount (username: string, code: string): Promise<boolean> {
        const params = {
            ClientId: this.clientId,
            ConfirmationCode: code,
            SecretHash: this.generateHash(username),
            Username: username
        }

        try {
            const data = await this.cognitoIdentity.confirmSignUp(params).promise()
            console.log(data)
            return true
        } catch (err) {
            console.log(err);
            return false
            
        }
    }

    public async signInUser(username: string, password: string): Promise<boolean> {
        const params = {
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: this.clientId,
            AuthParameters: {
                'USERNAME': username,
                'PASSWORD':password,
                'SECRET_HASH': this.generateHash(username)
            }
        }

        try{
            const data = await  this.cognitoIdentity.initiateAuth(params).promise()
            console.log(data);
            return true
        } catch (err) {
            console.log(err);
            return false
        }
        
    }
    private generateHash(username: string): string {
        const hello = {one: 1, two: 2}
        return createHmac('SHA256', this.secretHash).update(username + this.clientId).digest('base64')
    }

}

export default CognitoService