import express, {Request, Response} from 'express'
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'
import axios from 'axios'


const pems = {}
class AuthMiddleware {
    private poolRegion: string = process.env.REGION

    private userPoolId: string = process.env.USER_POOL_ID

    constructor() {
        this.setup()
    }

    verifyToken(req: Request, res: Response, next): void {
        const token = req.header('Auth')
        console.log(token);
        if(!token){
            console.log("no token");
            
            res.status(401).end()
        }

        let decodedJwt: any = jwt.decode(token,{complete:true})
        if (!decodedJwt) {
            console.log("no decodedJwt");
            res.status(401).end()
        }
        let kid = decodedJwt.header.kid
        
        
        const pem = pems[kid]
        if (!pem) {
            console.log("no pem");
            res.status(401).end()
        } 

        jwt.verify(token, pem, (err, payload) => {
            if (err) {
                console.log("no error with jwt signature");
                res.status(401).end()
            }
            next()
        })

        
    }
    private async setup () {
        const URL = `https://cognito-idp.${this.poolRegion}.amazonaws.com/${this.userPoolId}/.well-known/jwks.json`
        try{
            const response = await axios.get(URL)
            if (response.status !== 200) {
                throw 'request not successful'    
            }
            const keys = response.data['keys']
            
            keys.forEach(key => {

                const keyId = key.kid
                const keyType = key.kty
                const exponent = key.e
                const modulus = key.n

                const jwk = {kty: keyType, n: modulus, e: exponent}
                const pem = jwkToPem(jwk)
                pems[keyId] = pem
                
            }
            )
        } catch (err) {
            console.log(err);
            
        }
    }
}

export default AuthMiddleware