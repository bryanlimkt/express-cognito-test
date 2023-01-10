import express, {Request, Response} from 'express'
import { body, validationResult } from 'express-validator'
import CognitoService from '../../cognito.service'

class AuthController{
    public path = '/auth'
    public router = express.Router()

    constructor(){
        this.initRoutes()
    }

    private initRoutes(){
        this.router.post("/signUp", this.validateBody('signUp'), this.signUp)
        this.router.post("/signIn", this.validateBody('signIn'), this.signIn)
        this.router.post("/verify", this.validateBody('verify'), this.verify)
    }

    signUp(req: Request, res: Response) {
        const result = validationResult(req)
        if(!result.isEmpty()){
            return res.status(422).json({errors: result.array()})
        }
        const {username, password, email, name, family_name, birthdate} = req.body
        let userAttr = []
        userAttr.push({Name: 'email', Value: email})
        userAttr.push({Name: 'name', Value: name})
        userAttr.push({Name: 'family_name', Value: family_name})
        userAttr.push({Name: 'birthdate', Value: birthdate} )
        const cognito = new CognitoService()
        let success =  cognito.signUpUser(username, password, userAttr).then(success => {
            if (success) {
                res.status(200).end()
            } else{
                res.status(500).end()
            }
        })
    }
    signIn(req: Request, res: Response) {
        const result = validationResult(req)
        if(!result.isEmpty()){
            return res.status(422).json({errors: result.array()})
        }

        const {username, password} = req.body
        const cognito = new CognitoService()

        cognito.signInUser(username, password).then(success => {
            if (success) {
                res.status(200).end()
            } else {
                res.status(500).end()
            }
        })
    }
    verify(req: Request, res: Response) {
        const result = validationResult(req)
        if(!result.isEmpty()){
            return res.status(422).json({errors: result.array()})
        }
        const {username, code} = req.body
        const cognito = new CognitoService()
        cognito.verifyAccount(username, code ).then(success => {
            if (success){
                res.status(200).end()
            } else {
                res.status(500).end()
            }
        })
    }



private validateBody(type: string) {
    switch (type) {
        case 'signUp':
            return [
                body('username').notEmpty().isLength({min: 6}),
                body('email').notEmpty().normalizeEmail().isEmail(),
                body('password').notEmpty().isLength({min: 8}),
                body('birthdate').exists().isISO8601(),
                body('name').notEmpty().isString(),
                body('family_name').notEmpty().isString()
            ]
            
        case 'signIn':
             return [
                body('username').notEmpty().isLength({min: 6}),
                body('password').notEmpty().isLength({min: 8}),
            ]
        case 'verify':
            return [
                body('username').notEmpty().isLength({min: 6}),
                body('code').isString().isLength({min: 6, max:6}),
            ]
    
        default:
            break;
    }
}
}

export default AuthController