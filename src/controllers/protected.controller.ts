import express, {Request, Response} from 'express'
import AuthMiddleware from '../middleware/auth.middleware'

class ProtectedController{
    public path = '/'
    public router = express.Router()
    private authMiddleware

    constructor(){
        this.authMiddleware = new AuthMiddleware()
        this.initRoutes()
    }

    private initRoutes(){
        this.router.use(this.authMiddleware.verifyToken)
        this.router.get("/secret", this.secret)
    }

    secret(req: Request, res: Response) {
        console.log('sending');
        res.send("protected route")
    }
}

export default ProtectedController