import { CanActivate, ExecutionContext, Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Observable } from "rxjs";
import { Request } from "express";



@Injectable()
export class AuthGuard implements CanActivate {
    constructor(private jwtService: JwtService) { }
canActivate(context: ExecutionContext, 

): boolean | Promise<boolean> | Observable<boolean> {
const request  = context.switchToHttp().getRequest();
const token = this.extractTokenFromHeader(request);


if (!token) {
throw  new UnauthorizedException('Token not provided');
}
try {
const payload = this.jwtService.verify(token); // Vérifie la validité du token
request.userId = payload.userId;//On stocke payload.userId dans request.userId pour que l'application sache qui fait la requête.

} catch(e){
    Logger.error(e.message);
    throw new UnauthorizedException('Token is invalid');

}
return true;
}

private extractTokenFromHeader(request: Request): string | undefined {
    return request.headers.authorization?.split(' ')[1];
}
}