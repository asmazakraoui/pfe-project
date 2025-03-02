import { Injectable } from "@nestjs/common";
import * as nodemailer from "nodemailer";

@Injectable()
export class MailService  {
    private transporter: nodemailer.Transporter;
    
    constructor(){
        this.transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: 'asmazakraoui4@gmail.com',
                pass: 'wchc poag gjmd hisp'

            }
        });
    }

    async sendPasswordResetEmail(to: string, token: string){
            const resetLink =`http://localhost:4200/reset-password?token=${token}`;
            const mailOptions = {
                from: 'asmazakraoui4@gmail.com',
                to: to,
            subject: 'Password Reset Request',
                html: `
                <h2>Password Reset Request</h2>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <p><a href="${resetLink}" style="padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                <p>If you didn't request this, please ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
                `
            };
        await this.transporter.sendMail(mailOptions);
    }
}