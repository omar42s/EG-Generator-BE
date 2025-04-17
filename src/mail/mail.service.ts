import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private transporter;

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      service: 'gmail', // any service like Mailgun or SendGrid etc
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD,
      },
    });
  }

  // Send verification email
  async sendVerificationEmail(email: string, token: string) {
    const baseUrl = this.configService.get<string>('BASE_URL');
    const verificationUrl = `${baseUrl}/auth/verify?token=${token}`;
    const mailOptions = {
      from: this.configService.get<string>('EMAIL_USER'),
      to: email,
      subject: 'Email Verification',
      html: `
      <html>
        <head>
          <style>
            body {
              font-family: Arial, sans-serif;
              background-color: #f4f4f4;
              margin: 0;
              padding: 0;
            }
            .container {
              width: 100%;
              max-width: 600px;
              margin: 20px auto;
              background-color: #ffffff;
              padding: 20px;
              border-radius: 8px;
              box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            .header {
              text-align: center;
              background-color: #1cbadc; /* Easygenerator's primary color */
              padding: 20px;
              color: white;
              border-radius: 8px 8px 0 0;
            }
            .header h1 {
              margin: 0;
              font-size: 24px;
            }
            .content {
              margin: 20px 0;
              text-align: center;
            }
            .button {
              background-color: #1cbadc; /* Matching button color */
              color: white;
              padding: 15px 25px;
              text-decoration: none;
              font-size: 16px;
              border-radius: 5px;
              display: inline-block;
              margin-top: 10px;
              transition: background-color 0.3s ease;
            }
            .button:hover {
              background-color: #17a3c6; /* Slightly darker shade for hover effect */
            }
            .footer {
              text-align: center;
              font-size: 14px;
              color: #777;
              margin-top: 20px;
            }
            .footer p {
              margin: 5px 0;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Welcome to EasyGenerator!</h1>
            </div>
            <div class="content">
              <p>Please click the button below to verify your email address:</p>
              <a href="${verificationUrl}" class="button">Verify Email</a>
            </div>
            <div class="footer">
              <p>If you did not create an account, please ignore this email.</p>
              <p>&copy; ${new Date().getFullYear()} EasyGenerator. All rights reserved.</p>
            </div>
          </div>
        </body>
      </html>
    `,
    };

    await this.transporter.sendMail(mailOptions);
  }
}
