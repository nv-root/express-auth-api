import { Resend } from "resend";
import { APP_ORIGIN, EMAIL_SENDER, RESEND_API_KEY } from "./env.ts";

const resend = new Resend(RESEND_API_KEY);

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}

export const sendEmail = async ({ to, subject, html }: EmailOptions) => {
  try {
    const { data, error } = await resend.emails.send({
      from: EMAIL_SENDER,
      to,
      subject,
      html,
    });

    if (error) {
      console.error("Resend error:", error);
      throw new Error(error.message);
    }

    console.log("Email sent:", data?.id);
    return { success: true, message: data?.id };
  } catch (error) {
    console.log("Resend error:", error);
  }
};

export const sendVerificationEmail = async (
  email: string,
  name: string,
  token: string
) => {
  const verificationUrl = `${APP_ORIGIN}/api/auth/verify-email?token=${token}`;

  const html = `
  <html>
  <body>
  <h1>Welcome to Our App, ${name}!</h1>
  <h3>Please verify your email</h3>
  <p><a href="${verificationUrl}">${verificationUrl}</a></p>
  <p>The link will expire in 24 hours.</p>
  </body>
  </html>
  `;

  await sendEmail({ to: email, subject: "Verify Your Email Address", html });
};
