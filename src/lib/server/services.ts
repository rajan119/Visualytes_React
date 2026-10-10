
import "server-only";

import nodemailer from "nodemailer";
import { ValidationError, requiredText } from "./forms";

const CAPTCHA_VERIFY_URL =
  "https://www.google.com/recaptcha/api/siteverify";

function requiredEnv(
  name:
    | "EMAIL_USER"
    | "EMAIL_PASSWORD"
    | "SMTP_HOST"
    | "SMTP_PORT"
    | "RECAPTCHA_SECRET_KEY"
    | "STRIPE_SECRET_KEY"
    | "NEXT_PUBLIC_URL"
) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing required server configuration: ${name}`);
  }

  return value;
}

export function mailTransport() {
  const port = Number(requiredEnv("SMTP_PORT"));

  if (![465, 587].includes(port)) {
    throw new Error("SMTP_PORT must be 465 or 587.");
  }

  return nodemailer.createTransport({
    host: requiredEnv("SMTP_HOST"),
    port,
    secure: port === 465,
    auth: {
      user: requiredEnv("EMAIL_USER"),
      pass: requiredEnv("EMAIL_PASSWORD"),
    },
  });
}

export function mailRecipient() {
  return requiredEnv("EMAIL_USER");
}

export function applicationUrl() {
  return requiredEnv("NEXT_PUBLIC_URL").replace(/\/$/, "");
}

export function stripeSecretKey() {
  return requiredEnv("STRIPE_SECRET_KEY");
}

export async function verifyCaptcha(token: unknown) {
  const response = requiredText(token, "Robot verification token", {
    max: 4096,
  });

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const result = await fetch(CAPTCHA_VERIFY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        secret: requiredEnv("RECAPTCHA_SECRET_KEY"),
        response,
      }),
      signal: controller.signal,
      cache: "no-store",
    });

    if (!result.ok) {
      throw new ValidationError("Robot verification failed.");
    }

    const data = (await result.json()) as {
      success?: boolean;
    };

    if (!data.success) {
      throw new ValidationError("Robot verification failed.");
    }
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }

    throw new Error("Robot verification service is unavailable.");
  } finally {
    clearTimeout(timeout);
  }
}
