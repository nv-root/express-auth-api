import type { ErrorRequestHandler } from "express";
import { MongoServerError } from "mongodb";
import { AppError } from "../utils/appError.ts";
import z from "zod";

export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  let statusCode = 500;
  let message = "Internal Server Error";
  let errors: any = undefined;

  if (err instanceof AppError) {
    statusCode = err.statusCode;
    message = err.message;
  } else if (err instanceof z.ZodError) {
    statusCode = 400;
    message = "Validation failed";
    errors = err.issues.map((issue) => ({
      path: issue.path.join(","),
      message: issue.message,
    }));
  } else if (err instanceof MongoServerError && err.code === 11000) {
    statusCode = 409;
    const field = Object.keys(err.keyPattern || {})[0];
    const value = err.keyValue?.[field as string];
    message = "Duplicate key error";
    errors = [
      {
        field,
        message: `${field} '${value}' already exists`,
        type: "duplicate",
        value,
      },
    ];
  } else if (err instanceof MongoServerError && err.code === 121) {
    statusCode = 400;

    const schemaRules = err.errInfo?.details?.schemaRulesNotSatisfied || [];
    const validationErrors: any[] = [];

    schemaRules.forEach((rule: any) => {
      // Handle missing required fields
      if (rule.missingProperties) {
        rule.missingProperties.forEach((prop: string) => {
          validationErrors.push({
            field: prop,
            message: `${prop} is required`,
            type: "required",
          });
        });
      }

      // Handle property validation failures
      if (rule.propertiesNotSatisfied) {
        rule.propertiesNotSatisfied.forEach((prop: any) => {
          validationErrors.push({
            field: prop.propertyName,
            message: prop.description || "Validation failed",
            type: prop.details?.[0]?.operatorName || "validation",
          });
        });
      }
    });

    message = "Validation failed";
    errors = validationErrors.length > 0 ? validationErrors : undefined;
  } else if (err instanceof MongoServerError) {
    statusCode = 400;
    message = err.message;
  }

  if (process.env.NODE_ENV === "development") {
    console.error("Error:", {
      message: err.message,
      stack: err.stack,
      statusCode,
      ...(errors && { errors }),
    });
  }

  return res.status(statusCode).json({
    success: false,
    message,
    ...(errors && { errors }),
  });
};
