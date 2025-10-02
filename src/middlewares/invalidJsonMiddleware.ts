//D:\workspace\practice_lab16\src\middlewares\invalidJsonMiddleware.ts
import type { error } from "console";
import { type Request, type Response, type NextFunction } from "express";

// Define a custom interface for the error object if needed
interface CustomError extends Error {
  status?: number;
  type?: string;
}

const errorHandler = (
  err: CustomError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (
    err instanceof SyntaxError &&
    err.status === 400 &&
    err.type === "entity.parse.failed"
  ) {
    // Handle the JSON parse error specifically
    console.error("Bad JSON syntax:", err.message);
    return res.status(400).json({
      success: false,
      message: "Invalid JSON payload",
    });
  }

  // Pass other errors to the default Express error handler or another custom handler
  next(err);
};

export default errorHandler;
