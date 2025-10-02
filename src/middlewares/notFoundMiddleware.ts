//D:\workspace\practice_lab16\src\middlewares\notFoundMiddleware.ts
import { type Request, type Response, type NextFunction } from "express";

const notFoundMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  res.status(404).json({
    success: false,
    message: "Endpoint not found",
  });
};

export default notFoundMiddleware;
