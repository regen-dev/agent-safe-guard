import { AuthService } from "./auth";

export function handleLogin(user: string): boolean {
  const svc = new AuthService();
  return svc.login(user);
}

export function handleHealth(): string {
  return "ok";
}
