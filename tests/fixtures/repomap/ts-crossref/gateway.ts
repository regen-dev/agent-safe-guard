import { AuthService } from "./auth";
import { handleLogin } from "./api";

export function entrypoint(user: string): boolean {
  const result = handleLogin(user);
  const extra = new AuthService();
  return result && extra.login(user);
}
