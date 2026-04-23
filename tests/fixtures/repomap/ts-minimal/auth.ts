export class AuthService {
  login(user: string, password: string): boolean {
    return user.length > 0 && password.length > 0;
  }

  logout(): void {
    console.log("bye");
  }
}

export function createAuth(): AuthService {
  return new AuthService();
}
