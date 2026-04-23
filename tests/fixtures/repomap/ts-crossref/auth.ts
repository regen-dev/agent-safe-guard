export class AuthService {
  login(user: string): boolean {
    return user.length > 0;
  }
}

export class TokenStore {
  save(token: string): void {}
  load(): string {
    return "";
  }
}
