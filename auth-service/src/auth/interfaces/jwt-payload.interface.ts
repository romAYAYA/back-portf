export interface JwtPayload {
  sub: string
  email: string
  iat?: number
  exp?: number
}

export interface RefreshTokenData {
  userId: string
  email: string
  userAgent: string
  ipAddress: string
  createdAt: number
}
