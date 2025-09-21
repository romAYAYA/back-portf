export interface JwtPayload {
  sub: string
  email: string
  roles: string[]
  iat?: number
  exp?: number
}

export interface RefreshTokenData {
  userId: string
  email: string
  roles: string[]
  userAgent: string
  ipAddress: string
  createdAt: number
}
