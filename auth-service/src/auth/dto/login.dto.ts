import { IsEmail, IsString, IsNotEmpty, MinLength, ValidateIf } from 'class-validator'

export class LoginDto {
  @ValidateIf((o) => !o.userName)
  @IsEmail()
  email: string

  @ValidateIf((o) => !o.email)
  @IsNotEmpty()
  @IsString()
  username: string

  @IsNotEmpty()
  @MinLength(6)
  password: string
}
