import { IsEmail, IsString, IsNotEmpty, MinLength, ValidateIf } from 'class-validator'

export class RegisterDto {
  @IsEmail()
  email: string

  @IsString()
  @IsNotEmpty()
  username: string

  @IsNotEmpty()
  @MinLength(6)
  password: string
}
