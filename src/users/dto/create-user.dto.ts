import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';

export class CreateUserDto {
  @ApiProperty({ example: 'Juan Perez' })
  @IsString()
  name: string;

  @ApiProperty({ example: 'juan@tigo.bo' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'secreto123', minLength: 6 })
  @IsString()
  @MinLength(6)
  password: string;
}
