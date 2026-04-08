import { ArrayNotEmpty, IsArray, IsOptional, IsString, MinLength } from 'class-validator';

export class CreateRoleDto {
  @IsString()
  @MinLength(2)
  key!: string;

  @IsString()
  @MinLength(1)
  name!: string;

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  @IsOptional()
  permissionKeys?: string[];
}

