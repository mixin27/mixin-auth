import { ArrayNotEmpty, IsArray, IsOptional, IsString, MinLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateRoleDto {
  @ApiProperty({ example: 'manager' })
  @IsString()
  @MinLength(2)
  key!: string;

  @ApiProperty({ example: 'Manager' })
  @IsString()
  @MinLength(1)
  name!: string;

  @ApiPropertyOptional({
    example: ['orders:read'],
    description: 'Permission keys to attach to this role.',
  })
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  @IsOptional()
  permissionKeys?: string[];
}

