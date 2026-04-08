import { IsArray, IsEmail, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class InviteMemberDto {
  @ApiProperty({ example: 'invited@example.com' })
  @IsEmail()
  email!: string;

  @ApiPropertyOptional({
    example: ['manager'],
    description: 'Role keys to grant on invitation acceptance.',
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  roleKeys?: string[];
}

