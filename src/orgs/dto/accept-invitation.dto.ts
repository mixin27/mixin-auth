import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AcceptInvitationDto {
  @ApiProperty({ description: 'Invitation token received via email (or dev response).' })
  @IsString()
  token!: string;

  @ApiProperty({ example: 'Password123!' })
  @IsString()
  @MinLength(8)
  password!: string;

  @ApiPropertyOptional({ example: 'Invited User' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({
    example: 'invited@example.com',
    description: 'Optional; if provided must match the invitation email.',
  })
  @IsOptional()
  @IsEmail()
  email?: string;
}

