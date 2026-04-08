import { IsBoolean, IsOptional, IsString, MinLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateOrgDto {
  @ApiProperty({ example: 'acme', description: 'Unique org slug.' })
  @IsString()
  @MinLength(3)
  slug!: string;

  @ApiProperty({ example: 'Acme Inc' })
  @IsString()
  @MinLength(1)
  name!: string;

  @ApiPropertyOptional({
    default: true,
    description:
      'If true, sets this org as the active org for the current session and returns a new access token.',
  })
  @IsOptional()
  @IsBoolean()
  activate?: boolean;
}

