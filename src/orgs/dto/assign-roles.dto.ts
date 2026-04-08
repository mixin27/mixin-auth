import { IsArray, IsIn, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AssignRolesDto {
  @ApiProperty({ example: ['manager'] })
  @IsArray()
  @IsString({ each: true })
  roleKeys!: string[];

  @ApiPropertyOptional({ enum: ['add', 'replace'], default: 'add' })
  @IsOptional()
  @IsIn(['add', 'replace'])
  mode?: 'add' | 'replace';
}

