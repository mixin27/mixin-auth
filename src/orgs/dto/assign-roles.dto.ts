import { IsArray, IsIn, IsOptional, IsString } from 'class-validator';

export class AssignRolesDto {
  @IsArray()
  @IsString({ each: true })
  roleKeys!: string[];

  @IsOptional()
  @IsIn(['add', 'replace'])
  mode?: 'add' | 'replace';
}

