import { IsBoolean, IsOptional, IsString, MinLength } from 'class-validator';

export class CreateOrgDto {
  @IsString()
  @MinLength(3)
  slug!: string;

  @IsString()
  @MinLength(1)
  name!: string;

  @IsOptional()
  @IsBoolean()
  activate?: boolean;
}

