import { IsArray, IsEmail, IsOptional, IsString } from 'class-validator';

export class InviteMemberDto {
  @IsEmail()
  email!: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  roleKeys?: string[];
}

