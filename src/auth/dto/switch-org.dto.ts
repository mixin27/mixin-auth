import { IsString } from 'class-validator';

export class SwitchActiveOrgDto {
  @IsString()
  orgId!: string;
}

