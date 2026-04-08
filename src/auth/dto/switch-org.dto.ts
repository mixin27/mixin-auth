import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SwitchActiveOrgDto {
  @ApiProperty({
    description: 'Org id or org slug to become active in this session.',
    example: 'acme',
  })
  @IsString()
  orgId!: string;
}

