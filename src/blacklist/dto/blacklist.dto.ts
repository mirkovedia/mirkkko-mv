import { IsIn, IsString, MinLength } from 'class-validator';

export class CreateBlacklistEntryDto {
  @IsString()
  @MinLength(3)
  packageName!: string;

  @IsString()
  @MinLength(1)
  label!: string;

  @IsIn(['LOW', 'MEDIUM', 'HIGH'])
  severity!: 'LOW' | 'MEDIUM' | 'HIGH';
}
