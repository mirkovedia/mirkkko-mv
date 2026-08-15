import { IsISO8601, IsOptional, IsString, MinLength } from 'class-validator';

export class StartSessionDto {
  @IsString() deviceId!: string;
  @IsISO8601() clientTimestamp!: string;
  @IsString() @MinLength(1) signatureB64!: string;
}

export class SnapshotDto {
  @IsString() @MinLength(1) payloadB64!: string;
  @IsString() @MinLength(1) signatureB64!: string;
  @IsOptional() @IsString() integrityToken?: string | null;
}

export class EndSessionDto {
  @IsISO8601() clientTimestamp!: string;
  @IsString() @MinLength(1) signatureB64!: string;
}
