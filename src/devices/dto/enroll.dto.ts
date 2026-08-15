import {
  IsIn,
  IsObject,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class EnrollDeviceDto {
  @IsString()
  @MinLength(40) // SPKI DER en base64 (~44+ chars para P-256)
  publicKey!: string;

  @IsIn(['ANDROID', 'IOS'])
  platform!: 'ANDROID' | 'IOS';

  @IsOptional()
  @IsString()
  keyAlgo?: string;

  @IsOptional()
  @IsObject()
  attestation?: { type: string; certificateChain?: string[] };
}
