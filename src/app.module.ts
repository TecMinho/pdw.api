import { Global, Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { AuthController } from './controllers/auth.controller';
import { CredentialOfferController } from './controllers/credential-offer.controller';
import { VerifierController } from './controllers/verifier.controller';
import { HolderController } from './controllers/holder.controller';
import { WellKnownController } from './controllers/well-known.controller';
import { CredentialController } from './controllers/credential.controller';
import { VerifierService } from './services/verifier.service';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    HttpModule,
  ],
  controllers: [
    AuthController,
    CredentialOfferController,
    VerifierController,
    HolderController,
    WellKnownController,
    CredentialController,
  ],
  providers: [VerifierService],
})
export class AppModule {}
