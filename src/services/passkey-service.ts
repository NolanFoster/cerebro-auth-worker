/**
 * Thin wrapper around @simplewebauthn/server for generating and verifying
 * WebAuthn registration and authentication ceremonies.
 *
 * Keeps @simplewebauthn/server at arm's length so route handlers can mock this
 * service and so we can swap implementations without touching endpoints.
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL, isoUint8Array } from '@simplewebauthn/server/helpers';
import type {
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import type { Env } from '../types/env';
import type { CredentialRecord } from '../utils/passkey-manager';

export interface PasskeyRegistrationOptions {
  options: PublicKeyCredentialCreationOptionsJSON;
  challenge: string;
}

export interface PasskeyAuthenticationOptions {
  options: PublicKeyCredentialRequestOptionsJSON;
  challenge: string;
}

export interface VerifiedPasskeyRegistration {
  verified: boolean;
  credentialId?: string;
  publicKey?: string;
  counter?: number;
  transports?: AuthenticatorTransportFuture[];
  deviceType?: 'singleDevice' | 'multiDevice';
  backedUp?: boolean;
}

export interface VerifiedPasskeyAuthentication {
  verified: boolean;
  newCounter?: number;
  credentialId?: string;
}

export class PasskeyService {
  private readonly rpID: string;
  private readonly rpName: string;
  private readonly origins: string[];

  constructor(env: Env) {
    if (!env.RP_ID?.trim()) throw new Error('RP_ID not configured');
    if (!env.RP_NAME?.trim()) throw new Error('RP_NAME not configured');
    if (!env.RP_ORIGINS?.trim()) throw new Error('RP_ORIGINS not configured');

    this.rpID = env.RP_ID.trim();
    this.rpName = env.RP_NAME.trim();
    this.origins = env.RP_ORIGINS.split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    if (this.origins.length === 0) {
      throw new Error('RP_ORIGINS must contain at least one origin');
    }
  }

  async generateRegistration(
    userId: string,
    email: string,
    existingCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[]
  ): Promise<PasskeyRegistrationOptions> {
    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpID,
      userName: email,
      userID: isoUint8Array.fromUTF8String(userId),
      userDisplayName: email,
      attestationType: 'none',
      excludeCredentials: existingCredentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    return { options, challenge: options.challenge };
  }

  async verifyRegistration(
    response: RegistrationResponseJSON,
    expectedChallenge: string
  ): Promise<VerifiedPasskeyRegistration> {
    const result: VerifiedRegistrationResponse = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origins,
      expectedRPID: this.rpID,
    });

    if (!result.verified || !result.registrationInfo) {
      return { verified: false };
    }

    const { credential, credentialDeviceType, credentialBackedUp } = result.registrationInfo;

    return {
      verified: true,
      credentialId: credential.id,
      publicKey: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports ?? [],
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
    };
  }

  async generateAuthentication(
    allowCredentials?: { id: string; transports?: AuthenticatorTransportFuture[] }[]
  ): Promise<PasskeyAuthenticationOptions> {
    const options = await generateAuthenticationOptions({
      rpID: this.rpID,
      allowCredentials: allowCredentials?.map((cred) => ({
        id: cred.id,
        transports: cred.transports,
      })),
      userVerification: 'preferred',
    });

    return { options, challenge: options.challenge };
  }

  async verifyAuthentication(
    response: AuthenticationResponseJSON,
    expectedChallenge: string,
    storedCredential: CredentialRecord
  ): Promise<VerifiedPasskeyAuthentication> {
    const result: VerifiedAuthenticationResponse = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origins,
      expectedRPID: this.rpID,
      credential: {
        id: storedCredential.credentialId,
        publicKey: isoBase64URL.toBuffer(storedCredential.publicKey),
        counter: storedCredential.counter,
        transports: storedCredential.transports,
      },
    });

    return {
      verified: result.verified,
      newCounter: result.authenticationInfo?.newCounter,
      credentialId: result.authenticationInfo?.credentialID,
    };
  }
}
