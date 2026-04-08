export type AccessTokenPayload = {
  sub: string; // userId
  sid: string; // sessionId
  org_id?: string;
  roles?: string[];
  perms?: string[];
  iss: string;
  aud: string;
};

