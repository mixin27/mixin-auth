-- CreateTable
CREATE TABLE "OrgInvitation" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "invitedEmail" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "acceptedAt" TIMESTAMP(3),
    "invitedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrgInvitation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrgInvitationRole" (
    "invitationId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrgInvitationRole_pkey" PRIMARY KEY ("invitationId","roleId")
);

-- CreateIndex
CREATE UNIQUE INDEX "OrgInvitation_tokenHash_key" ON "OrgInvitation"("tokenHash");

-- CreateIndex
CREATE INDEX "OrgInvitation_orgId_idx" ON "OrgInvitation"("orgId");

-- CreateIndex
CREATE INDEX "OrgInvitation_invitedEmail_idx" ON "OrgInvitation"("invitedEmail");

-- CreateIndex
CREATE INDEX "OrgInvitation_expiresAt_idx" ON "OrgInvitation"("expiresAt");

-- AddForeignKey
ALTER TABLE "OrgInvitation" ADD CONSTRAINT "OrgInvitation_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Org"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgInvitation" ADD CONSTRAINT "OrgInvitation_invitedByUserId_fkey" FOREIGN KEY ("invitedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgInvitationRole" ADD CONSTRAINT "OrgInvitationRole_invitationId_fkey" FOREIGN KEY ("invitationId") REFERENCES "OrgInvitation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgInvitationRole" ADD CONSTRAINT "OrgInvitationRole_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "Role"("id") ON DELETE CASCADE ON UPDATE CASCADE;
