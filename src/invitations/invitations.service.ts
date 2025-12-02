// src/invitations/invitations.service.ts
import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class InvitationsService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
  ) {}

  async createInvitation(invitationData: {
    email: string;
    invitedByAdminId: string;
    adminLevel: string;
    ttl?: number;
    securitySettings?: any;
  }) {
    const token = this.generateToken();
    const ttl = invitationData.ttl || 24; // Default 24 hours
    const expiresAt = new Date(Date.now() + ttl * 60 * 60 * 1000);

    return this.prisma.invitation.create({
      data: {
        email: invitationData.email,
        token,
        invitedByAdminId: invitationData.invitedByAdminId,
        adminLevel: invitationData.adminLevel as any,
        expiresAt,
        ttl,
        securitySettings: invitationData.securitySettings,
      },
    });
  }

  async validateInvitation(token: string) {
    const invitation = await this.prisma.invitation.findUnique({
      where: { token },
    });

    if (!invitation) {
      throw new NotFoundException('Invalid invitation token');
    }

    if (invitation.status !== 'PENDING') {
      throw new BadRequestException('Invitation already used or revoked');
    }

    if (invitation.expiresAt < new Date()) {
      throw new BadRequestException('Invitation has expired');
    }

    return invitation;
  }

  async generateKycToken(userId: string) {
    const token = this.generateToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store KYC token (you might want a separate table for this)
    return token;
  }

  async resendInvitation(invitationId: string, adminId: string) {
    const invitation = await this.prisma.invitation.findUnique({
      where: { id: invitationId },
    });

    if (!invitation || invitation.invitedByAdminId !== adminId) {
      throw new NotFoundException('Invitation not found');
    }

    const newToken = this.generateToken();
    const expiresAt = new Date(Date.now() + (invitation.ttl || 24) * 60 * 60 * 1000);

    return this.prisma.invitation.update({
      where: { id: invitationId },
      data: {
        token: newToken,
        expiresAt,
        status: 'PENDING',
      },
    });
  }

  async getInvitations(adminId: string, page: number = 1, limit: number = 10) {
    const skip = (page - 1) * limit;

    const [invitations, total] = await Promise.all([
      this.prisma.invitation.findMany({
        where: { invitedByAdminId: adminId },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          invitedByAdmin: {
            include: {
              user: {
                select: {
                  firstName: true,
                  lastName: true,
                  email: true,
                },
              },
            },
          },
        },
      }),
      this.prisma.invitation.count({
        where: { invitedByAdminId: adminId },
      }),
    ]);

    return {
      invitations,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  private generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}