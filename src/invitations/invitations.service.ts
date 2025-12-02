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

// src/invitations/invitations.service.ts
import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { RbacService } from '../auth/rbac.service';
import * as crypto from 'crypto';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class InvitationsService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private rbacService: RbacService,
    private mailerService: MailerService,
  ) {}

  async createAdminInvitation(invitationData: {
    email: string;
    invitedByAdminId: string;
    adminLevel: string;
    marketId?: string;
    ttl?: number;
    securitySettings?: any;
  }) {
    // Verify inviting admin has permission
    const canInvite = await this.rbacService.hasPermission(
      invitationData.invitedByAdminId,
      'INVITATION',
      'CREATE'
    );

    if (!canInvite) {
      throw new BadRequestException('Insufficient permissions to send invitations');
    }

    const token = this.generateToken();
    const ttl = invitationData.ttl || 24;
    const expiresAt = new Date(Date.now() + ttl * 60 * 60 * 1000);

    const invitation = await this.prisma.invitation.create({
      data: {
        email: invitationData.email,
        token,
        type: 'ADMIN_ONBOARDING',
        invitedByAdminId: invitationData.invitedByAdminId,
        adminLevel: invitationData.adminLevel as any,
        marketId: invitationData.marketId,
        expiresAt,
        ttl,
        securitySettings: invitationData.securitySettings,
        metadata: {
          adminLevel: invitationData.adminLevel,
          marketId: invitationData.marketId,
        },
      },
    });

    // Send invitation email
    await this.sendAdminInvitationEmail(invitation);

    return invitation;
  }

  async createVendorKycInvitation(vendorId: string, invitedByAdminId: string) {
    const vendor = await this.prisma.vendor.findUnique({
      where: { id: vendorId },
      include: {
        stakeholder: {
          include: {
            user: true,
          },
        },
        market: true,
      },
    });

    if (!vendor) {
      throw new NotFoundException('Vendor not found');
    }

    const token = this.generateToken();
    const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000); // 72 hours for KYC

    const invitation = await this.prisma.invitation.create({
      data: {
        email: vendor.stakeholder.user.email,
        token,
        type: 'VENDOR_KYC',
        invitedByAdminId,
        vendorId,
        marketId: vendor.marketId,
        expiresAt,
        ttl: 72,
        metadata: {
          vendorId: vendor.id,
          businessName: vendor.stakeholder.businessName,
          marketName: vendor.market?.name,
        },
      },
    });

    // Send KYC invitation email
    await this.sendKycInvitationEmail(invitation, vendor);

    return invitation;
  }

  async validateInvitation(token: string, type?: string) {
    const invitation = await this.prisma.invitation.findUnique({
      where: { token },
      include: {
        market: true,
        vendor: {
          include: {
            stakeholder: {
              include: {
                user: true,
              },
            },
          },
        },
      },
    });

    if (!invitation) {
      throw new NotFoundException('Invalid invitation token');
    }

    if (type && invitation.type !== type) {
      throw new BadRequestException('Invalid invitation type');
    }

    if (invitation.status !== 'PENDING') {
      throw new BadRequestException('Invitation already used or revoked');
    }

    if (invitation.expiresAt < new Date()) {
      throw new BadRequestException('Invitation has expired');
    }

    return invitation;
  }

  async acceptAdminInvitation(token: string, userData: {
    password: string;
    firstName: string;
    lastName: string;
    phone?: string;
  }) {
    const invitation = await this.validateInvitation(token, 'ADMIN_ONBOARDING');
    
    const hashedPassword = await bcrypt.hash(userData.password, 12);
    
    // Create user and admin profile
    const user = await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          email: invitation.email,
          passwordHash: hashedPassword,
          firstName: userData.firstName,
          lastName: userData.lastName,
          phone: userData.phone,
          status: 'ACTIVE',
          emailVerified: true,
          admin: {
            create: {
              adminLevel: invitation.adminLevel,
              employeeId: `EMP-${Date.now()}`,
            },
          },
          profile: {
            create: {},
          },
        },
        include: {
          admin: true,
        },
      });

      // Assign role based on admin level
      const roleName = this.getRoleFromAdminLevel(invitation.adminLevel);
      await this.rbacService.assignRoleToUser(
        user.id, 
        roleName, 
        invitation.marketId
      );

      // Mark invitation as accepted
      await tx.invitation.update({
        where: { id: invitation.id },
        data: { status: 'ACCEPTED' },
      });

      return user;
    });

    return user;
  }

  async submitVendorKyc(token: string, kycData: any, documents: any[]) {
    const invitation = await this.validateInvitation(token, 'VENDOR_KYC');
    
    if (!invitation.vendorId) {
      throw new BadRequestException('Invalid KYC invitation');
    }

    return await this.prisma.$transaction(async (tx) => {
      // Update vendor KYC status and data
      await tx.stakeholder.update({
        where: { id: invitation.vendor.stakeholder.id },
        data: {
          kycStatus: 'UNDER_REVIEW',
          kycDocuments: documents,
          ...kycData,
        },
      });

      // Mark invitation as accepted
      await tx.invitation.update({
        where: { id: invitation.id },
        data: { status: 'ACCEPTED' },
      });

      // Notify admin for review
      await this.notifyAdminForKycReview(invitation.vendorId);
    });
  }

  private getRoleFromAdminLevel(adminLevel: string): string {
    const roleMap = {
      'SUPER_ADMIN': 'SUPER_ADMIN',
      'NATIONAL_ADMIN': 'NATIONAL_ADMIN', 
      'DISTRICT_ADMIN': 'DISTRICT_ADMIN',
      'CITY_ADMIN': 'CITY_ADMIN',
      'MARKET_MASTER': 'MARKET_MASTER',
      'PSEUDO_MARKET_MASTER': 'PSEUDO_MARKET_MASTER',
    };
    
    return roleMap[adminLevel] || 'MARKET_MASTER';
  }

  private async sendAdminInvitationEmail(invitation: any) {
    const invitationUrl = `${this.config.get('CLIENT_URL')}/invitation/accept?token=${invitation.token}`;
    
    await this.mailerService.sendMail({
      to: invitation.email,
      subject: 'Admin Invitation - Uganda Market Management System',
      template: 'admin-invitation',
      context: {
        invitationUrl,
        expiresAt: invitation.expiresAt,
        adminLevel: invitation.adminLevel,
      },
    });
  }

  private async sendKycInvitationEmail(invitation: any, vendor: any) {
    const kycUrl = `${this.config.get('CLIENT_URL')}/kyc/submit?token=${invitation.token}`;
    
    await this.mailerService.sendMail({
      to: invitation.email,
      subject: 'KYC Verification Required - Uganda Market Management System',
      template: 'kyc-invitation',
      context: {
        kycUrl,
        businessName: vendor.stakeholder.businessName,
        expiresAt: invitation.expiresAt,
      },
    });
  }

  private async notifyAdminForKycReview(vendorId: string) {
    // Find relevant admins for KYC approval
    const marketAdmins = await this.prisma.userRole.findMany({
      where: {
        role: { name: 'MARKET_MASTER' },
        user: { status: 'ACTIVE' },
      },
      include: {
        user: true,
      },
    });

    for (const admin of marketAdmins) {
      await this.mailerService.sendMail({
        to: admin.user.email,
        subject: 'KYC Review Required',
        template: 'kyc-review-notification',
        context: {
          vendorId,
        },
      });
    }
  }

  private generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}