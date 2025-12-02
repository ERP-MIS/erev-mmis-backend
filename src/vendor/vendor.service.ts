// src/vendor/vendor.service.ts
import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InvitationsService } from '../invitations/invitations.service';
import { RbacService } from '../auth/rbac.service';

@Injectable()
export class VendorService {
  constructor(
    private prisma: PrismaService,
    private invitationsService: InvitationsService,
    private rbacService: RbacService,
  ) {}

  async registerVendor(registerData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    phone: string;
    businessName: string;
    marketId: string;
    vendorType: string;
    businessLicenseNumber?: string;
  }) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: registerData.email },
    });

    if (existingUser) {
      throw new BadRequestException('User already exists with this email');
    }

    const hashedPassword = await bcrypt.hash(registerData.password, 12);

    return await this.prisma.$transaction(async (tx) => {
      // Create user and stakeholder
      const user = await tx.user.create({
        data: {
          email: registerData.email,
          passwordHash: hashedPassword,
          firstName: registerData.firstName,
          lastName: registerData.lastName,
          phone: registerData.phone,
          status: 'PENDING', // Wait for KYC verification
          stakeholder: {
            create: {
              kycStatus: 'PENDING',
              businessName: registerData.businessName,
              vendor: {
                create: {
                  vendorType: registerData.vendorType,
                  businessLicenseNumber: registerData.businessLicenseNumber,
                  marketId: registerData.marketId,
                },
              },
            },
          },
          profile: {
            create: {},
          },
        },
        include: {
          stakeholder: {
            include: {
              vendor: true,
            },
          },
        },
      });

      // Assign vendor role
      await this.rbacService.assignRoleToUser(
        user.id,
        'VENDOR',
        registerData.marketId
      );

      // Create KYC invitation (sent by system)
      const kycInvitation = await this.invitationsService.createVendorKycInvitation(
        user.stakeholder.vendor.id,
        'system' // System-generated invitation
      );

      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        vendor: user.stakeholder.vendor,
        kycInvitationSent: true,
      };
    });
  }

  async approveVendorKyc(vendorId: string, approvedByAdminId: string) {
    // Check if admin has KYC approval permission
    const canApprove = await this.rbacService.hasPermission(
      approvedByAdminId,
      'KYC',
      'APPROVE'
    );

    if (!canApprove) {
      throw new BadRequestException('Insufficient permissions to approve KYC');
    }

    return await this.prisma.$transaction(async (tx) => {
      const vendor = await tx.vendor.findUnique({
        where: { id: vendorId },
        include: {
          stakeholder: true,
        },
      });

      if (!vendor) {
        throw new BadRequestException('Vendor not found');
      }

      // Update KYC status
      await tx.stakeholder.update({
        where: { id: vendor.stakeholderId },
        data: {
          kycStatus: 'VERIFIED',
        },
      });

      // Activate user account
      await tx.user.update({
        where: { id: vendor.stakeholder.userId },
        data: {
          status: 'ACTIVE',
        },
      });

      // Send approval notification
      await this.sendKycApprovalNotification(vendor.stakeholder.userId);

      return { message: 'Vendor KYC approved successfully' };
    });
  }

  async getVendorsByMarket(marketId: string, adminId: string) {
    // Verify admin has access to this market
    const canView = await this.rbacService.hasPermission(
      adminId,
      'USER',
      'READ',
      marketId
    );

    if (!canView) {
      throw new BadRequestException('Insufficient permissions to view vendors in this market');
    }

    return this.prisma.vendor.findMany({
      where: { marketId },
      include: {
        stakeholder: {
          include: {
            user: {
              include: {
                profile: true,
              },
            },
          },
        },
        stalls: true,
      },
    });
  }

  private async sendKycApprovalNotification(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (user) {
      // Send approval email
      await this.mailerService.sendMail({
        to: user.email,
        subject: 'KYC Approved - Uganda Market Management System',
        template: 'kyc-approved',
        context: {
          loginUrl: `${this.config.get('CLIENT_URL')}/login`,
        },
      });
    }
  }
}