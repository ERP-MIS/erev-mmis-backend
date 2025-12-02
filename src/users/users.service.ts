// src/users/users.service.ts
import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findById(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: {
        admin: {
          include: {
            superAdmin: true,
            nationalAdmin: true,
            cityAdmin: { include: { city: true } },
            marketMaster: { include: { market: true } },
            pseudoMarketMaster: { include: { market: true } },
          },
        },
        stakeholder: {
          include: {
            marketAuthority: true,
            member: true,
            vendor: true,
            supplier: true,
            customer: true,
          },
        },
        profile: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
      include: {
        admin: true,
        stakeholder: true,
        profile: true,
      },
    });
  }

  async updateProfile(userId: string, profileData: any) {
    return this.prisma.userProfile.upsert({
      where: { userId },
      update: profileData,
      create: {
        userId,
        ...profileData,
      },
    });
  }

  async getDashboardData(userId: string) {
    const user = await this.findById(userId);
    
    let dashboardData = {};

    if (user.admin) {
      // Admin dashboard data
      dashboardData = await this.getAdminDashboardData(user.admin);
    } else if (user.stakeholder) {
      // Stakeholder dashboard data
      dashboardData = await this.getStakeholderDashboardData(user.stakeholder);
    }

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.admin ? 'ADMIN' : 'STAKEHOLDER',
        adminLevel: user.admin?.adminLevel,
      },
      ...dashboardData,
    };
  }

  private async getAdminDashboardData(admin: any) {
    // Implement admin-specific dashboard data
    const stats = await this.prisma.user.aggregate({
      _count: {
        _all: true,
      },
      where: {
        status: 'ACTIVE',
      },
    });

    return {
      totalUsers: stats._count._all,
      adminLevel: admin.adminLevel,
      // Add more admin-specific stats
    };
  }

  private async getStakeholderDashboardData(stakeholder: any) {
    // Implement stakeholder-specific dashboard data
    return {
      kycStatus: stakeholder.kycStatus,
      businessName: stakeholder.businessName,
      // Add more stakeholder-specific stats
    };
  }
}