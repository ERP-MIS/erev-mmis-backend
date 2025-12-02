// src/auth/auth.service.ts
import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { InvitationsService } from '../invitations/invitations.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private usersService: UsersService,
    private invitationsService: InvitationsService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: {
        admin: true,
        stakeholder: true,
        profile: true,
      },
    });

    if (user && await bcrypt.compare(password, user.passwordHash)) {
      const { passwordHash, ...result } = user;
      return result;
    }
    return null;
  }

  async login(loginDto: { email: string; password: string }) {
    const user = await this.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status !== 'ACTIVE') {
      throw new UnauthorizedException('Account is not active');
    }

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    const payload = { 
      email: user.email, 
      sub: user.id,
      role: user.admin ? 'ADMIN' : 'STAKEHOLDER',
      adminLevel: user.admin?.adminLevel,
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.admin ? 'ADMIN' : 'STAKEHOLDER',
        adminLevel: user.admin?.adminLevel,
        kycStatus: user.stakeholder?.kycStatus,
      },
    };
  }

  async acceptInvitation(token: string, password: string) {
    const invitation = await this.invitationsService.validateInvitation(token);
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const user = await this.prisma.user.create({
      data: {
        email: invitation.email,
        passwordHash: hashedPassword,
        firstName: 'Pending', // Will be updated in profile
        lastName: 'User',
        status: 'ACTIVE',
        emailVerified: true,
        admin: {
          create: {
            adminLevel: invitation.adminLevel,
            employeeId: `EMP-${Date.now()}`,
          },
        },
      },
      include: {
        admin: true,
      },
    });

    // Mark invitation as accepted
    await this.prisma.invitation.update({
      where: { id: invitation.id },
      data: { status: 'ACCEPTED' },
    });

    return user;
  }

  async registerStakeholder(registerDto: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    phone: string;
    businessName?: string;
    marketId: string;
  }) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: registerDto.email },
    });

    if (existingUser) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 12);

    return await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          email: registerDto.email,
          passwordHash: hashedPassword,
          firstName: registerDto.firstName,
          lastName: registerDto.lastName,
          phone: registerDto.phone,
          status: 'PENDING',
          stakeholder: {
            create: {
              kycStatus: 'PENDING',
              businessName: registerDto.businessName,
            },
          },
          profile: {
            create: {},
          },
        },
        include: {
          stakeholder: true,
        },
      });

      // Generate KYC invitation
      const kycToken = await this.invitationsService.generateKycToken(user.id);
      
      // TODO: Send KYC email with token

      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        kycToken,
      };
    });
  }
}

// src/auth/rbac.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class RbacService {
  constructor(private prisma: PrismaService) {}

  async getUserPermissions(userId: string, marketId?: string) {
    const userRoles = await this.prisma.userRole.findMany({
      where: {
        userId,
        OR: [
          { marketId: null }, // Global roles
          { marketId }, // Market-specific roles
        ],
      },
      include: {
        role: {
          include: {
            rolePermissions: {
              include: {
                permission: true,
              },
            },
          },
        },
      },
    });

    const permissions = new Map();
    
    for (const userRole of userRoles) {
      for (const rolePermission of userRole.role.rolePermissions) {
        const key = `${rolePermission.permission.resource}:${rolePermission.permission.action}`;
        permissions.set(key, {
          ...rolePermission.permission,
          conditions: rolePermission.conditions,
        });
      }
    }

    return Array.from(permissions.values());
  }

  async hasPermission(
    userId: string, 
    resource: string, 
    action: string, 
    marketId?: string
  ): Promise<boolean> {
    const permissions = await this.getUserPermissions(userId, marketId);
    
    // Check for exact permission or manage permission
    return permissions.some(perm => 
      (perm.resource === resource && perm.action === action) ||
      (perm.resource === resource && perm.action === 'MANAGE') ||
      (perm.resource === '*' && perm.action === '*')
    );
  }

  async assignRoleToUser(userId: string, roleName: string, marketId?: string) {
    const role = await this.prisma.role.findUnique({
      where: { name: roleName },
    });

    if (!role) {
      throw new Error(`Role ${roleName} not found`);
    }

    return this.prisma.userRole.create({
      data: {
        userId,
        roleId: role.id,
        marketId,
      },
    });
  }

  async getUsersByMarketAndRole(marketId: string, roleName: string) {
    const role = await this.prisma.role.findUnique({
      where: { name: roleName },
    });

    if (!role) {
      return [];
    }

    return this.prisma.userRole.findMany({
      where: {
        roleId: role.id,
        marketId,
      },
      include: {
        user: {
          include: {
            profile: true,
            admin: true,
            stakeholder: true,
          },
        },
      },
    });
  }
}