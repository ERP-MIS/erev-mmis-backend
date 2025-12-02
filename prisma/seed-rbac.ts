// prisma/seed-rbac.ts
import { PrismaClient, AdminLevel, PermissionResource, PermissionAction } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

const ROLES_HIERARCHY = {
  SUPER_ADMIN: { level: 1, description: 'Full system control' },
  NATIONAL_ADMIN: { level: 2, description: 'Country-wide governance' },
  DISTRICT_ADMIN: { level: 3, description: 'Regional management' },
  CITY_ADMIN: { level: 4, description: 'City-wide management' },
  MARKET_MASTER: { level: 5, description: 'Individual market operations' },
  PSEUDO_MARKET_MASTER: { level: 6, description: 'Specialized market roles' },
  VENDOR: { level: 7, description: 'Market vendors and shop owners' },
  SUPPLIER: { level: 8, description: 'Product suppliers' },
  CUSTOMER: { level: 9, description: 'End consumers' },
};

const PERMISSIONS = [
  // User Management
  { resource: PermissionResource.USER, action: PermissionAction.MANAGE, description: 'Full user management' },
  { resource: PermissionResource.USER, action: PermissionAction.CREATE, description: 'Create users' },
  { resource: PermissionResource.USER, action: PermissionAction.READ, description: 'View users' },
  { resource: PermissionResource.USER, action: PermissionAction.UPDATE, description: 'Update users' },
  { resource: PermissionResource.USER, action: PermissionAction.DELETE, description: 'Delete users' },

  // Market Management
  { resource: PermissionResource.MARKET, action: PermissionAction.MANAGE, description: 'Full market management' },
  { resource: PermissionResource.MARKET, action: PermissionAction.CREATE, description: 'Create markets' },
  { resource: PermissionResource.MARKET, action: PermissionAction.READ, description: 'View markets' },
  { resource: PermissionResource.MARKET, action: PermissionAction.UPDATE, description: 'Update markets' },

  // KYC Management
  { resource: PermissionResource.KYC, action: PermissionAction.MANAGE, description: 'Full KYC management' },
  { resource: PermissionResource.KYC, action: PermissionAction.APPROVE, description: 'Approve KYC' },
  { resource: PermissionResource.KYC, action: PermissionAction.VERIFY, description: 'Verify KYC documents' },

  // Invitation Management
  { resource: PermissionResource.INVITATION, action: PermissionAction.MANAGE, description: 'Full invitation management' },
  { resource: PermissionResource.INVITATION, action: PermissionAction.CREATE, description: 'Send invitations' },

  // Financial Permissions
  { resource: PermissionResource.PAYMENT, action: PermissionAction.MANAGE, description: 'Full payment management' },
  { resource: PermissionResource.TAX, action: PermissionAction.MANAGE, description: 'Full tax management' },

  // Reporting
  { resource: PermissionResource.REPORT, action: PermissionAction.READ, description: 'View reports' },
  { resource: PermissionResource.REPORT, action: PermissionAction.EXPORT, description: 'Export reports' },
];

const ROLE_PERMISSIONS = {
  SUPER_ADMIN: ['*'], // All permissions
  NATIONAL_ADMIN: [
    'USER:READ', 'USER:CREATE', 'USER:UPDATE',
    'MARKET:READ', 'MARKET:CREATE', 'MARKET:UPDATE',
    'KYC:MANAGE', 'INVITATION:MANAGE', 'REPORT:READ', 'REPORT:EXPORT'
  ],
  MARKET_MASTER: [
    'USER:READ', 'USER:CREATE', 'USER:UPDATE',
    'MARKET:READ', 'MARKET:UPDATE',
    'KYC:APPROVE', 'KYC:VERIFY',
    'INVITATION:CREATE',
    'REPORT:READ'
  ],
  VENDOR: [
    'USER:READ', 'USER:UPDATE',
    'PRODUCT:CREATE', 'PRODUCT:READ', 'PRODUCT:UPDATE',
    'INVENTORY:CREATE', 'INVENTORY:READ', 'INVENTORY:UPDATE',
    'PAYMENT:READ'
  ],
};

async function seedRBAC() {
  console.log('Seeding RBAC system...');

  // Create permissions
  for (const perm of PERMISSIONS) {
    await prisma.permission.upsert({
      where: { name: `${perm.resource}:${perm.action}` },
      update: {},
      create: {
        name: `${perm.resource}:${perm.action}`,
        resource: perm.resource,
        action: perm.action,
        description: perm.description,
      },
    });
  }

  // Create roles
  for (const [roleName, roleData] of Object.entries(ROLES_HIERARCHY)) {
    await prisma.role.upsert({
      where: { name: roleName },
      update: { level: roleData.level, description: roleData.description },
      create: {
        name: roleName,
        level: roleData.level,
        description: roleData.description,
        isSystemRole: true,
      },
    });
  }

  // Assign permissions to roles
  for (const [roleName, permissions] of Object.entries(ROLE_PERMISSIONS)) {
    const role = await prisma.role.findUnique({ where: { name: roleName } });
    
    if (permissions.includes('*')) {
      // Assign all permissions
      const allPermissions = await prisma.permission.findMany();
      for (const permission of allPermissions) {
        await prisma.rolePermission.upsert({
          where: { roleId_permissionId: { roleId: role.id, permissionId: permission.id } },
          update: {},
          create: {
            roleId: role.id,
            permissionId: permission.id,
          },
        });
      }
    } else {
      for (const permString of permissions) {
        const [resource, action] = permString.split(':');
        const permission = await prisma.permission.findUnique({
          where: { name: permString },
        });
        
        if (permission) {
          await prisma.rolePermission.upsert({
            where: { roleId_permissionId: { roleId: role.id, permissionId: permission.id } },
            update: {},
            create: {
              roleId: role.id,
              permissionId: permission.id,
            },
          });
        }
      }
    }
  }

  console.log('RBAC seeding completed');
}

export { seedRBAC };