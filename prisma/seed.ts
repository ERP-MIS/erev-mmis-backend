// prisma/seed.ts
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  // Create super admin
  const superAdminPassword = await bcrypt.hash('admin123', 12);
  
  const superAdmin = await prisma.user.create({
    data: {
      email: 'superadmin@uganda.gov',
      passwordHash: superAdminPassword,
      firstName: 'Super',
      lastName: 'Admin',
      status: 'ACTIVE',
      emailVerified: true,
      admin: {
        create: {
          adminLevel: 'SUPER_ADMIN',
          employeeId: 'SA-001',
          superAdmin: {
            create: {
              globalSettings: {},
            },
          },
        },
      },
      profile: {
        create: {},
      },
    },
  });

  // Create sample geolocation hierarchy
  const centralRegion = await prisma.geolocation.create({
    data: {
      name: 'Central Region',
      code: 'CENTRAL',
      country: 'Uganda',
      timezone: 'Africa/Kampala',
      districts: {
        create: [
          {
            name: 'Kampala District',
            code: 'KLA',
            cities: {
              create: [
                {
                  name: 'Kampala Central',
                  code: 'KLA-CENTRAL',
                  markets: {
                    create: [
                      {
                        name: 'Owino Market',
                        code: 'OWINO',
                        address: 'St. Balikuddembe Market, Kampala',
                        latitude: 0.3136,
                        longitude: 32.5811,
                      },
                    ],
                  },
                },
              ],
            },
          },
        ],
      },
    },
  });

  console.log('Seed data created successfully');
  console.log('Super Admin:', superAdmin.email);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });