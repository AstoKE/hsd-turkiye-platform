import { config } from 'dotenv';
config({ path: '../.env' });

import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient({
  datasourceUrl: process.env.DATABASE_URL,
});

async function main() {
  const adminRole = await prisma.role.upsert({
    where: { name: 'SUPER_ADMIN' },
    update: {},
    create: {
      name: 'SUPER_ADMIN',
      description: 'System super admin',
    },
  });

  const passwordHash = await argon2.hash('Admin123!');

  await prisma.user.upsert({
    where: { email: 'admin@hsd.local' },
    update: {},
    create: {
      fullName: 'System Admin',
      email: 'admin@hsd.local',
      passwordHash,
      roleId: adminRole.id,
    },
  });
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (error) => {
    console.error(error);
    await prisma.$disconnect();
    process.exit(1);
  });