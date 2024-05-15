import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import * as argon2 from 'argon2';

describe('AuthService', () => {
  let authService: AuthService;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        PrismaService,
        {
          provide: JwtService,
          useValue: new JwtService({
            secret: 'your_secret_key_here',
          }),
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('login', () => {
    it('should return an access token if the username and password are correct', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        password: await argon2.hash('password'), // Hashed password
        email: 'testemail@example.com',
      };
      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(mockUser);

      const argon2Compare = jest.fn().mockResolvedValue(true); // Correct password

      jest.spyOn(argon2, 'verify').mockImplementation(argon2Compare)
      const result = await authService.login('testuser', 'password');

      expect(result.accessToken).toBeDefined();
    });

    it('should throw NotFoundException if no user is found for the given username', async () => {
      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(null);

      await expect(authService.login('testuser', 'password')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw UnauthorizedException if the password is invalid', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        password: await argon2.hash('secretPassword'),
        email: 'testemail@example.com',
      };
      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(mockUser);

      const argon2Compare = jest.fn().mockResolvedValue(false);
      jest.spyOn(argon2, 'verify').mockImplementation(argon2Compare);

      await expect(authService.login('testuser', 'password')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
