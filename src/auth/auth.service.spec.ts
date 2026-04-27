import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';

jest.mock('bcryptjs', () => ({
  compare: jest.fn(),
  hash: jest.fn(),
}));

import * as bcrypt from 'bcryptjs';

const mockUser = {
  id: 'user-1',
  name: 'Test User',
  email: 'test@example.com',
  password: '$2a$10$hashedpassword',
  createdAt: new Date(),
};

const mockUsersService = {
  create: jest.fn(),
  findByEmail: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn().mockReturnValue('mock.jwt.token'),
};

describe('AuthService — Unit Tests', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: mockUsersService },
        { provide: JwtService, useValue: mockJwtService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jest.clearAllMocks();
  });

  // ─── register() ────────────────────────────────────────────────────────────

  describe('register()', () => {
    it('creates user and returns user + token', async () => {
      mockUsersService.create.mockResolvedValue(mockUser);

      const result = await service.register({ name: 'Test User', email: 'test@example.com', password: '123456' });

      expect(mockUsersService.create).toHaveBeenCalledWith({
        name: 'Test User',
        email: 'test@example.com',
        password: '123456',
      });
      expect(result.user).toEqual(mockUser);
      expect(result.token).toBe('mock.jwt.token');
    });

    it('signs JWT with user id, email, and name', async () => {
      mockUsersService.create.mockResolvedValue(mockUser);
      await service.register({ name: 'Test User', email: 'test@example.com', password: '123456' });

      expect(mockJwtService.sign).toHaveBeenCalledWith({
        sub: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
      });
    });

    it('propagates error when usersService.create throws', async () => {
      mockUsersService.create.mockRejectedValue(new Error('Email already in use'));
      await expect(
        service.register({ name: 'Dup', email: 'dup@example.com', password: '123456' }),
      ).rejects.toThrow('Email already in use');
    });
  });

  // ─── login() ───────────────────────────────────────────────────────────────

  describe('login()', () => {
    it('throws UnauthorizedException when user not found', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.login({ email: 'nobody@example.com', password: 'any' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('throws UnauthorizedException when password is wrong', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.login({ email: 'test@example.com', password: 'wrongpass' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('returns user (without password) and token on success', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.login({ email: 'test@example.com', password: 'correctpass' });

      expect(result.token).toBe('mock.jwt.token');
      expect(result.user).not.toHaveProperty('password');
      expect(result.user).toMatchObject({ id: 'user-1', email: 'test@example.com' });
    });

    it('signs JWT with correct payload on login', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      await service.login({ email: 'test@example.com', password: 'correctpass' });

      expect(mockJwtService.sign).toHaveBeenCalledWith({
        sub: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
      });
    });
  });
});
