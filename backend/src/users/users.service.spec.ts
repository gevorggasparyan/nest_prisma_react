import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UserEntity } from './entities/user.entity';

jest.mock('argon2', () => ({
  hash: jest.fn().mockResolvedValue('hashedPassword'),
}));

describe('UsersService', () => {
  let usersService: UsersService;
  let prisma: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              create: jest.fn(),
              findUnique: jest.fn(),
            },
          },
        },
      ],
    }).compile();

    usersService = module.get<UsersService>(UsersService);
    prisma = module.get<PrismaService>(PrismaService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should create a new user', async () => {
    const createUserDto: CreateUserDto = {
      username: 'test_user',
      email: 'test@example.com',
      password: 'test123435',
    };

    const createdUser: UserEntity = {
      id: 1,
      username: createUserDto.username,
      email: createUserDto.email,
      password: 'hashedPassword',
    };

    (prisma.user.create as jest.Mock).mockResolvedValueOnce(createdUser);

    const result = await usersService.create(createUserDto);

    expect(result).toBeDefined();
    expect(result).toEqual(
      expect.objectContaining({
        username: createUserDto.username,
        email: createUserDto.email,
      }),
    );
    expect(prisma.user.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        ...createUserDto,
        password: 'hashedPassword',
      }),
    });
  });
  it('should find a user by ID', async () => {
    const userId = 1;
    const user: UserEntity = {
      id: userId,
      username: 'test_user',
      email: 'test@example.com',
      password: 'hashedPassword',
    };

    (prisma.user.findUnique as jest.Mock).mockResolvedValueOnce(user);

    const foundUser = await usersService.findOne(userId);

    expect(foundUser).toBeDefined();
    expect(foundUser).toEqual(user);
    expect(prisma.user.findUnique).toHaveBeenCalledWith({
      where: { id: userId },
    });
  });

  it('should return null when user with given ID is not found', async () => {
    const userId = 1;

    (prisma.user.findUnique as jest.Mock).mockResolvedValueOnce(null);

    const foundUser = await usersService.findOne(userId);

    expect(foundUser).toBeNull();
    expect(prisma.user.findUnique).toHaveBeenCalledWith({
      where: { id: userId },
    });
  });
});
