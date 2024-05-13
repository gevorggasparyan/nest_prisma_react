import { Test, TestingModule } from '@nestjs/testing';
import { TasksService } from './tasks.service';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';

describe('TasksService', () => {
  let service: TasksService;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TasksService, PrismaService],
    }).compile();

    service = module.get<TasksService>(TasksService);
    prismaService = module.get<PrismaService>(PrismaService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    it('should create a task', async () => {
      const createTaskDto: CreateTaskDto = {
        title: 'Task Title',
        completed: false,
        description: 'Task Description',
      };

      const mockTask = { id: 1, ...createTaskDto };

      jest
        .spyOn(prismaService.task, 'create')
        .mockResolvedValueOnce(mockTask as any);

      const result = await service.create(1, createTaskDto);

      expect(result).toEqual(mockTask);
    });
  });

  describe('findAll', () => {
    it('should return tasks and totalTasksCount', async () => {
      const userId = 1;
      const page = 1;
      const pageSize = 10;

      const mockTasks = [
        { id: 1, userId: 1, description: 'Task 1' },
        { id: 2, userId: 1, description: 'Task 2' },
      ];

      const mockTotalTasksCount = 2;

      jest
        .spyOn(prismaService.task, 'findMany')
        .mockResolvedValue(mockTasks as any);
      jest
        .spyOn(prismaService.task, 'count')
        .mockResolvedValue(mockTotalTasksCount);

      const result = await service.findAll(userId, page, pageSize);

      expect(result.tasks).toEqual(mockTasks);
      expect(result.totalTasksCount).toBe(mockTotalTasksCount);
    });
  });

  describe('update', () => {
    it('should update a task by id for a user', async () => {
      const updateTaskDto: UpdateTaskDto = {
        title: 'Updated Task Title',
        completed: true,
        description: 'Updated Task Description',
      };

      const mockUpdatedTask = { id: 1, ...updateTaskDto };

      jest
        .spyOn(prismaService.task, 'update')
        .mockResolvedValueOnce(mockUpdatedTask as any);

      const result = await service.update(1, 1, updateTaskDto);

      expect(result).toEqual(mockUpdatedTask);
    });
  });
});
