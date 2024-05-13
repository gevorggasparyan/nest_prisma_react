import { Injectable } from '@nestjs/common';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class TasksService {
  constructor(private prisma: PrismaService) {}

  async create(userId: number, createTaskDto: CreateTaskDto) {
    return this.prisma.task.create({
      data: {
        userId,
        ...createTaskDto,
      },
    });
  }

  async findAll(userId: number, page: number, pageSize: number) {
    const skip = (page - 1) * pageSize;
    const take = pageSize;

    const tasks = await this.prisma.task.findMany({
      where: { userId },
      skip,
      take,
      orderBy: { id: 'desc' },
    });

    const totalTasksCount = await this.prisma.task.count({
      where: { userId },
    });

    return { tasks, totalTasksCount };
  }

  async update(userId: number, id: number, updateTaskDto: UpdateTaskDto) {
    return this.prisma.task.update({
      where: { userId, id },
      data: updateTaskDto,
    });
  }

  async remove(userId: number, id: number) {
    await this.prisma.task.delete({
      where: { userId, id },
    });
  }
}
