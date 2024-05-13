import { Injectable, PipeTransform } from '@nestjs/common';
import { BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateUserDto } from '../../users/dto/create-user.dto';

@Injectable()
export class IsUniquePipe implements PipeTransform {
  constructor(private prisma: PrismaService) {}

  async transform(value: CreateUserDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { username: value.username },
    });

    if (existingUser) {
      throw new BadRequestException('Username already exists');
    }

    return value;
  }
}
