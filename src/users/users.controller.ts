import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersService } from './users.service';
import { CurrentUser } from 'src/auth/current-user.decorator';
import { User } from './schema/user.schema';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@Controller('users')
export class UsersController {
    constructor(private readonly userService: UsersService){}

    @Post()
    async createUser(
        @Body() createUserDto: CreateUserDto
    ) {
        await this.userService.create(createUserDto);
    }

    @Get()
    @UseGuards(JwtAuthGuard)
    async getUsers(
        @CurrentUser() user: User
    ) {
        console.log(user);
        return this.userService.getUsers();
    }
}
