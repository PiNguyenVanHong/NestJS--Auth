import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { FilterQuery, Model, UpdateQuery } from 'mongoose';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    private SALT_ROUND = 10;
    constructor(
        @InjectModel(User.name) private readonly userModel: Model<User>,
    ){}

    async create(createUserDto: CreateUserDto) {
        await new this.userModel({
            ...createUserDto,
            password: await this.hashPlainContent(createUserDto.password),
        }).save();
    }

    async getUser(query: FilterQuery<User>) {
        const user = (await this.userModel.findOne(query)).toObject();

        if(!user) {
            throw new NotFoundException("Your email is not exist!!!");
        }

        return user;
    }

    async getUsers() {
        return await this.userModel.find({});
    }

    async hashPlainContent(plainText: string) {
        return await bcrypt.hash(plainText, this.SALT_ROUND);
    }

    async verifyPlainContentWithHashedContent(
        plain_text: string,
        hashed_text: string,
        message?: string,
    ) {
        const is_matching = await bcrypt.compare(plain_text, hashed_text);
        if (!is_matching) {
            throw new BadRequestException(message);
        }
    }

    async updateUser(query: FilterQuery<User>, data: UpdateQuery<User>) {
        return this.userModel.findOneAndUpdate(query, data);
    }
}
