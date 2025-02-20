import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from "typeorm";
//import { RefreshToken } from "./refresh-token";
import { RefreshToken } from './refresh-token.entity';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user, {
    cascade: true,
    eager: false,
    nullable: true
  })
  refreshTokens: RefreshToken[];
  /*@Column({
    type: 'enum',
    enum: ['employee', 'admin'],
    default: 'employee'
  })
  role: 'employee' | 'admin' = 'employee';*/
}