import { Column, Entity, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import User from "./User";
@Entity()
export class Profile {
  @PrimaryGeneratedColumn("uuid")
  id: string;

  @Column({ unique: true })
  username: string;

  @Column({ nullable: true })
  firstname: string;

  @Column({ nullable: true })
  lastname: string;

  @OneToOne(() => User, (user) => user.profile, { onDelete: "CASCADE" })
  user: User;
}
