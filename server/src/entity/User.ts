import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
} from "typeorm";
import { Profile } from "./Profile";

@Entity()
export default class User {
  @PrimaryGeneratedColumn("uuid")
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @OneToOne(() => Profile, (profile) => profile.user, { onDelete: "CASCADE" })
  @JoinColumn()
  profile: Profile;

  @Column({ type: "simple-array", nullable: true })
  refreshToken: string[];
}
