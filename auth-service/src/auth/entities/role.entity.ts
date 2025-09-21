import { Entity, ManyToMany, PrimaryGeneratedColumn, Column } from 'typeorm'
import { AuthUser } from './auth-user.entity'

@Entity('roles')
export class Role {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column({ unique: true })
  name: string

  @ManyToMany(() => AuthUser, (user) => user.roles)
  users: AuthUser[]
}
