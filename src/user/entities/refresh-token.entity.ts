import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from 'typeorm';
import { User } from './user.entity';  // Corrigez ce chemin

@Entity ()// Nom de la table MySQL
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid') // Génère un UUID unique
  id: string;

  @Column({ type: 'text', nullable: false }) // Stocke le token
  token: string;
  @ManyToOne(() => User, (user) => user.refreshTokens, {
    onDelete: 'CASCADE'
  })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column()
  userId: number;

  @Column({ type: 'timestamp', nullable: false })
  expiryDate: Date;
}
