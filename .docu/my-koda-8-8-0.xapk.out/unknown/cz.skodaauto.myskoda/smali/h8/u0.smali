.class public final Lh8/u0;
.super Lh8/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ly7/g;

.field public final i:Lgr/k;

.field public final j:Ld8/j;

.field public final k:Lmb/e;

.field public final l:I

.field public final m:Lt7/o;

.field public n:Z

.field public o:J

.field public p:Z

.field public q:Z

.field public r:Ly7/z;

.field public s:Lt7/x;


# direct methods
.method public constructor <init>(Lt7/x;Ly7/g;Lgr/k;Ld8/j;Lmb/e;ILt7/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lh8/a;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/u0;->s:Lt7/x;

    .line 5
    .line 6
    iput-object p2, p0, Lh8/u0;->h:Ly7/g;

    .line 7
    .line 8
    iput-object p3, p0, Lh8/u0;->i:Lgr/k;

    .line 9
    .line 10
    iput-object p4, p0, Lh8/u0;->j:Ld8/j;

    .line 11
    .line 12
    iput-object p5, p0, Lh8/u0;->k:Lmb/e;

    .line 13
    .line 14
    iput p6, p0, Lh8/u0;->l:I

    .line 15
    .line 16
    iput-object p7, p0, Lh8/u0;->m:Lt7/o;

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    iput-boolean p1, p0, Lh8/u0;->n:Z

    .line 20
    .line 21
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    iput-wide p1, p0, Lh8/u0;->o:J

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a(Lh8/b0;Lk8/e;J)Lh8/z;
    .locals 15

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    iget-object v1, p0, Lh8/u0;->h:Ly7/g;

    .line 4
    .line 5
    invoke-interface {v1}, Ly7/g;->i()Ly7/h;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iget-object v1, p0, Lh8/u0;->r:Ly7/z;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-interface {v2, v1}, Ly7/h;->l(Ly7/z;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    invoke-virtual {p0}, Lh8/u0;->g()Lt7/x;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iget-object v1, v1, Lt7/x;->b:Lt7/u;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    new-instance v3, Lh8/r0;

    .line 26
    .line 27
    iget-object v4, v1, Lt7/u;->a:Landroid/net/Uri;

    .line 28
    .line 29
    iget-object v5, p0, Lh8/a;->g:Lb8/k;

    .line 30
    .line 31
    invoke-static {v5}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object v5, p0, Lh8/u0;->i:Lgr/k;

    .line 35
    .line 36
    iget-object v5, v5, Lgr/k;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v5, Lo8/r;

    .line 39
    .line 40
    move-object v6, v3

    .line 41
    new-instance v3, Lgw0/c;

    .line 42
    .line 43
    invoke-direct {v3, v5}, Lgw0/c;-><init>(Lo8/r;)V

    .line 44
    .line 45
    .line 46
    new-instance v5, Ld8/f;

    .line 47
    .line 48
    iget-object v7, p0, Lh8/a;->d:Ld8/f;

    .line 49
    .line 50
    iget-object v7, v7, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 51
    .line 52
    const/4 v9, 0x0

    .line 53
    invoke-direct {v5, v7, v9, v0}, Ld8/f;-><init>(Ljava/util/concurrent/CopyOnWriteArrayList;ILh8/b0;)V

    .line 54
    .line 55
    .line 56
    new-instance v7, Ld8/f;

    .line 57
    .line 58
    iget-object v10, p0, Lh8/a;->c:Ld8/f;

    .line 59
    .line 60
    iget-object v10, v10, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 61
    .line 62
    invoke-direct {v7, v10, v9, v0}, Ld8/f;-><init>(Ljava/util/concurrent/CopyOnWriteArrayList;ILh8/b0;)V

    .line 63
    .line 64
    .line 65
    iget-wide v0, v1, Lt7/u;->e:J

    .line 66
    .line 67
    invoke-static {v0, v1}, Lw7/w;->D(J)J

    .line 68
    .line 69
    .line 70
    move-result-wide v12

    .line 71
    const/4 v14, 0x0

    .line 72
    move-object v1, v4

    .line 73
    iget-object v4, p0, Lh8/u0;->j:Ld8/j;

    .line 74
    .line 75
    move-object v0, v6

    .line 76
    iget-object v6, p0, Lh8/u0;->k:Lmb/e;

    .line 77
    .line 78
    iget v10, p0, Lh8/u0;->l:I

    .line 79
    .line 80
    iget-object v11, p0, Lh8/u0;->m:Lt7/o;

    .line 81
    .line 82
    move-object v8, p0

    .line 83
    move-object/from16 v9, p2

    .line 84
    .line 85
    invoke-direct/range {v0 .. v14}, Lh8/r0;-><init>(Landroid/net/Uri;Ly7/h;Lgw0/c;Ld8/j;Ld8/f;Lmb/e;Ld8/f;Lh8/u0;Lk8/e;ILt7/o;JLl8/a;)V

    .line 86
    .line 87
    .line 88
    return-object v0
.end method

.method public final declared-synchronized g()Lt7/x;
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lh8/u0;->s:Lt7/x;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    monitor-exit p0

    .line 5
    return-object v0

    .line 6
    :catchall_0
    move-exception v0

    .line 7
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 8
    throw v0
.end method

.method public final i()V
    .locals 0

    .line 1
    return-void
.end method

.method public final k(Ly7/z;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh8/u0;->r:Ly7/z;

    .line 2
    .line 3
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lh8/a;->g:Lb8/k;

    .line 11
    .line 12
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object p1, p0, Lh8/u0;->j:Ld8/j;

    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lh8/u0;->s()V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final m(Lh8/z;)V
    .locals 6

    .line 1
    check-cast p1, Lh8/r0;

    .line 2
    .line 3
    iget-boolean p0, p1, Lh8/r0;->z:Z

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_1

    .line 7
    .line 8
    iget-object p0, p1, Lh8/r0;->w:[Lh8/x0;

    .line 9
    .line 10
    array-length v1, p0

    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, v1, :cond_1

    .line 13
    .line 14
    aget-object v3, p0, v2

    .line 15
    .line 16
    invoke-virtual {v3}, Lh8/x0;->f()V

    .line 17
    .line 18
    .line 19
    iget-object v4, v3, Lh8/x0;->h:Laq/a;

    .line 20
    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    iget-object v5, v3, Lh8/x0;->e:Ld8/f;

    .line 24
    .line 25
    invoke-virtual {v4, v5}, Laq/a;->E(Ld8/f;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, v3, Lh8/x0;->h:Laq/a;

    .line 29
    .line 30
    iput-object v0, v3, Lh8/x0;->g:Lt7/o;

    .line 31
    .line 32
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    iget-object p0, p1, Lh8/r0;->o:Lk8/l;

    .line 36
    .line 37
    iget-object v1, p0, Lk8/l;->a:Ll8/a;

    .line 38
    .line 39
    iget-object p0, p0, Lk8/l;->b:Lk8/i;

    .line 40
    .line 41
    const/4 v2, 0x1

    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    invoke-virtual {p0, v2}, Lk8/i;->a(Z)V

    .line 45
    .line 46
    .line 47
    :cond_2
    new-instance p0, Laq/p;

    .line 48
    .line 49
    const/16 v3, 0xb

    .line 50
    .line 51
    invoke-direct {p0, p1, v3}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, p0}, Ll8/a;->execute(Ljava/lang/Runnable;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, v1, Ll8/a;->e:Lj9/d;

    .line 58
    .line 59
    iget-object v1, v1, Ll8/a;->d:Ljava/util/concurrent/Executor;

    .line 60
    .line 61
    invoke-virtual {p0, v1}, Lj9/d;->accept(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object p0, p1, Lh8/r0;->t:Landroid/os/Handler;

    .line 65
    .line 66
    invoke-virtual {p0, v0}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput-object v0, p1, Lh8/r0;->u:Lh8/y;

    .line 70
    .line 71
    iput-boolean v2, p1, Lh8/r0;->R:Z

    .line 72
    .line 73
    return-void
.end method

.method public final o()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/u0;->j:Ld8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final declared-synchronized r(Lt7/x;)V
    .locals 0

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iput-object p1, p0, Lh8/u0;->s:Lt7/x;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    monitor-exit p0

    .line 5
    return-void

    .line 6
    :catchall_0
    move-exception p1

    .line 7
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 8
    throw p1
.end method

.method public final s()V
    .locals 6

    .line 1
    new-instance v0, Lh8/b1;

    .line 2
    .line 3
    iget-wide v1, p0, Lh8/u0;->o:J

    .line 4
    .line 5
    iget-boolean v3, p0, Lh8/u0;->p:Z

    .line 6
    .line 7
    iget-boolean v4, p0, Lh8/u0;->q:Z

    .line 8
    .line 9
    invoke-virtual {p0}, Lh8/u0;->g()Lt7/x;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    invoke-direct/range {v0 .. v5}, Lh8/b1;-><init>(JZZLt7/x;)V

    .line 14
    .line 15
    .line 16
    iget-boolean v1, p0, Lh8/u0;->n:Z

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    new-instance v1, Lh8/s0;

    .line 21
    .line 22
    invoke-direct {v1, v0}, Lh8/q;-><init>(Lt7/p0;)V

    .line 23
    .line 24
    .line 25
    move-object v0, v1

    .line 26
    :cond_0
    invoke-virtual {p0, v0}, Lh8/a;->l(Lt7/p0;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final t(JLo8/c0;Z)V
    .locals 2

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    cmp-long v0, p1, v0

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-wide p1, p0, Lh8/u0;->o:J

    .line 11
    .line 12
    :cond_0
    invoke-interface {p3}, Lo8/c0;->g()Z

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    iget-boolean v0, p0, Lh8/u0;->n:Z

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    iget-wide v0, p0, Lh8/u0;->o:J

    .line 21
    .line 22
    cmp-long v0, v0, p1

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    iget-boolean v0, p0, Lh8/u0;->p:Z

    .line 27
    .line 28
    if-ne v0, p3, :cond_1

    .line 29
    .line 30
    iget-boolean v0, p0, Lh8/u0;->q:Z

    .line 31
    .line 32
    if-ne v0, p4, :cond_1

    .line 33
    .line 34
    return-void

    .line 35
    :cond_1
    iput-wide p1, p0, Lh8/u0;->o:J

    .line 36
    .line 37
    iput-boolean p3, p0, Lh8/u0;->p:Z

    .line 38
    .line 39
    iput-boolean p4, p0, Lh8/u0;->q:Z

    .line 40
    .line 41
    const/4 p1, 0x0

    .line 42
    iput-boolean p1, p0, Lh8/u0;->n:Z

    .line 43
    .line 44
    invoke-virtual {p0}, Lh8/u0;->s()V

    .line 45
    .line 46
    .line 47
    return-void
.end method
