.class public final Lk01/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/g0;


# instance fields
.field public final d:I

.field public final e:Lk01/p;

.field public final f:Lh/e0;

.field public g:J

.field public h:J

.field public final i:Ljava/util/ArrayDeque;

.field public j:Z

.field public final k:Lk01/v;

.field public final l:Lk01/u;

.field public final m:Lk01/w;

.field public final n:Lk01/w;

.field public o:Lk01/b;

.field public p:Ljava/io/IOException;


# direct methods
.method public constructor <init>(ILk01/p;ZZLd01/y;)V
    .locals 3

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lk01/x;->d:I

    .line 10
    .line 11
    iput-object p2, p0, Lk01/x;->e:Lk01/p;

    .line 12
    .line 13
    new-instance v0, Lh/e0;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Lh/e0;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lk01/x;->f:Lh/e0;

    .line 19
    .line 20
    iget-object p1, p2, Lk01/p;->u:Lk01/b0;

    .line 21
    .line 22
    invoke-virtual {p1}, Lk01/b0;->a()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    int-to-long v0, p1

    .line 27
    iput-wide v0, p0, Lk01/x;->h:J

    .line 28
    .line 29
    new-instance p1, Ljava/util/ArrayDeque;

    .line 30
    .line 31
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lk01/x;->i:Ljava/util/ArrayDeque;

    .line 35
    .line 36
    new-instance v0, Lk01/v;

    .line 37
    .line 38
    iget-object p2, p2, Lk01/p;->t:Lk01/b0;

    .line 39
    .line 40
    invoke-virtual {p2}, Lk01/b0;->a()I

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    int-to-long v1, p2

    .line 45
    invoke-direct {v0, p0, v1, v2, p4}, Lk01/v;-><init>(Lk01/x;JZ)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Lk01/x;->k:Lk01/v;

    .line 49
    .line 50
    new-instance p2, Lk01/u;

    .line 51
    .line 52
    invoke-direct {p2, p0, p3}, Lk01/u;-><init>(Lk01/x;Z)V

    .line 53
    .line 54
    .line 55
    iput-object p2, p0, Lk01/x;->l:Lk01/u;

    .line 56
    .line 57
    new-instance p2, Lk01/w;

    .line 58
    .line 59
    invoke-direct {p2, p0}, Lk01/w;-><init>(Lk01/x;)V

    .line 60
    .line 61
    .line 62
    iput-object p2, p0, Lk01/x;->m:Lk01/w;

    .line 63
    .line 64
    new-instance p2, Lk01/w;

    .line 65
    .line 66
    invoke-direct {p2, p0}, Lk01/w;-><init>(Lk01/x;)V

    .line 67
    .line 68
    .line 69
    iput-object p2, p0, Lk01/x;->n:Lk01/w;

    .line 70
    .line 71
    if-eqz p5, :cond_1

    .line 72
    .line 73
    invoke-virtual {p0}, Lk01/x;->h()Z

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-nez p0, :cond_0

    .line 78
    .line 79
    invoke-virtual {p1, p5}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    return-void

    .line 83
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 84
    .line 85
    const-string p1, "locally-initiated streams shouldn\'t have headers yet"

    .line 86
    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_1
    invoke-virtual {p0}, Lk01/x;->h()Z

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    if-eqz p0, :cond_2

    .line 96
    .line 97
    return-void

    .line 98
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 99
    .line 100
    const-string p1, "remotely-initiated streams should have headers"

    .line 101
    .line 102
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw p0
.end method


# virtual methods
.method public final a()Lu01/f0;
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/x;->l:Lk01/u;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()V
    .locals 2

    .line 1
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-object v0, p0, Lk01/x;->k:Lk01/v;

    .line 5
    .line 6
    iget-boolean v1, v0, Lk01/v;->e:Z

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    iget-boolean v0, v0, Lk01/v;->i:Z

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object v0, p0, Lk01/x;->l:Lk01/u;

    .line 15
    .line 16
    iget-boolean v1, v0, Lk01/u;->d:Z

    .line 17
    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    iget-boolean v0, v0, Lk01/u;->f:Z

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception v0

    .line 26
    goto :goto_2

    .line 27
    :cond_0
    :goto_0
    const/4 v0, 0x1

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/4 v0, 0x0

    .line 30
    :goto_1
    invoke-virtual {p0}, Lk01/x;->i()Z

    .line 31
    .line 32
    .line 33
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    monitor-exit p0

    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    sget-object v0, Lk01/b;->k:Lk01/b;

    .line 38
    .line 39
    const/4 v1, 0x0

    .line 40
    invoke-virtual {p0, v0, v1}, Lk01/x;->d(Lk01/b;Ljava/io/IOException;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    if-nez v1, :cond_3

    .line 45
    .line 46
    iget-object v0, p0, Lk01/x;->e:Lk01/p;

    .line 47
    .line 48
    iget p0, p0, Lk01/x;->d:I

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Lk01/p;->d(I)Lk01/x;

    .line 51
    .line 52
    .line 53
    :cond_3
    return-void

    .line 54
    :goto_2
    monitor-exit p0

    .line 55
    throw v0
.end method

.method public final c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lk01/x;->l:Lk01/u;

    .line 2
    .line 3
    iget-boolean v1, v0, Lk01/u;->f:Z

    .line 4
    .line 5
    if-nez v1, :cond_3

    .line 6
    .line 7
    iget-boolean v0, v0, Lk01/u;->d:Z

    .line 8
    .line 9
    if-nez v0, :cond_2

    .line 10
    .line 11
    invoke-virtual {p0}, Lk01/x;->g()Lk01/b;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    iget-object v0, p0, Lk01/x;->p:Ljava/io/IOException;

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v0, Lk01/c0;

    .line 23
    .line 24
    invoke-virtual {p0}, Lk01/x;->g()Lk01/b;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-direct {v0, p0}, Lk01/c0;-><init>(Lk01/b;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    throw v0

    .line 35
    :cond_1
    return-void

    .line 36
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 37
    .line 38
    const-string v0, "stream finished"

    .line 39
    .line 40
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 45
    .line 46
    const-string v0, "stream closed"

    .line 47
    .line 48
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0
.end method

.method public final cancel()V
    .locals 1

    .line 1
    sget-object v0, Lk01/b;->k:Lk01/b;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lk01/x;->f(Lk01/b;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d(Lk01/b;Ljava/io/IOException;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lk01/x;->e(Lk01/b;Ljava/io/IOException;)Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget p2, p0, Lk01/x;->d:I

    .line 9
    .line 10
    iget-object p0, p0, Lk01/x;->e:Lk01/p;

    .line 11
    .line 12
    iget-object p0, p0, Lk01/p;->z:Lk01/y;

    .line 13
    .line 14
    invoke-virtual {p0, p2, p1}, Lk01/y;->j(ILk01/b;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final e(Lk01/b;Ljava/io/IOException;)Z
    .locals 2

    .line 1
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Lk01/x;->g()Lk01/b;

    .line 5
    .line 6
    .line 7
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    monitor-exit p0

    .line 12
    return v1

    .line 13
    :cond_0
    :try_start_1
    iput-object p1, p0, Lk01/x;->o:Lk01/b;

    .line 14
    .line 15
    iput-object p2, p0, Lk01/x;->p:Ljava/io/IOException;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 18
    .line 19
    .line 20
    iget-object p1, p0, Lk01/x;->k:Lk01/v;

    .line 21
    .line 22
    iget-boolean p1, p1, Lk01/v;->e:Z

    .line 23
    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    iget-object p1, p0, Lk01/x;->l:Lk01/u;

    .line 27
    .line 28
    iget-boolean p1, p1, Lk01/u;->d:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    monitor-exit p0

    .line 33
    return v1

    .line 34
    :catchall_0
    move-exception p1

    .line 35
    goto :goto_0

    .line 36
    :cond_1
    monitor-exit p0

    .line 37
    iget-object p1, p0, Lk01/x;->e:Lk01/p;

    .line 38
    .line 39
    iget p0, p0, Lk01/x;->d:I

    .line 40
    .line 41
    invoke-virtual {p1, p0}, Lk01/p;->d(I)Lk01/x;

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    return p0

    .line 46
    :goto_0
    monitor-exit p0

    .line 47
    throw p1
.end method

.method public final f(Lk01/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Lk01/x;->e(Lk01/b;Ljava/io/IOException;)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object v0, p0, Lk01/x;->e:Lk01/p;

    .line 10
    .line 11
    iget p0, p0, Lk01/x;->d:I

    .line 12
    .line 13
    invoke-virtual {v0, p0, p1}, Lk01/p;->j(ILk01/b;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final g()Lk01/b;
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lk01/x;->o:Lk01/b;
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
    monitor-exit p0

    .line 8
    throw v0
.end method

.method public final getSource()Lu01/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/x;->k:Lk01/v;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Z
    .locals 3

    .line 1
    iget v0, p0, Lk01/x;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    and-int/2addr v0, v1

    .line 5
    const/4 v2, 0x0

    .line 6
    if-ne v0, v1, :cond_0

    .line 7
    .line 8
    move v0, v1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move v0, v2

    .line 11
    :goto_0
    iget-object p0, p0, Lk01/x;->e:Lk01/p;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    if-ne v1, v0, :cond_1

    .line 17
    .line 18
    return v1

    .line 19
    :cond_1
    return v2
.end method

.method public final i()Z
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lk01/x;->g()Lk01/b;

    .line 3
    .line 4
    .line 5
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    monitor-exit p0

    .line 10
    return v1

    .line 11
    :cond_0
    :try_start_1
    iget-object v0, p0, Lk01/x;->k:Lk01/v;

    .line 12
    .line 13
    iget-boolean v2, v0, Lk01/v;->e:Z

    .line 14
    .line 15
    if-nez v2, :cond_1

    .line 16
    .line 17
    iget-boolean v0, v0, Lk01/v;->i:Z

    .line 18
    .line 19
    if-eqz v0, :cond_3

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception v0

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    :goto_0
    iget-object v0, p0, Lk01/x;->l:Lk01/u;

    .line 25
    .line 26
    iget-boolean v2, v0, Lk01/u;->d:Z

    .line 27
    .line 28
    if-nez v2, :cond_2

    .line 29
    .line 30
    iget-boolean v0, v0, Lk01/u;->f:Z

    .line 31
    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    :cond_2
    iget-boolean v0, p0, Lk01/x;->j:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 35
    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    monitor-exit p0

    .line 39
    return v1

    .line 40
    :cond_3
    monitor-exit p0

    .line 41
    const/4 p0, 0x1

    .line 42
    return p0

    .line 43
    :goto_1
    monitor-exit p0

    .line 44
    throw v0
.end method

.method public final j(Ld01/y;Z)V
    .locals 2

    .line 1
    const-string v0, "headers"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 7
    .line 8
    monitor-enter p0

    .line 9
    :try_start_0
    iget-boolean v0, p0, Lk01/x;->j:Z

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    const-string v0, ":status"

    .line 15
    .line 16
    invoke-virtual {p1, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    const-string v0, ":method"

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object v0, p0, Lk01/x;->k:Lk01/v;

    .line 32
    .line 33
    iput-object p1, v0, Lk01/v;->h:Ld01/y;

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :catchall_0
    move-exception p1

    .line 37
    goto :goto_2

    .line 38
    :cond_1
    :goto_0
    iput-boolean v1, p0, Lk01/x;->j:Z

    .line 39
    .line 40
    iget-object v0, p0, Lk01/x;->i:Ljava/util/ArrayDeque;

    .line 41
    .line 42
    invoke-virtual {v0, p1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    :goto_1
    if-eqz p2, :cond_2

    .line 46
    .line 47
    iget-object p1, p0, Lk01/x;->k:Lk01/v;

    .line 48
    .line 49
    iput-boolean v1, p1, Lk01/v;->e:Z

    .line 50
    .line 51
    :cond_2
    invoke-virtual {p0}, Lk01/x;->i()Z

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 56
    .line 57
    .line 58
    monitor-exit p0

    .line 59
    if-nez p1, :cond_3

    .line 60
    .line 61
    iget-object p1, p0, Lk01/x;->e:Lk01/p;

    .line 62
    .line 63
    iget p0, p0, Lk01/x;->d:I

    .line 64
    .line 65
    invoke-virtual {p1, p0}, Lk01/p;->d(I)Lk01/x;

    .line 66
    .line 67
    .line 68
    :cond_3
    return-void

    .line 69
    :goto_2
    monitor-exit p0

    .line 70
    throw p1
.end method
