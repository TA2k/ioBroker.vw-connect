.class public final Lw7/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:J

.field public b:J

.field public c:J

.field public final d:Ljava/lang/ThreadLocal;


# direct methods
.method public constructor <init>(J)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lw7/u;->d:Ljava/lang/ThreadLocal;

    .line 10
    .line 11
    invoke-virtual {p0, p1, p2}, Lw7/u;->e(J)V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final declared-synchronized a(J)J
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 3
    .line 4
    .line 5
    .line 6
    .line 7
    cmp-long v2, p1, v0

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    monitor-exit p0

    .line 12
    return-wide v0

    .line 13
    :cond_0
    :try_start_0
    monitor-enter p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    :try_start_1
    iget-wide v2, p0, Lw7/u;->b:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 15
    .line 16
    cmp-long v0, v2, v0

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_1
    const/4 v0, 0x0

    .line 23
    :goto_0
    :try_start_2
    monitor-exit p0

    .line 24
    if-nez v0, :cond_3

    .line 25
    .line 26
    iget-wide v0, p0, Lw7/u;->a:J

    .line 27
    .line 28
    const-wide v2, 0x7ffffffffffffffeL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    cmp-long v2, v0, v2

    .line 34
    .line 35
    if-nez v2, :cond_2

    .line 36
    .line 37
    iget-object v0, p0, Lw7/u;->d:Ljava/lang/ThreadLocal;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Ljava/lang/Long;

    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 49
    .line 50
    .line 51
    move-result-wide v0

    .line 52
    goto :goto_1

    .line 53
    :catchall_0
    move-exception p1

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    :goto_1
    sub-long/2addr v0, p1

    .line 56
    iput-wide v0, p0, Lw7/u;->b:J

    .line 57
    .line 58
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 59
    .line 60
    .line 61
    :cond_3
    iput-wide p1, p0, Lw7/u;->c:J

    .line 62
    .line 63
    iget-wide v0, p0, Lw7/u;->b:J
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 64
    .line 65
    add-long/2addr p1, v0

    .line 66
    monitor-exit p0

    .line 67
    return-wide p1

    .line 68
    :catchall_1
    move-exception p1

    .line 69
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 70
    :try_start_4
    throw p1

    .line 71
    :goto_2
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 72
    throw p1
.end method

.method public final declared-synchronized b(J)J
    .locals 10

    .line 1
    monitor-enter p0

    .line 2
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 3
    .line 4
    .line 5
    .line 6
    .line 7
    cmp-long v2, p1, v0

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    monitor-exit p0

    .line 12
    return-wide v0

    .line 13
    :cond_0
    :try_start_0
    iget-wide v3, p0, Lw7/u;->c:J

    .line 14
    .line 15
    cmp-long v0, v3, v0

    .line 16
    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 20
    .line 21
    sget-object v9, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 22
    .line 23
    const-wide/32 v5, 0x15f90

    .line 24
    .line 25
    .line 26
    const-wide/32 v7, 0xf4240

    .line 27
    .line 28
    .line 29
    invoke-static/range {v3 .. v9}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    const-wide v2, 0x100000000L

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    add-long/2addr v2, v0

    .line 39
    const-wide v4, 0x200000000L

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    div-long/2addr v2, v4

    .line 45
    const-wide/16 v6, 0x1

    .line 46
    .line 47
    sub-long v6, v2, v6

    .line 48
    .line 49
    mul-long/2addr v6, v4

    .line 50
    add-long/2addr v6, p1

    .line 51
    mul-long/2addr v2, v4

    .line 52
    add-long/2addr v2, p1

    .line 53
    sub-long p1, v6, v0

    .line 54
    .line 55
    invoke-static {p1, p2}, Ljava/lang/Math;->abs(J)J

    .line 56
    .line 57
    .line 58
    move-result-wide p1

    .line 59
    sub-long v0, v2, v0

    .line 60
    .line 61
    invoke-static {v0, v1}, Ljava/lang/Math;->abs(J)J

    .line 62
    .line 63
    .line 64
    move-result-wide v0

    .line 65
    cmp-long p1, p1, v0

    .line 66
    .line 67
    if-gez p1, :cond_1

    .line 68
    .line 69
    move-wide p1, v6

    .line 70
    goto :goto_0

    .line 71
    :cond_1
    move-wide p1, v2

    .line 72
    :cond_2
    :goto_0
    move-wide v0, p1

    .line 73
    goto :goto_1

    .line 74
    :catchall_0
    move-exception v0

    .line 75
    move-object p1, v0

    .line 76
    goto :goto_2

    .line 77
    :goto_1
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 78
    .line 79
    sget-object v6, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 80
    .line 81
    const-wide/32 v2, 0xf4240

    .line 82
    .line 83
    .line 84
    const-wide/32 v4, 0x15f90

    .line 85
    .line 86
    .line 87
    invoke-static/range {v0 .. v6}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 88
    .line 89
    .line 90
    move-result-wide p1

    .line 91
    invoke-virtual {p0, p1, p2}, Lw7/u;->a(J)J

    .line 92
    .line 93
    .line 94
    move-result-wide p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 95
    monitor-exit p0

    .line 96
    return-wide p1

    .line 97
    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 98
    throw p1
.end method

.method public final declared-synchronized c(J)J
    .locals 10

    .line 1
    monitor-enter p0

    .line 2
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 3
    .line 4
    .line 5
    .line 6
    .line 7
    cmp-long v2, p1, v0

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    monitor-exit p0

    .line 12
    return-wide v0

    .line 13
    :cond_0
    :try_start_0
    iget-wide v3, p0, Lw7/u;->c:J

    .line 14
    .line 15
    cmp-long v0, v3, v0

    .line 16
    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 20
    .line 21
    sget-object v9, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 22
    .line 23
    const-wide/32 v5, 0x15f90

    .line 24
    .line 25
    .line 26
    const-wide/32 v7, 0xf4240

    .line 27
    .line 28
    .line 29
    invoke-static/range {v3 .. v9}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    const-wide v2, 0x200000000L

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    div-long v4, v0, v2

    .line 39
    .line 40
    mul-long v6, v4, v2

    .line 41
    .line 42
    add-long/2addr v6, p1

    .line 43
    const-wide/16 v8, 0x1

    .line 44
    .line 45
    add-long/2addr v4, v8

    .line 46
    mul-long/2addr v4, v2

    .line 47
    add-long/2addr v4, p1

    .line 48
    cmp-long p1, v6, v0

    .line 49
    .line 50
    if-ltz p1, :cond_1

    .line 51
    .line 52
    move-wide p1, v6

    .line 53
    goto :goto_0

    .line 54
    :cond_1
    move-wide p1, v4

    .line 55
    :cond_2
    :goto_0
    move-wide v0, p1

    .line 56
    goto :goto_1

    .line 57
    :catchall_0
    move-exception v0

    .line 58
    move-object p1, v0

    .line 59
    goto :goto_2

    .line 60
    :goto_1
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 61
    .line 62
    sget-object v6, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 63
    .line 64
    const-wide/32 v2, 0xf4240

    .line 65
    .line 66
    .line 67
    const-wide/32 v4, 0x15f90

    .line 68
    .line 69
    .line 70
    invoke-static/range {v0 .. v6}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 71
    .line 72
    .line 73
    move-result-wide p1

    .line 74
    invoke-virtual {p0, p1, p2}, Lw7/u;->a(J)J

    .line 75
    .line 76
    .line 77
    move-result-wide p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    monitor-exit p0

    .line 79
    return-wide p1

    .line 80
    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 81
    throw p1
.end method

.method public final declared-synchronized d()J
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-wide v0, p0, Lw7/u;->a:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    const-wide v2, 0x7fffffffffffffffL

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    cmp-long v2, v0, v2

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    const-wide v2, 0x7ffffffffffffffeL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    cmp-long v2, v0, v2

    .line 19
    .line 20
    if-nez v2, :cond_1

    .line 21
    .line 22
    :cond_0
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    :cond_1
    monitor-exit p0

    .line 28
    return-wide v0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 31
    throw v0
.end method

.method public final declared-synchronized e(J)V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iput-wide p1, p0, Lw7/u;->a:J

    .line 3
    .line 4
    const-wide v0, 0x7fffffffffffffffL

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    cmp-long p1, p1, v0

    .line 10
    .line 11
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    if-nez p1, :cond_0

    .line 17
    .line 18
    const-wide/16 p1, 0x0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-wide p1, v0

    .line 22
    :goto_0
    iput-wide p1, p0, Lw7/u;->b:J

    .line 23
    .line 24
    iput-wide v0, p0, Lw7/u;->c:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    .line 26
    monitor-exit p0

    .line 27
    return-void

    .line 28
    :catchall_0
    move-exception p1

    .line 29
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 30
    throw p1
.end method
