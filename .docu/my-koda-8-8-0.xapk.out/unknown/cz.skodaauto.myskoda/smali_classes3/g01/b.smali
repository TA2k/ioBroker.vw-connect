.class public final Lg01/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lg01/c;

.field public final b:Ljava/lang/String;

.field public c:Z

.field public d:Lg01/a;

.field public final e:Ljava/util/ArrayList;

.field public f:Z


# direct methods
.method public constructor <init>(Lg01/c;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "name"

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
    iput-object p1, p0, Lg01/b;->a:Lg01/c;

    .line 10
    .line 11
    iput-object p2, p0, Lg01/b;->b:Ljava/lang/String;

    .line 12
    .line 13
    new-instance p1, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lg01/b;->e:Ljava/util/ArrayList;

    .line 19
    .line 20
    return-void
.end method

.method public static c(Lg01/b;Ljava/lang/String;JLay0/a;I)V
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-wide/16 p2, 0x0

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p5, 0x4

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    const/4 p5, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_1
    const/4 p5, 0x0

    .line 14
    :goto_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const-string v0, "name"

    .line 18
    .line 19
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "block"

    .line 23
    .line 24
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lf01/e;

    .line 28
    .line 29
    invoke-direct {v0, p4, p1, p5}, Lf01/e;-><init>(Lay0/a;Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v0, p2, p3}, Lg01/b;->d(Lg01/a;J)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public static synthetic e(Lg01/b;Lg01/a;)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    invoke-virtual {p0, p1, v0, v1}, Lg01/b;->d(Lg01/a;J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lg01/b;->a:Lg01/c;

    .line 2
    .line 3
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    invoke-virtual {p0}, Lg01/b;->b()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object v1, p0, Lg01/b;->a:Lg01/c;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Lg01/c;->c(Lg01/b;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    :goto_0
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :goto_1
    monitor-exit v0

    .line 23
    throw p0
.end method

.method public final b()Z
    .locals 6

    .line 1
    iget-object v0, p0, Lg01/b;->d:Lg01/a;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-boolean v0, v0, Lg01/a;->b:Z

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iput-boolean v1, p0, Lg01/b;->f:Z

    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lg01/b;->e:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    sub-int/2addr v2, v1

    .line 19
    const/4 v3, 0x0

    .line 20
    :goto_0
    const/4 v4, -0x1

    .line 21
    if-ge v4, v2, :cond_3

    .line 22
    .line 23
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    check-cast v4, Lg01/a;

    .line 28
    .line 29
    iget-boolean v4, v4, Lg01/a;->b:Z

    .line 30
    .line 31
    if-eqz v4, :cond_2

    .line 32
    .line 33
    iget-object v3, p0, Lg01/b;->a:Lg01/c;

    .line 34
    .line 35
    iget-object v3, v3, Lg01/c;->b:Ljava/util/logging/Logger;

    .line 36
    .line 37
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    check-cast v4, Lg01/a;

    .line 42
    .line 43
    sget-object v5, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 44
    .line 45
    invoke-virtual {v3, v5}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-eqz v5, :cond_1

    .line 50
    .line 51
    const-string v5, "canceled"

    .line 52
    .line 53
    invoke-static {v3, v4, p0, v5}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    :cond_1
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move v3, v1

    .line 60
    :cond_2
    add-int/lit8 v2, v2, -0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    return v3
.end method

.method public final d(Lg01/a;J)V
    .locals 2

    .line 1
    const-string v0, "task"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lg01/b;->a:Lg01/c;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-boolean v1, p0, Lg01/b;->c:Z

    .line 10
    .line 11
    if-eqz v1, :cond_3

    .line 12
    .line 13
    iget-boolean p2, p1, Lg01/a;->b:Z

    .line 14
    .line 15
    if-eqz p2, :cond_1

    .line 16
    .line 17
    iget-object p2, p0, Lg01/b;->a:Lg01/c;

    .line 18
    .line 19
    iget-object p2, p2, Lg01/c;->b:Ljava/util/logging/Logger;

    .line 20
    .line 21
    sget-object p3, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 22
    .line 23
    invoke-virtual {p2, p3}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 24
    .line 25
    .line 26
    move-result p3

    .line 27
    if-eqz p3, :cond_0

    .line 28
    .line 29
    const-string p3, "schedule canceled (queue is shutdown)"

    .line 30
    .line 31
    invoke-static {p2, p1, p0, p3}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    :goto_0
    monitor-exit v0

    .line 38
    return-void

    .line 39
    :cond_1
    :try_start_1
    iget-object p2, p0, Lg01/b;->a:Lg01/c;

    .line 40
    .line 41
    iget-object p2, p2, Lg01/c;->b:Ljava/util/logging/Logger;

    .line 42
    .line 43
    sget-object p3, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 44
    .line 45
    invoke-virtual {p2, p3}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 46
    .line 47
    .line 48
    move-result p3

    .line 49
    if-eqz p3, :cond_2

    .line 50
    .line 51
    const-string p3, "schedule failed (queue is shutdown)"

    .line 52
    .line 53
    invoke-static {p2, p1, p0, p3}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    new-instance p0, Ljava/util/concurrent/RejectedExecutionException;

    .line 57
    .line 58
    invoke-direct {p0}, Ljava/util/concurrent/RejectedExecutionException;-><init>()V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_3
    const/4 v1, 0x0

    .line 63
    invoke-virtual {p0, p1, p2, p3, v1}, Lg01/b;->f(Lg01/a;JZ)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-eqz p1, :cond_4

    .line 68
    .line 69
    iget-object p1, p0, Lg01/b;->a:Lg01/c;

    .line 70
    .line 71
    invoke-virtual {p1, p0}, Lg01/c;->c(Lg01/b;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 72
    .line 73
    .line 74
    :cond_4
    monitor-exit v0

    .line 75
    return-void

    .line 76
    :goto_1
    monitor-exit v0

    .line 77
    throw p0
.end method

.method public final f(Lg01/a;JZ)Z
    .locals 11

    .line 1
    iget-object v0, p0, Lg01/b;->a:Lg01/c;

    .line 2
    .line 3
    iget-object v0, v0, Lg01/c;->b:Ljava/util/logging/Logger;

    .line 4
    .line 5
    const-string v1, "task"

    .line 6
    .line 7
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, p1, Lg01/a;->c:Lg01/b;

    .line 11
    .line 12
    if-ne v1, p0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    if-nez v1, :cond_9

    .line 16
    .line 17
    iput-object p0, p1, Lg01/a;->c:Lg01/b;

    .line 18
    .line 19
    :goto_0
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 20
    .line 21
    .line 22
    move-result-wide v1

    .line 23
    add-long v3, v1, p2

    .line 24
    .line 25
    iget-object v5, p0, Lg01/b;->e:Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-virtual {v5, p1}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    const/4 v7, 0x0

    .line 32
    const/4 v8, -0x1

    .line 33
    if-eq v6, v8, :cond_2

    .line 34
    .line 35
    iget-wide v9, p1, Lg01/a;->d:J

    .line 36
    .line 37
    cmp-long v9, v9, v3

    .line 38
    .line 39
    if-gtz v9, :cond_1

    .line 40
    .line 41
    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 42
    .line 43
    invoke-virtual {v0, p2}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    if-eqz p2, :cond_8

    .line 48
    .line 49
    const-string p2, "already scheduled"

    .line 50
    .line 51
    invoke-static {v0, p1, p0, p2}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    return v7

    .line 55
    :cond_1
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    :cond_2
    iput-wide v3, p1, Lg01/a;->d:J

    .line 59
    .line 60
    sget-object v6, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 61
    .line 62
    invoke-virtual {v0, v6}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 63
    .line 64
    .line 65
    move-result v6

    .line 66
    if-eqz v6, :cond_4

    .line 67
    .line 68
    if-eqz p4, :cond_3

    .line 69
    .line 70
    sub-long/2addr v3, v1

    .line 71
    invoke-static {v3, v4}, Lkp/k8;->c(J)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p4

    .line 75
    const-string v3, "run again after "

    .line 76
    .line 77
    invoke-virtual {v3, p4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p4

    .line 81
    goto :goto_1

    .line 82
    :cond_3
    sub-long/2addr v3, v1

    .line 83
    invoke-static {v3, v4}, Lkp/k8;->c(J)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p4

    .line 87
    const-string v3, "scheduled after "

    .line 88
    .line 89
    invoke-virtual {v3, p4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p4

    .line 93
    :goto_1
    invoke-static {v0, p1, p0, p4}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    :cond_4
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    move p4, v7

    .line 101
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    if-eqz v0, :cond_6

    .line 106
    .line 107
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    check-cast v0, Lg01/a;

    .line 112
    .line 113
    iget-wide v3, v0, Lg01/a;->d:J

    .line 114
    .line 115
    sub-long/2addr v3, v1

    .line 116
    cmp-long v0, v3, p2

    .line 117
    .line 118
    if-lez v0, :cond_5

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_5
    add-int/lit8 p4, p4, 0x1

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_6
    move p4, v8

    .line 125
    :goto_3
    if-ne p4, v8, :cond_7

    .line 126
    .line 127
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 128
    .line 129
    .line 130
    move-result p4

    .line 131
    :cond_7
    invoke-virtual {v5, p4, p1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    if-nez p4, :cond_8

    .line 135
    .line 136
    const/4 p0, 0x1

    .line 137
    return p0

    .line 138
    :cond_8
    return v7

    .line 139
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 140
    .line 141
    const-string p1, "task is in multiple queues"

    .line 142
    .line 143
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw p0
.end method

.method public final g()V
    .locals 2

    .line 1
    iget-object v0, p0, Lg01/b;->a:Lg01/c;

    .line 2
    .line 3
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    const/4 v1, 0x1

    .line 7
    :try_start_0
    iput-boolean v1, p0, Lg01/b;->c:Z

    .line 8
    .line 9
    invoke-virtual {p0}, Lg01/b;->b()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-object v1, p0, Lg01/b;->a:Lg01/c;

    .line 16
    .line 17
    invoke-virtual {v1, p0}, Lg01/c;->c(Lg01/b;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    :goto_0
    monitor-exit v0

    .line 24
    return-void

    .line 25
    :goto_1
    monitor-exit v0

    .line 26
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lg01/b;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
