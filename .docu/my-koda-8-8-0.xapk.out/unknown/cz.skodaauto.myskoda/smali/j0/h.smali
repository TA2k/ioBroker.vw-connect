.class public final Lj0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# instance fields
.field public final d:Ljava/util/ArrayDeque;

.field public final e:Ljava/util/concurrent/Executor;

.field public final f:Laq/p;

.field public g:I

.field public h:J


# direct methods
.method public constructor <init>(Ljava/util/concurrent/Executor;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayDeque;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 10
    .line 11
    new-instance v0, Laq/p;

    .line 12
    .line 13
    const/4 v1, 0x7

    .line 14
    invoke-direct {v0, p0, v1}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lj0/h;->f:Laq/p;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    iput v0, p0, Lj0/h;->g:I

    .line 21
    .line 22
    const-wide/16 v0, 0x0

    .line 23
    .line 24
    iput-wide v0, p0, Lj0/h;->h:J

    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lj0/h;->e:Ljava/util/concurrent/Executor;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 7

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget v1, p0, Lj0/h;->g:I

    .line 8
    .line 9
    const/4 v2, 0x4

    .line 10
    if-eq v1, v2, :cond_6

    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    goto :goto_5

    .line 16
    :cond_0
    iget-wide v3, p0, Lj0/h;->h:J

    .line 17
    .line 18
    new-instance v1, Lhs/j;

    .line 19
    .line 20
    const/4 v5, 0x1

    .line 21
    invoke-direct {v1, p1, v5}, Lhs/j;-><init>(Ljava/lang/Runnable;I)V

    .line 22
    .line 23
    .line 24
    iget-object p1, p0, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 25
    .line 26
    invoke-virtual {p1, v1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    const/4 p1, 0x2

    .line 30
    iput p1, p0, Lj0/h;->g:I

    .line 31
    .line 32
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 33
    :try_start_1
    iget-object v0, p0, Lj0/h;->e:Ljava/util/concurrent/Executor;

    .line 34
    .line 35
    iget-object v5, p0, Lj0/h;->f:Laq/p;

    .line 36
    .line 37
    invoke-interface {v0, v5}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/Error; {:try_start_1 .. :try_end_1} :catch_0

    .line 38
    .line 39
    .line 40
    iget v0, p0, Lj0/h;->g:I

    .line 41
    .line 42
    if-eq v0, p1, :cond_1

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_1
    iget-object v0, p0, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 46
    .line 47
    monitor-enter v0

    .line 48
    :try_start_2
    iget-wide v5, p0, Lj0/h;->h:J

    .line 49
    .line 50
    cmp-long v1, v5, v3

    .line 51
    .line 52
    if-nez v1, :cond_2

    .line 53
    .line 54
    iget v1, p0, Lj0/h;->g:I

    .line 55
    .line 56
    if-ne v1, p1, :cond_2

    .line 57
    .line 58
    iput v2, p0, Lj0/h;->g:I

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :catchall_0
    move-exception p0

    .line 62
    goto :goto_1

    .line 63
    :cond_2
    :goto_0
    monitor-exit v0

    .line 64
    return-void

    .line 65
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 66
    throw p0

    .line 67
    :catch_0
    move-exception v0

    .line 68
    iget-object v2, p0, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 69
    .line 70
    monitor-enter v2

    .line 71
    :try_start_3
    iget v3, p0, Lj0/h;->g:I

    .line 72
    .line 73
    const/4 v4, 0x1

    .line 74
    if-eq v3, v4, :cond_3

    .line 75
    .line 76
    if-ne v3, p1, :cond_4

    .line 77
    .line 78
    :cond_3
    iget-object p0, p0, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 79
    .line 80
    invoke-virtual {p0, v1}, Ljava/util/ArrayDeque;->removeLastOccurrence(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    if-eqz p0, :cond_4

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_4
    const/4 v4, 0x0

    .line 88
    :goto_2
    instance-of p0, v0, Ljava/util/concurrent/RejectedExecutionException;

    .line 89
    .line 90
    if-eqz p0, :cond_5

    .line 91
    .line 92
    if-nez v4, :cond_5

    .line 93
    .line 94
    monitor-exit v2

    .line 95
    :goto_3
    return-void

    .line 96
    :catchall_1
    move-exception p0

    .line 97
    goto :goto_4

    .line 98
    :cond_5
    throw v0

    .line 99
    :goto_4
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 100
    throw p0

    .line 101
    :catchall_2
    move-exception p0

    .line 102
    goto :goto_6

    .line 103
    :cond_6
    :goto_5
    :try_start_4
    iget-object p0, p0, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 104
    .line 105
    invoke-virtual {p0, p1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    monitor-exit v0

    .line 109
    return-void

    .line 110
    :goto_6
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 111
    throw p0
.end method
