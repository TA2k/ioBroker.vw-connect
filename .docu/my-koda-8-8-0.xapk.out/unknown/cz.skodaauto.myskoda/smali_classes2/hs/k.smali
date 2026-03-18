.class public final Lhs/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# static fields
.field public static final i:Ljava/util/logging/Logger;


# instance fields
.field public final d:Ljava/util/concurrent/Executor;

.field public final e:Ljava/util/ArrayDeque;

.field public f:I

.field public g:J

.field public final h:Llr/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lhs/k;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lhs/k;->i:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

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
    iput-object v0, p0, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    iput v0, p0, Lhs/k;->f:I

    .line 13
    .line 14
    const-wide/16 v0, 0x0

    .line 15
    .line 16
    iput-wide v0, p0, Lhs/k;->g:J

    .line 17
    .line 18
    new-instance v0, Llr/b;

    .line 19
    .line 20
    invoke-direct {v0, p0}, Llr/b;-><init>(Lhs/k;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lhs/k;->h:Llr/b;

    .line 24
    .line 25
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lhs/k;->d:Ljava/util/concurrent/Executor;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 7

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget v1, p0, Lhs/k;->f:I

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
    iget-wide v3, p0, Lhs/k;->g:J

    .line 17
    .line 18
    new-instance v1, Lhs/j;

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    invoke-direct {v1, p1, v5}, Lhs/j;-><init>(Ljava/lang/Runnable;I)V

    .line 22
    .line 23
    .line 24
    iget-object p1, p0, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 25
    .line 26
    invoke-virtual {p1, v1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    const/4 p1, 0x2

    .line 30
    iput p1, p0, Lhs/k;->f:I

    .line 31
    .line 32
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 33
    :try_start_1
    iget-object v0, p0, Lhs/k;->d:Ljava/util/concurrent/Executor;

    .line 34
    .line 35
    iget-object v5, p0, Lhs/k;->h:Llr/b;

    .line 36
    .line 37
    invoke-interface {v0, v5}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/Error; {:try_start_1 .. :try_end_1} :catch_0

    .line 38
    .line 39
    .line 40
    iget v0, p0, Lhs/k;->f:I

    .line 41
    .line 42
    if-eq v0, p1, :cond_1

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_1
    iget-object v0, p0, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 46
    .line 47
    monitor-enter v0

    .line 48
    :try_start_2
    iget-wide v5, p0, Lhs/k;->g:J

    .line 49
    .line 50
    cmp-long v1, v5, v3

    .line 51
    .line 52
    if-nez v1, :cond_2

    .line 53
    .line 54
    iget v1, p0, Lhs/k;->f:I

    .line 55
    .line 56
    if-ne v1, p1, :cond_2

    .line 57
    .line 58
    iput v2, p0, Lhs/k;->f:I

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
    iget-object v2, p0, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 69
    .line 70
    monitor-enter v2

    .line 71
    :try_start_3
    iget v3, p0, Lhs/k;->f:I

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
    iget-object p0, p0, Lhs/k;->e:Ljava/util/ArrayDeque;

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
    iget-object p0, p0, Lhs/k;->e:Ljava/util/ArrayDeque;

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

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SequentialExecutor@"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v1, "{"

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lhs/k;->d:Ljava/util/concurrent/Executor;

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, "}"

    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
