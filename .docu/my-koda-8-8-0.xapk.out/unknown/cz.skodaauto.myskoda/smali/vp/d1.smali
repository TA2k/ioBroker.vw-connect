.class public final Lvp/d1;
.super Ljava/lang/Thread;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Ljava/util/concurrent/BlockingQueue;

.field public f:Z

.field public final synthetic g:Lvp/e1;


# direct methods
.method public constructor <init>(Lvp/e1;Ljava/lang/String;Ljava/util/concurrent/BlockingQueue;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvp/d1;->g:Lvp/e1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Thread;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-boolean p1, p0, Lvp/d1;->f:Z

    .line 8
    .line 9
    invoke-static {p3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    new-instance p1, Ljava/lang/Object;

    .line 13
    .line 14
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lvp/d1;->d:Ljava/lang/Object;

    .line 18
    .line 19
    iput-object p3, p0, Lvp/d1;->e:Ljava/util/concurrent/BlockingQueue;

    .line 20
    .line 21
    invoke-virtual {p0, p2}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    iget-object v0, p0, Lvp/d1;->g:Lvp/e1;

    .line 2
    .line 3
    iget-object v1, v0, Lvp/e1;->m:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget-boolean v2, p0, Lvp/d1;->f:Z

    .line 7
    .line 8
    if-nez v2, :cond_2

    .line 9
    .line 10
    iget-object v2, v0, Lvp/e1;->n:Ljava/util/concurrent/Semaphore;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/util/concurrent/Semaphore;->release()V

    .line 13
    .line 14
    .line 15
    iget-object v2, v0, Lvp/e1;->m:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/Object;->notifyAll()V

    .line 18
    .line 19
    .line 20
    iget-object v2, v0, Lvp/e1;->g:Lvp/d1;

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    if-ne p0, v2, :cond_0

    .line 24
    .line 25
    iput-object v3, v0, Lvp/e1;->g:Lvp/d1;

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto :goto_1

    .line 30
    :cond_0
    iget-object v2, v0, Lvp/e1;->h:Lvp/d1;

    .line 31
    .line 32
    if-ne p0, v2, :cond_1

    .line 33
    .line 34
    iput-object v3, v0, Lvp/e1;->h:Lvp/d1;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, Lvp/g1;

    .line 40
    .line 41
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 42
    .line 43
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 47
    .line 48
    const-string v2, "Current scheduler thread is neither worker nor network"

    .line 49
    .line 50
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    :goto_0
    const/4 v0, 0x1

    .line 54
    iput-boolean v0, p0, Lvp/d1;->f:Z

    .line 55
    .line 56
    :cond_2
    monitor-exit v1

    .line 57
    return-void

    .line 58
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    throw p0
.end method

.method public final run()V
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    const/4 v1, 0x1

    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    iget-object v2, p0, Lvp/d1;->g:Lvp/e1;

    .line 6
    .line 7
    iget-object v2, v2, Lvp/e1;->n:Ljava/util/concurrent/Semaphore;

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/util/concurrent/Semaphore;->acquire()V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    .line 12
    move v0, v1

    .line 13
    goto :goto_0

    .line 14
    :catch_0
    move-exception v1

    .line 15
    iget-object v2, p0, Lvp/d1;->g:Lvp/e1;

    .line 16
    .line 17
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Lvp/g1;

    .line 20
    .line 21
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 22
    .line 23
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    iget-object v2, v2, Lvp/p0;->m:Lvp/n0;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    const-string v4, " was interrupted"

    .line 37
    .line 38
    invoke-virtual {v3, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    invoke-virtual {v2, v1, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    :try_start_1
    invoke-static {}, Landroid/os/Process;->myTid()I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    invoke-static {v0}, Landroid/os/Process;->getThreadPriority(I)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    :goto_1
    iget-object v2, p0, Lvp/d1;->e:Ljava/util/concurrent/BlockingQueue;

    .line 55
    .line 56
    invoke-interface {v2}, Ljava/util/Queue;->poll()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    check-cast v3, Lvp/c1;

    .line 61
    .line 62
    if-eqz v3, :cond_2

    .line 63
    .line 64
    iget-boolean v2, v3, Lvp/c1;->e:Z

    .line 65
    .line 66
    if-eq v1, v2, :cond_1

    .line 67
    .line 68
    const/16 v2, 0xa

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_1
    move v2, v0

    .line 72
    :goto_2
    invoke-static {v2}, Landroid/os/Process;->setThreadPriority(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3}, Ljava/util/concurrent/FutureTask;->run()V

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :catchall_0
    move-exception v0

    .line 80
    goto :goto_6

    .line 81
    :cond_2
    iget-object v3, p0, Lvp/d1;->d:Ljava/lang/Object;

    .line 82
    .line 83
    monitor-enter v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 84
    :try_start_2
    invoke-interface {v2}, Ljava/util/Queue;->peek()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    if-nez v2, :cond_3

    .line 89
    .line 90
    iget-object v2, p0, Lvp/d1;->g:Lvp/e1;

    .line 91
    .line 92
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 93
    .line 94
    .line 95
    const-wide/16 v4, 0x7530

    .line 96
    .line 97
    :try_start_3
    invoke-virtual {v3, v4, v5}, Ljava/lang/Object;->wait(J)V
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 98
    .line 99
    .line 100
    goto :goto_3

    .line 101
    :catchall_1
    move-exception v0

    .line 102
    goto :goto_5

    .line 103
    :catch_1
    move-exception v2

    .line 104
    :try_start_4
    iget-object v4, p0, Lvp/d1;->g:Lvp/e1;

    .line 105
    .line 106
    iget-object v4, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v4, Lvp/g1;

    .line 109
    .line 110
    iget-object v4, v4, Lvp/g1;->i:Lvp/p0;

    .line 111
    .line 112
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 113
    .line 114
    .line 115
    iget-object v4, v4, Lvp/p0;->m:Lvp/n0;

    .line 116
    .line 117
    invoke-virtual {p0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v5

    .line 121
    invoke-static {v5}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    const-string v6, " was interrupted"

    .line 126
    .line 127
    invoke-virtual {v5, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v5

    .line 131
    invoke-virtual {v4, v2, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    :cond_3
    :goto_3
    monitor-exit v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 135
    :try_start_5
    iget-object v2, p0, Lvp/d1;->g:Lvp/e1;

    .line 136
    .line 137
    iget-object v2, v2, Lvp/e1;->m:Ljava/lang/Object;

    .line 138
    .line 139
    monitor-enter v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 140
    :try_start_6
    iget-object v3, p0, Lvp/d1;->e:Ljava/util/concurrent/BlockingQueue;

    .line 141
    .line 142
    invoke-interface {v3}, Ljava/util/Queue;->peek()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    if-nez v3, :cond_4

    .line 147
    .line 148
    invoke-virtual {p0}, Lvp/d1;->a()V

    .line 149
    .line 150
    .line 151
    monitor-exit v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 152
    invoke-virtual {p0}, Lvp/d1;->a()V

    .line 153
    .line 154
    .line 155
    return-void

    .line 156
    :catchall_2
    move-exception v0

    .line 157
    goto :goto_4

    .line 158
    :cond_4
    :try_start_7
    monitor-exit v2

    .line 159
    goto :goto_1

    .line 160
    :goto_4
    monitor-exit v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 161
    :try_start_8
    throw v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 162
    :goto_5
    :try_start_9
    monitor-exit v3
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 163
    :try_start_a
    throw v0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 164
    :goto_6
    invoke-virtual {p0}, Lvp/d1;->a()V

    .line 165
    .line 166
    .line 167
    throw v0
.end method
