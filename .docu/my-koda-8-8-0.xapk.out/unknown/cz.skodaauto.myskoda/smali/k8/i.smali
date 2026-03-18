.class public final Lk8/i;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final d:I

.field public final e:Lh8/o0;

.field public f:Ljava/lang/Object;

.field public g:Ljava/io/IOException;

.field public h:I

.field public i:Ljava/lang/Thread;

.field public j:Z

.field public volatile k:Z

.field public final synthetic l:Lk8/l;


# direct methods
.method public constructor <init>(Lk8/l;Landroid/os/Looper;Lh8/o0;Lk8/h;IJ)V
    .locals 0

    .line 1
    iput-object p1, p0, Lk8/i;->l:Lk8/l;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 4
    .line 5
    .line 6
    iput-object p3, p0, Lk8/i;->e:Lh8/o0;

    .line 7
    .line 8
    iput-object p4, p0, Lk8/i;->f:Ljava/lang/Object;

    .line 9
    .line 10
    iput p5, p0, Lk8/i;->d:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Z)V
    .locals 4

    .line 1
    iput-boolean p1, p0, Lk8/i;->k:Z

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    iput-object v0, p0, Lk8/i;->g:Ljava/io/IOException;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-virtual {p0, v1}, Landroid/os/Handler;->hasMessages(I)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    iput-boolean v1, p0, Lk8/i;->j:Z

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Landroid/os/Handler;->removeMessages(I)V

    .line 16
    .line 17
    .line 18
    if-nez p1, :cond_2

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-virtual {p0, v2}, Landroid/os/Handler;->sendEmptyMessage(I)Z

    .line 22
    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    monitor-enter p0

    .line 26
    :try_start_0
    iput-boolean v1, p0, Lk8/i;->j:Z

    .line 27
    .line 28
    iget-object v2, p0, Lk8/i;->e:Lh8/o0;

    .line 29
    .line 30
    const/4 v3, 0x1

    .line 31
    iput-boolean v3, v2, Lh8/o0;->g:Z

    .line 32
    .line 33
    iget-object v2, p0, Lk8/i;->i:Ljava/lang/Thread;

    .line 34
    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    invoke-virtual {v2}, Ljava/lang/Thread;->interrupt()V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception p1

    .line 42
    goto :goto_2

    .line 43
    :cond_1
    :goto_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    :cond_2
    :goto_1
    if-eqz p1, :cond_3

    .line 45
    .line 46
    iget-object p1, p0, Lk8/i;->l:Lk8/l;

    .line 47
    .line 48
    iput-object v0, p1, Lk8/l;->b:Lk8/i;

    .line 49
    .line 50
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lk8/i;->f:Ljava/lang/Object;

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    iget-object v2, p0, Lk8/i;->e:Lh8/o0;

    .line 59
    .line 60
    invoke-interface {p1, v2, v1}, Lk8/h;->i(Lh8/o0;Z)V

    .line 61
    .line 62
    .line 63
    iput-object v0, p0, Lk8/i;->f:Ljava/lang/Object;

    .line 64
    .line 65
    :cond_3
    return-void

    .line 66
    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 67
    throw p1
.end method

.method public final b()V
    .locals 5

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-object v2, p0, Lk8/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v3, p0, Lk8/i;->e:Lh8/o0;

    .line 11
    .line 12
    iget v4, p0, Lk8/i;->h:I

    .line 13
    .line 14
    invoke-interface {v2, v3, v0, v1, v4}, Lk8/h;->f(Lh8/o0;JI)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lk8/i;->g:Ljava/io/IOException;

    .line 19
    .line 20
    iget-object p0, p0, Lk8/i;->l:Lk8/l;

    .line 21
    .line 22
    iget-object v0, p0, Lk8/l;->a:Ll8/a;

    .line 23
    .line 24
    iget-object p0, p0, Lk8/l;->b:Lk8/i;

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ll8/a;->execute(Ljava/lang/Runnable;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final handleMessage(Landroid/os/Message;)V
    .locals 8

    .line 1
    iget-boolean v0, p0, Lk8/i;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_1

    .line 6
    .line 7
    :cond_0
    iget v0, p1, Landroid/os/Message;->what:I

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    invoke-virtual {p0}, Lk8/i;->b()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_1
    const/4 v2, 0x4

    .line 17
    if-eq v0, v2, :cond_b

    .line 18
    .line 19
    iget-object v0, p0, Lk8/i;->l:Lk8/l;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    iput-object v2, v0, Lk8/l;->b:Lk8/i;

    .line 23
    .line 24
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 25
    .line 26
    .line 27
    iget-object v0, p0, Lk8/i;->f:Ljava/lang/Object;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    iget-boolean v2, p0, Lk8/i;->j:Z

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    iget-object p0, p0, Lk8/i;->e:Lh8/o0;

    .line 38
    .line 39
    invoke-interface {v0, p0, v3}, Lk8/h;->i(Lh8/o0;Z)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_2
    iget v2, p1, Landroid/os/Message;->what:I

    .line 44
    .line 45
    const/4 v4, 0x2

    .line 46
    if-eq v2, v4, :cond_a

    .line 47
    .line 48
    const/4 v5, 0x3

    .line 49
    if-eq v2, v5, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p1, Ljava/io/IOException;

    .line 55
    .line 56
    iput-object p1, p0, Lk8/i;->g:Ljava/io/IOException;

    .line 57
    .line 58
    iget v2, p0, Lk8/i;->h:I

    .line 59
    .line 60
    add-int/2addr v2, v1

    .line 61
    iput v2, p0, Lk8/i;->h:I

    .line 62
    .line 63
    iget-object v6, p0, Lk8/i;->e:Lh8/o0;

    .line 64
    .line 65
    invoke-interface {v0, v6, p1, v2}, Lk8/h;->j(Lh8/o0;Ljava/io/IOException;I)Lin/p;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    iget v0, p1, Lin/p;->d:I

    .line 70
    .line 71
    if-ne v0, v5, :cond_4

    .line 72
    .line 73
    iget-object p1, p0, Lk8/i;->l:Lk8/l;

    .line 74
    .line 75
    iget-object p0, p0, Lk8/i;->g:Ljava/io/IOException;

    .line 76
    .line 77
    iput-object p0, p1, Lk8/l;->c:Ljava/io/IOException;

    .line 78
    .line 79
    return-void

    .line 80
    :cond_4
    if-eq v0, v4, :cond_9

    .line 81
    .line 82
    if-ne v0, v1, :cond_5

    .line 83
    .line 84
    iput v1, p0, Lk8/i;->h:I

    .line 85
    .line 86
    :cond_5
    iget-wide v4, p1, Lin/p;->e:J

    .line 87
    .line 88
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    cmp-long p1, v4, v6

    .line 94
    .line 95
    if-eqz p1, :cond_6

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_6
    iget p1, p0, Lk8/i;->h:I

    .line 99
    .line 100
    sub-int/2addr p1, v1

    .line 101
    mul-int/lit16 p1, p1, 0x3e8

    .line 102
    .line 103
    const/16 v0, 0x1388

    .line 104
    .line 105
    invoke-static {p1, v0}, Ljava/lang/Math;->min(II)I

    .line 106
    .line 107
    .line 108
    move-result p1

    .line 109
    int-to-long v4, p1

    .line 110
    :goto_0
    iget-object p1, p0, Lk8/i;->l:Lk8/l;

    .line 111
    .line 112
    iget-object v0, p1, Lk8/l;->b:Lk8/i;

    .line 113
    .line 114
    if-nez v0, :cond_7

    .line 115
    .line 116
    move v3, v1

    .line 117
    :cond_7
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 118
    .line 119
    .line 120
    iput-object p0, p1, Lk8/l;->b:Lk8/i;

    .line 121
    .line 122
    const-wide/16 v2, 0x0

    .line 123
    .line 124
    cmp-long p1, v4, v2

    .line 125
    .line 126
    if-lez p1, :cond_8

    .line 127
    .line 128
    invoke-virtual {p0, v1, v4, v5}, Landroid/os/Handler;->sendEmptyMessageDelayed(IJ)Z

    .line 129
    .line 130
    .line 131
    return-void

    .line 132
    :cond_8
    invoke-virtual {p0}, Lk8/i;->b()V

    .line 133
    .line 134
    .line 135
    :cond_9
    :goto_1
    return-void

    .line 136
    :cond_a
    :try_start_0
    iget-object p1, p0, Lk8/i;->e:Lh8/o0;

    .line 137
    .line 138
    invoke-interface {v0, p1}, Lk8/h;->t(Lh8/o0;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 139
    .line 140
    .line 141
    return-void

    .line 142
    :catch_0
    move-exception p1

    .line 143
    const-string v0, "LoadTask"

    .line 144
    .line 145
    const-string v1, "Unexpected exception handling load completed"

    .line 146
    .line 147
    invoke-static {v0, v1, p1}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 148
    .line 149
    .line 150
    iget-object p0, p0, Lk8/i;->l:Lk8/l;

    .line 151
    .line 152
    new-instance v0, Lk8/k;

    .line 153
    .line 154
    invoke-direct {v0, p1}, Lk8/k;-><init>(Ljava/lang/Throwable;)V

    .line 155
    .line 156
    .line 157
    iput-object v0, p0, Lk8/l;->c:Ljava/io/IOException;

    .line 158
    .line 159
    return-void

    .line 160
    :cond_b
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast p0, Ljava/lang/Error;

    .line 163
    .line 164
    throw p0
.end method

.method public final run()V
    .locals 4

    .line 1
    const-string v0, "load:"

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    :try_start_0
    monitor-enter p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/OutOfMemoryError; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Error; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    :try_start_1
    iget-boolean v2, p0, Lk8/i;->j:Z

    .line 6
    .line 7
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    iput-object v3, p0, Lk8/i;->i:Ljava/lang/Thread;

    .line 12
    .line 13
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    :try_start_2
    iget-object v2, p0, Lk8/i;->e:Lh8/o0;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_3
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/OutOfMemoryError; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/Error; {:try_start_2 .. :try_end_2} :catch_0

    .line 31
    .line 32
    .line 33
    :try_start_3
    iget-object v0, p0, Lk8/i;->e:Lh8/o0;

    .line 34
    .line 35
    invoke-virtual {v0}, Lh8/o0;->b()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 36
    .line 37
    .line 38
    :try_start_4
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catch_0
    move-exception v0

    .line 43
    goto :goto_1

    .line 44
    :catch_1
    move-exception v0

    .line 45
    goto :goto_2

    .line 46
    :catch_2
    move-exception v0

    .line 47
    goto :goto_3

    .line 48
    :catch_3
    move-exception v0

    .line 49
    goto :goto_4

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 52
    .line 53
    .line 54
    throw v0

    .line 55
    :cond_0
    :goto_0
    monitor-enter p0
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_2
    .catch Ljava/lang/OutOfMemoryError; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/lang/Error; {:try_start_4 .. :try_end_4} :catch_0

    .line 56
    const/4 v0, 0x0

    .line 57
    :try_start_5
    iput-object v0, p0, Lk8/i;->i:Ljava/lang/Thread;

    .line 58
    .line 59
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 60
    .line 61
    .line 62
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 63
    :try_start_6
    iget-boolean v0, p0, Lk8/i;->k:Z

    .line 64
    .line 65
    if-nez v0, :cond_2

    .line 66
    .line 67
    const/4 v0, 0x2

    .line 68
    invoke-virtual {p0, v0}, Landroid/os/Handler;->sendEmptyMessage(I)Z
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_3
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_2
    .catch Ljava/lang/OutOfMemoryError; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/lang/Error; {:try_start_6 .. :try_end_6} :catch_0

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :catchall_1
    move-exception v0

    .line 73
    :try_start_7
    monitor-exit p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 74
    :try_start_8
    throw v0
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_3
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_2
    .catch Ljava/lang/OutOfMemoryError; {:try_start_8 .. :try_end_8} :catch_1
    .catch Ljava/lang/Error; {:try_start_8 .. :try_end_8} :catch_0

    .line 75
    :catchall_2
    move-exception v0

    .line 76
    :try_start_9
    monitor-exit p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 77
    :try_start_a
    throw v0
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_3
    .catch Ljava/lang/Exception; {:try_start_a .. :try_end_a} :catch_2
    .catch Ljava/lang/OutOfMemoryError; {:try_start_a .. :try_end_a} :catch_1
    .catch Ljava/lang/Error; {:try_start_a .. :try_end_a} :catch_0

    .line 78
    :goto_1
    iget-boolean v1, p0, Lk8/i;->k:Z

    .line 79
    .line 80
    if-nez v1, :cond_1

    .line 81
    .line 82
    const-string v1, "LoadTask"

    .line 83
    .line 84
    const-string v2, "Unexpected error loading stream"

    .line 85
    .line 86
    invoke-static {v1, v2, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 87
    .line 88
    .line 89
    const/4 v1, 0x4

    .line 90
    invoke-virtual {p0, v1, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 95
    .line 96
    .line 97
    :cond_1
    throw v0

    .line 98
    :goto_2
    iget-boolean v2, p0, Lk8/i;->k:Z

    .line 99
    .line 100
    if-nez v2, :cond_2

    .line 101
    .line 102
    const-string v2, "LoadTask"

    .line 103
    .line 104
    const-string v3, "OutOfMemory error loading stream"

    .line 105
    .line 106
    invoke-static {v2, v3, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 107
    .line 108
    .line 109
    new-instance v2, Lk8/k;

    .line 110
    .line 111
    invoke-direct {v2, v0}, Lk8/k;-><init>(Ljava/lang/Throwable;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {p0, v1, v2}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 119
    .line 120
    .line 121
    goto :goto_5

    .line 122
    :goto_3
    iget-boolean v2, p0, Lk8/i;->k:Z

    .line 123
    .line 124
    if-nez v2, :cond_2

    .line 125
    .line 126
    const-string v2, "LoadTask"

    .line 127
    .line 128
    const-string v3, "Unexpected exception loading stream"

    .line 129
    .line 130
    invoke-static {v2, v3, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 131
    .line 132
    .line 133
    new-instance v2, Lk8/k;

    .line 134
    .line 135
    invoke-direct {v2, v0}, Lk8/k;-><init>(Ljava/lang/Throwable;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0, v1, v2}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 143
    .line 144
    .line 145
    goto :goto_5

    .line 146
    :goto_4
    iget-boolean v2, p0, Lk8/i;->k:Z

    .line 147
    .line 148
    if-nez v2, :cond_2

    .line 149
    .line 150
    invoke-virtual {p0, v1, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 155
    .line 156
    .line 157
    :cond_2
    :goto_5
    return-void
.end method
