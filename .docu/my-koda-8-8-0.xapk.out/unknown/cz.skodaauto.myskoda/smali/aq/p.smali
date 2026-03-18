.class public final Laq/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Laq/p;->d:I

    iput-object p1, p0, Laq/p;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lvp/u0;Z)V
    .locals 0

    const/16 p2, 0x19

    iput p2, p0, Laq/p;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Laq/p;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/z3;Lca/d;)V
    .locals 0

    const/16 p2, 0x1d

    iput p2, p0, Laq/p;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Laq/p;->e:Ljava/lang/Object;

    return-void
.end method

.method private final a()V
    .locals 15

    .line 1
    iget-object v0, p0, Laq/p;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lg01/c;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget v1, v0, Lg01/c;->g:I

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    add-int/2addr v1, v2

    .line 10
    iput v1, v0, Lg01/c;->g:I

    .line 11
    .line 12
    invoke-virtual {v0}, Lg01/c;->b()Lg01/a;

    .line 13
    .line 14
    .line 15
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_5

    .line 16
    monitor-exit v0

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    :goto_0
    const-wide/16 v4, -0x1

    .line 29
    .line 30
    :try_start_1
    iget-object v6, v1, Lg01/a;->a:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v0, v6}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object v6, p0, Laq/p;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v6, Lg01/c;

    .line 38
    .line 39
    iget-object v6, v6, Lg01/c;->b:Ljava/util/logging/Logger;

    .line 40
    .line 41
    iget-object v7, v1, Lg01/a;->c:Lg01/b;

    .line 42
    .line 43
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    sget-object v8, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 47
    .line 48
    invoke-virtual {v6, v8}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    if-eqz v8, :cond_1

    .line 53
    .line 54
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 55
    .line 56
    .line 57
    move-result-wide v9

    .line 58
    const-string v11, "starting"

    .line 59
    .line 60
    invoke-static {v6, v1, v7, v11}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :catchall_0
    move-exception v2

    .line 65
    goto :goto_2

    .line 66
    :cond_1
    move-wide v9, v4

    .line 67
    :goto_1
    :try_start_2
    invoke-virtual {v1}, Lg01/a;->a()J

    .line 68
    .line 69
    .line 70
    move-result-wide v11
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 71
    if-eqz v8, :cond_2

    .line 72
    .line 73
    :try_start_3
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 74
    .line 75
    .line 76
    move-result-wide v13

    .line 77
    sub-long/2addr v13, v9

    .line 78
    new-instance v8, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 81
    .line 82
    .line 83
    const-string v9, "finished run in "

    .line 84
    .line 85
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-static {v13, v14}, Lkp/k8;->c(J)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v9

    .line 92
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v8

    .line 99
    invoke-static {v6, v1, v7, v8}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    :cond_2
    iget-object v6, p0, Laq/p;->e:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v6, Lg01/c;

    .line 105
    .line 106
    monitor-enter v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 107
    :try_start_4
    invoke-static {v6, v1, v11, v12, v2}, Lg01/c;->a(Lg01/c;Lg01/a;JZ)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v6}, Lg01/c;->b()Lg01/a;

    .line 111
    .line 112
    .line 113
    move-result-object v7
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 114
    :try_start_5
    monitor-exit v6
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 115
    if-nez v7, :cond_3

    .line 116
    .line 117
    invoke-virtual {v0, v3}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    return-void

    .line 121
    :cond_3
    move-object v1, v7

    .line 122
    goto :goto_0

    .line 123
    :catchall_1
    move-exception v2

    .line 124
    :try_start_6
    monitor-exit v6

    .line 125
    throw v2

    .line 126
    :catchall_2
    move-exception v2

    .line 127
    if-eqz v8, :cond_4

    .line 128
    .line 129
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 130
    .line 131
    .line 132
    move-result-wide v11

    .line 133
    sub-long/2addr v11, v9

    .line 134
    new-instance v8, Ljava/lang/StringBuilder;

    .line 135
    .line 136
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 137
    .line 138
    .line 139
    const-string v9, "failed a run in "

    .line 140
    .line 141
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-static {v11, v12}, Lkp/k8;->c(J)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v9

    .line 148
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v8

    .line 155
    invoke-static {v6, v1, v7, v8}, Lkp/k8;->b(Ljava/util/logging/Logger;Lg01/a;Lg01/b;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    :cond_4
    throw v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 159
    :goto_2
    :try_start_7
    iget-object p0, p0, Laq/p;->e:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast p0, Lg01/c;

    .line 162
    .line 163
    monitor-enter p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 164
    const/4 v6, 0x0

    .line 165
    :try_start_8
    invoke-static {p0, v1, v4, v5, v6}, Lg01/c;->a(Lg01/c;Lg01/a;JZ)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 166
    .line 167
    .line 168
    :try_start_9
    monitor-exit p0

    .line 169
    instance-of p0, v2, Ljava/lang/InterruptedException;

    .line 170
    .line 171
    if-eqz p0, :cond_5

    .line 172
    .line 173
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 178
    .line 179
    .line 180
    invoke-virtual {v0, v3}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    return-void

    .line 184
    :catchall_3
    move-exception p0

    .line 185
    goto :goto_3

    .line 186
    :cond_5
    :try_start_a
    throw v2

    .line 187
    :catchall_4
    move-exception v1

    .line 188
    monitor-exit p0

    .line 189
    throw v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 190
    :goto_3
    invoke-virtual {v0, v3}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw p0

    .line 194
    :catchall_5
    move-exception p0

    .line 195
    monitor-exit v0

    .line 196
    throw p0
.end method


# virtual methods
.method public b()V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    :try_start_0
    iget-object v2, p0, Laq/p;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v2, Lj0/h;

    .line 6
    .line 7
    iget-object v2, v2, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 8
    .line 9
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 10
    const/4 v3, 0x1

    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    :try_start_1
    iget-object v0, p0, Laq/p;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lj0/h;

    .line 16
    .line 17
    iget v4, v0, Lj0/h;->g:I

    .line 18
    .line 19
    const/4 v5, 0x4

    .line 20
    if-ne v4, v5, :cond_0

    .line 21
    .line 22
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    :goto_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V

    .line 30
    .line 31
    .line 32
    goto :goto_2

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_3

    .line 35
    :cond_0
    :try_start_2
    iget-wide v6, v0, Lj0/h;->h:J

    .line 36
    .line 37
    const-wide/16 v8, 0x1

    .line 38
    .line 39
    add-long/2addr v6, v8

    .line 40
    iput-wide v6, v0, Lj0/h;->h:J

    .line 41
    .line 42
    iput v5, v0, Lj0/h;->g:I

    .line 43
    .line 44
    move v0, v3

    .line 45
    :cond_1
    iget-object v4, p0, Laq/p;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v4, Lj0/h;

    .line 48
    .line 49
    iget-object v4, v4, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    check-cast v4, Ljava/lang/Runnable;

    .line 56
    .line 57
    if-nez v4, :cond_3

    .line 58
    .line 59
    iget-object p0, p0, Laq/p;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Lj0/h;

    .line 62
    .line 63
    iput v3, p0, Lj0/h;->g:I

    .line 64
    .line 65
    monitor-exit v2

    .line 66
    if-eqz v1, :cond_2

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_2
    :goto_2
    return-void

    .line 70
    :cond_3
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 71
    :try_start_3
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 72
    .line 73
    .line 74
    move-result v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 75
    or-int/2addr v1, v2

    .line 76
    :try_start_4
    invoke-interface {v4}, Ljava/lang/Runnable;->run()V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :catchall_1
    move-exception p0

    .line 81
    goto :goto_4

    .line 82
    :catch_0
    move-exception v2

    .line 83
    :try_start_5
    const-string v3, "SequentialExecutor"

    .line 84
    .line 85
    new-instance v5, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 88
    .line 89
    .line 90
    const-string v6, "Exception while executing runnable "

    .line 91
    .line 92
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    invoke-static {v3, v4, v2}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :goto_3
    :try_start_6
    monitor-exit v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 107
    :try_start_7
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 108
    :goto_4
    if-eqz v1, :cond_4

    .line 109
    .line 110
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    invoke-virtual {v0}, Ljava/lang/Thread;->interrupt()V

    .line 115
    .line 116
    .line 117
    :cond_4
    throw p0
.end method

.method public final run()V
    .locals 23

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget v0, v1, Laq/p;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    const/4 v3, 0x0

    .line 7
    const-wide/16 v4, 0x0

    .line 8
    .line 9
    const/4 v6, 0x2

    .line 10
    const/4 v7, 0x0

    .line 11
    const/4 v8, 0x0

    .line 12
    const/4 v9, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lvp/z3;

    .line 19
    .line 20
    invoke-virtual {v0}, Lvp/z3;->f()Lvp/e1;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1}, Lvp/e1;->a0()V

    .line 25
    .line 26
    .line 27
    new-instance v1, Lvp/y0;

    .line 28
    .line 29
    invoke-direct {v1, v0}, Lvp/y0;-><init>(Lvp/z3;)V

    .line 30
    .line 31
    .line 32
    iput-object v1, v0, Lvp/z3;->n:Lvp/y0;

    .line 33
    .line 34
    new-instance v1, Lvp/n;

    .line 35
    .line 36
    invoke-direct {v1, v0}, Lvp/n;-><init>(Lvp/z3;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1}, Lvp/u3;->c0()V

    .line 40
    .line 41
    .line 42
    iput-object v1, v0, Lvp/z3;->f:Lvp/n;

    .line 43
    .line 44
    iget-object v1, v0, Lvp/z3;->d:Lvp/a1;

    .line 45
    .line 46
    invoke-virtual {v0}, Lvp/z3;->d0()Lvp/h;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object v1, v2, Lvp/h;->h:Lvp/g;

    .line 54
    .line 55
    new-instance v1, Lvp/f3;

    .line 56
    .line 57
    invoke-direct {v1, v0}, Lvp/f3;-><init>(Lvp/z3;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Lvp/u3;->c0()V

    .line 61
    .line 62
    .line 63
    iput-object v1, v0, Lvp/z3;->l:Lvp/f3;

    .line 64
    .line 65
    new-instance v1, Lvp/d;

    .line 66
    .line 67
    invoke-direct {v1, v0}, Lvp/u3;-><init>(Lvp/z3;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1}, Lvp/u3;->c0()V

    .line 71
    .line 72
    .line 73
    iput-object v1, v0, Lvp/z3;->i:Lvp/d;

    .line 74
    .line 75
    new-instance v1, Lvp/s0;

    .line 76
    .line 77
    invoke-direct {v1, v0, v9}, Lvp/s0;-><init>(Lvp/z3;I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v1}, Lvp/u3;->c0()V

    .line 81
    .line 82
    .line 83
    iput-object v1, v0, Lvp/z3;->k:Lvp/s0;

    .line 84
    .line 85
    new-instance v1, Lvp/p3;

    .line 86
    .line 87
    invoke-direct {v1, v0}, Lvp/p3;-><init>(Lvp/z3;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v1}, Lvp/u3;->c0()V

    .line 91
    .line 92
    .line 93
    iput-object v1, v0, Lvp/z3;->h:Lvp/p3;

    .line 94
    .line 95
    new-instance v1, Lvp/u0;

    .line 96
    .line 97
    invoke-direct {v1, v0}, Lvp/u0;-><init>(Lvp/z3;)V

    .line 98
    .line 99
    .line 100
    iput-object v1, v0, Lvp/z3;->g:Lvp/u0;

    .line 101
    .line 102
    iget v1, v0, Lvp/z3;->u:I

    .line 103
    .line 104
    iget v2, v0, Lvp/z3;->v:I

    .line 105
    .line 106
    if-eq v1, v2, :cond_0

    .line 107
    .line 108
    invoke-virtual {v0}, Lvp/z3;->d()Lvp/p0;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 113
    .line 114
    iget v2, v0, Lvp/z3;->u:I

    .line 115
    .line 116
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    iget v3, v0, Lvp/z3;->v:I

    .line 121
    .line 122
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    const-string v6, "Not all upload components initialized"

    .line 127
    .line 128
    invoke-virtual {v1, v2, v3, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    :cond_0
    iget-object v1, v0, Lvp/z3;->p:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 132
    .line 133
    invoke-virtual {v1, v9}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v0}, Lvp/z3;->d()Lvp/p0;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 141
    .line 142
    const-string v2, "UploadController is now fully initialized"

    .line 143
    .line 144
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0}, Lvp/z3;->f()Lvp/e1;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {v1}, Lvp/e1;->a0()V

    .line 152
    .line 153
    .line 154
    iget-object v1, v0, Lvp/z3;->f:Lvp/n;

    .line 155
    .line 156
    invoke-static {v1}, Lvp/z3;->T(Lvp/u3;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v1}, Lvp/n;->k0()V

    .line 160
    .line 161
    .line 162
    iget-object v1, v0, Lvp/z3;->f:Lvp/n;

    .line 163
    .line 164
    invoke-static {v1}, Lvp/z3;->T(Lvp/u3;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v1}, Lvp/n;->H0()Z

    .line 174
    .line 175
    .line 176
    move-result v2

    .line 177
    if-eqz v2, :cond_2

    .line 178
    .line 179
    sget-object v2, Lvp/z;->v0:Lvp/y;

    .line 180
    .line 181
    invoke-virtual {v2, v7}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    check-cast v3, Ljava/lang/Long;

    .line 186
    .line 187
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 188
    .line 189
    .line 190
    move-result-wide v8

    .line 191
    cmp-long v3, v8, v4

    .line 192
    .line 193
    if-nez v3, :cond_1

    .line 194
    .line 195
    goto :goto_0

    .line 196
    :cond_1
    invoke-virtual {v1}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 197
    .line 198
    .line 199
    move-result-object v3

    .line 200
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v1, Lvp/g1;

    .line 203
    .line 204
    iget-object v6, v1, Lvp/g1;->n:Lto/a;

    .line 205
    .line 206
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 207
    .line 208
    .line 209
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 210
    .line 211
    .line 212
    move-result-wide v8

    .line 213
    invoke-static {v8, v9}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v6

    .line 217
    invoke-virtual {v2, v7}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v2

    .line 221
    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v2

    .line 225
    filled-new-array {v6, v2}, [Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    const-string v6, "trigger_uris"

    .line 230
    .line 231
    const-string v7, "abs(timestamp_millis - ?) > cast(? as integer)"

    .line 232
    .line 233
    invoke-virtual {v3, v6, v7, v2}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    .line 234
    .line 235
    .line 236
    move-result v2

    .line 237
    if-lez v2, :cond_2

    .line 238
    .line 239
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 240
    .line 241
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 242
    .line 243
    .line 244
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 245
    .line 246
    const-string v3, "Deleted stale trigger uris. rowsDeleted"

    .line 247
    .line 248
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    invoke-virtual {v1, v2, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    :cond_2
    :goto_0
    iget-object v1, v0, Lvp/z3;->l:Lvp/f3;

    .line 256
    .line 257
    iget-object v1, v1, Lvp/f3;->l:La8/s1;

    .line 258
    .line 259
    invoke-virtual {v1}, La8/s1;->g()J

    .line 260
    .line 261
    .line 262
    move-result-wide v1

    .line 263
    cmp-long v1, v1, v4

    .line 264
    .line 265
    if-nez v1, :cond_3

    .line 266
    .line 267
    iget-object v1, v0, Lvp/z3;->l:Lvp/f3;

    .line 268
    .line 269
    iget-object v1, v1, Lvp/f3;->l:La8/s1;

    .line 270
    .line 271
    invoke-virtual {v0}, Lvp/z3;->l()Lto/a;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 276
    .line 277
    .line 278
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 279
    .line 280
    .line 281
    move-result-wide v2

    .line 282
    invoke-virtual {v1, v2, v3}, La8/s1;->h(J)V

    .line 283
    .line 284
    .line 285
    :cond_3
    invoke-virtual {v0}, Lvp/z3;->N()V

    .line 286
    .line 287
    .line 288
    return-void

    .line 289
    :pswitch_0
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v0, Lvp/i3;

    .line 292
    .line 293
    iget-object v1, v0, Lvp/i3;->f:Lb81/d;

    .line 294
    .line 295
    iget-object v1, v1, Lb81/d;->f:Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v1, Lvp/k3;

    .line 298
    .line 299
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 300
    .line 301
    .line 302
    iget-object v2, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 303
    .line 304
    check-cast v2, Lvp/g1;

    .line 305
    .line 306
    iget-object v3, v2, Lvp/g1;->i:Lvp/p0;

    .line 307
    .line 308
    iget-object v4, v2, Lvp/g1;->d:Landroid/content/Context;

    .line 309
    .line 310
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 311
    .line 312
    .line 313
    iget-object v5, v3, Lvp/p0;->q:Lvp/n0;

    .line 314
    .line 315
    const-string v6, "Application going to the background"

    .line 316
    .line 317
    invoke-virtual {v5, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 318
    .line 319
    .line 320
    iget-object v5, v2, Lvp/g1;->h:Lvp/w0;

    .line 321
    .line 322
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 323
    .line 324
    .line 325
    iget-object v5, v5, Lvp/w0;->w:Lvp/v0;

    .line 326
    .line 327
    invoke-virtual {v5, v9}, Lvp/v0;->b(Z)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 331
    .line 332
    .line 333
    iput-boolean v9, v1, Lvp/k3;->h:Z

    .line 334
    .line 335
    iget-object v5, v2, Lvp/g1;->g:Lvp/h;

    .line 336
    .line 337
    invoke-virtual {v5}, Lvp/h;->o0()Z

    .line 338
    .line 339
    .line 340
    move-result v6

    .line 341
    if-nez v6, :cond_4

    .line 342
    .line 343
    iget-wide v10, v0, Lvp/i3;->e:J

    .line 344
    .line 345
    iget-object v1, v1, Lvp/k3;->j:Lc1/i2;

    .line 346
    .line 347
    invoke-virtual {v1, v10, v11, v8, v8}, Lc1/i2;->i(JZZ)Z

    .line 348
    .line 349
    .line 350
    iget-object v1, v1, Lc1/i2;->f:Ljava/lang/Object;

    .line 351
    .line 352
    check-cast v1, Lvp/j3;

    .line 353
    .line 354
    invoke-virtual {v1}, Lvp/o;->c()V

    .line 355
    .line 356
    .line 357
    :cond_4
    iget-wide v0, v0, Lvp/i3;->d:J

    .line 358
    .line 359
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 360
    .line 361
    .line 362
    iget-object v6, v3, Lvp/p0;->p:Lvp/n0;

    .line 363
    .line 364
    const-string v8, "Application backgrounded at: timestamp_millis"

    .line 365
    .line 366
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 367
    .line 368
    .line 369
    move-result-object v0

    .line 370
    invoke-virtual {v6, v0, v8}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    iget-object v0, v2, Lvp/g1;->p:Lvp/j2;

    .line 374
    .line 375
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 379
    .line 380
    .line 381
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 382
    .line 383
    check-cast v1, Lvp/g1;

    .line 384
    .line 385
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 389
    .line 390
    .line 391
    move-result-object v0

    .line 392
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 393
    .line 394
    .line 395
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 396
    .line 397
    .line 398
    invoke-virtual {v0}, Lvp/d3;->h0()Z

    .line 399
    .line 400
    .line 401
    move-result v6

    .line 402
    if-nez v6, :cond_5

    .line 403
    .line 404
    goto :goto_1

    .line 405
    :cond_5
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 406
    .line 407
    check-cast v0, Lvp/g1;

    .line 408
    .line 409
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 410
    .line 411
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v0}, Lvp/d4;->G0()I

    .line 415
    .line 416
    .line 417
    move-result v0

    .line 418
    const v6, 0x3b3a8

    .line 419
    .line 420
    .line 421
    if-lt v0, v6, :cond_6

    .line 422
    .line 423
    :goto_1
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 428
    .line 429
    .line 430
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 431
    .line 432
    .line 433
    invoke-virtual {v0, v9}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 434
    .line 435
    .line 436
    move-result-object v1

    .line 437
    new-instance v6, Lvp/y2;

    .line 438
    .line 439
    invoke-direct {v6, v0, v1, v9}, Lvp/y2;-><init>(Lvp/d3;Lvp/f4;I)V

    .line 440
    .line 441
    .line 442
    invoke-virtual {v0, v6}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 443
    .line 444
    .line 445
    :cond_6
    sget-object v0, Lvp/z;->N0:Lvp/y;

    .line 446
    .line 447
    invoke-virtual {v5, v7, v0}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 448
    .line 449
    .line 450
    move-result v0

    .line 451
    if-eqz v0, :cond_8

    .line 452
    .line 453
    iget-object v0, v2, Lvp/g1;->l:Lvp/d4;

    .line 454
    .line 455
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 459
    .line 460
    .line 461
    move-result-object v1

    .line 462
    iget-object v6, v5, Lvp/h;->g:Ljava/lang/String;

    .line 463
    .line 464
    invoke-virtual {v0, v1, v6}, Lvp/d4;->A0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 465
    .line 466
    .line 467
    move-result v0

    .line 468
    if-eqz v0, :cond_7

    .line 469
    .line 470
    const-wide/16 v0, 0x3e8

    .line 471
    .line 472
    goto :goto_2

    .line 473
    :cond_7
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 474
    .line 475
    .line 476
    move-result-object v0

    .line 477
    sget-object v1, Lvp/z;->E:Lvp/y;

    .line 478
    .line 479
    invoke-virtual {v5, v0, v1}, Lvp/h;->h0(Ljava/lang/String;Lvp/y;)J

    .line 480
    .line 481
    .line 482
    move-result-wide v0

    .line 483
    :goto_2
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 484
    .line 485
    .line 486
    iget-object v3, v3, Lvp/p0;->r:Lvp/n0;

    .line 487
    .line 488
    const-string v4, "[sgtm] Scheduling batch upload with minimum latency in millis"

    .line 489
    .line 490
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 491
    .line 492
    .line 493
    move-result-object v5

    .line 494
    invoke-virtual {v3, v5, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 495
    .line 496
    .line 497
    iget-object v3, v2, Lvp/g1;->x:Lvp/o2;

    .line 498
    .line 499
    invoke-static {v3}, Lvp/g1;->e(Lvp/x;)V

    .line 500
    .line 501
    .line 502
    iget-object v2, v2, Lvp/g1;->x:Lvp/o2;

    .line 503
    .line 504
    invoke-virtual {v2, v0, v1}, Lvp/o2;->e0(J)V

    .line 505
    .line 506
    .line 507
    :cond_8
    return-void

    .line 508
    :pswitch_1
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 509
    .line 510
    check-cast v0, Lk0/g;

    .line 511
    .line 512
    iget-object v0, v0, Lk0/g;->f:Ljava/lang/Object;

    .line 513
    .line 514
    check-cast v0, Lvp/c3;

    .line 515
    .line 516
    iget-object v0, v0, Lvp/c3;->c:Lvp/d3;

    .line 517
    .line 518
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 519
    .line 520
    check-cast v1, Lvp/g1;

    .line 521
    .line 522
    iget-object v1, v1, Lvp/g1;->j:Lvp/e1;

    .line 523
    .line 524
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 525
    .line 526
    .line 527
    new-instance v2, Lvp/b3;

    .line 528
    .line 529
    invoke-direct {v2, v0, v8}, Lvp/b3;-><init>(Lvp/d3;I)V

    .line 530
    .line 531
    .line 532
    invoke-virtual {v1, v2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 533
    .line 534
    .line 535
    return-void

    .line 536
    :pswitch_2
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast v0, Lvp/c3;

    .line 539
    .line 540
    iget-object v0, v0, Lvp/c3;->c:Lvp/d3;

    .line 541
    .line 542
    new-instance v1, Landroid/content/ComponentName;

    .line 543
    .line 544
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 545
    .line 546
    check-cast v2, Lvp/g1;

    .line 547
    .line 548
    iget-object v2, v2, Lvp/g1;->d:Landroid/content/Context;

    .line 549
    .line 550
    const-string v3, "com.google.android.gms.measurement.AppMeasurementService"

    .line 551
    .line 552
    invoke-direct {v1, v2, v3}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 553
    .line 554
    .line 555
    invoke-virtual {v0, v1}, Lvp/d3;->l0(Landroid/content/ComponentName;)V

    .line 556
    .line 557
    .line 558
    return-void

    .line 559
    :pswitch_3
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 560
    .line 561
    check-cast v0, Lvp/u0;

    .line 562
    .line 563
    iget-object v0, v0, Lvp/u0;->a:Lvp/z3;

    .line 564
    .line 565
    invoke-virtual {v0}, Lvp/z3;->N()V

    .line 566
    .line 567
    .line 568
    return-void

    .line 569
    :pswitch_4
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 570
    .line 571
    check-cast v0, Ltu/b;

    .line 572
    .line 573
    iget-object v1, v0, Ltu/b;->d:Lqp/g;

    .line 574
    .line 575
    if-eqz v1, :cond_9

    .line 576
    .line 577
    invoke-virtual {v1, v0}, Lqp/g;->h(Lqp/c;)V

    .line 578
    .line 579
    .line 580
    invoke-virtual {v1, v0}, Lqp/g;->i(Lqp/d;)V

    .line 581
    .line 582
    .line 583
    invoke-virtual {v1, v0}, Lqp/g;->j(Lqp/e;)V

    .line 584
    .line 585
    .line 586
    invoke-virtual {v1, v0}, Lqp/g;->k(Lqp/f;)V

    .line 587
    .line 588
    .line 589
    invoke-virtual {v1, v0}, Lqp/g;->g(Lqp/a;)V

    .line 590
    .line 591
    .line 592
    :cond_9
    return-void

    .line 593
    :pswitch_5
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 594
    .line 595
    check-cast v0, Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 596
    .line 597
    iget-object v1, v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 598
    .line 599
    if-nez v1, :cond_a

    .line 600
    .line 601
    new-instance v1, Lzt/h;

    .line 602
    .line 603
    invoke-direct {v1}, Lzt/h;-><init>()V

    .line 604
    .line 605
    .line 606
    iput-object v1, v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->m:Lzt/h;

    .line 607
    .line 608
    :cond_a
    return-void

    .line 609
    :pswitch_6
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 610
    .line 611
    check-cast v0, Lq/z;

    .line 612
    .line 613
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 614
    .line 615
    .line 616
    move-result-object v1

    .line 617
    if-nez v1, :cond_b

    .line 618
    .line 619
    const-string v0, "FingerprintFragment"

    .line 620
    .line 621
    const-string v1, "Not resetting the dialog. Context is null."

    .line 622
    .line 623
    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 624
    .line 625
    .line 626
    goto :goto_3

    .line 627
    :cond_b
    iget-object v2, v0, Lq/z;->v:Lq/s;

    .line 628
    .line 629
    invoke-virtual {v2, v9}, Lq/s;->d(I)V

    .line 630
    .line 631
    .line 632
    iget-object v0, v0, Lq/z;->v:Lq/s;

    .line 633
    .line 634
    const v2, 0x7f120335

    .line 635
    .line 636
    .line 637
    invoke-virtual {v1, v2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 638
    .line 639
    .line 640
    move-result-object v1

    .line 641
    invoke-virtual {v0, v1}, Lq/s;->b(Ljava/lang/CharSequence;)V

    .line 642
    .line 643
    .line 644
    :goto_3
    return-void

    .line 645
    :pswitch_7
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 646
    .line 647
    check-cast v0, Lq/k;

    .line 648
    .line 649
    iget-object v0, v0, Lq/k;->e:Lq/s;

    .line 650
    .line 651
    iget-object v1, v0, Lq/s;->e:Ljp/he;

    .line 652
    .line 653
    if-nez v1, :cond_c

    .line 654
    .line 655
    new-instance v1, Lq/o;

    .line 656
    .line 657
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 658
    .line 659
    .line 660
    iput-object v1, v0, Lq/s;->e:Ljp/he;

    .line 661
    .line 662
    :cond_c
    iget-object v0, v0, Lq/s;->e:Ljp/he;

    .line 663
    .line 664
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 665
    .line 666
    .line 667
    return-void

    .line 668
    :pswitch_8
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 669
    .line 670
    check-cast v0, Landroidx/appcompat/widget/Toolbar;

    .line 671
    .line 672
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 673
    .line 674
    if-eqz v0, :cond_d

    .line 675
    .line 676
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 677
    .line 678
    if-eqz v0, :cond_d

    .line 679
    .line 680
    invoke-virtual {v0}, Lm/j;->l()Z

    .line 681
    .line 682
    .line 683
    :cond_d
    return-void

    .line 684
    :pswitch_9
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 685
    .line 686
    check-cast v0, Landroidx/appcompat/widget/SearchView$SearchAutoComplete;

    .line 687
    .line 688
    iget-boolean v1, v0, Landroidx/appcompat/widget/SearchView$SearchAutoComplete;->i:Z

    .line 689
    .line 690
    if-eqz v1, :cond_e

    .line 691
    .line 692
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 693
    .line 694
    .line 695
    move-result-object v1

    .line 696
    const-string v2, "input_method"

    .line 697
    .line 698
    invoke-virtual {v1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 699
    .line 700
    .line 701
    move-result-object v1

    .line 702
    check-cast v1, Landroid/view/inputmethod/InputMethodManager;

    .line 703
    .line 704
    invoke-virtual {v1, v0, v8}, Landroid/view/inputmethod/InputMethodManager;->showSoftInput(Landroid/view/View;I)Z

    .line 705
    .line 706
    .line 707
    iput-boolean v8, v0, Landroidx/appcompat/widget/SearchView$SearchAutoComplete;->i:Z

    .line 708
    .line 709
    :cond_e
    return-void

    .line 710
    :pswitch_a
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 711
    .line 712
    check-cast v0, Lm/m1;

    .line 713
    .line 714
    iput-object v7, v0, Lm/m1;->o:Laq/p;

    .line 715
    .line 716
    invoke-virtual {v0}, Lm/m1;->drawableStateChanged()V

    .line 717
    .line 718
    .line 719
    return-void

    .line 720
    :pswitch_b
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 721
    .line 722
    check-cast v0, Llo/b0;

    .line 723
    .line 724
    iget-object v0, v0, Llo/b0;->j:Lh8/o;

    .line 725
    .line 726
    new-instance v1, Ljo/b;

    .line 727
    .line 728
    const/4 v2, 0x4

    .line 729
    invoke-direct {v1, v2}, Ljo/b;-><init>(I)V

    .line 730
    .line 731
    .line 732
    invoke-virtual {v0, v1}, Lh8/o;->e(Ljo/b;)V

    .line 733
    .line 734
    .line 735
    return-void

    .line 736
    :pswitch_c
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 737
    .line 738
    check-cast v0, Lhu/q;

    .line 739
    .line 740
    iget-object v0, v0, Lhu/q;->e:Ljava/lang/Object;

    .line 741
    .line 742
    check-cast v0, Llo/s;

    .line 743
    .line 744
    iget-object v0, v0, Llo/s;->d:Lko/c;

    .line 745
    .line 746
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 747
    .line 748
    .line 749
    move-result-object v1

    .line 750
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 751
    .line 752
    .line 753
    move-result-object v1

    .line 754
    const-string v2, " disconnecting because it was signed out."

    .line 755
    .line 756
    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 757
    .line 758
    .line 759
    move-result-object v1

    .line 760
    invoke-interface {v0, v1}, Lko/c;->a(Ljava/lang/String;)V

    .line 761
    .line 762
    .line 763
    return-void

    .line 764
    :pswitch_d
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 765
    .line 766
    check-cast v0, Llo/s;

    .line 767
    .line 768
    invoke-virtual {v0}, Llo/s;->i()V

    .line 769
    .line 770
    .line 771
    return-void

    .line 772
    :pswitch_e
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 773
    .line 774
    check-cast v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 775
    .line 776
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->C0()Z

    .line 777
    .line 778
    .line 779
    return-void

    .line 780
    :pswitch_f
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 781
    .line 782
    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    .line 783
    .line 784
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->M:Lka/c0;

    .line 785
    .line 786
    if-eqz v1, :cond_1b

    .line 787
    .line 788
    check-cast v1, Lka/h;

    .line 789
    .line 790
    iget-wide v6, v1, Lka/c0;->d:J

    .line 791
    .line 792
    iget-object v2, v1, Lka/h;->h:Ljava/util/ArrayList;

    .line 793
    .line 794
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 795
    .line 796
    .line 797
    move-result v10

    .line 798
    iget-object v11, v1, Lka/h;->j:Ljava/util/ArrayList;

    .line 799
    .line 800
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 801
    .line 802
    .line 803
    move-result v12

    .line 804
    iget-object v13, v1, Lka/h;->k:Ljava/util/ArrayList;

    .line 805
    .line 806
    invoke-virtual {v13}, Ljava/util/ArrayList;->isEmpty()Z

    .line 807
    .line 808
    .line 809
    move-result v14

    .line 810
    iget-object v15, v1, Lka/h;->i:Ljava/util/ArrayList;

    .line 811
    .line 812
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 813
    .line 814
    .line 815
    move-result v16

    .line 816
    if-eqz v10, :cond_f

    .line 817
    .line 818
    if-eqz v12, :cond_f

    .line 819
    .line 820
    if-eqz v16, :cond_f

    .line 821
    .line 822
    if-eqz v14, :cond_f

    .line 823
    .line 824
    goto/16 :goto_c

    .line 825
    .line 826
    :cond_f
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 827
    .line 828
    .line 829
    move-result-object v17

    .line 830
    :goto_4
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->hasNext()Z

    .line 831
    .line 832
    .line 833
    move-result v18

    .line 834
    if-eqz v18, :cond_10

    .line 835
    .line 836
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v18

    .line 840
    move-wide/from16 v19, v4

    .line 841
    .line 842
    move-object/from16 v4, v18

    .line 843
    .line 844
    check-cast v4, Lka/v0;

    .line 845
    .line 846
    iget-object v5, v4, Lka/v0;->a:Landroid/view/View;

    .line 847
    .line 848
    invoke-virtual {v5}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 849
    .line 850
    .line 851
    move-result-object v9

    .line 852
    iget-object v8, v1, Lka/h;->q:Ljava/util/ArrayList;

    .line 853
    .line 854
    invoke-virtual {v8, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 855
    .line 856
    .line 857
    invoke-virtual {v9, v6, v7}, Landroid/view/ViewPropertyAnimator;->setDuration(J)Landroid/view/ViewPropertyAnimator;

    .line 858
    .line 859
    .line 860
    move-result-object v8

    .line 861
    invoke-virtual {v8, v3}, Landroid/view/ViewPropertyAnimator;->alpha(F)Landroid/view/ViewPropertyAnimator;

    .line 862
    .line 863
    .line 864
    move-result-object v8

    .line 865
    move/from16 v22, v3

    .line 866
    .line 867
    new-instance v3, Lka/c;

    .line 868
    .line 869
    invoke-direct {v3, v1, v4, v9, v5}, Lka/c;-><init>(Lka/h;Lka/v0;Landroid/view/ViewPropertyAnimator;Landroid/view/View;)V

    .line 870
    .line 871
    .line 872
    invoke-virtual {v8, v3}, Landroid/view/ViewPropertyAnimator;->setListener(Landroid/animation/Animator$AnimatorListener;)Landroid/view/ViewPropertyAnimator;

    .line 873
    .line 874
    .line 875
    move-result-object v3

    .line 876
    invoke-virtual {v3}, Landroid/view/ViewPropertyAnimator;->start()V

    .line 877
    .line 878
    .line 879
    move-wide/from16 v4, v19

    .line 880
    .line 881
    move/from16 v3, v22

    .line 882
    .line 883
    const/4 v8, 0x0

    .line 884
    const/4 v9, 0x1

    .line 885
    goto :goto_4

    .line 886
    :cond_10
    move-wide/from16 v19, v4

    .line 887
    .line 888
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 889
    .line 890
    .line 891
    if-nez v12, :cond_12

    .line 892
    .line 893
    new-instance v2, Ljava/util/ArrayList;

    .line 894
    .line 895
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 896
    .line 897
    .line 898
    invoke-virtual {v2, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 899
    .line 900
    .line 901
    iget-object v3, v1, Lka/h;->m:Ljava/util/ArrayList;

    .line 902
    .line 903
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 904
    .line 905
    .line 906
    invoke-virtual {v11}, Ljava/util/ArrayList;->clear()V

    .line 907
    .line 908
    .line 909
    new-instance v3, Lka/b;

    .line 910
    .line 911
    const/4 v4, 0x0

    .line 912
    invoke-direct {v3, v1, v2, v4}, Lka/b;-><init>(Lka/h;Ljava/util/ArrayList;I)V

    .line 913
    .line 914
    .line 915
    if-nez v10, :cond_11

    .line 916
    .line 917
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 918
    .line 919
    .line 920
    move-result-object v2

    .line 921
    check-cast v2, Lka/g;

    .line 922
    .line 923
    iget-object v2, v2, Lka/g;->a:Lka/v0;

    .line 924
    .line 925
    iget-object v2, v2, Lka/v0;->a:Landroid/view/View;

    .line 926
    .line 927
    sget-object v4, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 928
    .line 929
    invoke-virtual {v2, v3, v6, v7}, Landroid/view/View;->postOnAnimationDelayed(Ljava/lang/Runnable;J)V

    .line 930
    .line 931
    .line 932
    goto :goto_5

    .line 933
    :cond_11
    invoke-virtual {v3}, Lka/b;->run()V

    .line 934
    .line 935
    .line 936
    :cond_12
    :goto_5
    if-nez v14, :cond_14

    .line 937
    .line 938
    new-instance v2, Ljava/util/ArrayList;

    .line 939
    .line 940
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 941
    .line 942
    .line 943
    invoke-virtual {v2, v13}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 944
    .line 945
    .line 946
    iget-object v3, v1, Lka/h;->n:Ljava/util/ArrayList;

    .line 947
    .line 948
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 949
    .line 950
    .line 951
    invoke-virtual {v13}, Ljava/util/ArrayList;->clear()V

    .line 952
    .line 953
    .line 954
    new-instance v3, Llr/b;

    .line 955
    .line 956
    const/16 v4, 0xb

    .line 957
    .line 958
    const/4 v5, 0x0

    .line 959
    invoke-direct {v3, v1, v2, v5, v4}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 960
    .line 961
    .line 962
    if-nez v10, :cond_13

    .line 963
    .line 964
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 965
    .line 966
    .line 967
    move-result-object v2

    .line 968
    check-cast v2, Lka/f;

    .line 969
    .line 970
    iget-object v2, v2, Lka/f;->a:Lka/v0;

    .line 971
    .line 972
    iget-object v2, v2, Lka/v0;->a:Landroid/view/View;

    .line 973
    .line 974
    sget-object v4, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 975
    .line 976
    invoke-virtual {v2, v3, v6, v7}, Landroid/view/View;->postOnAnimationDelayed(Ljava/lang/Runnable;J)V

    .line 977
    .line 978
    .line 979
    goto :goto_6

    .line 980
    :cond_13
    invoke-virtual {v3}, Llr/b;->run()V

    .line 981
    .line 982
    .line 983
    :cond_14
    :goto_6
    if-nez v16, :cond_1a

    .line 984
    .line 985
    new-instance v2, Ljava/util/ArrayList;

    .line 986
    .line 987
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 988
    .line 989
    .line 990
    invoke-virtual {v2, v15}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 991
    .line 992
    .line 993
    iget-object v3, v1, Lka/h;->l:Ljava/util/ArrayList;

    .line 994
    .line 995
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 996
    .line 997
    .line 998
    invoke-virtual {v15}, Ljava/util/ArrayList;->clear()V

    .line 999
    .line 1000
    .line 1001
    new-instance v3, Lka/b;

    .line 1002
    .line 1003
    const/4 v4, 0x1

    .line 1004
    invoke-direct {v3, v1, v2, v4}, Lka/b;-><init>(Lka/h;Ljava/util/ArrayList;I)V

    .line 1005
    .line 1006
    .line 1007
    if-eqz v10, :cond_16

    .line 1008
    .line 1009
    if-eqz v12, :cond_16

    .line 1010
    .line 1011
    if-nez v14, :cond_15

    .line 1012
    .line 1013
    goto :goto_7

    .line 1014
    :cond_15
    invoke-virtual {v3}, Lka/b;->run()V

    .line 1015
    .line 1016
    .line 1017
    goto :goto_b

    .line 1018
    :cond_16
    :goto_7
    if-nez v10, :cond_17

    .line 1019
    .line 1020
    goto :goto_8

    .line 1021
    :cond_17
    move-wide/from16 v6, v19

    .line 1022
    .line 1023
    :goto_8
    if-nez v12, :cond_18

    .line 1024
    .line 1025
    iget-wide v4, v1, Lka/c0;->e:J

    .line 1026
    .line 1027
    goto :goto_9

    .line 1028
    :cond_18
    move-wide/from16 v4, v19

    .line 1029
    .line 1030
    :goto_9
    if-nez v14, :cond_19

    .line 1031
    .line 1032
    iget-wide v8, v1, Lka/c0;->f:J

    .line 1033
    .line 1034
    goto :goto_a

    .line 1035
    :cond_19
    move-wide/from16 v8, v19

    .line 1036
    .line 1037
    :goto_a
    invoke-static {v4, v5, v8, v9}, Ljava/lang/Math;->max(JJ)J

    .line 1038
    .line 1039
    .line 1040
    move-result-wide v4

    .line 1041
    add-long/2addr v4, v6

    .line 1042
    const/4 v1, 0x0

    .line 1043
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1044
    .line 1045
    .line 1046
    move-result-object v2

    .line 1047
    check-cast v2, Lka/v0;

    .line 1048
    .line 1049
    iget-object v2, v2, Lka/v0;->a:Landroid/view/View;

    .line 1050
    .line 1051
    sget-object v6, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 1052
    .line 1053
    invoke-virtual {v2, v3, v4, v5}, Landroid/view/View;->postOnAnimationDelayed(Ljava/lang/Runnable;J)V

    .line 1054
    .line 1055
    .line 1056
    goto :goto_d

    .line 1057
    :cond_1a
    :goto_b
    const/4 v1, 0x0

    .line 1058
    goto :goto_d

    .line 1059
    :cond_1b
    :goto_c
    move v1, v8

    .line 1060
    :goto_d
    iput-boolean v1, v0, Landroidx/recyclerview/widget/RecyclerView;->w1:Z

    .line 1061
    .line 1062
    return-void

    .line 1063
    :pswitch_10
    move/from16 v22, v3

    .line 1064
    .line 1065
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1066
    .line 1067
    check-cast v0, Lka/k;

    .line 1068
    .line 1069
    iget-object v1, v0, Lka/k;->z:Landroid/animation/ValueAnimator;

    .line 1070
    .line 1071
    iget v3, v0, Lka/k;->A:I

    .line 1072
    .line 1073
    const/4 v4, 0x1

    .line 1074
    if-eq v3, v4, :cond_1c

    .line 1075
    .line 1076
    if-eq v3, v6, :cond_1d

    .line 1077
    .line 1078
    goto :goto_e

    .line 1079
    :cond_1c
    invoke-virtual {v1}, Landroid/animation/ValueAnimator;->cancel()V

    .line 1080
    .line 1081
    .line 1082
    :cond_1d
    iput v2, v0, Lka/k;->A:I

    .line 1083
    .line 1084
    invoke-virtual {v1}, Landroid/animation/ValueAnimator;->getAnimatedValue()Ljava/lang/Object;

    .line 1085
    .line 1086
    .line 1087
    move-result-object v0

    .line 1088
    check-cast v0, Ljava/lang/Float;

    .line 1089
    .line 1090
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 1091
    .line 1092
    .line 1093
    move-result v0

    .line 1094
    new-array v2, v6, [F

    .line 1095
    .line 1096
    const/16 v21, 0x0

    .line 1097
    .line 1098
    aput v0, v2, v21

    .line 1099
    .line 1100
    const/16 v18, 0x1

    .line 1101
    .line 1102
    aput v22, v2, v18

    .line 1103
    .line 1104
    invoke-virtual {v1, v2}, Landroid/animation/ValueAnimator;->setFloatValues([F)V

    .line 1105
    .line 1106
    .line 1107
    const/16 v0, 0x1f4

    .line 1108
    .line 1109
    int-to-long v2, v0

    .line 1110
    invoke-virtual {v1, v2, v3}, Landroid/animation/ValueAnimator;->setDuration(J)Landroid/animation/ValueAnimator;

    .line 1111
    .line 1112
    .line 1113
    invoke-virtual {v1}, Landroid/animation/ValueAnimator;->start()V

    .line 1114
    .line 1115
    .line 1116
    :goto_e
    return-void

    .line 1117
    :pswitch_11
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1118
    .line 1119
    check-cast v0, Lk8/j;

    .line 1120
    .line 1121
    check-cast v0, Lh8/r0;

    .line 1122
    .line 1123
    iget-object v1, v0, Lh8/r0;->w:[Lh8/x0;

    .line 1124
    .line 1125
    array-length v2, v1

    .line 1126
    const/4 v8, 0x0

    .line 1127
    :goto_f
    if-ge v8, v2, :cond_1f

    .line 1128
    .line 1129
    aget-object v3, v1, v8

    .line 1130
    .line 1131
    const/4 v4, 0x1

    .line 1132
    invoke-virtual {v3, v4}, Lh8/x0;->l(Z)V

    .line 1133
    .line 1134
    .line 1135
    iget-object v4, v3, Lh8/x0;->h:Laq/a;

    .line 1136
    .line 1137
    if-eqz v4, :cond_1e

    .line 1138
    .line 1139
    iget-object v5, v3, Lh8/x0;->e:Ld8/f;

    .line 1140
    .line 1141
    invoke-virtual {v4, v5}, Laq/a;->E(Ld8/f;)V

    .line 1142
    .line 1143
    .line 1144
    iput-object v7, v3, Lh8/x0;->h:Laq/a;

    .line 1145
    .line 1146
    iput-object v7, v3, Lh8/x0;->g:Lt7/o;

    .line 1147
    .line 1148
    :cond_1e
    add-int/lit8 v8, v8, 0x1

    .line 1149
    .line 1150
    goto :goto_f

    .line 1151
    :cond_1f
    iget-object v0, v0, Lh8/r0;->p:Lgw0/c;

    .line 1152
    .line 1153
    iget-object v1, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 1154
    .line 1155
    check-cast v1, Lo8/o;

    .line 1156
    .line 1157
    if-eqz v1, :cond_20

    .line 1158
    .line 1159
    invoke-interface {v1}, Lo8/o;->b()V

    .line 1160
    .line 1161
    .line 1162
    iput-object v7, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 1163
    .line 1164
    :cond_20
    iput-object v7, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 1165
    .line 1166
    return-void

    .line 1167
    :pswitch_12
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1168
    .line 1169
    check-cast v0, Lk6/f;

    .line 1170
    .line 1171
    const/4 v1, 0x0

    .line 1172
    invoke-virtual {v0, v1}, Lk6/f;->n(I)V

    .line 1173
    .line 1174
    .line 1175
    return-void

    .line 1176
    :pswitch_13
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1177
    .line 1178
    check-cast v0, Lk0/k;

    .line 1179
    .line 1180
    iput-object v7, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 1181
    .line 1182
    iput-object v7, v0, Lk0/k;->d:Ljava/util/ArrayList;

    .line 1183
    .line 1184
    return-void

    .line 1185
    :pswitch_14
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1186
    .line 1187
    check-cast v0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 1188
    .line 1189
    const/4 v4, 0x1

    .line 1190
    invoke-interface {v0, v4}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 1191
    .line 1192
    .line 1193
    return-void

    .line 1194
    :pswitch_15
    :try_start_0
    invoke-virtual {v1}, Laq/p;->b()V
    :try_end_0
    .catch Ljava/lang/Error; {:try_start_0 .. :try_end_0} :catch_0

    .line 1195
    .line 1196
    .line 1197
    return-void

    .line 1198
    :catch_0
    move-exception v0

    .line 1199
    iget-object v2, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1200
    .line 1201
    check-cast v2, Lj0/h;

    .line 1202
    .line 1203
    iget-object v2, v2, Lj0/h;->d:Ljava/util/ArrayDeque;

    .line 1204
    .line 1205
    monitor-enter v2

    .line 1206
    :try_start_1
    iget-object v1, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1207
    .line 1208
    check-cast v1, Lj0/h;

    .line 1209
    .line 1210
    const/4 v4, 0x1

    .line 1211
    iput v4, v1, Lj0/h;->g:I

    .line 1212
    .line 1213
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 1214
    throw v0

    .line 1215
    :catchall_0
    move-exception v0

    .line 1216
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 1217
    throw v0

    .line 1218
    :pswitch_16
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1219
    .line 1220
    check-cast v0, Lil/g;

    .line 1221
    .line 1222
    iget-object v1, v0, Lil/g;->g:Ljava/lang/Object;

    .line 1223
    .line 1224
    check-cast v1, Lj0/b;

    .line 1225
    .line 1226
    iget-object v1, v1, Lj0/b;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 1227
    .line 1228
    invoke-virtual {v1, v7}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1229
    .line 1230
    .line 1231
    move-result-object v1

    .line 1232
    if-eqz v1, :cond_21

    .line 1233
    .line 1234
    iget-object v1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 1235
    .line 1236
    check-cast v1, Landroid/os/Handler;

    .line 1237
    .line 1238
    iget-object v0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 1239
    .line 1240
    check-cast v0, Lj0/b;

    .line 1241
    .line 1242
    invoke-virtual {v1, v0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 1243
    .line 1244
    .line 1245
    :cond_21
    return-void

    .line 1246
    :pswitch_17
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1247
    .line 1248
    check-cast v0, Lh6/i;

    .line 1249
    .line 1250
    const/4 v1, 0x0

    .line 1251
    iput-boolean v1, v0, Lh6/i;->c:Z

    .line 1252
    .line 1253
    iget-object v1, v0, Lh6/i;->e:Ljava/lang/Object;

    .line 1254
    .line 1255
    check-cast v1, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 1256
    .line 1257
    iget-object v2, v1, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->O:Lk6/f;

    .line 1258
    .line 1259
    if-eqz v2, :cond_22

    .line 1260
    .line 1261
    invoke-virtual {v2}, Lk6/f;->f()Z

    .line 1262
    .line 1263
    .line 1264
    move-result v2

    .line 1265
    if-eqz v2, :cond_22

    .line 1266
    .line 1267
    iget v1, v0, Lh6/i;->b:I

    .line 1268
    .line 1269
    invoke-virtual {v0, v1}, Lh6/i;->b(I)V

    .line 1270
    .line 1271
    .line 1272
    goto :goto_10

    .line 1273
    :cond_22
    iget v2, v1, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->N:I

    .line 1274
    .line 1275
    if-ne v2, v6, :cond_23

    .line 1276
    .line 1277
    iget v0, v0, Lh6/i;->b:I

    .line 1278
    .line 1279
    invoke-virtual {v1, v0}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->C(I)V

    .line 1280
    .line 1281
    .line 1282
    :cond_23
    :goto_10
    return-void

    .line 1283
    :pswitch_18
    new-instance v0, Ljava/io/IOException;

    .line 1284
    .line 1285
    const-string v2, "TIMEOUT"

    .line 1286
    .line 1287
    invoke-direct {v0, v2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 1288
    .line 1289
    .line 1290
    iget-object v1, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1291
    .line 1292
    check-cast v1, Laq/k;

    .line 1293
    .line 1294
    invoke-virtual {v1, v0}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 1295
    .line 1296
    .line 1297
    move-result v0

    .line 1298
    if-eqz v0, :cond_24

    .line 1299
    .line 1300
    const-string v0, "Rpc"

    .line 1301
    .line 1302
    const-string v1, "No response"

    .line 1303
    .line 1304
    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1305
    .line 1306
    .line 1307
    :cond_24
    return-void

    .line 1308
    :pswitch_19
    move-wide/from16 v19, v4

    .line 1309
    .line 1310
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1311
    .line 1312
    check-cast v0, Lh6/d;

    .line 1313
    .line 1314
    iget-object v2, v0, Lh6/d;->f:Lm/m1;

    .line 1315
    .line 1316
    iget-object v3, v0, Lh6/d;->d:Lh6/a;

    .line 1317
    .line 1318
    iget-boolean v4, v0, Lh6/d;->r:Z

    .line 1319
    .line 1320
    if-nez v4, :cond_25

    .line 1321
    .line 1322
    goto/16 :goto_13

    .line 1323
    .line 1324
    :cond_25
    iget-boolean v4, v0, Lh6/d;->p:Z

    .line 1325
    .line 1326
    if-eqz v4, :cond_26

    .line 1327
    .line 1328
    const/4 v4, 0x0

    .line 1329
    iput-boolean v4, v0, Lh6/d;->p:Z

    .line 1330
    .line 1331
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 1332
    .line 1333
    .line 1334
    move-result-wide v4

    .line 1335
    iput-wide v4, v3, Lh6/a;->e:J

    .line 1336
    .line 1337
    const-wide/16 v6, -0x1

    .line 1338
    .line 1339
    iput-wide v6, v3, Lh6/a;->g:J

    .line 1340
    .line 1341
    iput-wide v4, v3, Lh6/a;->f:J

    .line 1342
    .line 1343
    const/high16 v4, 0x3f000000    # 0.5f

    .line 1344
    .line 1345
    iput v4, v3, Lh6/a;->h:F

    .line 1346
    .line 1347
    :cond_26
    iget-wide v4, v3, Lh6/a;->g:J

    .line 1348
    .line 1349
    cmp-long v4, v4, v19

    .line 1350
    .line 1351
    if-lez v4, :cond_27

    .line 1352
    .line 1353
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 1354
    .line 1355
    .line 1356
    move-result-wide v4

    .line 1357
    iget-wide v6, v3, Lh6/a;->g:J

    .line 1358
    .line 1359
    iget v8, v3, Lh6/a;->i:I

    .line 1360
    .line 1361
    int-to-long v8, v8

    .line 1362
    add-long/2addr v6, v8

    .line 1363
    cmp-long v4, v4, v6

    .line 1364
    .line 1365
    if-lez v4, :cond_27

    .line 1366
    .line 1367
    :goto_11
    const/4 v4, 0x0

    .line 1368
    goto :goto_12

    .line 1369
    :cond_27
    invoke-virtual {v0}, Lh6/d;->e()Z

    .line 1370
    .line 1371
    .line 1372
    move-result v4

    .line 1373
    if-nez v4, :cond_28

    .line 1374
    .line 1375
    goto :goto_11

    .line 1376
    :goto_12
    iput-boolean v4, v0, Lh6/d;->r:Z

    .line 1377
    .line 1378
    goto :goto_13

    .line 1379
    :cond_28
    const/4 v4, 0x0

    .line 1380
    iget-boolean v5, v0, Lh6/d;->q:Z

    .line 1381
    .line 1382
    if-eqz v5, :cond_29

    .line 1383
    .line 1384
    iput-boolean v4, v0, Lh6/d;->q:Z

    .line 1385
    .line 1386
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 1387
    .line 1388
    .line 1389
    move-result-wide v6

    .line 1390
    const/4 v12, 0x0

    .line 1391
    const/4 v13, 0x0

    .line 1392
    const/4 v10, 0x3

    .line 1393
    const/4 v11, 0x0

    .line 1394
    move-wide v8, v6

    .line 1395
    invoke-static/range {v6 .. v13}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    .line 1396
    .line 1397
    .line 1398
    move-result-object v4

    .line 1399
    invoke-virtual {v2, v4}, Lm/m1;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 1400
    .line 1401
    .line 1402
    invoke-virtual {v4}, Landroid/view/MotionEvent;->recycle()V

    .line 1403
    .line 1404
    .line 1405
    :cond_29
    iget-wide v4, v3, Lh6/a;->f:J

    .line 1406
    .line 1407
    cmp-long v4, v4, v19

    .line 1408
    .line 1409
    if-eqz v4, :cond_2a

    .line 1410
    .line 1411
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 1412
    .line 1413
    .line 1414
    move-result-wide v4

    .line 1415
    invoke-virtual {v3, v4, v5}, Lh6/a;->a(J)F

    .line 1416
    .line 1417
    .line 1418
    move-result v6

    .line 1419
    const/high16 v7, -0x3f800000    # -4.0f

    .line 1420
    .line 1421
    mul-float/2addr v7, v6

    .line 1422
    mul-float/2addr v7, v6

    .line 1423
    const/high16 v8, 0x40800000    # 4.0f

    .line 1424
    .line 1425
    mul-float/2addr v6, v8

    .line 1426
    add-float/2addr v6, v7

    .line 1427
    iget-wide v7, v3, Lh6/a;->f:J

    .line 1428
    .line 1429
    sub-long v7, v4, v7

    .line 1430
    .line 1431
    iput-wide v4, v3, Lh6/a;->f:J

    .line 1432
    .line 1433
    long-to-float v4, v7

    .line 1434
    mul-float/2addr v4, v6

    .line 1435
    iget v3, v3, Lh6/a;->d:F

    .line 1436
    .line 1437
    mul-float/2addr v4, v3

    .line 1438
    float-to-int v3, v4

    .line 1439
    iget-object v0, v0, Lh6/d;->t:Lm/m1;

    .line 1440
    .line 1441
    invoke-virtual {v0, v3}, Landroid/widget/AbsListView;->scrollListBy(I)V

    .line 1442
    .line 1443
    .line 1444
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 1445
    .line 1446
    invoke-virtual {v2, v1}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 1447
    .line 1448
    .line 1449
    :goto_13
    return-void

    .line 1450
    :cond_2a
    new-instance v0, Ljava/lang/RuntimeException;

    .line 1451
    .line 1452
    const-string v1, "Cannot compute scroll delta before calling start()"

    .line 1453
    .line 1454
    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 1455
    .line 1456
    .line 1457
    throw v0

    .line 1458
    :pswitch_1a
    invoke-direct {v1}, Laq/p;->a()V

    .line 1459
    .line 1460
    .line 1461
    return-void

    .line 1462
    :pswitch_1b
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1463
    .line 1464
    move-object v3, v0

    .line 1465
    check-cast v3, Ldu/l;

    .line 1466
    .line 1467
    monitor-enter v3

    .line 1468
    :try_start_3
    invoke-virtual {v3}, Ldu/l;->a()Z

    .line 1469
    .line 1470
    .line 1471
    move-result v0

    .line 1472
    if-eqz v0, :cond_2b

    .line 1473
    .line 1474
    monitor-enter v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 1475
    const/4 v4, 0x1

    .line 1476
    :try_start_4
    iput-boolean v4, v3, Ldu/l;->b:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 1477
    .line 1478
    :try_start_5
    monitor-exit v3
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 1479
    goto :goto_14

    .line 1480
    :catchall_1
    move-exception v0

    .line 1481
    :try_start_6
    monitor-exit v3
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 1482
    :try_start_7
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 1483
    :cond_2b
    :goto_14
    monitor-exit v3

    .line 1484
    if-nez v0, :cond_2c

    .line 1485
    .line 1486
    goto :goto_15

    .line 1487
    :cond_2c
    iget-object v0, v3, Ldu/l;->q:Ldu/n;

    .line 1488
    .line 1489
    invoke-virtual {v0}, Ldu/n;->c()Ldu/m;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v0

    .line 1493
    new-instance v1, Ljava/util/Date;

    .line 1494
    .line 1495
    iget-object v4, v3, Ldu/l;->p:Lto/a;

    .line 1496
    .line 1497
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1498
    .line 1499
    .line 1500
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1501
    .line 1502
    .line 1503
    move-result-wide v4

    .line 1504
    invoke-direct {v1, v4, v5}, Ljava/util/Date;-><init>(J)V

    .line 1505
    .line 1506
    .line 1507
    iget-object v0, v0, Ldu/m;->b:Ljava/util/Date;

    .line 1508
    .line 1509
    invoke-virtual {v1, v0}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 1510
    .line 1511
    .line 1512
    move-result v0

    .line 1513
    if-eqz v0, :cond_2d

    .line 1514
    .line 1515
    invoke-virtual {v3}, Ldu/l;->h()V

    .line 1516
    .line 1517
    .line 1518
    goto :goto_15

    .line 1519
    :cond_2d
    iget-object v0, v3, Ldu/l;->k:Lht/d;

    .line 1520
    .line 1521
    check-cast v0, Lht/c;

    .line 1522
    .line 1523
    invoke-virtual {v0}, Lht/c;->d()Laq/t;

    .line 1524
    .line 1525
    .line 1526
    move-result-object v1

    .line 1527
    invoke-virtual {v0}, Lht/c;->c()Laq/t;

    .line 1528
    .line 1529
    .line 1530
    move-result-object v0

    .line 1531
    new-array v4, v6, [Laq/j;

    .line 1532
    .line 1533
    const/16 v21, 0x0

    .line 1534
    .line 1535
    aput-object v1, v4, v21

    .line 1536
    .line 1537
    const/4 v5, 0x1

    .line 1538
    aput-object v0, v4, v5

    .line 1539
    .line 1540
    invoke-static {v4}, Ljp/l1;->g([Laq/j;)Laq/t;

    .line 1541
    .line 1542
    .line 1543
    move-result-object v4

    .line 1544
    iget-object v6, v3, Ldu/l;->h:Ljava/util/concurrent/ScheduledExecutorService;

    .line 1545
    .line 1546
    new-instance v7, Lbb/i;

    .line 1547
    .line 1548
    invoke-direct {v7, v3, v1, v0, v2}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 1549
    .line 1550
    .line 1551
    invoke-virtual {v4, v6, v7}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 1552
    .line 1553
    .line 1554
    move-result-object v0

    .line 1555
    new-array v1, v5, [Laq/j;

    .line 1556
    .line 1557
    aput-object v0, v1, v21

    .line 1558
    .line 1559
    invoke-static {v1}, Ljp/l1;->g([Laq/j;)Laq/t;

    .line 1560
    .line 1561
    .line 1562
    move-result-object v1

    .line 1563
    iget-object v2, v3, Ldu/l;->h:Ljava/util/concurrent/ScheduledExecutorService;

    .line 1564
    .line 1565
    new-instance v4, La0/h;

    .line 1566
    .line 1567
    const/16 v5, 0xd

    .line 1568
    .line 1569
    invoke-direct {v4, v5, v3, v0}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1570
    .line 1571
    .line 1572
    invoke-virtual {v1, v2, v4}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 1573
    .line 1574
    .line 1575
    :goto_15
    return-void

    .line 1576
    :catchall_2
    move-exception v0

    .line 1577
    :try_start_8
    monitor-exit v3
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 1578
    throw v0

    .line 1579
    :pswitch_1c
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1580
    .line 1581
    check-cast v0, Laq/q;

    .line 1582
    .line 1583
    iget-object v2, v0, Laq/q;->f:Ljava/lang/Object;

    .line 1584
    .line 1585
    monitor-enter v2

    .line 1586
    :try_start_9
    iget-object v0, v1, Laq/p;->e:Ljava/lang/Object;

    .line 1587
    .line 1588
    check-cast v0, Laq/q;

    .line 1589
    .line 1590
    iget-object v0, v0, Laq/q;->g:Ljava/lang/Object;

    .line 1591
    .line 1592
    check-cast v0, Laq/d;

    .line 1593
    .line 1594
    invoke-interface {v0}, Laq/d;->s()V

    .line 1595
    .line 1596
    .line 1597
    monitor-exit v2

    .line 1598
    return-void

    .line 1599
    :catchall_3
    move-exception v0

    .line 1600
    monitor-exit v2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 1601
    throw v0

    .line 1602
    nop

    .line 1603
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
