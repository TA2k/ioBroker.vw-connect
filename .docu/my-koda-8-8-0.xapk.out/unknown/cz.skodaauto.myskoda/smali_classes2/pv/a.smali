.class public final Lpv/a;
.super Leb/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final l:La8/b;

.field public static m:Z = true


# instance fields
.field public final h:Lpv/c;

.field public final i:Llp/lg;

.field public final j:Lb81/d;

.field public final k:Lov/f;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, La8/b;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1}, La8/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lpv/a;->l:La8/b;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Llp/lg;Lpv/c;Lqv/a;)V
    .locals 1

    .line 1
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Lpv/a;->l:La8/b;

    .line 5
    .line 6
    invoke-direct {p0, v0}, Leb/j0;-><init>(La8/b;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lpv/a;->i:Llp/lg;

    .line 10
    .line 11
    iput-object p2, p0, Lpv/a;->h:Lpv/c;

    .line 12
    .line 13
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p1}, Lfv/f;->b()Landroid/content/Context;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    new-instance p2, Lb81/d;

    .line 22
    .line 23
    const/16 v0, 0xe

    .line 24
    .line 25
    invoke-direct {p2, p1, v0}, Lb81/d;-><init>(Landroid/content/Context;I)V

    .line 26
    .line 27
    .line 28
    iput-object p2, p0, Lpv/a;->j:Lb81/d;

    .line 29
    .line 30
    iput-object p3, p0, Lpv/a;->k:Lov/f;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final declared-synchronized D()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    const/4 v0, 0x1

    .line 3
    :try_start_0
    sput-boolean v0, Lpv/a;->m:Z

    .line 4
    .line 5
    iget-object v0, p0, Lpv/a;->h:Lpv/c;

    .line 6
    .line 7
    invoke-interface {v0}, Lpv/c;->j()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    .line 9
    .line 10
    monitor-exit p0

    .line 11
    return-void

    .line 12
    :catchall_0
    move-exception v0

    .line 13
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 14
    throw v0
.end method

.method public final E(Lmv/a;)Ljava/lang/Object;
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 3
    .line 4
    .line 5
    move-result-wide v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    :try_start_1
    iget-object v2, p0, Lpv/a;->h:Lpv/c;

    .line 7
    .line 8
    invoke-interface {v2, p1}, Lpv/c;->a(Lmv/a;)Lov/d;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    sget-object v3, Llp/tb;->e:Llp/tb;

    .line 13
    .line 14
    invoke-virtual {p0, v3, v0, v1, p1}, Lpv/a;->J(Llp/tb;JLmv/a;)V

    .line 15
    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    sput-boolean v3, Lpv/a;->m:Z
    :try_end_1
    .catch Lbv/a; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 19
    .line 20
    monitor-exit p0

    .line 21
    return-object v2

    .line 22
    :catchall_0
    move-exception p1

    .line 23
    goto :goto_1

    .line 24
    :catch_0
    move-exception v2

    .line 25
    :try_start_2
    iget v3, v2, Lbv/a;->d:I

    .line 26
    .line 27
    const/16 v4, 0xe

    .line 28
    .line 29
    if-ne v3, v4, :cond_0

    .line 30
    .line 31
    sget-object v3, Llp/tb;->f:Llp/tb;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    sget-object v3, Llp/tb;->i:Llp/tb;

    .line 35
    .line 36
    :goto_0
    invoke-virtual {p0, v3, v0, v1, p1}, Lpv/a;->J(Llp/tb;JLmv/a;)V

    .line 37
    .line 38
    .line 39
    throw v2

    .line 40
    :goto_1
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 41
    throw p1
.end method

.method public final J(Llp/tb;JLmv/a;)V
    .locals 22

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sub-long v2, v0, p2

    .line 6
    .line 7
    new-instance v0, Lh01/q;

    .line 8
    .line 9
    move-object/from16 v1, p0

    .line 10
    .line 11
    move-object/from16 v4, p1

    .line 12
    .line 13
    move-object/from16 v5, p4

    .line 14
    .line 15
    invoke-direct/range {v0 .. v5}, Lh01/q;-><init>(Lpv/a;JLlp/tb;Lmv/a;)V

    .line 16
    .line 17
    .line 18
    move-object/from16 v21, v4

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    move-object/from16 v0, v21

    .line 22
    .line 23
    iget-object v5, v1, Lpv/a;->i:Llp/lg;

    .line 24
    .line 25
    sget-object v6, Llp/ub;->j:Llp/ub;

    .line 26
    .line 27
    invoke-virtual {v5, v4, v6}, Llp/lg;->b(Llp/kg;Llp/ub;)V

    .line 28
    .line 29
    .line 30
    new-instance v4, Llp/f0;

    .line 31
    .line 32
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v0, v4, Llp/f0;->d:Ljava/lang/Object;

    .line 36
    .line 37
    sget-boolean v5, Lpv/a;->m:Z

    .line 38
    .line 39
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    iput-object v5, v4, Llp/f0;->e:Ljava/lang/Object;

    .line 44
    .line 45
    new-instance v5, Lh6/e;

    .line 46
    .line 47
    const/16 v6, 0x12

    .line 48
    .line 49
    invoke-direct {v5, v6}, Lh6/e;-><init>(I)V

    .line 50
    .line 51
    .line 52
    iget-object v6, v1, Lpv/a;->k:Lov/f;

    .line 53
    .line 54
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    sget-object v6, Llp/ve;->e:Llp/ve;

    .line 58
    .line 59
    iput-object v6, v5, Lh6/e;->e:Ljava/lang/Object;

    .line 60
    .line 61
    new-instance v6, Llp/we;

    .line 62
    .line 63
    invoke-direct {v6, v5}, Llp/we;-><init>(Lh6/e;)V

    .line 64
    .line 65
    .line 66
    iput-object v6, v4, Llp/f0;->f:Ljava/lang/Object;

    .line 67
    .line 68
    new-instance v5, Llp/r1;

    .line 69
    .line 70
    invoke-direct {v5, v4}, Llp/r1;-><init>(Llp/f0;)V

    .line 71
    .line 72
    .line 73
    new-instance v7, Lpv/g;

    .line 74
    .line 75
    const/4 v4, 0x0

    .line 76
    invoke-direct {v7, v1, v4}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    sget-object v8, Lfv/l;->d:Lfv/l;

    .line 80
    .line 81
    move-object v4, v5

    .line 82
    move-wide v5, v2

    .line 83
    new-instance v2, Lcom/google/firebase/messaging/z;

    .line 84
    .line 85
    iget-object v3, v1, Lpv/a;->i:Llp/lg;

    .line 86
    .line 87
    invoke-direct/range {v2 .. v7}, Lcom/google/firebase/messaging/z;-><init>(Llp/lg;Llp/r1;JLpv/g;)V

    .line 88
    .line 89
    .line 90
    move-object v4, v2

    .line 91
    move-wide v2, v5

    .line 92
    invoke-virtual {v8, v4}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 93
    .line 94
    .line 95
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 96
    .line 97
    .line 98
    move-result-wide v15

    .line 99
    sub-long v13, v15, v2

    .line 100
    .line 101
    iget-object v2, v1, Lpv/a;->j:Lb81/d;

    .line 102
    .line 103
    iget-object v1, v1, Lpv/a;->k:Lov/f;

    .line 104
    .line 105
    check-cast v1, Lqv/a;

    .line 106
    .line 107
    invoke-virtual {v1}, Lqv/a;->a()Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_0

    .line 112
    .line 113
    const/16 v1, 0x5efd

    .line 114
    .line 115
    :goto_0
    move v10, v1

    .line 116
    goto :goto_1

    .line 117
    :cond_0
    const/16 v1, 0x5ef2

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :goto_1
    iget v11, v0, Llp/tb;->d:I

    .line 121
    .line 122
    monitor-enter v2

    .line 123
    :try_start_0
    iget-object v0, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 126
    .line 127
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 128
    .line 129
    .line 130
    move-result-wide v3

    .line 131
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 132
    .line 133
    .line 134
    move-result-wide v0

    .line 135
    const-wide/16 v5, -0x1

    .line 136
    .line 137
    cmp-long v0, v0, v5

    .line 138
    .line 139
    if-nez v0, :cond_1

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_1
    iget-object v0, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 147
    .line 148
    .line 149
    move-result-wide v0

    .line 150
    sub-long v0, v3, v0

    .line 151
    .line 152
    sget-object v5, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 153
    .line 154
    const-wide/16 v6, 0x1e

    .line 155
    .line 156
    invoke-virtual {v5, v6, v7}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 157
    .line 158
    .line 159
    move-result-wide v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 160
    cmp-long v0, v0, v5

    .line 161
    .line 162
    if-gtz v0, :cond_2

    .line 163
    .line 164
    monitor-exit v2

    .line 165
    return-void

    .line 166
    :cond_2
    :goto_2
    :try_start_1
    iget-object v0, v2, Lb81/d;->e:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast v0, Lpo/b;

    .line 169
    .line 170
    new-instance v1, Lno/p;

    .line 171
    .line 172
    new-instance v9, Lno/l;

    .line 173
    .line 174
    const/16 v19, 0x0

    .line 175
    .line 176
    const/16 v20, -0x1

    .line 177
    .line 178
    const/4 v12, 0x0

    .line 179
    const/16 v17, 0x0

    .line 180
    .line 181
    const/16 v18, 0x0

    .line 182
    .line 183
    invoke-direct/range {v9 .. v20}, Lno/l;-><init>(IIIJJLjava/lang/String;Ljava/lang/String;II)V

    .line 184
    .line 185
    .line 186
    filled-new-array {v9}, [Lno/l;

    .line 187
    .line 188
    .line 189
    move-result-object v5

    .line 190
    invoke-static {v5}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 191
    .line 192
    .line 193
    move-result-object v5

    .line 194
    const/4 v6, 0x0

    .line 195
    invoke-direct {v1, v6, v5}, Lno/p;-><init>(ILjava/util/List;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v0, v1}, Lpo/b;->f(Lno/p;)Laq/t;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    new-instance v1, Lg1/i3;

    .line 203
    .line 204
    const/4 v5, 0x4

    .line 205
    invoke-direct {v1, v2, v3, v4, v5}, Lg1/i3;-><init>(Ljava/lang/Object;JI)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v0, v1}, Laq/t;->l(Laq/f;)Laq/t;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 209
    .line 210
    .line 211
    monitor-exit v2

    .line 212
    return-void

    .line 213
    :catchall_0
    move-exception v0

    .line 214
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 215
    throw v0
.end method

.method public final declared-synchronized x()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lpv/a;->h:Lpv/c;

    .line 3
    .line 4
    invoke-interface {v0}, Lpv/c;->l()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    .line 7
    monitor-exit p0

    .line 8
    return-void

    .line 9
    :catchall_0
    move-exception v0

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw v0
.end method
