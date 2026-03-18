.class public final Llv/e;
.super Leb/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static n:Z = true


# instance fields
.field public final h:Lhv/b;

.field public final i:Llv/f;

.field public final j:Ljp/vg;

.field public final k:Lb81/b;

.field public final l:Lnv/a;

.field public m:Z


# direct methods
.method public constructor <init>(Lfv/f;Lhv/b;Llv/f;Ljp/vg;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-direct {p0, v0}, Leb/j0;-><init>(I)V

    .line 3
    .line 4
    .line 5
    new-instance v0, Lnv/a;

    .line 6
    .line 7
    invoke-direct {v0}, Lnv/a;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Llv/e;->l:Lnv/a;

    .line 11
    .line 12
    const-string v0, "MlKitContext can not be null"

    .line 13
    .line 14
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "BarcodeScannerOptions can not be null"

    .line 18
    .line 19
    invoke-static {p2, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iput-object p2, p0, Llv/e;->h:Lhv/b;

    .line 23
    .line 24
    iput-object p3, p0, Llv/e;->i:Llv/f;

    .line 25
    .line 26
    iput-object p4, p0, Llv/e;->j:Ljp/vg;

    .line 27
    .line 28
    invoke-virtual {p1}, Lfv/f;->b()Landroid/content/Context;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    new-instance p2, Lb81/b;

    .line 33
    .line 34
    invoke-direct {p2, p1}, Lb81/b;-><init>(Landroid/content/Context;)V

    .line 35
    .line 36
    .line 37
    iput-object p2, p0, Llv/e;->k:Lb81/b;

    .line 38
    .line 39
    return-void
.end method


# virtual methods
.method public final declared-synchronized D()V
    .locals 8

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Llv/e;->i:Llv/f;

    .line 3
    .line 4
    invoke-interface {v0}, Llv/f;->l()V

    .line 5
    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    sput-boolean v0, Llv/e;->n:Z

    .line 9
    .line 10
    new-instance v0, Lin/z1;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iget-boolean v1, p0, Llv/e;->m:Z

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    sget-object v1, Ljp/zb;->f:Ljp/zb;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception v0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    sget-object v1, Ljp/zb;->e:Ljp/zb;

    .line 25
    .line 26
    :goto_0
    iget-object v3, p0, Llv/e;->j:Ljp/vg;

    .line 27
    .line 28
    iput-object v1, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 29
    .line 30
    new-instance v1, Landroidx/lifecycle/c1;

    .line 31
    .line 32
    const/16 v2, 0xc

    .line 33
    .line 34
    invoke-direct {v1, v2}, Landroidx/lifecycle/c1;-><init>(I)V

    .line 35
    .line 36
    .line 37
    iget-object v2, p0, Llv/e;->h:Lhv/b;

    .line 38
    .line 39
    invoke-static {v2}, Llv/a;->a(Lhv/b;)Ljp/pg;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    iput-object v2, v1, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 44
    .line 45
    new-instance v2, Ljp/mc;

    .line 46
    .line 47
    invoke-direct {v2, v1}, Ljp/mc;-><init>(Landroidx/lifecycle/c1;)V

    .line 48
    .line 49
    .line 50
    iput-object v2, v0, Lin/z1;->d:Ljava/lang/Object;

    .line 51
    .line 52
    new-instance v4, Lbb/g0;

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    invoke-direct {v4, v0, v1}, Lbb/g0;-><init>(Lin/z1;I)V

    .line 56
    .line 57
    .line 58
    sget-object v5, Ljp/bc;->p:Ljp/bc;

    .line 59
    .line 60
    invoke-virtual {v3}, Ljp/vg;->c()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v6

    .line 64
    sget-object v0, Lfv/l;->d:Lfv/l;

    .line 65
    .line 66
    new-instance v2, Ld6/z0;

    .line 67
    .line 68
    const/4 v7, 0x1

    .line 69
    invoke-direct/range {v2 .. v7}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v2}, Lfv/l;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 73
    .line 74
    .line 75
    monitor-exit p0

    .line 76
    return-void

    .line 77
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 78
    throw v0
.end method

.method public final E(Lmv/a;)Ljava/lang/Object;
    .locals 7

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Llv/e;->l:Lnv/a;

    .line 3
    .line 4
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 5
    .line 6
    .line 7
    move-result-wide v3

    .line 8
    invoke-virtual {v0, p1}, Lnv/a;->a(Lmv/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 9
    .line 10
    .line 11
    :try_start_1
    iget-object v0, p0, Llv/e;->i:Llv/f;

    .line 12
    .line 13
    invoke-interface {v0, p1}, Llv/f;->a(Lmv/a;)Ljava/util/ArrayList;

    .line 14
    .line 15
    .line 16
    move-result-object v6

    .line 17
    sget-object v2, Ljp/ac;->e:Ljp/ac;
    :try_end_1
    .catch Lbv/a; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 18
    .line 19
    move-object v1, p0

    .line 20
    move-object v5, p1

    .line 21
    :try_start_2
    invoke-virtual/range {v1 .. v6}, Llv/e;->J(Ljp/ac;JLmv/a;Ljava/util/List;)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    sput-boolean p0, Llv/e;->n:Z
    :try_end_2
    .catch Lbv/a; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 26
    .line 27
    monitor-exit v1

    .line 28
    return-object v6

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    :goto_0
    move-object p0, v0

    .line 31
    goto :goto_5

    .line 32
    :catch_0
    move-exception v0

    .line 33
    :goto_1
    move-object p0, v0

    .line 34
    goto :goto_2

    .line 35
    :catchall_1
    move-exception v0

    .line 36
    move-object v1, p0

    .line 37
    goto :goto_0

    .line 38
    :catch_1
    move-exception v0

    .line 39
    move-object v1, p0

    .line 40
    move-object v5, p1

    .line 41
    goto :goto_1

    .line 42
    :goto_2
    :try_start_3
    iget p1, p0, Lbv/a;->d:I

    .line 43
    .line 44
    const/16 v0, 0xe

    .line 45
    .line 46
    if-ne p1, v0, :cond_0

    .line 47
    .line 48
    sget-object p1, Ljp/ac;->f:Ljp/ac;

    .line 49
    .line 50
    :goto_3
    move-object v2, p1

    .line 51
    goto :goto_4

    .line 52
    :cond_0
    sget-object p1, Ljp/ac;->i:Ljp/ac;

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :goto_4
    const/4 v6, 0x0

    .line 56
    invoke-virtual/range {v1 .. v6}, Llv/e;->J(Ljp/ac;JLmv/a;Ljava/util/List;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :goto_5
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 61
    throw p0
.end method

.method public final J(Ljp/ac;JLmv/a;Ljava/util/List;)V
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    new-instance v2, Lin/o;

    .line 6
    .line 7
    invoke-direct {v2}, Lin/o;-><init>()V

    .line 8
    .line 9
    .line 10
    new-instance v3, Lin/o;

    .line 11
    .line 12
    invoke-direct {v3}, Lin/o;-><init>()V

    .line 13
    .line 14
    .line 15
    if-eqz p5, :cond_4

    .line 16
    .line 17
    invoke-interface/range {p5 .. p5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    if-eqz v5, :cond_4

    .line 26
    .line 27
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    check-cast v5, Ljv/a;

    .line 32
    .line 33
    iget-object v6, v5, Ljv/a;->a:Lkv/a;

    .line 34
    .line 35
    invoke-interface {v6}, Lkv/a;->getFormat()I

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    const/16 v7, 0x1000

    .line 40
    .line 41
    if-gt v6, v7, :cond_0

    .line 42
    .line 43
    if-nez v6, :cond_1

    .line 44
    .line 45
    :cond_0
    const/4 v6, -0x1

    .line 46
    :cond_1
    sget-object v7, Llv/a;->a:Landroid/util/SparseArray;

    .line 47
    .line 48
    invoke-virtual {v7, v6}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v6

    .line 52
    check-cast v6, Ljp/kc;

    .line 53
    .line 54
    if-nez v6, :cond_2

    .line 55
    .line 56
    sget-object v6, Ljp/kc;->e:Ljp/kc;

    .line 57
    .line 58
    :cond_2
    invoke-virtual {v2, v6}, Lin/o;->q(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object v5, v5, Ljv/a;->a:Lkv/a;

    .line 62
    .line 63
    invoke-interface {v5}, Lkv/a;->k()I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    sget-object v6, Llv/a;->b:Landroid/util/SparseArray;

    .line 68
    .line 69
    invoke-virtual {v6, v5}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    check-cast v5, Ljp/lc;

    .line 74
    .line 75
    if-nez v5, :cond_3

    .line 76
    .line 77
    sget-object v5, Ljp/lc;->e:Ljp/lc;

    .line 78
    .line 79
    :cond_3
    invoke-virtual {v3, v5}, Lin/o;->q(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_4
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 84
    .line 85
    .line 86
    move-result-wide v4

    .line 87
    sub-long v9, v4, p2

    .line 88
    .line 89
    new-instance v4, Ldu/d;

    .line 90
    .line 91
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 92
    .line 93
    .line 94
    iput-object v0, v4, Ldu/d;->b:Ljava/lang/Object;

    .line 95
    .line 96
    iput-wide v9, v4, Ldu/d;->a:J

    .line 97
    .line 98
    iput-object v1, v4, Ldu/d;->c:Ljava/lang/Object;

    .line 99
    .line 100
    iput-object v2, v4, Ldu/d;->d:Ljava/lang/Object;

    .line 101
    .line 102
    iput-object v3, v4, Ldu/d;->e:Ljava/lang/Object;

    .line 103
    .line 104
    move-object/from16 v5, p4

    .line 105
    .line 106
    iput-object v5, v4, Ldu/d;->f:Ljava/lang/Object;

    .line 107
    .line 108
    iget-object v5, v0, Llv/e;->j:Ljp/vg;

    .line 109
    .line 110
    sget-object v6, Ljp/bc;->n:Ljp/bc;

    .line 111
    .line 112
    invoke-virtual {v5, v4, v6}, Ljp/vg;->b(Ljp/ug;Ljp/bc;)V

    .line 113
    .line 114
    .line 115
    new-instance v4, Landroidx/lifecycle/c1;

    .line 116
    .line 117
    const/16 v5, 0xa

    .line 118
    .line 119
    invoke-direct {v4, v5}, Landroidx/lifecycle/c1;-><init>(I)V

    .line 120
    .line 121
    .line 122
    iput-object v1, v4, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 123
    .line 124
    sget-boolean v5, Llv/e;->n:Z

    .line 125
    .line 126
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    iput-object v5, v4, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 131
    .line 132
    iget-object v5, v0, Llv/e;->h:Lhv/b;

    .line 133
    .line 134
    invoke-static {v5}, Llv/a;->a(Lhv/b;)Ljp/pg;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    iput-object v5, v4, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 139
    .line 140
    invoke-virtual {v2}, Lin/o;->s()Ljp/c0;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    iput-object v2, v4, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 145
    .line 146
    invoke-virtual {v3}, Lin/o;->s()Ljp/c0;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    iput-object v2, v4, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 151
    .line 152
    new-instance v8, Ljp/u0;

    .line 153
    .line 154
    invoke-direct {v8, v4}, Ljp/u0;-><init>(Landroidx/lifecycle/c1;)V

    .line 155
    .line 156
    .line 157
    new-instance v11, Lj1/a;

    .line 158
    .line 159
    const/16 v2, 0xc

    .line 160
    .line 161
    invoke-direct {v11, v0, v2}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 162
    .line 163
    .line 164
    iget-object v7, v0, Llv/e;->j:Ljp/vg;

    .line 165
    .line 166
    sget-object v2, Lfv/l;->d:Lfv/l;

    .line 167
    .line 168
    new-instance v6, Lcom/google/firebase/messaging/z;

    .line 169
    .line 170
    invoke-direct/range {v6 .. v11}, Lcom/google/firebase/messaging/z;-><init>(Ljp/vg;Ljp/u0;JLj1/a;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v2, v6}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 174
    .line 175
    .line 176
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 177
    .line 178
    .line 179
    move-result-wide v17

    .line 180
    iget-boolean v2, v0, Llv/e;->m:Z

    .line 181
    .line 182
    sub-long v15, v17, v9

    .line 183
    .line 184
    iget-object v3, v0, Llv/e;->k:Lb81/b;

    .line 185
    .line 186
    const/4 v0, 0x1

    .line 187
    if-eq v0, v2, :cond_5

    .line 188
    .line 189
    const/16 v0, 0x5eed

    .line 190
    .line 191
    :goto_1
    move v12, v0

    .line 192
    goto :goto_2

    .line 193
    :cond_5
    const/16 v0, 0x5eee

    .line 194
    .line 195
    goto :goto_1

    .line 196
    :goto_2
    iget v13, v1, Ljp/ac;->d:I

    .line 197
    .line 198
    monitor-enter v3

    .line 199
    :try_start_0
    iget-object v0, v3, Lb81/b;->f:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 202
    .line 203
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 204
    .line 205
    .line 206
    move-result-wide v1

    .line 207
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 208
    .line 209
    .line 210
    move-result-wide v4

    .line 211
    const-wide/16 v6, -0x1

    .line 212
    .line 213
    cmp-long v0, v4, v6

    .line 214
    .line 215
    if-nez v0, :cond_6

    .line 216
    .line 217
    goto :goto_3

    .line 218
    :cond_6
    iget-object v0, v3, Lb81/b;->f:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 221
    .line 222
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 223
    .line 224
    .line 225
    move-result-wide v4

    .line 226
    sub-long v4, v1, v4

    .line 227
    .line 228
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 229
    .line 230
    const-wide/16 v6, 0x1e

    .line 231
    .line 232
    invoke-virtual {v0, v6, v7}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 233
    .line 234
    .line 235
    move-result-wide v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 236
    cmp-long v0, v4, v6

    .line 237
    .line 238
    if-gtz v0, :cond_7

    .line 239
    .line 240
    monitor-exit v3

    .line 241
    return-void

    .line 242
    :cond_7
    :goto_3
    :try_start_1
    iget-object v0, v3, Lb81/b;->e:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast v0, Lpo/b;

    .line 245
    .line 246
    new-instance v4, Lno/p;

    .line 247
    .line 248
    new-instance v11, Lno/l;

    .line 249
    .line 250
    const/16 v21, 0x0

    .line 251
    .line 252
    const/16 v22, -0x1

    .line 253
    .line 254
    const/4 v14, 0x0

    .line 255
    const/16 v19, 0x0

    .line 256
    .line 257
    const/16 v20, 0x0

    .line 258
    .line 259
    invoke-direct/range {v11 .. v22}, Lno/l;-><init>(IIIJJLjava/lang/String;Ljava/lang/String;II)V

    .line 260
    .line 261
    .line 262
    filled-new-array {v11}, [Lno/l;

    .line 263
    .line 264
    .line 265
    move-result-object v5

    .line 266
    invoke-static {v5}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 267
    .line 268
    .line 269
    move-result-object v5

    .line 270
    const/4 v6, 0x0

    .line 271
    invoke-direct {v4, v6, v5}, Lno/p;-><init>(ILjava/util/List;)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v0, v4}, Lpo/b;->f(Lno/p;)Laq/t;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    new-instance v4, Lg1/i3;

    .line 279
    .line 280
    const/4 v5, 0x2

    .line 281
    invoke-direct {v4, v3, v1, v2, v5}, Lg1/i3;-><init>(Ljava/lang/Object;JI)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v0, v4}, Laq/t;->l(Laq/f;)Laq/t;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 285
    .line 286
    .line 287
    monitor-exit v3

    .line 288
    return-void

    .line 289
    :catchall_0
    move-exception v0

    .line 290
    :try_start_2
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 291
    throw v0
.end method

.method public final declared-synchronized x()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Llv/e;->i:Llv/f;

    .line 3
    .line 4
    invoke-interface {v0}, Llv/f;->j()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    iput-boolean v0, p0, Llv/e;->m:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

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
