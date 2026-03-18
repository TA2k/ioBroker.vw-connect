.class public final Lh8/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/net/Uri;

.field public final b:Ly7/y;

.field public final c:Lgw0/c;

.field public final d:Lh8/r0;

.field public final e:Lw7/e;

.field public final f:Lo8/s;

.field public volatile g:Z

.field public h:Z

.field public i:J

.field public j:Ly7/j;

.field public k:Lo8/i0;

.field public l:Z

.field public final synthetic m:Lh8/r0;


# direct methods
.method public constructor <init>(Lh8/r0;Landroid/net/Uri;Ly7/h;Lgw0/c;Lh8/r0;Lw7/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/o0;->m:Lh8/r0;

    .line 5
    .line 6
    iput-object p2, p0, Lh8/o0;->a:Landroid/net/Uri;

    .line 7
    .line 8
    new-instance p1, Ly7/y;

    .line 9
    .line 10
    invoke-direct {p1, p3}, Ly7/y;-><init>(Ly7/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lh8/o0;->b:Ly7/y;

    .line 14
    .line 15
    iput-object p4, p0, Lh8/o0;->c:Lgw0/c;

    .line 16
    .line 17
    iput-object p5, p0, Lh8/o0;->d:Lh8/r0;

    .line 18
    .line 19
    iput-object p6, p0, Lh8/o0;->e:Lw7/e;

    .line 20
    .line 21
    new-instance p1, Lo8/s;

    .line 22
    .line 23
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lh8/o0;->f:Lo8/s;

    .line 27
    .line 28
    const/4 p1, 0x1

    .line 29
    iput-boolean p1, p0, Lh8/o0;->h:Z

    .line 30
    .line 31
    sget-object p1, Lh8/s;->a:Ljava/util/concurrent/atomic/AtomicLong;

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicLong;->getAndIncrement()J

    .line 34
    .line 35
    .line 36
    const-wide/16 p1, 0x0

    .line 37
    .line 38
    invoke-virtual {p0, p1, p2}, Lh8/o0;->a(J)Ly7/j;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iput-object p1, p0, Lh8/o0;->j:Ly7/j;

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final a(J)Ly7/j;
    .locals 11

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 2
    .line 3
    sget-object v5, Lh8/r0;->S:Ljava/util/Map;

    .line 4
    .line 5
    const-string v0, "The uri must be set."

    .line 6
    .line 7
    iget-object v2, p0, Lh8/o0;->a:Landroid/net/Uri;

    .line 8
    .line 9
    invoke-static {v2, v0}, Lw7/a;->l(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Ly7/j;

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    const/4 v4, 0x0

    .line 16
    const-wide/16 v8, -0x1

    .line 17
    .line 18
    const/4 v10, 0x6

    .line 19
    move-wide v6, p1

    .line 20
    invoke-direct/range {v1 .. v10}, Ly7/j;-><init>(Landroid/net/Uri;I[BLjava/util/Map;JJI)V

    .line 21
    .line 22
    .line 23
    return-object v1
.end method

.method public final b()V
    .locals 15

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :catch_0
    :cond_0
    :goto_0
    if-nez v1, :cond_f

    .line 4
    .line 5
    iget-boolean v2, p0, Lh8/o0;->g:Z

    .line 6
    .line 7
    if-nez v2, :cond_f

    .line 8
    .line 9
    const-wide/16 v2, -0x1

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    :try_start_0
    iget-object v5, p0, Lh8/o0;->f:Lo8/s;

    .line 13
    .line 14
    iget-wide v10, v5, Lo8/s;->a:J

    .line 15
    .line 16
    invoke-virtual {p0, v10, v11}, Lh8/o0;->a(J)Ly7/j;

    .line 17
    .line 18
    .line 19
    move-result-object v5

    .line 20
    iput-object v5, p0, Lh8/o0;->j:Ly7/j;

    .line 21
    .line 22
    iget-object v6, p0, Lh8/o0;->b:Ly7/y;

    .line 23
    .line 24
    invoke-virtual {v6, v5}, Ly7/y;->g(Ly7/j;)J

    .line 25
    .line 26
    .line 27
    move-result-wide v5

    .line 28
    iget-boolean v7, p0, Lh8/o0;->g:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    .line 30
    if-eqz v7, :cond_3

    .line 31
    .line 32
    if-ne v1, v4, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iget-object v0, p0, Lh8/o0;->c:Lgw0/c;

    .line 36
    .line 37
    invoke-virtual {v0}, Lgw0/c;->i()J

    .line 38
    .line 39
    .line 40
    move-result-wide v0

    .line 41
    cmp-long v0, v0, v2

    .line 42
    .line 43
    if-eqz v0, :cond_2

    .line 44
    .line 45
    iget-object v0, p0, Lh8/o0;->f:Lo8/s;

    .line 46
    .line 47
    iget-object v1, p0, Lh8/o0;->c:Lgw0/c;

    .line 48
    .line 49
    invoke-virtual {v1}, Lgw0/c;->i()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    iput-wide v1, v0, Lo8/s;->a:J

    .line 54
    .line 55
    :cond_2
    :goto_1
    iget-object p0, p0, Lh8/o0;->b:Ly7/y;

    .line 56
    .line 57
    if-eqz p0, :cond_f

    .line 58
    .line 59
    :try_start_1
    invoke-virtual {p0}, Ly7/y;->close()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_3

    .line 60
    .line 61
    .line 62
    goto/16 :goto_a

    .line 63
    .line 64
    :cond_3
    cmp-long v7, v5, v2

    .line 65
    .line 66
    if-eqz v7, :cond_4

    .line 67
    .line 68
    add-long/2addr v5, v10

    .line 69
    :try_start_2
    iget-object v7, p0, Lh8/o0;->m:Lh8/r0;

    .line 70
    .line 71
    iget-object v8, v7, Lh8/r0;->t:Landroid/os/Handler;

    .line 72
    .line 73
    new-instance v9, Lh8/m0;

    .line 74
    .line 75
    const/4 v12, 0x0

    .line 76
    invoke-direct {v9, v7, v12}, Lh8/m0;-><init>(Lh8/r0;I)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v8, v9}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 80
    .line 81
    .line 82
    :cond_4
    move-wide v12, v5

    .line 83
    goto :goto_2

    .line 84
    :catchall_0
    move-exception v0

    .line 85
    goto/16 :goto_9

    .line 86
    .line 87
    :goto_2
    iget-object v5, p0, Lh8/o0;->m:Lh8/r0;

    .line 88
    .line 89
    iget-object v6, p0, Lh8/o0;->b:Ly7/y;

    .line 90
    .line 91
    iget-object v6, v6, Ly7/y;->d:Ly7/h;

    .line 92
    .line 93
    invoke-interface {v6}, Ly7/h;->d()Ljava/util/Map;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    invoke-static {v6}, Lb9/b;->d(Ljava/util/Map;)Lb9/b;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    iput-object v6, v5, Lh8/r0;->v:Lb9/b;

    .line 102
    .line 103
    iget-object v5, p0, Lh8/o0;->b:Ly7/y;

    .line 104
    .line 105
    iget-object v6, p0, Lh8/o0;->m:Lh8/r0;

    .line 106
    .line 107
    iget-object v6, v6, Lh8/r0;->v:Lb9/b;

    .line 108
    .line 109
    if-eqz v6, :cond_5

    .line 110
    .line 111
    iget v6, v6, Lb9/b;->f:I

    .line 112
    .line 113
    const/4 v7, -0x1

    .line 114
    if-eq v6, v7, :cond_5

    .line 115
    .line 116
    new-instance v7, Lh8/r;

    .line 117
    .line 118
    invoke-direct {v7, v5, v6, p0}, Lh8/r;-><init>(Ly7/h;ILh8/o0;)V

    .line 119
    .line 120
    .line 121
    iget-object v5, p0, Lh8/o0;->m:Lh8/r0;

    .line 122
    .line 123
    new-instance v6, Lh8/q0;

    .line 124
    .line 125
    invoke-direct {v6, v0, v4}, Lh8/q0;-><init>(IZ)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v5, v6}, Lh8/r0;->B(Lh8/q0;)Lo8/i0;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    iput-object v5, p0, Lh8/o0;->k:Lo8/i0;

    .line 133
    .line 134
    sget-object v6, Lh8/r0;->T:Lt7/o;

    .line 135
    .line 136
    invoke-interface {v5, v6}, Lo8/i0;->c(Lt7/o;)V

    .line 137
    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_5
    move-object v7, v5

    .line 141
    :goto_3
    iget-object v6, p0, Lh8/o0;->c:Lgw0/c;

    .line 142
    .line 143
    iget-object v8, p0, Lh8/o0;->a:Landroid/net/Uri;

    .line 144
    .line 145
    iget-object v5, p0, Lh8/o0;->b:Ly7/y;

    .line 146
    .line 147
    iget-object v5, v5, Ly7/y;->d:Ly7/h;

    .line 148
    .line 149
    invoke-interface {v5}, Ly7/h;->d()Ljava/util/Map;

    .line 150
    .line 151
    .line 152
    move-result-object v9

    .line 153
    iget-object v14, p0, Lh8/o0;->d:Lh8/r0;

    .line 154
    .line 155
    invoke-virtual/range {v6 .. v14}, Lgw0/c;->q(Ly7/h;Landroid/net/Uri;Ljava/util/Map;JJLh8/r0;)V

    .line 156
    .line 157
    .line 158
    iget-object v5, p0, Lh8/o0;->m:Lh8/r0;

    .line 159
    .line 160
    iget-object v5, v5, Lh8/r0;->v:Lb9/b;

    .line 161
    .line 162
    if-eqz v5, :cond_7

    .line 163
    .line 164
    iget-object v5, p0, Lh8/o0;->c:Lgw0/c;

    .line 165
    .line 166
    iget-object v5, v5, Lgw0/c;->f:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast v5, Lo8/o;

    .line 169
    .line 170
    if-nez v5, :cond_6

    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_6
    instance-of v6, v5, Lh9/d;

    .line 174
    .line 175
    if-eqz v6, :cond_7

    .line 176
    .line 177
    check-cast v5, Lh9/d;

    .line 178
    .line 179
    iput-boolean v4, v5, Lh9/d;->q:Z

    .line 180
    .line 181
    :cond_7
    :goto_4
    iget-boolean v5, p0, Lh8/o0;->h:Z

    .line 182
    .line 183
    if-eqz v5, :cond_8

    .line 184
    .line 185
    iget-object v5, p0, Lh8/o0;->c:Lgw0/c;

    .line 186
    .line 187
    iget-wide v6, p0, Lh8/o0;->i:J

    .line 188
    .line 189
    iget-object v5, v5, Lgw0/c;->f:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v5, Lo8/o;

    .line 192
    .line 193
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 194
    .line 195
    .line 196
    invoke-interface {v5, v10, v11, v6, v7}, Lo8/o;->d(JJ)V

    .line 197
    .line 198
    .line 199
    iput-boolean v0, p0, Lh8/o0;->h:Z

    .line 200
    .line 201
    :cond_8
    :goto_5
    if-nez v1, :cond_a

    .line 202
    .line 203
    iget-boolean v5, p0, Lh8/o0;->g:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 204
    .line 205
    if-nez v5, :cond_a

    .line 206
    .line 207
    :try_start_3
    iget-object v5, p0, Lh8/o0;->e:Lw7/e;

    .line 208
    .line 209
    monitor-enter v5
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 210
    :goto_6
    :try_start_4
    iget-boolean v6, v5, Lw7/e;->b:Z

    .line 211
    .line 212
    if-nez v6, :cond_9

    .line 213
    .line 214
    iget-object v6, v5, Lw7/e;->a:Lw7/r;

    .line 215
    .line 216
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 217
    .line 218
    .line 219
    invoke-virtual {v5}, Ljava/lang/Object;->wait()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 220
    .line 221
    .line 222
    goto :goto_6

    .line 223
    :catchall_1
    move-exception v0

    .line 224
    goto :goto_7

    .line 225
    :cond_9
    :try_start_5
    monitor-exit v5
    :try_end_5
    .catch Ljava/lang/InterruptedException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 226
    :try_start_6
    iget-object v5, p0, Lh8/o0;->c:Lgw0/c;

    .line 227
    .line 228
    iget-object v6, p0, Lh8/o0;->f:Lo8/s;

    .line 229
    .line 230
    iget-object v7, v5, Lgw0/c;->f:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v7, Lo8/o;

    .line 233
    .line 234
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    iget-object v5, v5, Lgw0/c;->g:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v5, Lo8/l;

    .line 240
    .line 241
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 242
    .line 243
    .line 244
    invoke-interface {v7, v5, v6}, Lo8/o;->h(Lo8/p;Lo8/s;)I

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    iget-object v5, p0, Lh8/o0;->c:Lgw0/c;

    .line 249
    .line 250
    invoke-virtual {v5}, Lgw0/c;->i()J

    .line 251
    .line 252
    .line 253
    move-result-wide v5

    .line 254
    iget-object v7, p0, Lh8/o0;->m:Lh8/r0;

    .line 255
    .line 256
    iget-wide v7, v7, Lh8/r0;->l:J

    .line 257
    .line 258
    add-long/2addr v7, v10

    .line 259
    cmp-long v7, v5, v7

    .line 260
    .line 261
    if-lez v7, :cond_8

    .line 262
    .line 263
    iget-object v7, p0, Lh8/o0;->e:Lw7/e;

    .line 264
    .line 265
    monitor-enter v7
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 266
    :try_start_7
    iput-boolean v0, v7, Lw7/e;->b:Z
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 267
    .line 268
    :try_start_8
    monitor-exit v7

    .line 269
    iget-object v7, p0, Lh8/o0;->m:Lh8/r0;

    .line 270
    .line 271
    iget-object v8, v7, Lh8/r0;->t:Landroid/os/Handler;

    .line 272
    .line 273
    iget-object v7, v7, Lh8/r0;->s:Lh8/m0;

    .line 274
    .line 275
    invoke-virtual {v8, v7}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 276
    .line 277
    .line 278
    move-wide v10, v5

    .line 279
    goto :goto_5

    .line 280
    :catchall_2
    move-exception v0

    .line 281
    :try_start_9
    monitor-exit v7
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 282
    :try_start_a
    throw v0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 283
    :goto_7
    :try_start_b
    monitor-exit v5
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 284
    :try_start_c
    throw v0
    :try_end_c
    .catch Ljava/lang/InterruptedException; {:try_start_c .. :try_end_c} :catch_1
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 285
    :catch_1
    :try_start_d
    new-instance v0, Ljava/io/InterruptedIOException;

    .line 286
    .line 287
    invoke-direct {v0}, Ljava/io/InterruptedIOException;-><init>()V

    .line 288
    .line 289
    .line 290
    throw v0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_0

    .line 291
    :cond_a
    if-ne v1, v4, :cond_b

    .line 292
    .line 293
    move v1, v0

    .line 294
    goto :goto_8

    .line 295
    :cond_b
    iget-object v4, p0, Lh8/o0;->c:Lgw0/c;

    .line 296
    .line 297
    invoke-virtual {v4}, Lgw0/c;->i()J

    .line 298
    .line 299
    .line 300
    move-result-wide v4

    .line 301
    cmp-long v2, v4, v2

    .line 302
    .line 303
    if-eqz v2, :cond_c

    .line 304
    .line 305
    iget-object v2, p0, Lh8/o0;->f:Lo8/s;

    .line 306
    .line 307
    iget-object v3, p0, Lh8/o0;->c:Lgw0/c;

    .line 308
    .line 309
    invoke-virtual {v3}, Lgw0/c;->i()J

    .line 310
    .line 311
    .line 312
    move-result-wide v3

    .line 313
    iput-wide v3, v2, Lo8/s;->a:J

    .line 314
    .line 315
    :cond_c
    :goto_8
    iget-object v2, p0, Lh8/o0;->b:Ly7/y;

    .line 316
    .line 317
    if-eqz v2, :cond_0

    .line 318
    .line 319
    :try_start_e
    invoke-virtual {v2}, Ly7/y;->close()V
    :try_end_e
    .catch Ljava/io/IOException; {:try_start_e .. :try_end_e} :catch_0

    .line 320
    .line 321
    .line 322
    goto/16 :goto_0

    .line 323
    .line 324
    :goto_9
    if-eq v1, v4, :cond_d

    .line 325
    .line 326
    iget-object v1, p0, Lh8/o0;->c:Lgw0/c;

    .line 327
    .line 328
    invoke-virtual {v1}, Lgw0/c;->i()J

    .line 329
    .line 330
    .line 331
    move-result-wide v4

    .line 332
    cmp-long v1, v4, v2

    .line 333
    .line 334
    if-eqz v1, :cond_d

    .line 335
    .line 336
    iget-object v1, p0, Lh8/o0;->f:Lo8/s;

    .line 337
    .line 338
    iget-object v2, p0, Lh8/o0;->c:Lgw0/c;

    .line 339
    .line 340
    invoke-virtual {v2}, Lgw0/c;->i()J

    .line 341
    .line 342
    .line 343
    move-result-wide v2

    .line 344
    iput-wide v2, v1, Lo8/s;->a:J

    .line 345
    .line 346
    :cond_d
    iget-object p0, p0, Lh8/o0;->b:Ly7/y;

    .line 347
    .line 348
    if-eqz p0, :cond_e

    .line 349
    .line 350
    :try_start_f
    invoke-virtual {p0}, Ly7/y;->close()V
    :try_end_f
    .catch Ljava/io/IOException; {:try_start_f .. :try_end_f} :catch_2

    .line 351
    .line 352
    .line 353
    :catch_2
    :cond_e
    throw v0

    .line 354
    :catch_3
    :cond_f
    :goto_a
    return-void
.end method
