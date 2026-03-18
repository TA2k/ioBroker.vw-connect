.class public final La8/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Handler$Callback;
.implements Lh8/y;
.implements La8/j1;
.implements Lm8/x;


# static fields
.field public static final q1:J


# instance fields
.field public final A:Lw7/t;

.field public final B:Z

.field public final C:La8/e;

.field public D:La8/r1;

.field public E:La8/q1;

.field public F:Z

.field public G:Z

.field public H:La8/p0;

.field public I:La8/i1;

.field public J:La8/n0;

.field public K:Z

.field public L:Z

.field public M:Z

.field public N:Z

.field public O:J

.field public P:Z

.field public Q:I

.field public R:Z

.field public S:Z

.field public T:Z

.field public U:Z

.field public V:I

.field public W:La8/p0;

.field public X:J

.field public Y:J

.field public Z:I

.field public a0:Z

.field public b0:La8/o;

.field public c0:J

.field public final d:[La8/p1;

.field public d0:La8/r;

.field public final e:[La8/f;

.field public e0:J

.field public final f:[Z

.field public f0:Z

.field public final g:Lh/w;

.field public g0:F

.field public final h:Lj8/s;

.field public final i:La8/k;

.field public final j:Lk8/d;

.field public final k:Lw7/t;

.field public final l:Lio/o;

.field public final m:Landroid/os/Looper;

.field public final n:Lt7/o0;

.field public final o:Lt7/n0;

.field public final p:J

.field public final q:La8/l;

.field public final r:Ljava/util/ArrayList;

.field public final s:Lw7/r;

.field public final t:La8/y;

.field public final u:La8/z0;

.field public final v:Lac/i;

.field public final w:La8/i;

.field public final x:J

.field public final y:Lb8/k;

.field public final z:Lb8/e;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x2710

    .line 2
    .line 3
    invoke-static {v0, v1}, Lw7/w;->N(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    sput-wide v0, La8/q0;->q1:J

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;[La8/f;[La8/f;Lh/w;Lj8/s;La8/k;Lk8/d;IZLb8/e;La8/r1;La8/i;JLandroid/os/Looper;Lw7/r;La8/y;Lb8/k;La8/r;Lm8/x;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    move-object/from16 v3, p6

    .line 8
    .line 9
    move-object/from16 v4, p7

    .line 10
    .line 11
    move-object/from16 v5, p10

    .line 12
    .line 13
    move-object/from16 v6, p16

    .line 14
    .line 15
    move-object/from16 v7, p18

    .line 16
    .line 17
    move-object/from16 v8, p19

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    const-wide v9, -0x7fffffffffffffffL    # -4.9E-324

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    iput-wide v9, v0, La8/q0;->e0:J

    .line 28
    .line 29
    move-object/from16 v11, p17

    .line 30
    .line 31
    iput-object v11, v0, La8/q0;->t:La8/y;

    .line 32
    .line 33
    iput-object v2, v0, La8/q0;->g:Lh/w;

    .line 34
    .line 35
    move-object/from16 v11, p5

    .line 36
    .line 37
    iput-object v11, v0, La8/q0;->h:Lj8/s;

    .line 38
    .line 39
    iput-object v3, v0, La8/q0;->i:La8/k;

    .line 40
    .line 41
    iput-object v4, v0, La8/q0;->j:Lk8/d;

    .line 42
    .line 43
    move/from16 v12, p8

    .line 44
    .line 45
    iput v12, v0, La8/q0;->Q:I

    .line 46
    .line 47
    move/from16 v12, p9

    .line 48
    .line 49
    iput-boolean v12, v0, La8/q0;->R:Z

    .line 50
    .line 51
    move-object/from16 v12, p11

    .line 52
    .line 53
    iput-object v12, v0, La8/q0;->D:La8/r1;

    .line 54
    .line 55
    move-object/from16 v12, p12

    .line 56
    .line 57
    iput-object v12, v0, La8/q0;->w:La8/i;

    .line 58
    .line 59
    move-wide/from16 v12, p13

    .line 60
    .line 61
    iput-wide v12, v0, La8/q0;->x:J

    .line 62
    .line 63
    const/4 v12, 0x0

    .line 64
    iput-boolean v12, v0, La8/q0;->L:Z

    .line 65
    .line 66
    iput-object v6, v0, La8/q0;->s:Lw7/r;

    .line 67
    .line 68
    iput-object v7, v0, La8/q0;->y:Lb8/k;

    .line 69
    .line 70
    iput-object v8, v0, La8/q0;->d0:La8/r;

    .line 71
    .line 72
    iput-object v5, v0, La8/q0;->z:Lb8/e;

    .line 73
    .line 74
    const/high16 v13, 0x3f800000    # 1.0f

    .line 75
    .line 76
    iput v13, v0, La8/q0;->g0:F

    .line 77
    .line 78
    sget-object v13, La8/q1;->b:La8/q1;

    .line 79
    .line 80
    iput-object v13, v0, La8/q0;->E:La8/q1;

    .line 81
    .line 82
    iput-wide v9, v0, La8/q0;->c0:J

    .line 83
    .line 84
    iput-wide v9, v0, La8/q0;->O:J

    .line 85
    .line 86
    iget-wide v9, v3, La8/k;->g:J

    .line 87
    .line 88
    iput-wide v9, v0, La8/q0;->p:J

    .line 89
    .line 90
    sget-object v3, Lt7/p0;->a:Lt7/m0;

    .line 91
    .line 92
    invoke-static {v11}, La8/i1;->k(Lj8/s;)La8/i1;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    iput-object v3, v0, La8/q0;->I:La8/i1;

    .line 97
    .line 98
    new-instance v9, La8/n0;

    .line 99
    .line 100
    invoke-direct {v9, v3}, La8/n0;-><init>(La8/i1;)V

    .line 101
    .line 102
    .line 103
    iput-object v9, v0, La8/q0;->J:La8/n0;

    .line 104
    .line 105
    array-length v3, v1

    .line 106
    new-array v3, v3, [La8/f;

    .line 107
    .line 108
    iput-object v3, v0, La8/q0;->e:[La8/f;

    .line 109
    .line 110
    array-length v3, v1

    .line 111
    new-array v3, v3, [Z

    .line 112
    .line 113
    iput-object v3, v0, La8/q0;->f:[Z

    .line 114
    .line 115
    move-object v3, v2

    .line 116
    check-cast v3, Lj8/o;

    .line 117
    .line 118
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    array-length v9, v1

    .line 122
    new-array v9, v9, [La8/p1;

    .line 123
    .line 124
    iput-object v9, v0, La8/q0;->d:[La8/p1;

    .line 125
    .line 126
    move v9, v12

    .line 127
    move v10, v9

    .line 128
    :goto_0
    array-length v11, v1

    .line 129
    const/4 v13, 0x1

    .line 130
    if-ge v9, v11, :cond_1

    .line 131
    .line 132
    aget-object v11, v1, v9

    .line 133
    .line 134
    iput v9, v11, La8/f;->h:I

    .line 135
    .line 136
    iput-object v7, v11, La8/f;->i:Lb8/k;

    .line 137
    .line 138
    iput-object v6, v11, La8/f;->j:Lw7/r;

    .line 139
    .line 140
    iget-object v14, v0, La8/q0;->e:[La8/f;

    .line 141
    .line 142
    aput-object v11, v14, v9

    .line 143
    .line 144
    iget-object v11, v0, La8/q0;->e:[La8/f;

    .line 145
    .line 146
    aget-object v11, v11, v9

    .line 147
    .line 148
    iget-object v14, v11, La8/f;->d:Ljava/lang/Object;

    .line 149
    .line 150
    monitor-enter v14

    .line 151
    :try_start_0
    iput-object v3, v11, La8/f;->u:Lj8/o;

    .line 152
    .line 153
    monitor-exit v14
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 154
    aget-object v11, p3, v9

    .line 155
    .line 156
    if-eqz v11, :cond_0

    .line 157
    .line 158
    iput v9, v11, La8/f;->h:I

    .line 159
    .line 160
    iput-object v7, v11, La8/f;->i:Lb8/k;

    .line 161
    .line 162
    iput-object v6, v11, La8/f;->j:Lw7/r;

    .line 163
    .line 164
    move v10, v13

    .line 165
    :cond_0
    iget-object v13, v0, La8/q0;->d:[La8/p1;

    .line 166
    .line 167
    new-instance v14, La8/p1;

    .line 168
    .line 169
    aget-object v15, v1, v9

    .line 170
    .line 171
    invoke-direct {v14}, Ljava/lang/Object;-><init>()V

    .line 172
    .line 173
    .line 174
    iput-object v15, v14, La8/p1;->e:Ljava/lang/Object;

    .line 175
    .line 176
    iput v9, v14, La8/p1;->c:I

    .line 177
    .line 178
    iput-object v11, v14, La8/p1;->f:Ljava/lang/Object;

    .line 179
    .line 180
    const/4 v11, 0x0

    .line 181
    iput v11, v14, La8/p1;->d:I

    .line 182
    .line 183
    iput-boolean v11, v14, La8/p1;->a:Z

    .line 184
    .line 185
    iput-boolean v11, v14, La8/p1;->b:Z

    .line 186
    .line 187
    aput-object v14, v13, v9

    .line 188
    .line 189
    add-int/lit8 v9, v9, 0x1

    .line 190
    .line 191
    goto :goto_0

    .line 192
    :catchall_0
    move-exception v0

    .line 193
    :try_start_1
    monitor-exit v14
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 194
    throw v0

    .line 195
    :cond_1
    iput-boolean v10, v0, La8/q0;->B:Z

    .line 196
    .line 197
    new-instance v1, La8/l;

    .line 198
    .line 199
    invoke-direct {v1, v0, v6}, La8/l;-><init>(La8/q0;Lw7/r;)V

    .line 200
    .line 201
    .line 202
    iput-object v1, v0, La8/q0;->q:La8/l;

    .line 203
    .line 204
    new-instance v1, Ljava/util/ArrayList;

    .line 205
    .line 206
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 207
    .line 208
    .line 209
    iput-object v1, v0, La8/q0;->r:Ljava/util/ArrayList;

    .line 210
    .line 211
    new-instance v1, Lt7/o0;

    .line 212
    .line 213
    invoke-direct {v1}, Lt7/o0;-><init>()V

    .line 214
    .line 215
    .line 216
    iput-object v1, v0, La8/q0;->n:Lt7/o0;

    .line 217
    .line 218
    new-instance v1, Lt7/n0;

    .line 219
    .line 220
    invoke-direct {v1}, Lt7/n0;-><init>()V

    .line 221
    .line 222
    .line 223
    iput-object v1, v0, La8/q0;->o:Lt7/n0;

    .line 224
    .line 225
    iget-object v1, v2, Lh/w;->b:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v1, La8/q0;

    .line 228
    .line 229
    if-nez v1, :cond_2

    .line 230
    .line 231
    move v1, v13

    .line 232
    goto :goto_1

    .line 233
    :cond_2
    move v1, v12

    .line 234
    :goto_1
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 235
    .line 236
    .line 237
    iput-object v0, v2, Lh/w;->b:Ljava/lang/Object;

    .line 238
    .line 239
    iput-object v4, v2, Lh/w;->c:Ljava/lang/Object;

    .line 240
    .line 241
    iput-boolean v13, v0, La8/q0;->a0:Z

    .line 242
    .line 243
    const/4 v1, 0x0

    .line 244
    move-object/from16 v2, p15

    .line 245
    .line 246
    invoke-virtual {v6, v2, v1}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    iput-object v1, v0, La8/q0;->A:Lw7/t;

    .line 251
    .line 252
    new-instance v2, La8/z0;

    .line 253
    .line 254
    new-instance v3, La8/t;

    .line 255
    .line 256
    const/4 v4, 0x5

    .line 257
    invoke-direct {v3, v0, v4}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 258
    .line 259
    .line 260
    invoke-direct {v2, v5, v1, v3, v8}, La8/z0;-><init>(Lb8/e;Lw7/t;La8/t;La8/r;)V

    .line 261
    .line 262
    .line 263
    iput-object v2, v0, La8/q0;->u:La8/z0;

    .line 264
    .line 265
    new-instance v2, Lac/i;

    .line 266
    .line 267
    invoke-direct {v2, v0, v5, v1, v7}, Lac/i;-><init>(La8/q0;Lb8/e;Lw7/t;Lb8/k;)V

    .line 268
    .line 269
    .line 270
    iput-object v2, v0, La8/q0;->v:Lac/i;

    .line 271
    .line 272
    new-instance v1, Lio/o;

    .line 273
    .line 274
    const/4 v2, 0x1

    .line 275
    invoke-direct {v1, v2}, Lio/o;-><init>(I)V

    .line 276
    .line 277
    .line 278
    iput-object v1, v0, La8/q0;->l:Lio/o;

    .line 279
    .line 280
    iget-object v2, v1, Lio/o;->e:Ljava/lang/Object;

    .line 281
    .line 282
    monitor-enter v2

    .line 283
    :try_start_2
    iget-object v3, v1, Lio/o;->f:Ljava/lang/Object;

    .line 284
    .line 285
    check-cast v3, Landroid/os/Looper;

    .line 286
    .line 287
    if-nez v3, :cond_4

    .line 288
    .line 289
    iget v3, v1, Lio/o;->d:I

    .line 290
    .line 291
    if-nez v3, :cond_3

    .line 292
    .line 293
    iget-object v3, v1, Lio/o;->g:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast v3, Landroid/os/HandlerThread;

    .line 296
    .line 297
    if-nez v3, :cond_3

    .line 298
    .line 299
    move v12, v13

    .line 300
    :cond_3
    invoke-static {v12}, Lw7/a;->j(Z)V

    .line 301
    .line 302
    .line 303
    new-instance v3, Landroid/os/HandlerThread;

    .line 304
    .line 305
    const-string v4, "ExoPlayer:Playback"

    .line 306
    .line 307
    const/16 v5, -0x10

    .line 308
    .line 309
    invoke-direct {v3, v4, v5}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;I)V

    .line 310
    .line 311
    .line 312
    iput-object v3, v1, Lio/o;->g:Ljava/lang/Object;

    .line 313
    .line 314
    invoke-virtual {v3}, Ljava/lang/Thread;->start()V

    .line 315
    .line 316
    .line 317
    iget-object v3, v1, Lio/o;->g:Ljava/lang/Object;

    .line 318
    .line 319
    check-cast v3, Landroid/os/HandlerThread;

    .line 320
    .line 321
    invoke-virtual {v3}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 322
    .line 323
    .line 324
    move-result-object v3

    .line 325
    iput-object v3, v1, Lio/o;->f:Ljava/lang/Object;

    .line 326
    .line 327
    goto :goto_2

    .line 328
    :catchall_1
    move-exception v0

    .line 329
    goto :goto_3

    .line 330
    :cond_4
    :goto_2
    iget v3, v1, Lio/o;->d:I

    .line 331
    .line 332
    add-int/2addr v3, v13

    .line 333
    iput v3, v1, Lio/o;->d:I

    .line 334
    .line 335
    iget-object v1, v1, Lio/o;->f:Ljava/lang/Object;

    .line 336
    .line 337
    check-cast v1, Landroid/os/Looper;

    .line 338
    .line 339
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 340
    iput-object v1, v0, La8/q0;->m:Landroid/os/Looper;

    .line 341
    .line 342
    invoke-virtual {v6, v1, v0}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 343
    .line 344
    .line 345
    move-result-object v2

    .line 346
    iput-object v2, v0, La8/q0;->k:Lw7/t;

    .line 347
    .line 348
    new-instance v3, La8/e;

    .line 349
    .line 350
    move-object/from16 v4, p1

    .line 351
    .line 352
    invoke-direct {v3, v4, v1, v0}, La8/e;-><init>(Landroid/content/Context;Landroid/os/Looper;La8/q0;)V

    .line 353
    .line 354
    .line 355
    iput-object v3, v0, La8/q0;->C:La8/e;

    .line 356
    .line 357
    new-instance v1, La8/k0;

    .line 358
    .line 359
    move-object/from16 v3, p20

    .line 360
    .line 361
    invoke-direct {v1, v0, v3}, La8/k0;-><init>(La8/q0;Lm8/x;)V

    .line 362
    .line 363
    .line 364
    const/16 v0, 0x23

    .line 365
    .line 366
    invoke-virtual {v2, v0, v1}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 367
    .line 368
    .line 369
    move-result-object v0

    .line 370
    invoke-virtual {v0}, Lw7/s;->b()V

    .line 371
    .line 372
    .line 373
    return-void

    .line 374
    :goto_3
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 375
    throw v0
.end method

.method public static S(Lt7/p0;La8/p0;ZIZLt7/o0;Lt7/n0;)Landroid/util/Pair;
    .locals 9

    .line 1
    iget-object v0, p1, La8/p0;->a:Lt7/p0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lt7/p0;->p()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto/16 :goto_2

    .line 10
    .line 11
    :cond_0
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    move-object v2, p0

    .line 18
    goto :goto_0

    .line 19
    :cond_1
    move-object v2, v0

    .line 20
    :goto_0
    :try_start_0
    iget v5, p1, La8/p0;->b:I

    .line 21
    .line 22
    iget-wide v6, p1, La8/p0;->c:J

    .line 23
    .line 24
    move-object v3, p5

    .line 25
    move-object v4, p6

    .line 26
    invoke-virtual/range {v2 .. v7}, Lt7/p0;->i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;

    .line 27
    .line 28
    .line 29
    move-result-object p5
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    move-object v5, v4

    .line 31
    move-object v4, v3

    .line 32
    invoke-virtual {p0, v2}, Lt7/p0;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p6

    .line 36
    if-eqz p6, :cond_2

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    iget-object p6, p5, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-virtual {p0, p6}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 42
    .line 43
    .line 44
    move-result p6

    .line 45
    const/4 v0, -0x1

    .line 46
    if-eq p6, v0, :cond_4

    .line 47
    .line 48
    iget-object p2, p5, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 49
    .line 50
    invoke-virtual {v2, p2, v5}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    iget-boolean p2, p2, Lt7/n0;->f:Z

    .line 55
    .line 56
    if-eqz p2, :cond_3

    .line 57
    .line 58
    iget p2, v5, Lt7/n0;->c:I

    .line 59
    .line 60
    const-wide/16 p3, 0x0

    .line 61
    .line 62
    invoke-virtual {v2, p2, v4, p3, p4}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    iget p2, p2, Lt7/o0;->m:I

    .line 67
    .line 68
    iget-object p3, p5, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-virtual {v2, p3}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 71
    .line 72
    .line 73
    move-result p3

    .line 74
    if-ne p2, p3, :cond_3

    .line 75
    .line 76
    iget-object p2, p5, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 77
    .line 78
    invoke-virtual {p0, p2, v5}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    iget v6, p2, Lt7/n0;->c:I

    .line 83
    .line 84
    iget-wide v7, p1, La8/p0;->c:J

    .line 85
    .line 86
    move-object v3, p0

    .line 87
    invoke-virtual/range {v3 .. v8}, Lt7/p0;->i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0

    .line 92
    :cond_3
    :goto_1
    return-object p5

    .line 93
    :cond_4
    move-object v3, p0

    .line 94
    if-eqz p2, :cond_5

    .line 95
    .line 96
    iget-object p0, p5, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 97
    .line 98
    move p2, p3

    .line 99
    move p3, p4

    .line 100
    move-object p5, v2

    .line 101
    move-object p6, v3

    .line 102
    move-object p1, v5

    .line 103
    move-object p4, p0

    .line 104
    move-object p0, v4

    .line 105
    invoke-static/range {p0 .. p6}, La8/q0;->T(Lt7/o0;Lt7/n0;IZLjava/lang/Object;Lt7/p0;Lt7/p0;)I

    .line 106
    .line 107
    .line 108
    move-result v6

    .line 109
    if-eq v6, v0, :cond_5

    .line 110
    .line 111
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 112
    .line 113
    .line 114
    .line 115
    .line 116
    invoke-virtual/range {v3 .. v8}, Lt7/p0;->i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0

    .line 121
    :catch_0
    :cond_5
    :goto_2
    const/4 p0, 0x0

    .line 122
    return-object p0
.end method

.method public static T(Lt7/o0;Lt7/n0;IZLjava/lang/Object;Lt7/p0;Lt7/p0;)I
    .locals 12

    .line 1
    move-object v3, p0

    .line 2
    move-object v2, p1

    .line 3
    move-object/from16 v0, p4

    .line 4
    .line 5
    move-object/from16 v1, p5

    .line 6
    .line 7
    move-object/from16 v6, p6

    .line 8
    .line 9
    invoke-virtual {v1, v0, p1}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    iget v4, v4, Lt7/n0;->c:I

    .line 14
    .line 15
    const-wide/16 v7, 0x0

    .line 16
    .line 17
    invoke-virtual {v1, v4, p0, v7, v8}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-object v4, v4, Lt7/o0;->a:Ljava/lang/Object;

    .line 22
    .line 23
    const/4 v9, 0x0

    .line 24
    move v5, v9

    .line 25
    :goto_0
    invoke-virtual {v6}, Lt7/p0;->o()I

    .line 26
    .line 27
    .line 28
    move-result v10

    .line 29
    if-ge v5, v10, :cond_1

    .line 30
    .line 31
    invoke-virtual {v6, v5, p0, v7, v8}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 32
    .line 33
    .line 34
    move-result-object v10

    .line 35
    iget-object v10, v10, Lt7/o0;->a:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-virtual {v10, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v10

    .line 41
    if-eqz v10, :cond_0

    .line 42
    .line 43
    return v5

    .line 44
    :cond_0
    add-int/lit8 v5, v5, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    invoke-virtual {v1, v0}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    invoke-virtual {v1}, Lt7/p0;->h()I

    .line 52
    .line 53
    .line 54
    move-result v7

    .line 55
    const/4 v8, -0x1

    .line 56
    move v11, v8

    .line 57
    move v10, v9

    .line 58
    :goto_1
    if-ge v10, v7, :cond_3

    .line 59
    .line 60
    if-ne v11, v8, :cond_3

    .line 61
    .line 62
    move-object v4, v1

    .line 63
    move v1, v0

    .line 64
    move-object v0, v4

    .line 65
    move v4, p2

    .line 66
    move v5, p3

    .line 67
    invoke-virtual/range {v0 .. v5}, Lt7/p0;->d(ILt7/n0;Lt7/o0;IZ)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-ne v1, v8, :cond_2

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_2
    invoke-virtual {v0, v1}, Lt7/p0;->l(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    invoke-virtual {v6, v3}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    add-int/lit8 v10, v10, 0x1

    .line 83
    .line 84
    move v3, v1

    .line 85
    move-object v1, v0

    .line 86
    move v0, v3

    .line 87
    move-object v3, p0

    .line 88
    goto :goto_1

    .line 89
    :cond_3
    :goto_2
    if-ne v11, v8, :cond_4

    .line 90
    .line 91
    return v8

    .line 92
    :cond_4
    invoke-virtual {v6, v11, p1, v9}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    iget v0, v0, Lt7/n0;->c:I

    .line 97
    .line 98
    return v0
.end method

.method public static z(La8/w0;)Z
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_4

    .line 3
    .line 4
    :try_start_0
    iget-object v1, p0, La8/w0;->a:Ljava/lang/Object;

    .line 5
    .line 6
    iget-boolean v2, p0, La8/w0;->e:Z

    .line 7
    .line 8
    if-nez v2, :cond_0

    .line 9
    .line 10
    invoke-interface {v1}, Lh8/z;->k()V

    .line 11
    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_0
    iget-object v2, p0, La8/w0;->c:[Lh8/y0;

    .line 15
    .line 16
    array-length v3, v2

    .line 17
    move v4, v0

    .line 18
    :goto_0
    if-ge v4, v3, :cond_2

    .line 19
    .line 20
    aget-object v5, v2, v4

    .line 21
    .line 22
    if-eqz v5, :cond_1

    .line 23
    .line 24
    invoke-interface {v5}, Lh8/y0;->c()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    .line 26
    .line 27
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_2
    :goto_1
    iget-boolean p0, p0, La8/w0;->e:Z

    .line 31
    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    const-wide/16 v1, 0x0

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_3
    invoke-interface {v1}, Lh8/z0;->a()J

    .line 38
    .line 39
    .line 40
    move-result-wide v1

    .line 41
    :goto_2
    const-wide/high16 v3, -0x8000000000000000L

    .line 42
    .line 43
    cmp-long p0, v1, v3

    .line 44
    .line 45
    if-eqz p0, :cond_4

    .line 46
    .line 47
    const/4 p0, 0x1

    .line 48
    return p0

    .line 49
    :catch_0
    :cond_4
    return v0
.end method


# virtual methods
.method public final A(ILh8/b0;)Z
    .locals 4

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v1, v0, La8/z0;->k:La8/w0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_5

    .line 7
    .line 8
    iget-object v1, v1, La8/w0;->g:La8/x0;

    .line 9
    .line 10
    iget-object v1, v1, La8/x0;->a:Lh8/b0;

    .line 11
    .line 12
    invoke-virtual {v1, p2}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    if-nez p2, :cond_0

    .line 17
    .line 18
    goto :goto_2

    .line 19
    :cond_0
    iget-object p0, p0, La8/q0;->d:[La8/p1;

    .line 20
    .line 21
    aget-object p0, p0, p1

    .line 22
    .line 23
    iget-object p1, v0, La8/z0;->k:La8/w0;

    .line 24
    .line 25
    iget p2, p0, La8/p1;->d:I

    .line 26
    .line 27
    const/4 v0, 0x2

    .line 28
    const/4 v1, 0x1

    .line 29
    if-eq p2, v0, :cond_1

    .line 30
    .line 31
    const/4 v0, 0x4

    .line 32
    if-ne p2, v0, :cond_2

    .line 33
    .line 34
    :cond_1
    invoke-virtual {p0, p1}, La8/p1;->d(La8/w0;)La8/f;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    iget-object v0, p0, La8/p1;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, La8/f;

    .line 41
    .line 42
    if-ne p2, v0, :cond_2

    .line 43
    .line 44
    move p2, v1

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    move p2, v2

    .line 47
    :goto_0
    iget v0, p0, La8/p1;->d:I

    .line 48
    .line 49
    const/4 v3, 0x3

    .line 50
    if-ne v0, v3, :cond_3

    .line 51
    .line 52
    invoke-virtual {p0, p1}, La8/p1;->d(La8/w0;)La8/f;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    iget-object p0, p0, La8/p1;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, La8/f;

    .line 59
    .line 60
    if-ne p1, p0, :cond_3

    .line 61
    .line 62
    move p0, v1

    .line 63
    goto :goto_1

    .line 64
    :cond_3
    move p0, v2

    .line 65
    :goto_1
    if-nez p2, :cond_4

    .line 66
    .line 67
    if-eqz p0, :cond_5

    .line 68
    .line 69
    :cond_4
    return v1

    .line 70
    :cond_5
    :goto_2
    return v2
.end method

.method public final A0(Lt7/p0;Lh8/b0;Lt7/p0;Lh8/b0;JZ)V
    .locals 8

    .line 1
    invoke-virtual {p0, p1, p2}, La8/q0;->r0(Lt7/p0;Lh8/b0;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p2, Lh8/b0;->a:Ljava/lang/Object;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    invoke-virtual {p2}, Lh8/b0;->b()Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    sget-object p1, Lt7/g0;->d:Lt7/g0;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 19
    .line 20
    iget-object p1, p1, La8/i1;->o:Lt7/g0;

    .line 21
    .line 22
    :goto_0
    iget-object p2, p0, La8/q0;->q:La8/l;

    .line 23
    .line 24
    invoke-virtual {p2}, La8/l;->c()Lt7/g0;

    .line 25
    .line 26
    .line 27
    move-result-object p3

    .line 28
    invoke-virtual {p3, p1}, Lt7/g0;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p3

    .line 32
    if-nez p3, :cond_7

    .line 33
    .line 34
    iget-object p3, p0, La8/q0;->k:Lw7/t;

    .line 35
    .line 36
    const/16 p4, 0x10

    .line 37
    .line 38
    invoke-virtual {p3, p4}, Lw7/t;->d(I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p2, p1}, La8/l;->d(Lt7/g0;)V

    .line 42
    .line 43
    .line 44
    iget-object p2, p0, La8/q0;->I:La8/i1;

    .line 45
    .line 46
    iget-object p2, p2, La8/i1;->o:Lt7/g0;

    .line 47
    .line 48
    iget p1, p1, Lt7/g0;->a:F

    .line 49
    .line 50
    const/4 p3, 0x0

    .line 51
    invoke-virtual {p0, p2, p1, p3, p3}, La8/q0;->x(Lt7/g0;FZZ)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    iget-object p2, p0, La8/q0;->o:Lt7/n0;

    .line 56
    .line 57
    invoke-virtual {p1, v1, p2}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iget v0, v0, Lt7/n0;->c:I

    .line 62
    .line 63
    iget-object v2, p0, La8/q0;->n:Lt7/o0;

    .line 64
    .line 65
    invoke-virtual {p1, v0, v2}, Lt7/p0;->n(ILt7/o0;)V

    .line 66
    .line 67
    .line 68
    iget-object v0, v2, Lt7/o0;->i:Lt7/t;

    .line 69
    .line 70
    iget-object v3, p0, La8/q0;->w:La8/i;

    .line 71
    .line 72
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    iget-wide v4, v0, Lt7/t;->a:J

    .line 76
    .line 77
    invoke-static {v4, v5}, Lw7/w;->D(J)J

    .line 78
    .line 79
    .line 80
    move-result-wide v4

    .line 81
    iput-wide v4, v3, La8/i;->c:J

    .line 82
    .line 83
    iget-wide v4, v0, Lt7/t;->b:J

    .line 84
    .line 85
    invoke-static {v4, v5}, Lw7/w;->D(J)J

    .line 86
    .line 87
    .line 88
    move-result-wide v4

    .line 89
    iput-wide v4, v3, La8/i;->f:J

    .line 90
    .line 91
    iget-wide v4, v0, Lt7/t;->c:J

    .line 92
    .line 93
    invoke-static {v4, v5}, Lw7/w;->D(J)J

    .line 94
    .line 95
    .line 96
    move-result-wide v4

    .line 97
    iput-wide v4, v3, La8/i;->g:J

    .line 98
    .line 99
    iget v4, v0, Lt7/t;->d:F

    .line 100
    .line 101
    const v5, -0x800001

    .line 102
    .line 103
    .line 104
    cmpl-float v6, v4, v5

    .line 105
    .line 106
    if-eqz v6, :cond_2

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_2
    const v4, 0x3f7851ec    # 0.97f

    .line 110
    .line 111
    .line 112
    :goto_1
    iput v4, v3, La8/i;->j:F

    .line 113
    .line 114
    iget v0, v0, Lt7/t;->e:F

    .line 115
    .line 116
    cmpl-float v5, v0, v5

    .line 117
    .line 118
    if-eqz v5, :cond_3

    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_3
    const v0, 0x3f83d70a    # 1.03f

    .line 122
    .line 123
    .line 124
    :goto_2
    iput v0, v3, La8/i;->i:F

    .line 125
    .line 126
    const/high16 v5, 0x3f800000    # 1.0f

    .line 127
    .line 128
    cmpl-float v4, v4, v5

    .line 129
    .line 130
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 131
    .line 132
    .line 133
    .line 134
    .line 135
    if-nez v4, :cond_4

    .line 136
    .line 137
    cmpl-float v0, v0, v5

    .line 138
    .line 139
    if-nez v0, :cond_4

    .line 140
    .line 141
    iput-wide v6, v3, La8/i;->c:J

    .line 142
    .line 143
    :cond_4
    invoke-virtual {v3}, La8/i;->a()V

    .line 144
    .line 145
    .line 146
    cmp-long v0, p5, v6

    .line 147
    .line 148
    if-eqz v0, :cond_5

    .line 149
    .line 150
    invoke-virtual {p0, p1, v1, p5, p6}, La8/q0;->m(Lt7/p0;Ljava/lang/Object;J)J

    .line 151
    .line 152
    .line 153
    move-result-wide p0

    .line 154
    iput-wide p0, v3, La8/i;->d:J

    .line 155
    .line 156
    invoke-virtual {v3}, La8/i;->a()V

    .line 157
    .line 158
    .line 159
    return-void

    .line 160
    :cond_5
    iget-object p0, v2, Lt7/o0;->a:Ljava/lang/Object;

    .line 161
    .line 162
    invoke-virtual {p3}, Lt7/p0;->p()Z

    .line 163
    .line 164
    .line 165
    move-result p1

    .line 166
    if-nez p1, :cond_6

    .line 167
    .line 168
    iget-object p1, p4, Lh8/b0;->a:Ljava/lang/Object;

    .line 169
    .line 170
    invoke-virtual {p3, p1, p2}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    iget p1, p1, Lt7/n0;->c:I

    .line 175
    .line 176
    const-wide/16 p4, 0x0

    .line 177
    .line 178
    invoke-virtual {p3, p1, v2, p4, p5}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    iget-object p1, p1, Lt7/o0;->a:Ljava/lang/Object;

    .line 183
    .line 184
    goto :goto_3

    .line 185
    :cond_6
    const/4 p1, 0x0

    .line 186
    :goto_3
    invoke-static {p1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    move-result p0

    .line 190
    if-eqz p0, :cond_8

    .line 191
    .line 192
    if-eqz p7, :cond_7

    .line 193
    .line 194
    goto :goto_4

    .line 195
    :cond_7
    return-void

    .line 196
    :cond_8
    :goto_4
    iput-wide v6, v3, La8/i;->d:J

    .line 197
    .line 198
    invoke-virtual {v3}, La8/i;->a()V

    .line 199
    .line 200
    .line 201
    return-void
.end method

.method public final B()Z
    .locals 5

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->i:La8/w0;

    .line 4
    .line 5
    iget-object v1, v0, La8/w0;->g:La8/x0;

    .line 6
    .line 7
    iget-wide v1, v1, La8/x0;->e:J

    .line 8
    .line 9
    iget-boolean v0, v0, La8/w0;->e:Z

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    cmp-long v0, v1, v3

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 23
    .line 24
    iget-wide v3, v0, La8/i1;->s:J

    .line 25
    .line 26
    cmp-long v0, v3, v1

    .line 27
    .line 28
    if-ltz v0, :cond_0

    .line 29
    .line 30
    invoke-virtual {p0}, La8/q0;->q0()Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-nez p0, :cond_1

    .line 35
    .line 36
    :cond_0
    const/4 p0, 0x1

    .line 37
    return p0

    .line 38
    :cond_1
    const/4 p0, 0x0

    .line 39
    return p0
.end method

.method public final B0(ZZ)V
    .locals 0

    .line 1
    iput-boolean p1, p0, La8/q0;->N:Z

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, La8/q0;->s:Lw7/r;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 13
    .line 14
    .line 15
    move-result-wide p1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    :goto_0
    iput-wide p1, p0, La8/q0;->O:J

    .line 23
    .line 24
    return-void
.end method

.method public final C()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 4
    .line 5
    iget-object v1, v1, La8/z0;->l:La8/w0;

    .line 6
    .line 7
    invoke-static {v1}, La8/q0;->z(La8/w0;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    const-wide/16 v4, 0x0

    .line 17
    .line 18
    const/4 v6, 0x0

    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    move v1, v6

    .line 22
    goto/16 :goto_2

    .line 23
    .line 24
    :cond_0
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 25
    .line 26
    iget-object v1, v1, La8/z0;->l:La8/w0;

    .line 27
    .line 28
    iget-boolean v7, v1, La8/w0;->e:Z

    .line 29
    .line 30
    if-nez v7, :cond_1

    .line 31
    .line 32
    move-wide v7, v4

    .line 33
    goto :goto_0

    .line 34
    :cond_1
    iget-object v7, v1, La8/w0;->a:Ljava/lang/Object;

    .line 35
    .line 36
    invoke-interface {v7}, Lh8/z0;->a()J

    .line 37
    .line 38
    .line 39
    move-result-wide v7

    .line 40
    :goto_0
    invoke-virtual {v0, v7, v8}, La8/q0;->p(J)J

    .line 41
    .line 42
    .line 43
    move-result-wide v11

    .line 44
    iget-object v7, v0, La8/q0;->u:La8/z0;

    .line 45
    .line 46
    iget-object v7, v7, La8/z0;->i:La8/w0;

    .line 47
    .line 48
    iget-object v7, v0, La8/q0;->I:La8/i1;

    .line 49
    .line 50
    iget-object v7, v7, La8/i1;->a:Lt7/p0;

    .line 51
    .line 52
    iget-object v1, v1, La8/w0;->g:La8/x0;

    .line 53
    .line 54
    iget-object v1, v1, La8/x0;->a:Lh8/b0;

    .line 55
    .line 56
    invoke-virtual {v0, v7, v1}, La8/q0;->r0(Lt7/p0;Lh8/b0;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eqz v1, :cond_2

    .line 61
    .line 62
    iget-object v1, v0, La8/q0;->w:La8/i;

    .line 63
    .line 64
    iget-wide v7, v1, La8/i;->h:J

    .line 65
    .line 66
    move-wide v15, v7

    .line 67
    goto :goto_1

    .line 68
    :cond_2
    move-wide v15, v2

    .line 69
    :goto_1
    new-instance v9, La8/s0;

    .line 70
    .line 71
    iget-object v10, v0, La8/q0;->y:Lb8/k;

    .line 72
    .line 73
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 74
    .line 75
    iget-object v1, v1, La8/i1;->a:Lt7/p0;

    .line 76
    .line 77
    iget-object v1, v0, La8/q0;->q:La8/l;

    .line 78
    .line 79
    invoke-virtual {v1}, La8/l;->c()Lt7/g0;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    iget v13, v1, Lt7/g0;->a:F

    .line 84
    .line 85
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 86
    .line 87
    iget-boolean v1, v1, La8/i1;->l:Z

    .line 88
    .line 89
    iget-boolean v14, v0, La8/q0;->N:Z

    .line 90
    .line 91
    invoke-direct/range {v9 .. v16}, La8/s0;-><init>(Lb8/k;JFZJ)V

    .line 92
    .line 93
    .line 94
    iget-object v1, v0, La8/q0;->i:La8/k;

    .line 95
    .line 96
    invoke-virtual {v1, v9}, La8/k;->c(La8/s0;)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    iget-object v7, v0, La8/q0;->u:La8/z0;

    .line 101
    .line 102
    iget-object v7, v7, La8/z0;->i:La8/w0;

    .line 103
    .line 104
    if-nez v1, :cond_4

    .line 105
    .line 106
    iget-boolean v8, v7, La8/w0;->e:Z

    .line 107
    .line 108
    if-eqz v8, :cond_4

    .line 109
    .line 110
    const-wide/32 v13, 0x7a120

    .line 111
    .line 112
    .line 113
    cmp-long v8, v11, v13

    .line 114
    .line 115
    if-gez v8, :cond_4

    .line 116
    .line 117
    iget-wide v10, v0, La8/q0;->p:J

    .line 118
    .line 119
    cmp-long v8, v10, v4

    .line 120
    .line 121
    if-gtz v8, :cond_3

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_3
    iget-object v1, v7, La8/w0;->a:Ljava/lang/Object;

    .line 125
    .line 126
    iget-object v7, v0, La8/q0;->I:La8/i1;

    .line 127
    .line 128
    iget-wide v7, v7, La8/i1;->s:J

    .line 129
    .line 130
    invoke-interface {v1, v7, v8}, Lh8/z;->l(J)V

    .line 131
    .line 132
    .line 133
    iget-object v1, v0, La8/q0;->i:La8/k;

    .line 134
    .line 135
    invoke-virtual {v1, v9}, La8/k;->c(La8/s0;)Z

    .line 136
    .line 137
    .line 138
    move-result v1

    .line 139
    :cond_4
    :goto_2
    iput-boolean v1, v0, La8/q0;->P:Z

    .line 140
    .line 141
    if-eqz v1, :cond_a

    .line 142
    .line 143
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 144
    .line 145
    iget-object v1, v1, La8/z0;->l:La8/w0;

    .line 146
    .line 147
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    new-instance v7, La8/t0;

    .line 151
    .line 152
    invoke-direct {v7}, La8/t0;-><init>()V

    .line 153
    .line 154
    .line 155
    iget-wide v8, v0, La8/q0;->X:J

    .line 156
    .line 157
    iget-wide v10, v1, La8/w0;->p:J

    .line 158
    .line 159
    sub-long/2addr v8, v10

    .line 160
    iput-wide v8, v7, La8/t0;->a:J

    .line 161
    .line 162
    iget-object v8, v0, La8/q0;->q:La8/l;

    .line 163
    .line 164
    invoke-virtual {v8}, La8/l;->c()Lt7/g0;

    .line 165
    .line 166
    .line 167
    move-result-object v8

    .line 168
    iget v8, v8, Lt7/g0;->a:F

    .line 169
    .line 170
    const/4 v9, 0x0

    .line 171
    cmpl-float v9, v8, v9

    .line 172
    .line 173
    const/4 v10, 0x1

    .line 174
    if-gtz v9, :cond_6

    .line 175
    .line 176
    const v9, -0x800001

    .line 177
    .line 178
    .line 179
    cmpl-float v9, v8, v9

    .line 180
    .line 181
    if-nez v9, :cond_5

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_5
    move v9, v6

    .line 185
    goto :goto_4

    .line 186
    :cond_6
    :goto_3
    move v9, v10

    .line 187
    :goto_4
    invoke-static {v9}, Lw7/a;->c(Z)V

    .line 188
    .line 189
    .line 190
    iput v8, v7, La8/t0;->b:F

    .line 191
    .line 192
    iget-wide v8, v0, La8/q0;->O:J

    .line 193
    .line 194
    cmp-long v4, v8, v4

    .line 195
    .line 196
    if-gez v4, :cond_8

    .line 197
    .line 198
    cmp-long v2, v8, v2

    .line 199
    .line 200
    if-nez v2, :cond_7

    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_7
    move v2, v6

    .line 204
    goto :goto_6

    .line 205
    :cond_8
    :goto_5
    move v2, v10

    .line 206
    :goto_6
    invoke-static {v2}, Lw7/a;->c(Z)V

    .line 207
    .line 208
    .line 209
    iput-wide v8, v7, La8/t0;->c:J

    .line 210
    .line 211
    new-instance v2, La8/u0;

    .line 212
    .line 213
    invoke-direct {v2, v7}, La8/u0;-><init>(La8/t0;)V

    .line 214
    .line 215
    .line 216
    iget-object v3, v1, La8/w0;->m:La8/w0;

    .line 217
    .line 218
    if-nez v3, :cond_9

    .line 219
    .line 220
    move v6, v10

    .line 221
    :cond_9
    invoke-static {v6}, Lw7/a;->j(Z)V

    .line 222
    .line 223
    .line 224
    iget-object v1, v1, La8/w0;->a:Ljava/lang/Object;

    .line 225
    .line 226
    invoke-interface {v1, v2}, Lh8/z0;->p(La8/u0;)Z

    .line 227
    .line 228
    .line 229
    :cond_a
    invoke-virtual {v0}, La8/q0;->v0()V

    .line 230
    .line 231
    .line 232
    return-void
.end method

.method public final D()V
    .locals 9

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    invoke-virtual {v0}, La8/z0;->k()V

    .line 4
    .line 5
    .line 6
    iget-object v0, v0, La8/z0;->m:La8/w0;

    .line 7
    .line 8
    if-eqz v0, :cond_a

    .line 9
    .line 10
    iget-object v1, v0, La8/w0;->a:Ljava/lang/Object;

    .line 11
    .line 12
    iget-boolean v2, v0, La8/w0;->d:Z

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    iget-boolean v2, v0, La8/w0;->e:Z

    .line 17
    .line 18
    if-eqz v2, :cond_a

    .line 19
    .line 20
    :cond_0
    invoke-interface {v1}, Lh8/z0;->e()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-nez v2, :cond_a

    .line 25
    .line 26
    iget-object v2, p0, La8/q0;->I:La8/i1;

    .line 27
    .line 28
    iget-object v2, v2, La8/i1;->a:Lt7/p0;

    .line 29
    .line 30
    iget-boolean v2, v0, La8/w0;->e:Z

    .line 31
    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    invoke-interface {v1}, Lh8/z0;->r()J

    .line 35
    .line 36
    .line 37
    :cond_1
    iget-object v2, p0, La8/q0;->i:La8/k;

    .line 38
    .line 39
    iget-object v2, v2, La8/k;->h:Ljava/util/HashMap;

    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    :cond_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_3

    .line 54
    .line 55
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v3, La8/j;

    .line 60
    .line 61
    iget-boolean v3, v3, La8/j;->a:Z

    .line 62
    .line 63
    if-eqz v3, :cond_2

    .line 64
    .line 65
    goto/16 :goto_5

    .line 66
    .line 67
    :cond_3
    iget-boolean v2, v0, La8/w0;->d:Z

    .line 68
    .line 69
    const/4 v3, 0x1

    .line 70
    if-nez v2, :cond_4

    .line 71
    .line 72
    iget-object v2, v0, La8/w0;->g:La8/x0;

    .line 73
    .line 74
    iget-wide v4, v2, La8/x0;->b:J

    .line 75
    .line 76
    iput-boolean v3, v0, La8/w0;->d:Z

    .line 77
    .line 78
    invoke-interface {v1, p0, v4, v5}, Lh8/z;->h(Lh8/y;J)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :cond_4
    new-instance v2, La8/t0;

    .line 83
    .line 84
    invoke-direct {v2}, La8/t0;-><init>()V

    .line 85
    .line 86
    .line 87
    iget-wide v4, p0, La8/q0;->X:J

    .line 88
    .line 89
    iget-wide v6, v0, La8/w0;->p:J

    .line 90
    .line 91
    sub-long/2addr v4, v6

    .line 92
    iput-wide v4, v2, La8/t0;->a:J

    .line 93
    .line 94
    iget-object v4, p0, La8/q0;->q:La8/l;

    .line 95
    .line 96
    invoke-virtual {v4}, La8/l;->c()Lt7/g0;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    iget v4, v4, Lt7/g0;->a:F

    .line 101
    .line 102
    const/4 v5, 0x0

    .line 103
    cmpl-float v5, v4, v5

    .line 104
    .line 105
    const/4 v6, 0x0

    .line 106
    if-gtz v5, :cond_6

    .line 107
    .line 108
    const v5, -0x800001

    .line 109
    .line 110
    .line 111
    cmpl-float v5, v4, v5

    .line 112
    .line 113
    if-nez v5, :cond_5

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_5
    move v5, v6

    .line 117
    goto :goto_1

    .line 118
    :cond_6
    :goto_0
    move v5, v3

    .line 119
    :goto_1
    invoke-static {v5}, Lw7/a;->c(Z)V

    .line 120
    .line 121
    .line 122
    iput v4, v2, La8/t0;->b:F

    .line 123
    .line 124
    iget-wide v4, p0, La8/q0;->O:J

    .line 125
    .line 126
    const-wide/16 v7, 0x0

    .line 127
    .line 128
    cmp-long p0, v4, v7

    .line 129
    .line 130
    if-gez p0, :cond_8

    .line 131
    .line 132
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 133
    .line 134
    .line 135
    .line 136
    .line 137
    cmp-long p0, v4, v7

    .line 138
    .line 139
    if-nez p0, :cond_7

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_7
    move p0, v6

    .line 143
    goto :goto_3

    .line 144
    :cond_8
    :goto_2
    move p0, v3

    .line 145
    :goto_3
    invoke-static {p0}, Lw7/a;->c(Z)V

    .line 146
    .line 147
    .line 148
    iput-wide v4, v2, La8/t0;->c:J

    .line 149
    .line 150
    new-instance p0, La8/u0;

    .line 151
    .line 152
    invoke-direct {p0, v2}, La8/u0;-><init>(La8/t0;)V

    .line 153
    .line 154
    .line 155
    iget-object v0, v0, La8/w0;->m:La8/w0;

    .line 156
    .line 157
    if-nez v0, :cond_9

    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_9
    move v3, v6

    .line 161
    :goto_4
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 162
    .line 163
    .line 164
    invoke-interface {v1, p0}, Lh8/z0;->p(La8/u0;)Z

    .line 165
    .line 166
    .line 167
    :cond_a
    :goto_5
    return-void
.end method

.method public final E()V
    .locals 5

    .line 1
    iget-object v0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    iget-object v1, p0, La8/q0;->I:La8/i1;

    .line 4
    .line 5
    iget-boolean v2, v0, La8/n0;->d:Z

    .line 6
    .line 7
    iget-object v3, v0, La8/n0;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, La8/i1;

    .line 10
    .line 11
    if-eq v3, v1, :cond_0

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v3, 0x0

    .line 16
    :goto_0
    or-int/2addr v2, v3

    .line 17
    iput-boolean v2, v0, La8/n0;->d:Z

    .line 18
    .line 19
    iput-object v1, v0, La8/n0;->f:Ljava/lang/Object;

    .line 20
    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    iget-object v1, p0, La8/q0;->t:La8/y;

    .line 24
    .line 25
    iget-object v1, v1, La8/y;->d:La8/i0;

    .line 26
    .line 27
    iget-object v2, v1, La8/i0;->n:Lw7/t;

    .line 28
    .line 29
    new-instance v3, La8/z;

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    invoke-direct {v3, v4, v1, v0}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2, v3}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 36
    .line 37
    .line 38
    new-instance v0, La8/n0;

    .line 39
    .line 40
    iget-object v1, p0, La8/q0;->I:La8/i1;

    .line 41
    .line 42
    invoke-direct {v0, v1}, La8/n0;-><init>(La8/i1;)V

    .line 43
    .line 44
    .line 45
    iput-object v0, p0, La8/q0;->J:La8/n0;

    .line 46
    .line 47
    :cond_1
    return-void
.end method

.method public final F(I)V
    .locals 10

    .line 1
    iget-object v0, p0, La8/q0;->d:[La8/p1;

    .line 2
    .line 3
    aget-object v1, v0, p1

    .line 4
    .line 5
    :try_start_0
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 6
    .line 7
    iget-object v0, v0, La8/z0;->i:La8/w0;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, La8/p1;->d(La8/w0;)La8/f;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget-object v0, v0, La8/f;->l:Lh8/y0;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    invoke-interface {v0}, Lh8/y0;->c()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :catch_0
    move-exception v0

    .line 29
    iget-object v1, v1, La8/p1;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, La8/f;

    .line 32
    .line 33
    iget v1, v1, La8/f;->e:I

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    if-eq v1, v2, :cond_1

    .line 37
    .line 38
    const/4 v2, 0x5

    .line 39
    if-ne v1, v2, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    throw v0

    .line 43
    :cond_1
    :goto_0
    iget-object v1, p0, La8/q0;->u:La8/z0;

    .line 44
    .line 45
    iget-object v1, v1, La8/z0;->i:La8/w0;

    .line 46
    .line 47
    iget-object v1, v1, La8/w0;->o:Lj8/s;

    .line 48
    .line 49
    new-instance v2, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    const-string v3, "Disabling track due to error: "

    .line 52
    .line 53
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v3, v1, Lj8/s;->c:[Lj8/q;

    .line 57
    .line 58
    aget-object v3, v3, p1

    .line 59
    .line 60
    invoke-interface {v3}, Lj8/q;->k()Lt7/o;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    invoke-static {v3}, Lt7/o;->c(Lt7/o;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    const-string v3, "ExoPlayerImplInternal"

    .line 76
    .line 77
    invoke-static {v3, v2, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 78
    .line 79
    .line 80
    new-instance v5, Lj8/s;

    .line 81
    .line 82
    iget-object v0, v1, Lj8/s;->b:[La8/o1;

    .line 83
    .line 84
    invoke-virtual {v0}, [La8/o1;->clone()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, [La8/o1;

    .line 89
    .line 90
    iget-object v2, v1, Lj8/s;->c:[Lj8/q;

    .line 91
    .line 92
    invoke-virtual {v2}, [Lj8/q;->clone()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    check-cast v2, [Lj8/q;

    .line 97
    .line 98
    iget-object v3, v1, Lj8/s;->d:Lt7/w0;

    .line 99
    .line 100
    iget-object v1, v1, Lj8/s;->e:Ljava/lang/Object;

    .line 101
    .line 102
    invoke-direct {v5, v0, v2, v3, v1}, Lj8/s;-><init>([La8/o1;[Lj8/q;Lt7/w0;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object v0, v5, Lj8/s;->b:[La8/o1;

    .line 106
    .line 107
    const/4 v1, 0x0

    .line 108
    aput-object v1, v0, p1

    .line 109
    .line 110
    iget-object v0, v5, Lj8/s;->c:[Lj8/q;

    .line 111
    .line 112
    aput-object v1, v0, p1

    .line 113
    .line 114
    invoke-virtual {p0, p1}, La8/q0;->i(I)V

    .line 115
    .line 116
    .line 117
    iget-object p1, p0, La8/q0;->u:La8/z0;

    .line 118
    .line 119
    iget-object v4, p1, La8/z0;->i:La8/w0;

    .line 120
    .line 121
    iget-object p0, p0, La8/q0;->I:La8/i1;

    .line 122
    .line 123
    iget-wide v6, p0, La8/i1;->s:J

    .line 124
    .line 125
    iget-object p0, v4, La8/w0;->j:[La8/f;

    .line 126
    .line 127
    array-length p0, p0

    .line 128
    new-array v9, p0, [Z

    .line 129
    .line 130
    const/4 v8, 0x0

    .line 131
    invoke-virtual/range {v4 .. v9}, La8/w0;->a(Lj8/s;JZ[Z)J

    .line 132
    .line 133
    .line 134
    return-void
.end method

.method public final G(IZ)V
    .locals 2

    .line 1
    iget-object v0, p0, La8/q0;->f:[Z

    .line 2
    .line 3
    aget-boolean v1, v0, p1

    .line 4
    .line 5
    if-eq v1, p2, :cond_0

    .line 6
    .line 7
    aput-boolean p2, v0, p1

    .line 8
    .line 9
    new-instance v0, La8/j0;

    .line 10
    .line 11
    invoke-direct {v0, p0, p1, p2}, La8/j0;-><init>(La8/q0;IZ)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, La8/q0;->A:Lw7/t;

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public final H()V
    .locals 2

    .line 1
    iget-object v0, p0, La8/q0;->v:Lac/i;

    .line 2
    .line 3
    invoke-virtual {v0}, Lac/i;->c()Lt7/p0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-virtual {p0, v0, v1}, La8/q0;->v(Lt7/p0;Z)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final I()V
    .locals 1

    .line 1
    iget-object p0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-virtual {p0, v0}, La8/n0;->f(I)V

    .line 5
    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    throw p0
.end method

.method public final J()V
    .locals 10

    .line 1
    iget-object v0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, La8/n0;->f(I)V

    .line 5
    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, v0, v0, v0, v1}, La8/q0;->O(ZZZZ)V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, La8/q0;->i:La8/k;

    .line 12
    .line 13
    iget-object v3, v2, La8/k;->h:Ljava/util/HashMap;

    .line 14
    .line 15
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual {v4}, Ljava/lang/Thread;->getId()J

    .line 20
    .line 21
    .line 22
    move-result-wide v4

    .line 23
    iget-wide v6, v2, La8/k;->i:J

    .line 24
    .line 25
    const-wide/16 v8, -0x1

    .line 26
    .line 27
    cmp-long v8, v6, v8

    .line 28
    .line 29
    if-eqz v8, :cond_1

    .line 30
    .line 31
    cmp-long v6, v6, v4

    .line 32
    .line 33
    if-nez v6, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move v6, v0

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    :goto_0
    move v6, v1

    .line 39
    :goto_1
    const-string v7, "Players that share the same LoadControl must share the same playback thread. See ExoPlayer.Builder.setPlaybackLooper(Looper)."

    .line 40
    .line 41
    invoke-static {v7, v6}, Lw7/a;->i(Ljava/lang/String;Z)V

    .line 42
    .line 43
    .line 44
    iput-wide v4, v2, La8/k;->i:J

    .line 45
    .line 46
    iget-object v4, p0, La8/q0;->y:Lb8/k;

    .line 47
    .line 48
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v5

    .line 52
    if-nez v5, :cond_2

    .line 53
    .line 54
    new-instance v5, La8/j;

    .line 55
    .line 56
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    :cond_2
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    check-cast v3, La8/j;

    .line 67
    .line 68
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    iget v2, v2, La8/k;->f:I

    .line 72
    .line 73
    const/4 v4, -0x1

    .line 74
    if-ne v2, v4, :cond_3

    .line 75
    .line 76
    const/high16 v2, 0xc80000

    .line 77
    .line 78
    :cond_3
    iput v2, v3, La8/j;->b:I

    .line 79
    .line 80
    iput-boolean v0, v3, La8/j;->a:Z

    .line 81
    .line 82
    iget-object v2, p0, La8/q0;->I:La8/i1;

    .line 83
    .line 84
    iget-object v2, v2, La8/i1;->a:Lt7/p0;

    .line 85
    .line 86
    invoke-virtual {v2}, Lt7/p0;->p()Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    const/4 v3, 0x2

    .line 91
    if-eqz v2, :cond_4

    .line 92
    .line 93
    const/4 v2, 0x4

    .line 94
    goto :goto_2

    .line 95
    :cond_4
    move v2, v3

    .line 96
    :goto_2
    invoke-virtual {p0, v2}, La8/q0;->m0(I)V

    .line 97
    .line 98
    .line 99
    iget-object v2, p0, La8/q0;->I:La8/i1;

    .line 100
    .line 101
    iget-boolean v4, v2, La8/i1;->l:Z

    .line 102
    .line 103
    iget v5, v2, La8/i1;->n:I

    .line 104
    .line 105
    iget v6, v2, La8/i1;->m:I

    .line 106
    .line 107
    iget-object v7, p0, La8/q0;->C:La8/e;

    .line 108
    .line 109
    iget v2, v2, La8/i1;->e:I

    .line 110
    .line 111
    invoke-virtual {v7, v2, v4}, La8/e;->d(IZ)I

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    invoke-virtual {p0, v2, v5, v6, v4}, La8/q0;->y0(IIIZ)V

    .line 116
    .line 117
    .line 118
    iget-object v2, p0, La8/q0;->j:Lk8/d;

    .line 119
    .line 120
    check-cast v2, Lk8/g;

    .line 121
    .line 122
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    iget-object v4, p0, La8/q0;->v:Lac/i;

    .line 126
    .line 127
    iget-object v5, v4, Lac/i;->c:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v5, Ljava/util/ArrayList;

    .line 130
    .line 131
    iget-boolean v6, v4, Lac/i;->a:Z

    .line 132
    .line 133
    xor-int/2addr v6, v1

    .line 134
    invoke-static {v6}, Lw7/a;->j(Z)V

    .line 135
    .line 136
    .line 137
    iput-object v2, v4, Lac/i;->l:Ljava/lang/Object;

    .line 138
    .line 139
    :goto_3
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    if-ge v0, v2, :cond_5

    .line 144
    .line 145
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    check-cast v2, La8/h1;

    .line 150
    .line 151
    invoke-virtual {v4, v2}, Lac/i;->i(La8/h1;)V

    .line 152
    .line 153
    .line 154
    iget-object v6, v4, Lac/i;->h:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v6, Ljava/util/HashSet;

    .line 157
    .line 158
    invoke-virtual {v6, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    add-int/lit8 v0, v0, 0x1

    .line 162
    .line 163
    goto :goto_3

    .line 164
    :cond_5
    iput-boolean v1, v4, Lac/i;->a:Z

    .line 165
    .line 166
    iget-object p0, p0, La8/q0;->k:Lw7/t;

    .line 167
    .line 168
    invoke-virtual {p0, v3}, Lw7/t;->e(I)Z

    .line 169
    .line 170
    .line 171
    return-void
.end method

.method public final K(Lw7/e;)V
    .locals 8

    .line 1
    iget-object v0, p0, La8/q0;->l:Lio/o;

    .line 2
    .line 3
    iget-object v1, p0, La8/q0;->k:Lw7/t;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v4, 0x1

    .line 8
    :try_start_0
    invoke-virtual {p0, v4, v3, v4, v3}, La8/q0;->O(ZZZZ)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, La8/q0;->L()V

    .line 12
    .line 13
    .line 14
    iget-object v5, p0, La8/q0;->i:La8/k;

    .line 15
    .line 16
    iget-object v6, p0, La8/q0;->y:Lb8/k;

    .line 17
    .line 18
    iget-object v7, v5, La8/k;->h:Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-virtual {v7, v6}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    if-eqz v6, :cond_0

    .line 25
    .line 26
    invoke-virtual {v5}, La8/k;->d()V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v6, v5, La8/k;->h:Ljava/util/HashMap;

    .line 30
    .line 31
    invoke-virtual {v6}, Ljava/util/HashMap;->isEmpty()Z

    .line 32
    .line 33
    .line 34
    move-result v6

    .line 35
    if-eqz v6, :cond_1

    .line 36
    .line 37
    const-wide/16 v6, -0x1

    .line 38
    .line 39
    iput-wide v6, v5, La8/k;->i:J

    .line 40
    .line 41
    :cond_1
    iget-object v5, p0, La8/q0;->C:La8/e;

    .line 42
    .line 43
    iput-object v2, v5, La8/e;->c:La8/q0;

    .line 44
    .line 45
    invoke-virtual {v5}, La8/e;->a()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5, v3}, La8/e;->c(I)V

    .line 49
    .line 50
    .line 51
    iget-object v3, p0, La8/q0;->g:Lh/w;

    .line 52
    .line 53
    invoke-virtual {v3}, Lh/w;->n()V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v4}, La8/q0;->m0(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 57
    .line 58
    .line 59
    iget-object p0, v1, Lw7/t;->a:Landroid/os/Handler;

    .line 60
    .line 61
    invoke-virtual {p0, v2}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0}, Lio/o;->c()V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p1}, Lw7/e;->c()Z

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :catchall_0
    move-exception p0

    .line 72
    iget-object v1, v1, Lw7/t;->a:Landroid/os/Handler;

    .line 73
    .line 74
    invoke-virtual {v1, v2}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Lio/o;->c()V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1}, Lw7/e;->c()Z

    .line 81
    .line 82
    .line 83
    throw p0
.end method

.method public final L()V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, La8/q0;->d:[La8/p1;

    .line 4
    .line 5
    array-length v2, v2

    .line 6
    if-ge v1, v2, :cond_3

    .line 7
    .line 8
    iget-object v2, p0, La8/q0;->e:[La8/f;

    .line 9
    .line 10
    aget-object v2, v2, v1

    .line 11
    .line 12
    iget-object v3, v2, La8/f;->d:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v3

    .line 15
    const/4 v4, 0x0

    .line 16
    :try_start_0
    iput-object v4, v2, La8/f;->u:Lj8/o;

    .line 17
    .line 18
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    iget-object v2, p0, La8/q0;->d:[La8/p1;

    .line 20
    .line 21
    aget-object v2, v2, v1

    .line 22
    .line 23
    iget-object v3, v2, La8/p1;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v3, La8/f;

    .line 26
    .line 27
    iget v4, v3, La8/f;->k:I

    .line 28
    .line 29
    const/4 v5, 0x1

    .line 30
    if-nez v4, :cond_0

    .line 31
    .line 32
    move v4, v5

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    move v4, v0

    .line 35
    :goto_1
    invoke-static {v4}, Lw7/a;->j(Z)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v3}, La8/f;->s()V

    .line 39
    .line 40
    .line 41
    iput-boolean v0, v2, La8/p1;->a:Z

    .line 42
    .line 43
    iget-object v3, v2, La8/p1;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v3, La8/f;

    .line 46
    .line 47
    if-eqz v3, :cond_2

    .line 48
    .line 49
    iget v4, v3, La8/f;->k:I

    .line 50
    .line 51
    if-nez v4, :cond_1

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_1
    move v5, v0

    .line 55
    :goto_2
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v3}, La8/f;->s()V

    .line 59
    .line 60
    .line 61
    iput-boolean v0, v2, La8/p1;->b:Z

    .line 62
    .line 63
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception p0

    .line 67
    :try_start_1
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    throw p0

    .line 69
    :cond_3
    return-void
.end method

.method public final M(IILh8/a1;)V
    .locals 4

    .line 1
    iget-object v0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, La8/n0;->f(I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, La8/q0;->v:Lac/i;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    if-ltz p1, :cond_0

    .line 14
    .line 15
    if-gt p1, p2, :cond_0

    .line 16
    .line 17
    iget-object v3, v0, Lac/i;->c:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v3, Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-gt p2, v3, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v1, v2

    .line 29
    :goto_0
    invoke-static {v1}, Lw7/a;->c(Z)V

    .line 30
    .line 31
    .line 32
    iput-object p3, v0, Lac/i;->k:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-virtual {v0, p1, p2}, Lac/i;->k(II)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lac/i;->c()Lt7/p0;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p0, p1, v2}, La8/q0;->v(Lt7/p0;Z)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public final N()V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, La8/q0;->q:La8/l;

    .line 4
    .line 5
    invoke-virtual {v1}, La8/l;->c()Lt7/g0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget v1, v1, Lt7/g0;->a:F

    .line 10
    .line 11
    iget-object v2, v0, La8/q0;->u:La8/z0;

    .line 12
    .line 13
    iget-object v3, v2, La8/z0;->i:La8/w0;

    .line 14
    .line 15
    iget-object v2, v2, La8/z0;->j:La8/w0;

    .line 16
    .line 17
    const/4 v10, 0x1

    .line 18
    const/4 v4, 0x0

    .line 19
    move-object v11, v3

    .line 20
    move v3, v10

    .line 21
    :goto_0
    if-eqz v11, :cond_13

    .line 22
    .line 23
    iget-boolean v5, v11, La8/w0;->e:Z

    .line 24
    .line 25
    if-nez v5, :cond_0

    .line 26
    .line 27
    goto/16 :goto_a

    .line 28
    .line 29
    :cond_0
    iget-object v5, v0, La8/q0;->I:La8/i1;

    .line 30
    .line 31
    iget-object v6, v5, La8/i1;->a:Lt7/p0;

    .line 32
    .line 33
    iget-boolean v5, v5, La8/i1;->l:Z

    .line 34
    .line 35
    invoke-virtual {v11, v1, v6, v5}, La8/w0;->j(FLt7/p0;Z)Lj8/s;

    .line 36
    .line 37
    .line 38
    move-result-object v12

    .line 39
    iget-object v5, v0, La8/q0;->u:La8/z0;

    .line 40
    .line 41
    iget-object v5, v5, La8/z0;->i:La8/w0;

    .line 42
    .line 43
    if-ne v11, v5, :cond_1

    .line 44
    .line 45
    move-object v14, v12

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    move-object v14, v4

    .line 48
    :goto_1
    iget-object v4, v11, La8/w0;->o:Lj8/s;

    .line 49
    .line 50
    iget-object v5, v12, Lj8/s;->c:[Lj8/q;

    .line 51
    .line 52
    const/4 v6, 0x0

    .line 53
    if-eqz v4, :cond_6

    .line 54
    .line 55
    iget-object v7, v4, Lj8/s;->c:[Lj8/q;

    .line 56
    .line 57
    array-length v7, v7

    .line 58
    array-length v8, v5

    .line 59
    if-eq v7, v8, :cond_2

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_2
    move v7, v6

    .line 63
    :goto_2
    array-length v8, v5

    .line 64
    if-ge v7, v8, :cond_4

    .line 65
    .line 66
    invoke-virtual {v12, v4, v7}, Lj8/s;->a(Lj8/s;I)Z

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    if-nez v8, :cond_3

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    add-int/lit8 v7, v7, 0x1

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    if-ne v11, v2, :cond_5

    .line 77
    .line 78
    move v3, v6

    .line 79
    :cond_5
    iget-object v11, v11, La8/w0;->m:La8/w0;

    .line 80
    .line 81
    move-object v4, v14

    .line 82
    goto :goto_0

    .line 83
    :cond_6
    :goto_3
    const/4 v1, 0x4

    .line 84
    if-eqz v3, :cond_11

    .line 85
    .line 86
    iget-object v2, v0, La8/q0;->u:La8/z0;

    .line 87
    .line 88
    iget-object v13, v2, La8/z0;->i:La8/w0;

    .line 89
    .line 90
    invoke-virtual {v2, v13}, La8/z0;->n(La8/w0;)I

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    and-int/2addr v2, v10

    .line 95
    if-eqz v2, :cond_7

    .line 96
    .line 97
    move/from16 v17, v10

    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_7
    move/from16 v17, v6

    .line 101
    .line 102
    :goto_4
    iget-object v2, v0, La8/q0;->d:[La8/p1;

    .line 103
    .line 104
    array-length v2, v2

    .line 105
    new-array v2, v2, [Z

    .line 106
    .line 107
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    iget-object v3, v0, La8/q0;->I:La8/i1;

    .line 111
    .line 112
    iget-wide v3, v3, La8/i1;->s:J

    .line 113
    .line 114
    move-object/from16 v18, v2

    .line 115
    .line 116
    move-wide v15, v3

    .line 117
    invoke-virtual/range {v13 .. v18}, La8/w0;->a(Lj8/s;JZ[Z)J

    .line 118
    .line 119
    .line 120
    move-result-wide v2

    .line 121
    iget-object v4, v0, La8/q0;->I:La8/i1;

    .line 122
    .line 123
    iget v5, v4, La8/i1;->e:I

    .line 124
    .line 125
    if-eq v5, v1, :cond_8

    .line 126
    .line 127
    iget-wide v4, v4, La8/i1;->s:J

    .line 128
    .line 129
    cmp-long v4, v2, v4

    .line 130
    .line 131
    if-eqz v4, :cond_8

    .line 132
    .line 133
    move v8, v10

    .line 134
    goto :goto_5

    .line 135
    :cond_8
    move v8, v6

    .line 136
    :goto_5
    iget-object v4, v0, La8/q0;->I:La8/i1;

    .line 137
    .line 138
    move v5, v1

    .line 139
    iget-object v1, v4, La8/i1;->b:Lh8/b0;

    .line 140
    .line 141
    iget-wide v11, v4, La8/i1;->c:J

    .line 142
    .line 143
    iget-wide v14, v4, La8/i1;->d:J

    .line 144
    .line 145
    const/4 v9, 0x5

    .line 146
    move-wide/from16 v19, v14

    .line 147
    .line 148
    move v14, v5

    .line 149
    move-wide v4, v11

    .line 150
    move v11, v6

    .line 151
    move-wide/from16 v6, v19

    .line 152
    .line 153
    invoke-virtual/range {v0 .. v9}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    iput-object v1, v0, La8/q0;->I:La8/i1;

    .line 158
    .line 159
    if-eqz v8, :cond_9

    .line 160
    .line 161
    invoke-virtual {v0, v2, v3}, La8/q0;->Q(J)V

    .line 162
    .line 163
    .line 164
    :cond_9
    invoke-virtual {v0}, La8/q0;->h()V

    .line 165
    .line 166
    .line 167
    iget-object v1, v0, La8/q0;->d:[La8/p1;

    .line 168
    .line 169
    array-length v1, v1

    .line 170
    new-array v1, v1, [Z

    .line 171
    .line 172
    move v6, v11

    .line 173
    :goto_6
    iget-object v2, v0, La8/q0;->d:[La8/p1;

    .line 174
    .line 175
    array-length v3, v2

    .line 176
    if-ge v6, v3, :cond_f

    .line 177
    .line 178
    aget-object v2, v2, v6

    .line 179
    .line 180
    invoke-virtual {v2}, La8/p1;->c()I

    .line 181
    .line 182
    .line 183
    move-result v2

    .line 184
    iget-object v3, v0, La8/q0;->d:[La8/p1;

    .line 185
    .line 186
    aget-object v3, v3, v6

    .line 187
    .line 188
    invoke-virtual {v3}, La8/p1;->g()Z

    .line 189
    .line 190
    .line 191
    move-result v3

    .line 192
    aput-boolean v3, v1, v6

    .line 193
    .line 194
    iget-object v3, v0, La8/q0;->d:[La8/p1;

    .line 195
    .line 196
    aget-object v3, v3, v6

    .line 197
    .line 198
    iget-object v4, v13, La8/w0;->c:[Lh8/y0;

    .line 199
    .line 200
    aget-object v4, v4, v6

    .line 201
    .line 202
    iget-object v5, v0, La8/q0;->q:La8/l;

    .line 203
    .line 204
    iget-wide v7, v0, La8/q0;->X:J

    .line 205
    .line 206
    aget-boolean v9, v18, v6

    .line 207
    .line 208
    iget-object v12, v3, La8/p1;->e:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v12, La8/f;

    .line 211
    .line 212
    invoke-static {v12}, La8/p1;->h(La8/f;)Z

    .line 213
    .line 214
    .line 215
    move-result v15

    .line 216
    if-eqz v15, :cond_b

    .line 217
    .line 218
    iget-object v15, v12, La8/f;->l:Lh8/y0;

    .line 219
    .line 220
    if-eq v4, v15, :cond_a

    .line 221
    .line 222
    invoke-virtual {v3, v12, v5}, La8/p1;->a(La8/f;La8/l;)V

    .line 223
    .line 224
    .line 225
    goto :goto_7

    .line 226
    :cond_a
    if-eqz v9, :cond_b

    .line 227
    .line 228
    iput-boolean v11, v12, La8/f;->q:Z

    .line 229
    .line 230
    iput-wide v7, v12, La8/f;->o:J

    .line 231
    .line 232
    iput-wide v7, v12, La8/f;->p:J

    .line 233
    .line 234
    invoke-virtual {v12, v7, v8, v11}, La8/f;->r(JZ)V

    .line 235
    .line 236
    .line 237
    :cond_b
    :goto_7
    iget-object v12, v3, La8/p1;->f:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v12, La8/f;

    .line 240
    .line 241
    if-eqz v12, :cond_d

    .line 242
    .line 243
    invoke-static {v12}, La8/p1;->h(La8/f;)Z

    .line 244
    .line 245
    .line 246
    move-result v15

    .line 247
    if-eqz v15, :cond_d

    .line 248
    .line 249
    iget-object v15, v12, La8/f;->l:Lh8/y0;

    .line 250
    .line 251
    if-eq v4, v15, :cond_c

    .line 252
    .line 253
    invoke-virtual {v3, v12, v5}, La8/p1;->a(La8/f;La8/l;)V

    .line 254
    .line 255
    .line 256
    goto :goto_8

    .line 257
    :cond_c
    if-eqz v9, :cond_d

    .line 258
    .line 259
    iput-boolean v11, v12, La8/f;->q:Z

    .line 260
    .line 261
    iput-wide v7, v12, La8/f;->o:J

    .line 262
    .line 263
    iput-wide v7, v12, La8/f;->p:J

    .line 264
    .line 265
    invoke-virtual {v12, v7, v8, v11}, La8/f;->r(JZ)V

    .line 266
    .line 267
    .line 268
    :cond_d
    :goto_8
    iget-object v3, v0, La8/q0;->d:[La8/p1;

    .line 269
    .line 270
    aget-object v3, v3, v6

    .line 271
    .line 272
    invoke-virtual {v3}, La8/p1;->c()I

    .line 273
    .line 274
    .line 275
    move-result v3

    .line 276
    sub-int v3, v2, v3

    .line 277
    .line 278
    if-lez v3, :cond_e

    .line 279
    .line 280
    invoke-virtual {v0, v6, v11}, La8/q0;->G(IZ)V

    .line 281
    .line 282
    .line 283
    :cond_e
    iget v3, v0, La8/q0;->V:I

    .line 284
    .line 285
    iget-object v4, v0, La8/q0;->d:[La8/p1;

    .line 286
    .line 287
    aget-object v4, v4, v6

    .line 288
    .line 289
    invoke-virtual {v4}, La8/p1;->c()I

    .line 290
    .line 291
    .line 292
    move-result v4

    .line 293
    sub-int/2addr v2, v4

    .line 294
    sub-int/2addr v3, v2

    .line 295
    iput v3, v0, La8/q0;->V:I

    .line 296
    .line 297
    add-int/lit8 v6, v6, 0x1

    .line 298
    .line 299
    goto :goto_6

    .line 300
    :cond_f
    iget-wide v2, v0, La8/q0;->X:J

    .line 301
    .line 302
    invoke-virtual {v0, v1, v2, v3}, La8/q0;->l([ZJ)V

    .line 303
    .line 304
    .line 305
    iput-boolean v10, v13, La8/w0;->h:Z

    .line 306
    .line 307
    :cond_10
    move v5, v14

    .line 308
    goto :goto_9

    .line 309
    :cond_11
    move v14, v1

    .line 310
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 311
    .line 312
    invoke-virtual {v1, v11}, La8/z0;->n(La8/w0;)I

    .line 313
    .line 314
    .line 315
    iget-boolean v1, v11, La8/w0;->e:Z

    .line 316
    .line 317
    if-eqz v1, :cond_10

    .line 318
    .line 319
    iget-object v1, v11, La8/w0;->g:La8/x0;

    .line 320
    .line 321
    iget-wide v1, v1, La8/x0;->b:J

    .line 322
    .line 323
    iget-wide v3, v0, La8/q0;->X:J

    .line 324
    .line 325
    iget-wide v5, v11, La8/w0;->p:J

    .line 326
    .line 327
    sub-long/2addr v3, v5

    .line 328
    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->max(JJ)J

    .line 329
    .line 330
    .line 331
    move-result-wide v1

    .line 332
    iget-boolean v3, v0, La8/q0;->B:Z

    .line 333
    .line 334
    if-eqz v3, :cond_12

    .line 335
    .line 336
    invoke-virtual {v0}, La8/q0;->e()Z

    .line 337
    .line 338
    .line 339
    move-result v3

    .line 340
    if-eqz v3, :cond_12

    .line 341
    .line 342
    iget-object v3, v0, La8/q0;->u:La8/z0;

    .line 343
    .line 344
    iget-object v3, v3, La8/z0;->k:La8/w0;

    .line 345
    .line 346
    if-ne v3, v11, :cond_12

    .line 347
    .line 348
    invoke-virtual {v0}, La8/q0;->h()V

    .line 349
    .line 350
    .line 351
    :cond_12
    iget-object v3, v11, La8/w0;->j:[La8/f;

    .line 352
    .line 353
    array-length v3, v3

    .line 354
    new-array v3, v3, [Z

    .line 355
    .line 356
    const/4 v15, 0x0

    .line 357
    move-object/from16 v16, v3

    .line 358
    .line 359
    move v5, v14

    .line 360
    move-wide v13, v1

    .line 361
    invoke-virtual/range {v11 .. v16}, La8/w0;->a(Lj8/s;JZ[Z)J

    .line 362
    .line 363
    .line 364
    :goto_9
    invoke-virtual {v0, v10}, La8/q0;->u(Z)V

    .line 365
    .line 366
    .line 367
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 368
    .line 369
    iget v1, v1, La8/i1;->e:I

    .line 370
    .line 371
    if-eq v1, v5, :cond_13

    .line 372
    .line 373
    invoke-virtual {v0}, La8/q0;->C()V

    .line 374
    .line 375
    .line 376
    invoke-virtual {v0}, La8/q0;->z0()V

    .line 377
    .line 378
    .line 379
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 380
    .line 381
    const/4 v1, 0x2

    .line 382
    invoke-virtual {v0, v1}, Lw7/t;->e(I)Z

    .line 383
    .line 384
    .line 385
    :cond_13
    :goto_a
    return-void
.end method

.method public final O(ZZZZ)V
    .locals 35

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v2, "ExoPlayerImplInternal"

    .line 4
    .line 5
    iget-object v0, v1, La8/q0;->k:Lw7/t;

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    invoke-virtual {v0, v3}, Lw7/t;->d(I)V

    .line 9
    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    iput-boolean v3, v1, La8/q0;->G:Z

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    iput-object v4, v1, La8/q0;->H:La8/p0;

    .line 16
    .line 17
    iput-object v4, v1, La8/q0;->b0:La8/o;

    .line 18
    .line 19
    const/4 v5, 0x1

    .line 20
    invoke-virtual {v1, v3, v5}, La8/q0;->B0(ZZ)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v1, La8/q0;->q:La8/l;

    .line 24
    .line 25
    iput-boolean v3, v0, La8/l;->e:Z

    .line 26
    .line 27
    iget-object v0, v0, La8/l;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v0, La8/s1;

    .line 30
    .line 31
    iget-boolean v6, v0, La8/s1;->e:Z

    .line 32
    .line 33
    if-eqz v6, :cond_0

    .line 34
    .line 35
    invoke-virtual {v0}, La8/s1;->e()J

    .line 36
    .line 37
    .line 38
    move-result-wide v6

    .line 39
    invoke-virtual {v0, v6, v7}, La8/s1;->a(J)V

    .line 40
    .line 41
    .line 42
    iput-boolean v3, v0, La8/s1;->e:Z

    .line 43
    .line 44
    :cond_0
    const-wide v6, 0xe8d4a51000L

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    iput-wide v6, v1, La8/q0;->X:J

    .line 50
    .line 51
    move v0, v3

    .line 52
    :goto_0
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    :try_start_0
    iget-object v8, v1, La8/q0;->d:[La8/p1;

    .line 58
    .line 59
    array-length v8, v8

    .line 60
    if-ge v0, v8, :cond_1

    .line 61
    .line 62
    invoke-virtual {v1, v0}, La8/q0;->i(I)V

    .line 63
    .line 64
    .line 65
    add-int/lit8 v0, v0, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :catch_0
    move-exception v0

    .line 69
    goto :goto_1

    .line 70
    :cond_1
    iput-wide v6, v1, La8/q0;->e0:J
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catch La8/o; {:try_start_0 .. :try_end_0} :catch_0

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :goto_1
    const-string v8, "Disable failed."

    .line 74
    .line 75
    invoke-static {v2, v8, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 76
    .line 77
    .line 78
    :goto_2
    if-eqz p1, :cond_2

    .line 79
    .line 80
    iget-object v8, v1, La8/q0;->d:[La8/p1;

    .line 81
    .line 82
    array-length v9, v8

    .line 83
    move v10, v3

    .line 84
    :goto_3
    if-ge v10, v9, :cond_2

    .line 85
    .line 86
    aget-object v0, v8, v10

    .line 87
    .line 88
    :try_start_1
    invoke-virtual {v0}, La8/p1;->k()V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    .line 89
    .line 90
    .line 91
    goto :goto_4

    .line 92
    :catch_1
    move-exception v0

    .line 93
    const-string v11, "Reset failed."

    .line 94
    .line 95
    invoke-static {v2, v11, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 96
    .line 97
    .line 98
    :goto_4
    add-int/lit8 v10, v10, 0x1

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_2
    iput v3, v1, La8/q0;->V:I

    .line 102
    .line 103
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 104
    .line 105
    iget-object v2, v0, La8/i1;->b:Lh8/b0;

    .line 106
    .line 107
    iget-wide v8, v0, La8/i1;->s:J

    .line 108
    .line 109
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 110
    .line 111
    iget-object v0, v0, La8/i1;->b:Lh8/b0;

    .line 112
    .line 113
    invoke-virtual {v0}, Lh8/b0;->b()Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-nez v0, :cond_4

    .line 118
    .line 119
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 120
    .line 121
    iget-object v10, v1, La8/q0;->o:Lt7/n0;

    .line 122
    .line 123
    iget-object v11, v0, La8/i1;->b:Lh8/b0;

    .line 124
    .line 125
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 126
    .line 127
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 128
    .line 129
    .line 130
    move-result v12

    .line 131
    if-nez v12, :cond_4

    .line 132
    .line 133
    iget-object v11, v11, Lh8/b0;->a:Ljava/lang/Object;

    .line 134
    .line 135
    invoke-virtual {v0, v11, v10}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    iget-boolean v0, v0, Lt7/n0;->f:Z

    .line 140
    .line 141
    if-eqz v0, :cond_3

    .line 142
    .line 143
    goto :goto_5

    .line 144
    :cond_3
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 145
    .line 146
    iget-wide v10, v0, La8/i1;->s:J

    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_4
    :goto_5
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 150
    .line 151
    iget-wide v10, v0, La8/i1;->c:J

    .line 152
    .line 153
    :goto_6
    if-eqz p2, :cond_6

    .line 154
    .line 155
    iput-object v4, v1, La8/q0;->W:La8/p0;

    .line 156
    .line 157
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 158
    .line 159
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 160
    .line 161
    invoke-virtual {v1, v0}, La8/q0;->o(Lt7/p0;)Landroid/util/Pair;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    iget-object v2, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast v2, Lh8/b0;

    .line 168
    .line 169
    iget-object v0, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v0, Ljava/lang/Long;

    .line 172
    .line 173
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 174
    .line 175
    .line 176
    move-result-wide v8

    .line 177
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 178
    .line 179
    iget-object v0, v0, La8/i1;->b:Lh8/b0;

    .line 180
    .line 181
    invoke-virtual {v2, v0}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    if-nez v0, :cond_5

    .line 186
    .line 187
    :goto_7
    move-wide v11, v8

    .line 188
    move-wide v9, v6

    .line 189
    goto :goto_8

    .line 190
    :cond_5
    move v5, v3

    .line 191
    goto :goto_7

    .line 192
    :cond_6
    move-wide/from16 v33, v10

    .line 193
    .line 194
    move-wide v11, v8

    .line 195
    move-wide/from16 v9, v33

    .line 196
    .line 197
    move v5, v3

    .line 198
    :goto_8
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 199
    .line 200
    invoke-virtual {v0}, La8/z0;->b()V

    .line 201
    .line 202
    .line 203
    iput-boolean v3, v1, La8/q0;->P:Z

    .line 204
    .line 205
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 206
    .line 207
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 208
    .line 209
    if-eqz p3, :cond_9

    .line 210
    .line 211
    instance-of v6, v0, La8/n1;

    .line 212
    .line 213
    if-eqz v6, :cond_9

    .line 214
    .line 215
    check-cast v0, La8/n1;

    .line 216
    .line 217
    iget-object v6, v1, La8/q0;->v:Lac/i;

    .line 218
    .line 219
    iget-object v6, v6, Lac/i;->k:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v6, Lh8/a1;

    .line 222
    .line 223
    iget-object v7, v0, La8/n1;->h:[Lt7/p0;

    .line 224
    .line 225
    array-length v8, v7

    .line 226
    new-array v8, v8, [Lt7/p0;

    .line 227
    .line 228
    move v13, v3

    .line 229
    :goto_9
    array-length v14, v7

    .line 230
    if-ge v13, v14, :cond_7

    .line 231
    .line 232
    new-instance v14, La8/m1;

    .line 233
    .line 234
    aget-object v15, v7, v13

    .line 235
    .line 236
    invoke-direct {v14, v15}, La8/m1;-><init>(Lt7/p0;)V

    .line 237
    .line 238
    .line 239
    aput-object v14, v8, v13

    .line 240
    .line 241
    add-int/lit8 v13, v13, 0x1

    .line 242
    .line 243
    goto :goto_9

    .line 244
    :cond_7
    new-instance v7, La8/n1;

    .line 245
    .line 246
    iget-object v0, v0, La8/n1;->i:[Ljava/lang/Object;

    .line 247
    .line 248
    invoke-direct {v7, v8, v0, v6}, La8/n1;-><init>([Lt7/p0;[Ljava/lang/Object;Lh8/a1;)V

    .line 249
    .line 250
    .line 251
    iget v0, v2, Lh8/b0;->b:I

    .line 252
    .line 253
    const/4 v6, -0x1

    .line 254
    if-eq v0, v6, :cond_8

    .line 255
    .line 256
    iget-object v0, v2, Lh8/b0;->a:Ljava/lang/Object;

    .line 257
    .line 258
    iget-object v6, v1, La8/q0;->o:Lt7/n0;

    .line 259
    .line 260
    invoke-virtual {v7, v0, v6}, La8/n1;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 261
    .line 262
    .line 263
    iget-object v0, v1, La8/q0;->o:Lt7/n0;

    .line 264
    .line 265
    iget v0, v0, Lt7/n0;->c:I

    .line 266
    .line 267
    iget-object v6, v1, La8/q0;->n:Lt7/o0;

    .line 268
    .line 269
    const-wide/16 v13, 0x0

    .line 270
    .line 271
    invoke-virtual {v7, v0, v6, v13, v14}, La8/n1;->m(ILt7/o0;J)Lt7/o0;

    .line 272
    .line 273
    .line 274
    invoke-virtual {v6}, Lt7/o0;->a()Z

    .line 275
    .line 276
    .line 277
    move-result v0

    .line 278
    if-eqz v0, :cond_8

    .line 279
    .line 280
    new-instance v0, Lh8/b0;

    .line 281
    .line 282
    iget-object v6, v2, Lh8/b0;->a:Ljava/lang/Object;

    .line 283
    .line 284
    iget-wide v13, v2, Lh8/b0;->d:J

    .line 285
    .line 286
    invoke-direct {v0, v13, v14, v6}, Lh8/b0;-><init>(JLjava/lang/Object;)V

    .line 287
    .line 288
    .line 289
    move-object v8, v0

    .line 290
    goto :goto_b

    .line 291
    :cond_8
    :goto_a
    move-object v8, v2

    .line 292
    goto :goto_b

    .line 293
    :cond_9
    move-object v7, v0

    .line 294
    goto :goto_a

    .line 295
    :goto_b
    new-instance v6, La8/i1;

    .line 296
    .line 297
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 298
    .line 299
    iget v13, v0, La8/i1;->e:I

    .line 300
    .line 301
    if-eqz p4, :cond_a

    .line 302
    .line 303
    move-object v14, v4

    .line 304
    goto :goto_c

    .line 305
    :cond_a
    iget-object v2, v0, La8/i1;->f:La8/o;

    .line 306
    .line 307
    move-object v14, v2

    .line 308
    :goto_c
    if-eqz v5, :cond_b

    .line 309
    .line 310
    sget-object v2, Lh8/e1;->d:Lh8/e1;

    .line 311
    .line 312
    :goto_d
    move-object/from16 v16, v2

    .line 313
    .line 314
    goto :goto_e

    .line 315
    :cond_b
    iget-object v2, v0, La8/i1;->h:Lh8/e1;

    .line 316
    .line 317
    goto :goto_d

    .line 318
    :goto_e
    if-eqz v5, :cond_c

    .line 319
    .line 320
    iget-object v2, v1, La8/q0;->h:Lj8/s;

    .line 321
    .line 322
    :goto_f
    move-object/from16 v17, v2

    .line 323
    .line 324
    goto :goto_10

    .line 325
    :cond_c
    iget-object v2, v0, La8/i1;->i:Lj8/s;

    .line 326
    .line 327
    goto :goto_f

    .line 328
    :goto_10
    if-eqz v5, :cond_d

    .line 329
    .line 330
    sget-object v2, Lhr/h0;->e:Lhr/f0;

    .line 331
    .line 332
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 333
    .line 334
    :goto_11
    move-object/from16 v18, v2

    .line 335
    .line 336
    goto :goto_12

    .line 337
    :cond_d
    iget-object v2, v0, La8/i1;->j:Ljava/util/List;

    .line 338
    .line 339
    goto :goto_11

    .line 340
    :goto_12
    iget-boolean v2, v0, La8/i1;->l:Z

    .line 341
    .line 342
    iget v5, v0, La8/i1;->m:I

    .line 343
    .line 344
    iget v15, v0, La8/i1;->n:I

    .line 345
    .line 346
    iget-object v0, v0, La8/i1;->o:Lt7/g0;

    .line 347
    .line 348
    const-wide/16 v30, 0x0

    .line 349
    .line 350
    const/16 v32, 0x0

    .line 351
    .line 352
    move/from16 v22, v15

    .line 353
    .line 354
    const/4 v15, 0x0

    .line 355
    const-wide/16 v26, 0x0

    .line 356
    .line 357
    move-object/from16 v19, v8

    .line 358
    .line 359
    move-wide/from16 v24, v11

    .line 360
    .line 361
    move-wide/from16 v28, v11

    .line 362
    .line 363
    move-object/from16 v23, v0

    .line 364
    .line 365
    move/from16 v20, v2

    .line 366
    .line 367
    move/from16 v21, v5

    .line 368
    .line 369
    invoke-direct/range {v6 .. v32}, La8/i1;-><init>(Lt7/p0;Lh8/b0;JJILa8/o;ZLh8/e1;Lj8/s;Ljava/util/List;Lh8/b0;ZIILt7/g0;JJJJZ)V

    .line 370
    .line 371
    .line 372
    iput-object v6, v1, La8/q0;->I:La8/i1;

    .line 373
    .line 374
    if-eqz p3, :cond_11

    .line 375
    .line 376
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 377
    .line 378
    iget-object v2, v0, La8/z0;->q:Ljava/util/ArrayList;

    .line 379
    .line 380
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 381
    .line 382
    .line 383
    move-result v2

    .line 384
    if-nez v2, :cond_f

    .line 385
    .line 386
    new-instance v2, Ljava/util/ArrayList;

    .line 387
    .line 388
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 389
    .line 390
    .line 391
    move v5, v3

    .line 392
    :goto_13
    iget-object v6, v0, La8/z0;->q:Ljava/util/ArrayList;

    .line 393
    .line 394
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 395
    .line 396
    .line 397
    move-result v6

    .line 398
    if-ge v5, v6, :cond_e

    .line 399
    .line 400
    iget-object v6, v0, La8/z0;->q:Ljava/util/ArrayList;

    .line 401
    .line 402
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    move-result-object v6

    .line 406
    check-cast v6, La8/w0;

    .line 407
    .line 408
    invoke-virtual {v6}, La8/w0;->i()V

    .line 409
    .line 410
    .line 411
    add-int/lit8 v5, v5, 0x1

    .line 412
    .line 413
    goto :goto_13

    .line 414
    :cond_e
    iput-object v2, v0, La8/z0;->q:Ljava/util/ArrayList;

    .line 415
    .line 416
    iput-object v4, v0, La8/z0;->m:La8/w0;

    .line 417
    .line 418
    invoke-virtual {v0}, La8/z0;->k()V

    .line 419
    .line 420
    .line 421
    :cond_f
    iget-object v1, v1, La8/q0;->v:Lac/i;

    .line 422
    .line 423
    iget-object v0, v1, Lac/i;->g:Ljava/lang/Object;

    .line 424
    .line 425
    move-object v2, v0

    .line 426
    check-cast v2, Ljava/util/HashMap;

    .line 427
    .line 428
    invoke-virtual {v2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 429
    .line 430
    .line 431
    move-result-object v0

    .line 432
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 433
    .line 434
    .line 435
    move-result-object v4

    .line 436
    :goto_14
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 437
    .line 438
    .line 439
    move-result v0

    .line 440
    if-eqz v0, :cond_10

    .line 441
    .line 442
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 443
    .line 444
    .line 445
    move-result-object v0

    .line 446
    move-object v5, v0

    .line 447
    check-cast v5, La8/g1;

    .line 448
    .line 449
    :try_start_2
    iget-object v0, v5, La8/g1;->a:Lh8/a;

    .line 450
    .line 451
    iget-object v6, v5, La8/g1;->b:La8/b1;

    .line 452
    .line 453
    invoke-virtual {v0, v6}, Lh8/a;->n(Lh8/c0;)V
    :try_end_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_2

    .line 454
    .line 455
    .line 456
    goto :goto_15

    .line 457
    :catch_2
    move-exception v0

    .line 458
    const-string v6, "MediaSourceList"

    .line 459
    .line 460
    const-string v7, "Failed to release child source."

    .line 461
    .line 462
    invoke-static {v6, v7, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 463
    .line 464
    .line 465
    :goto_15
    iget-object v0, v5, La8/g1;->a:Lh8/a;

    .line 466
    .line 467
    iget-object v6, v5, La8/g1;->c:La8/f1;

    .line 468
    .line 469
    invoke-virtual {v0, v6}, Lh8/a;->q(Lh8/h0;)V

    .line 470
    .line 471
    .line 472
    iget-object v0, v5, La8/g1;->a:Lh8/a;

    .line 473
    .line 474
    invoke-virtual {v0, v6}, Lh8/a;->p(Ld8/g;)V

    .line 475
    .line 476
    .line 477
    goto :goto_14

    .line 478
    :cond_10
    invoke-virtual {v2}, Ljava/util/HashMap;->clear()V

    .line 479
    .line 480
    .line 481
    iget-object v0, v1, Lac/i;->h:Ljava/lang/Object;

    .line 482
    .line 483
    check-cast v0, Ljava/util/HashSet;

    .line 484
    .line 485
    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    .line 486
    .line 487
    .line 488
    iput-boolean v3, v1, Lac/i;->a:Z

    .line 489
    .line 490
    :cond_11
    return-void
.end method

.method public final P()V
    .locals 1

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->i:La8/w0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, v0, La8/w0;->g:La8/x0;

    .line 8
    .line 9
    iget-boolean v0, v0, La8/x0;->i:Z

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-boolean v0, p0, La8/q0;->L:Z

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v0, 0x0

    .line 20
    :goto_0
    iput-boolean v0, p0, La8/q0;->M:Z

    .line 21
    .line 22
    return-void
.end method

.method public final Q(J)V
    .locals 7

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v1, v0, La8/z0;->i:La8/w0;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    const-wide v2, 0xe8d4a51000L

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    :goto_0
    add-long/2addr p1, v2

    .line 13
    goto :goto_1

    .line 14
    :cond_0
    iget-wide v2, v1, La8/w0;->p:J

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :goto_1
    iput-wide p1, p0, La8/q0;->X:J

    .line 18
    .line 19
    iget-object v2, p0, La8/q0;->q:La8/l;

    .line 20
    .line 21
    iget-object v2, v2, La8/l;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, La8/s1;

    .line 24
    .line 25
    invoke-virtual {v2, p1, p2}, La8/s1;->a(J)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, La8/q0;->d:[La8/p1;

    .line 29
    .line 30
    array-length p2, p1

    .line 31
    const/4 v2, 0x0

    .line 32
    move v3, v2

    .line 33
    :goto_2
    if-ge v3, p2, :cond_2

    .line 34
    .line 35
    aget-object v4, p1, v3

    .line 36
    .line 37
    iget-wide v5, p0, La8/q0;->X:J

    .line 38
    .line 39
    invoke-virtual {v4, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    if-eqz v4, :cond_1

    .line 44
    .line 45
    iput-boolean v2, v4, La8/f;->q:Z

    .line 46
    .line 47
    iput-wide v5, v4, La8/f;->o:J

    .line 48
    .line 49
    iput-wide v5, v4, La8/f;->p:J

    .line 50
    .line 51
    invoke-virtual {v4, v5, v6, v2}, La8/f;->r(JZ)V

    .line 52
    .line 53
    .line 54
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    iget-object p0, v0, La8/z0;->i:La8/w0;

    .line 58
    .line 59
    :goto_3
    if-eqz p0, :cond_5

    .line 60
    .line 61
    iget-object p1, p0, La8/w0;->o:Lj8/s;

    .line 62
    .line 63
    iget-object p1, p1, Lj8/s;->c:[Lj8/q;

    .line 64
    .line 65
    array-length p2, p1

    .line 66
    move v0, v2

    .line 67
    :goto_4
    if-ge v0, p2, :cond_4

    .line 68
    .line 69
    aget-object v1, p1, v0

    .line 70
    .line 71
    if-eqz v1, :cond_3

    .line 72
    .line 73
    invoke-interface {v1}, Lj8/q;->e()V

    .line 74
    .line 75
    .line 76
    :cond_3
    add-int/lit8 v0, v0, 0x1

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    iget-object p0, p0, La8/w0;->m:La8/w0;

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_5
    return-void
.end method

.method public final R(Lt7/p0;Lt7/p0;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Lt7/p0;->p()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p2}, Lt7/p0;->p()Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object p0, p0, La8/q0;->r:Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    add-int/lit8 p1, p1, -0x1

    .line 21
    .line 22
    if-gez p1, :cond_1

    .line 23
    .line 24
    invoke-static {p0}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_1
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-static {p0}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    const/4 p0, 0x0

    .line 36
    throw p0
.end method

.method public final U(J)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, La8/q0;->F:Z

    .line 4
    .line 5
    const-wide/16 v2, 0x3e8

    .line 6
    .line 7
    const/4 v4, 0x3

    .line 8
    sget-wide v5, La8/q0;->q1:J

    .line 9
    .line 10
    if-eqz v1, :cond_5

    .line 11
    .line 12
    iget-object v1, v0, La8/q0;->E:La8/q1;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 18
    .line 19
    iget v1, v1, La8/i1;->e:I

    .line 20
    .line 21
    if-ne v1, v4, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move-wide v2, v5

    .line 25
    :goto_0
    iget-object v1, v0, La8/q0;->d:[La8/p1;

    .line 26
    .line 27
    array-length v4, v1

    .line 28
    const/4 v7, 0x0

    .line 29
    :goto_1
    if-ge v7, v4, :cond_3

    .line 30
    .line 31
    aget-object v8, v1, v7

    .line 32
    .line 33
    iget-wide v9, v0, La8/q0;->X:J

    .line 34
    .line 35
    iget-wide v11, v0, La8/q0;->Y:J

    .line 36
    .line 37
    iget-object v13, v8, La8/p1;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v13, La8/f;

    .line 40
    .line 41
    iget-object v8, v8, La8/p1;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v8, La8/f;

    .line 44
    .line 45
    invoke-static {v8}, La8/p1;->h(La8/f;)Z

    .line 46
    .line 47
    .line 48
    move-result v14

    .line 49
    if-eqz v14, :cond_1

    .line 50
    .line 51
    invoke-virtual {v8, v9, v10, v11, v12}, La8/f;->i(JJ)J

    .line 52
    .line 53
    .line 54
    move-result-wide v14

    .line 55
    goto :goto_2

    .line 56
    :cond_1
    const-wide v14, 0x7fffffffffffffffL

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    :goto_2
    if-eqz v13, :cond_2

    .line 62
    .line 63
    iget v8, v13, La8/f;->k:I

    .line 64
    .line 65
    if-eqz v8, :cond_2

    .line 66
    .line 67
    invoke-virtual {v13, v9, v10, v11, v12}, La8/f;->i(JJ)J

    .line 68
    .line 69
    .line 70
    move-result-wide v8

    .line 71
    invoke-static {v14, v15, v8, v9}, Ljava/lang/Math;->min(JJ)J

    .line 72
    .line 73
    .line 74
    move-result-wide v14

    .line 75
    :cond_2
    invoke-static {v14, v15}, Lw7/w;->N(J)J

    .line 76
    .line 77
    .line 78
    move-result-wide v8

    .line 79
    invoke-static {v2, v3, v8, v9}, Ljava/lang/Math;->min(JJ)J

    .line 80
    .line 81
    .line 82
    move-result-wide v2

    .line 83
    add-int/lit8 v7, v7, 0x1

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_3
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 87
    .line 88
    invoke-virtual {v1}, La8/i1;->m()Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-eqz v1, :cond_7

    .line 93
    .line 94
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 95
    .line 96
    iget-object v1, v1, La8/z0;->i:La8/w0;

    .line 97
    .line 98
    if-eqz v1, :cond_4

    .line 99
    .line 100
    iget-object v1, v1, La8/w0;->m:La8/w0;

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_4
    const/4 v1, 0x0

    .line 104
    :goto_3
    if-eqz v1, :cond_7

    .line 105
    .line 106
    iget-wide v7, v0, La8/q0;->X:J

    .line 107
    .line 108
    long-to-float v4, v7

    .line 109
    invoke-static {v2, v3}, Lw7/w;->D(J)J

    .line 110
    .line 111
    .line 112
    move-result-wide v7

    .line 113
    long-to-float v7, v7

    .line 114
    iget-object v8, v0, La8/q0;->I:La8/i1;

    .line 115
    .line 116
    iget-object v8, v8, La8/i1;->o:Lt7/g0;

    .line 117
    .line 118
    iget v8, v8, Lt7/g0;->a:F

    .line 119
    .line 120
    mul-float/2addr v7, v8

    .line 121
    add-float/2addr v7, v4

    .line 122
    invoke-virtual {v1}, La8/w0;->e()J

    .line 123
    .line 124
    .line 125
    move-result-wide v8

    .line 126
    long-to-float v1, v8

    .line 127
    cmpl-float v1, v7, v1

    .line 128
    .line 129
    if-ltz v1, :cond_7

    .line 130
    .line 131
    invoke-static {v2, v3, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 132
    .line 133
    .line 134
    move-result-wide v2

    .line 135
    goto :goto_4

    .line 136
    :cond_5
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 137
    .line 138
    iget v1, v1, La8/i1;->e:I

    .line 139
    .line 140
    if-ne v1, v4, :cond_6

    .line 141
    .line 142
    invoke-virtual {v0}, La8/q0;->q0()Z

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    if-nez v1, :cond_6

    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_6
    move-wide v2, v5

    .line 150
    :cond_7
    :goto_4
    add-long v1, p1, v2

    .line 151
    .line 152
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 153
    .line 154
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 155
    .line 156
    const/4 v3, 0x2

    .line 157
    invoke-virtual {v0, v3, v1, v2}, Landroid/os/Handler;->sendEmptyMessageAtTime(IJ)Z

    .line 158
    .line 159
    .line 160
    return-void
.end method

.method public final V(Z)V
    .locals 11

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->i:La8/w0;

    .line 4
    .line 5
    iget-object v0, v0, La8/w0;->g:La8/x0;

    .line 6
    .line 7
    iget-object v2, v0, La8/x0;->a:Lh8/b0;

    .line 8
    .line 9
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 10
    .line 11
    iget-wide v3, v0, La8/i1;->s:J

    .line 12
    .line 13
    const/4 v5, 0x1

    .line 14
    const/4 v6, 0x0

    .line 15
    move-object v1, p0

    .line 16
    invoke-virtual/range {v1 .. v6}, La8/q0;->X(Lh8/b0;JZZ)J

    .line 17
    .line 18
    .line 19
    move-result-wide v3

    .line 20
    iget-object p0, v1, La8/q0;->I:La8/i1;

    .line 21
    .line 22
    iget-wide v5, p0, La8/i1;->s:J

    .line 23
    .line 24
    cmp-long p0, v3, v5

    .line 25
    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    iget-object p0, v1, La8/q0;->I:La8/i1;

    .line 29
    .line 30
    iget-wide v5, p0, La8/i1;->c:J

    .line 31
    .line 32
    iget-wide v7, p0, La8/i1;->d:J

    .line 33
    .line 34
    const/4 v10, 0x5

    .line 35
    move v9, p1

    .line 36
    invoke-virtual/range {v1 .. v10}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    iput-object p0, v1, La8/q0;->I:La8/i1;

    .line 41
    .line 42
    :cond_0
    return-void
.end method

.method public final W(La8/p0;Z)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    iget-object v0, v1, La8/q0;->J:La8/n0;

    .line 6
    .line 7
    move/from16 v2, p2

    .line 8
    .line 9
    invoke-virtual {v0, v2}, La8/n0;->f(I)V

    .line 10
    .line 11
    .line 12
    iget-boolean v0, v1, La8/q0;->G:Z

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iput-object v3, v1, La8/q0;->H:La8/p0;

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 20
    .line 21
    iget-object v2, v0, La8/i1;->a:Lt7/p0;

    .line 22
    .line 23
    iget v5, v1, La8/q0;->Q:I

    .line 24
    .line 25
    iget-boolean v6, v1, La8/q0;->R:Z

    .line 26
    .line 27
    iget-object v7, v1, La8/q0;->n:Lt7/o0;

    .line 28
    .line 29
    iget-object v8, v1, La8/q0;->o:Lt7/n0;

    .line 30
    .line 31
    const/4 v4, 0x1

    .line 32
    invoke-static/range {v2 .. v8}, La8/q0;->S(Lt7/p0;La8/p0;ZIZLt7/o0;Lt7/n0;)Landroid/util/Pair;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const/4 v7, 0x0

    .line 37
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    const/4 v10, 0x1

    .line 43
    if-nez v0, :cond_1

    .line 44
    .line 45
    iget-object v2, v1, La8/q0;->I:La8/i1;

    .line 46
    .line 47
    iget-object v2, v2, La8/i1;->a:Lt7/p0;

    .line 48
    .line 49
    invoke-virtual {v1, v2}, La8/q0;->o(Lt7/p0;)Landroid/util/Pair;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    iget-object v6, v2, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v6, Lh8/b0;

    .line 56
    .line 57
    iget-object v2, v2, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v2, Ljava/lang/Long;

    .line 60
    .line 61
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 62
    .line 63
    .line 64
    move-result-wide v11

    .line 65
    iget-object v2, v1, La8/q0;->I:La8/i1;

    .line 66
    .line 67
    iget-object v2, v2, La8/i1;->a:Lt7/p0;

    .line 68
    .line 69
    invoke-virtual {v2}, Lt7/p0;->p()Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    xor-int/2addr v2, v10

    .line 74
    move-wide v13, v8

    .line 75
    :goto_0
    const-wide/16 v15, 0x0

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_1
    iget-object v2, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 79
    .line 80
    iget-object v6, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v6, Ljava/lang/Long;

    .line 83
    .line 84
    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    .line 85
    .line 86
    .line 87
    move-result-wide v11

    .line 88
    iget-wide v13, v3, La8/p0;->c:J

    .line 89
    .line 90
    cmp-long v6, v13, v8

    .line 91
    .line 92
    if-nez v6, :cond_2

    .line 93
    .line 94
    move-wide v13, v8

    .line 95
    goto :goto_1

    .line 96
    :cond_2
    move-wide v13, v11

    .line 97
    :goto_1
    iget-object v6, v1, La8/q0;->u:La8/z0;

    .line 98
    .line 99
    iget-object v15, v1, La8/q0;->I:La8/i1;

    .line 100
    .line 101
    iget-object v15, v15, La8/i1;->a:Lt7/p0;

    .line 102
    .line 103
    invoke-virtual {v6, v15, v2, v11, v12}, La8/z0;->p(Lt7/p0;Ljava/lang/Object;J)Lh8/b0;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    invoke-virtual {v6}, Lh8/b0;->b()Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-eqz v2, :cond_4

    .line 112
    .line 113
    iget-object v2, v1, La8/q0;->I:La8/i1;

    .line 114
    .line 115
    iget-object v2, v2, La8/i1;->a:Lt7/p0;

    .line 116
    .line 117
    iget-object v11, v6, Lh8/b0;->a:Ljava/lang/Object;

    .line 118
    .line 119
    iget-object v12, v1, La8/q0;->o:Lt7/n0;

    .line 120
    .line 121
    invoke-virtual {v2, v11, v12}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 122
    .line 123
    .line 124
    iget-object v2, v1, La8/q0;->o:Lt7/n0;

    .line 125
    .line 126
    iget v11, v6, Lh8/b0;->b:I

    .line 127
    .line 128
    invoke-virtual {v2, v11}, Lt7/n0;->e(I)I

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    iget v11, v6, Lh8/b0;->c:I

    .line 133
    .line 134
    if-ne v2, v11, :cond_3

    .line 135
    .line 136
    iget-object v2, v1, La8/q0;->o:Lt7/n0;

    .line 137
    .line 138
    iget-object v2, v2, Lt7/n0;->g:Lt7/b;

    .line 139
    .line 140
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    :cond_3
    move v2, v10

    .line 144
    const-wide/16 v11, 0x0

    .line 145
    .line 146
    goto :goto_0

    .line 147
    :cond_4
    const-wide/16 v15, 0x0

    .line 148
    .line 149
    iget-wide v4, v3, La8/p0;->c:J

    .line 150
    .line 151
    cmp-long v2, v4, v8

    .line 152
    .line 153
    if-nez v2, :cond_5

    .line 154
    .line 155
    move v2, v10

    .line 156
    goto :goto_2

    .line 157
    :cond_5
    move v2, v7

    .line 158
    :goto_2
    :try_start_0
    iget-object v4, v1, La8/q0;->I:La8/i1;

    .line 159
    .line 160
    iget-object v4, v4, La8/i1;->a:Lt7/p0;

    .line 161
    .line 162
    invoke-virtual {v4}, Lt7/p0;->p()Z

    .line 163
    .line 164
    .line 165
    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_6

    .line 166
    if-eqz v4, :cond_6

    .line 167
    .line 168
    :try_start_1
    iput-object v3, v1, La8/q0;->W:La8/p0;

    .line 169
    .line 170
    goto :goto_3

    .line 171
    :catchall_0
    move-exception v0

    .line 172
    move v9, v2

    .line 173
    move-object v2, v6

    .line 174
    move-wide v3, v11

    .line 175
    move-wide v5, v13

    .line 176
    goto/16 :goto_10

    .line 177
    .line 178
    :cond_6
    const/4 v3, 0x4

    .line 179
    if-nez v0, :cond_8

    .line 180
    .line 181
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 182
    .line 183
    iget v0, v0, La8/i1;->e:I

    .line 184
    .line 185
    if-eq v0, v10, :cond_7

    .line 186
    .line 187
    invoke-virtual {v1, v3}, La8/q0;->m0(I)V

    .line 188
    .line 189
    .line 190
    :cond_7
    invoke-virtual {v1, v7, v10, v7, v10}, La8/q0;->O(ZZZZ)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 191
    .line 192
    .line 193
    :goto_3
    move v9, v2

    .line 194
    move-object v2, v6

    .line 195
    move-wide v3, v11

    .line 196
    move-wide v5, v13

    .line 197
    goto/16 :goto_b

    .line 198
    .line 199
    :cond_8
    :try_start_2
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 200
    .line 201
    iget-object v0, v0, La8/i1;->b:Lh8/b0;

    .line 202
    .line 203
    invoke-virtual {v6, v0}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_6

    .line 207
    if-eqz v0, :cond_d

    .line 208
    .line 209
    :try_start_3
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 210
    .line 211
    iget-object v0, v0, La8/z0;->i:La8/w0;

    .line 212
    .line 213
    if-eqz v0, :cond_a

    .line 214
    .line 215
    iget-boolean v4, v0, La8/w0;->e:Z

    .line 216
    .line 217
    if-eqz v4, :cond_a

    .line 218
    .line 219
    cmp-long v4, v11, v15

    .line 220
    .line 221
    if-eqz v4, :cond_a

    .line 222
    .line 223
    iget-object v0, v0, La8/w0;->a:Ljava/lang/Object;

    .line 224
    .line 225
    iget-object v4, v1, La8/q0;->n:Lt7/o0;

    .line 226
    .line 227
    iget-wide v4, v4, Lt7/o0;->l:J

    .line 228
    .line 229
    iget-boolean v15, v1, La8/q0;->F:Z

    .line 230
    .line 231
    if-eqz v15, :cond_9

    .line 232
    .line 233
    cmp-long v4, v4, v8

    .line 234
    .line 235
    if-eqz v4, :cond_9

    .line 236
    .line 237
    iget-object v4, v1, La8/q0;->E:La8/q1;

    .line 238
    .line 239
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 240
    .line 241
    .line 242
    :cond_9
    iget-object v4, v1, La8/q0;->D:La8/r1;

    .line 243
    .line 244
    invoke-interface {v0, v11, v12, v4}, Lh8/z;->b(JLa8/r1;)J

    .line 245
    .line 246
    .line 247
    move-result-wide v4

    .line 248
    goto :goto_4

    .line 249
    :cond_a
    move-wide v4, v11

    .line 250
    :goto_4
    invoke-static {v4, v5}, Lw7/w;->N(J)J

    .line 251
    .line 252
    .line 253
    move-result-wide v8

    .line 254
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 255
    .line 256
    move-wide v15, v8

    .line 257
    iget-wide v7, v0, La8/i1;->s:J

    .line 258
    .line 259
    invoke-static {v7, v8}, Lw7/w;->N(J)J

    .line 260
    .line 261
    .line 262
    move-result-wide v7

    .line 263
    cmp-long v0, v15, v7

    .line 264
    .line 265
    if-nez v0, :cond_b

    .line 266
    .line 267
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 268
    .line 269
    iget v7, v0, La8/i1;->e:I

    .line 270
    .line 271
    const/4 v8, 0x2

    .line 272
    if-eq v7, v8, :cond_c

    .line 273
    .line 274
    const/4 v8, 0x3

    .line 275
    if-ne v7, v8, :cond_b

    .line 276
    .line 277
    goto :goto_5

    .line 278
    :cond_b
    move v9, v2

    .line 279
    move-object v2, v6

    .line 280
    goto :goto_7

    .line 281
    :cond_c
    :goto_5
    iget-wide v3, v0, La8/i1;->s:J
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 282
    .line 283
    const/4 v10, 0x2

    .line 284
    move-wide v7, v3

    .line 285
    move v9, v2

    .line 286
    move-object v2, v6

    .line 287
    move-wide v5, v13

    .line 288
    :goto_6
    invoke-virtual/range {v1 .. v10}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    iput-object v0, v1, La8/q0;->I:La8/i1;

    .line 293
    .line 294
    return-void

    .line 295
    :cond_d
    move v9, v2

    .line 296
    move-object v2, v6

    .line 297
    move-wide v4, v11

    .line 298
    :goto_7
    :try_start_4
    iget-boolean v0, v1, La8/q0;->F:Z

    .line 299
    .line 300
    iput-boolean v0, v1, La8/q0;->G:Z

    .line 301
    .line 302
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 303
    .line 304
    iget v0, v0, La8/i1;->e:I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_5

    .line 305
    .line 306
    if-ne v0, v3, :cond_e

    .line 307
    .line 308
    move v6, v10

    .line 309
    goto :goto_8

    .line 310
    :cond_e
    const/4 v6, 0x0

    .line 311
    :goto_8
    :try_start_5
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 312
    .line 313
    iget-object v3, v0, La8/z0;->i:La8/w0;

    .line 314
    .line 315
    iget-object v0, v0, La8/z0;->j:La8/w0;

    .line 316
    .line 317
    if-eq v3, v0, :cond_f

    .line 318
    .line 319
    move-wide v3, v4

    .line 320
    move v5, v10

    .line 321
    goto :goto_9

    .line 322
    :cond_f
    move-wide v3, v4

    .line 323
    const/4 v5, 0x0

    .line 324
    :goto_9
    invoke-virtual/range {v1 .. v6}, La8/q0;->X(Lh8/b0;JZZ)J

    .line 325
    .line 326
    .line 327
    move-result-wide v15
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 328
    cmp-long v0, v11, v15

    .line 329
    .line 330
    if-eqz v0, :cond_10

    .line 331
    .line 332
    move v7, v10

    .line 333
    goto :goto_a

    .line 334
    :cond_10
    const/4 v7, 0x0

    .line 335
    :goto_a
    or-int/2addr v9, v7

    .line 336
    :try_start_6
    iget-object v0, v1, La8/q0;->I:La8/i1;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 337
    .line 338
    move-object v3, v2

    .line 339
    :try_start_7
    iget-object v2, v0, La8/i1;->a:Lt7/p0;

    .line 340
    .line 341
    iget-object v5, v0, La8/i1;->b:Lh8/b0;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 342
    .line 343
    const/4 v8, 0x1

    .line 344
    move-object v4, v2

    .line 345
    move-wide v6, v13

    .line 346
    :try_start_8
    invoke-virtual/range {v1 .. v8}, La8/q0;->A0(Lt7/p0;Lh8/b0;Lt7/p0;Lh8/b0;JZ)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 347
    .line 348
    .line 349
    move-object v2, v3

    .line 350
    move-wide v5, v6

    .line 351
    move-wide v3, v15

    .line 352
    :goto_b
    const/4 v10, 0x2

    .line 353
    move-wide v7, v3

    .line 354
    move-object/from16 v1, p0

    .line 355
    .line 356
    goto :goto_6

    .line 357
    :catchall_1
    move-exception v0

    .line 358
    move-object v2, v3

    .line 359
    move-wide v5, v6

    .line 360
    :goto_c
    move-wide v3, v15

    .line 361
    goto :goto_10

    .line 362
    :catchall_2
    move-exception v0

    .line 363
    move-object v2, v3

    .line 364
    :goto_d
    move-wide v5, v13

    .line 365
    goto :goto_c

    .line 366
    :catchall_3
    move-exception v0

    .line 367
    goto :goto_d

    .line 368
    :catchall_4
    move-exception v0

    .line 369
    goto :goto_f

    .line 370
    :goto_e
    move-wide v3, v11

    .line 371
    goto :goto_10

    .line 372
    :catchall_5
    move-exception v0

    .line 373
    :goto_f
    move-wide v5, v13

    .line 374
    goto :goto_e

    .line 375
    :catchall_6
    move-exception v0

    .line 376
    move v9, v2

    .line 377
    move-object v2, v6

    .line 378
    goto :goto_f

    .line 379
    :goto_10
    const/4 v10, 0x2

    .line 380
    move-wide v7, v3

    .line 381
    invoke-virtual/range {v1 .. v10}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 382
    .line 383
    .line 384
    move-result-object v2

    .line 385
    iput-object v2, v1, La8/q0;->I:La8/i1;

    .line 386
    .line 387
    throw v0
.end method

.method public final X(Lh8/b0;JZZ)J
    .locals 9

    .line 1
    invoke-virtual {p0}, La8/q0;->u0()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-virtual {p0, v0, v1}, La8/q0;->B0(ZZ)V

    .line 7
    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-nez p5, :cond_0

    .line 11
    .line 12
    iget-object p5, p0, La8/q0;->I:La8/i1;

    .line 13
    .line 14
    iget p5, p5, La8/i1;->e:I

    .line 15
    .line 16
    const/4 v3, 0x3

    .line 17
    if-ne p5, v3, :cond_1

    .line 18
    .line 19
    :cond_0
    invoke-virtual {p0, v2}, La8/q0;->m0(I)V

    .line 20
    .line 21
    .line 22
    :cond_1
    iget-object p5, p0, La8/q0;->u:La8/z0;

    .line 23
    .line 24
    iget-object v3, p5, La8/z0;->i:La8/w0;

    .line 25
    .line 26
    move-object v4, v3

    .line 27
    :goto_0
    if-eqz v4, :cond_3

    .line 28
    .line 29
    iget-object v5, v4, La8/w0;->g:La8/x0;

    .line 30
    .line 31
    iget-object v5, v5, La8/x0;->a:Lh8/b0;

    .line 32
    .line 33
    invoke-virtual {p1, v5}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_2

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    iget-object v4, v4, La8/w0;->m:La8/w0;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_3
    :goto_1
    if-nez p4, :cond_4

    .line 44
    .line 45
    if-ne v3, v4, :cond_4

    .line 46
    .line 47
    if-eqz v4, :cond_7

    .line 48
    .line 49
    iget-wide v5, v4, La8/w0;->p:J

    .line 50
    .line 51
    add-long/2addr v5, p2

    .line 52
    const-wide/16 v7, 0x0

    .line 53
    .line 54
    cmp-long p1, v5, v7

    .line 55
    .line 56
    if-gez p1, :cond_7

    .line 57
    .line 58
    :cond_4
    move p1, v0

    .line 59
    :goto_2
    iget-object p4, p0, La8/q0;->d:[La8/p1;

    .line 60
    .line 61
    array-length v3, p4

    .line 62
    if-ge p1, v3, :cond_5

    .line 63
    .line 64
    invoke-virtual {p0, p1}, La8/q0;->i(I)V

    .line 65
    .line 66
    .line 67
    add-int/lit8 p1, p1, 0x1

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_5
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 71
    .line 72
    .line 73
    .line 74
    .line 75
    iput-wide v5, p0, La8/q0;->e0:J

    .line 76
    .line 77
    if-eqz v4, :cond_7

    .line 78
    .line 79
    :goto_3
    iget-object p1, p5, La8/z0;->i:La8/w0;

    .line 80
    .line 81
    if-eq p1, v4, :cond_6

    .line 82
    .line 83
    invoke-virtual {p5}, La8/z0;->a()La8/w0;

    .line 84
    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_6
    invoke-virtual {p5, v4}, La8/z0;->n(La8/w0;)I

    .line 88
    .line 89
    .line 90
    const-wide v5, 0xe8d4a51000L

    .line 91
    .line 92
    .line 93
    .line 94
    .line 95
    iput-wide v5, v4, La8/w0;->p:J

    .line 96
    .line 97
    array-length p1, p4

    .line 98
    new-array p1, p1, [Z

    .line 99
    .line 100
    iget-object p4, p5, La8/z0;->j:La8/w0;

    .line 101
    .line 102
    invoke-virtual {p4}, La8/w0;->e()J

    .line 103
    .line 104
    .line 105
    move-result-wide v5

    .line 106
    invoke-virtual {p0, p1, v5, v6}, La8/q0;->l([ZJ)V

    .line 107
    .line 108
    .line 109
    iput-boolean v1, v4, La8/w0;->h:Z

    .line 110
    .line 111
    :cond_7
    invoke-virtual {p0}, La8/q0;->h()V

    .line 112
    .line 113
    .line 114
    if-eqz v4, :cond_a

    .line 115
    .line 116
    iget-object p1, v4, La8/w0;->a:Ljava/lang/Object;

    .line 117
    .line 118
    invoke-virtual {p5, v4}, La8/z0;->n(La8/w0;)I

    .line 119
    .line 120
    .line 121
    iget-boolean p4, v4, La8/w0;->e:Z

    .line 122
    .line 123
    if-nez p4, :cond_8

    .line 124
    .line 125
    iget-object p1, v4, La8/w0;->g:La8/x0;

    .line 126
    .line 127
    invoke-virtual {p1, p2, p3}, La8/x0;->b(J)La8/x0;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    iput-object p1, v4, La8/w0;->g:La8/x0;

    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_8
    iget-boolean p4, v4, La8/w0;->f:Z

    .line 135
    .line 136
    if-eqz p4, :cond_9

    .line 137
    .line 138
    invoke-interface {p1, p2, p3}, Lh8/z;->d(J)J

    .line 139
    .line 140
    .line 141
    move-result-wide p2

    .line 142
    iget-wide p4, p0, La8/q0;->p:J

    .line 143
    .line 144
    sub-long p4, p2, p4

    .line 145
    .line 146
    invoke-interface {p1, p4, p5}, Lh8/z;->l(J)V

    .line 147
    .line 148
    .line 149
    :cond_9
    :goto_4
    invoke-virtual {p0, p2, p3}, La8/q0;->Q(J)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p0}, La8/q0;->C()V

    .line 153
    .line 154
    .line 155
    goto :goto_5

    .line 156
    :cond_a
    invoke-virtual {p5}, La8/z0;->b()V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p0, p2, p3}, La8/q0;->Q(J)V

    .line 160
    .line 161
    .line 162
    :goto_5
    invoke-virtual {p0, v0}, La8/q0;->u(Z)V

    .line 163
    .line 164
    .line 165
    iget-object p0, p0, La8/q0;->k:Lw7/t;

    .line 166
    .line 167
    invoke-virtual {p0, v2}, Lw7/t;->e(I)Z

    .line 168
    .line 169
    .line 170
    return-wide p2
.end method

.method public final Y(La8/l1;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, La8/q0;->k:Lw7/t;

    .line 5
    .line 6
    iget-object v1, p1, La8/l1;->e:Landroid/os/Looper;

    .line 7
    .line 8
    iget-object v2, p0, La8/q0;->m:Landroid/os/Looper;

    .line 9
    .line 10
    if-ne v1, v2, :cond_2

    .line 11
    .line 12
    monitor-enter p1

    .line 13
    monitor-exit p1

    .line 14
    const/4 v1, 0x1

    .line 15
    :try_start_0
    iget-object v2, p1, La8/l1;->a:La8/k1;

    .line 16
    .line 17
    iget v3, p1, La8/l1;->c:I

    .line 18
    .line 19
    iget-object v4, p1, La8/l1;->d:Ljava/lang/Object;

    .line 20
    .line 21
    invoke-interface {v2, v3, v4}, La8/k1;->a(ILjava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1, v1}, La8/l1;->a(Z)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, La8/q0;->I:La8/i1;

    .line 28
    .line 29
    iget p0, p0, La8/i1;->e:I

    .line 30
    .line 31
    const/4 p1, 0x3

    .line 32
    const/4 v1, 0x2

    .line 33
    if-eq p0, p1, :cond_1

    .line 34
    .line 35
    if-ne p0, v1, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    return-void

    .line 39
    :cond_1
    :goto_0
    invoke-virtual {v0, v1}, Lw7/t;->e(I)Z

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    invoke-virtual {p1, v1}, La8/l1;->a(Z)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    const/16 p0, 0xf

    .line 49
    .line 50
    invoke-virtual {v0, p0, p1}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p0}, Lw7/s;->b()V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method public final Z(La8/l1;)V
    .locals 3

    .line 1
    iget-object v0, p1, La8/l1;->e:Landroid/os/Looper;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v1}, Ljava/lang/Thread;->isAlive()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    const-string p0, "TAG"

    .line 14
    .line 15
    const-string v0, "Trying to send message on a dead thread."

    .line 16
    .line 17
    invoke-static {p0, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    invoke-virtual {p1, p0}, La8/l1;->a(Z)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    const/4 v1, 0x0

    .line 26
    iget-object v2, p0, La8/q0;->s:Lw7/r;

    .line 27
    .line 28
    invoke-virtual {v2, v0, v1}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    new-instance v1, La0/d;

    .line 33
    .line 34
    invoke-direct {v1, p0, p1}, La0/d;-><init>(La8/q0;La8/l1;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v1}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public final a(La8/m0;I)V
    .locals 2

    .line 1
    iget-object v0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, La8/n0;->f(I)V

    .line 5
    .line 6
    .line 7
    const/4 v0, -0x1

    .line 8
    iget-object v1, p0, La8/q0;->v:Lac/i;

    .line 9
    .line 10
    if-ne p2, v0, :cond_0

    .line 11
    .line 12
    iget-object p2, v1, Lac/i;->c:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p2, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    :cond_0
    iget-object v0, p1, La8/m0;->a:Ljava/util/ArrayList;

    .line 21
    .line 22
    iget-object p1, p1, La8/m0;->b:Lh8/a1;

    .line 23
    .line 24
    invoke-virtual {v1, p2, v0, p1}, Lac/i;->a(ILjava/util/ArrayList;Lh8/a1;)Lt7/p0;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const/4 p2, 0x0

    .line 29
    invoke-virtual {p0, p1, p2}, La8/q0;->v(Lt7/p0;Z)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final a0(Lt7/c;Z)V
    .locals 3

    .line 1
    iget-object v0, p0, La8/q0;->g:Lh/w;

    .line 2
    .line 3
    check-cast v0, Lj8/o;

    .line 4
    .line 5
    iget-object v1, v0, Lj8/o;->j:Lt7/c;

    .line 6
    .line 7
    invoke-virtual {v1, p1}, Lt7/c;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iput-object p1, v0, Lj8/o;->j:Lt7/c;

    .line 15
    .line 16
    invoke-virtual {v0}, Lj8/o;->t()V

    .line 17
    .line 18
    .line 19
    :goto_0
    if-eqz p2, :cond_1

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    const/4 p1, 0x0

    .line 23
    :goto_1
    iget-object p2, p0, La8/q0;->C:La8/e;

    .line 24
    .line 25
    iget-object v0, p2, La8/e;->d:Lt7/c;

    .line 26
    .line 27
    invoke-static {v0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_5

    .line 32
    .line 33
    iput-object p1, p2, La8/e;->d:Lt7/c;

    .line 34
    .line 35
    const/4 v0, 0x0

    .line 36
    const/4 v1, 0x1

    .line 37
    if-nez p1, :cond_2

    .line 38
    .line 39
    move p1, v0

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    move p1, v1

    .line 42
    :goto_2
    iput p1, p2, La8/e;->f:I

    .line 43
    .line 44
    if-eq p1, v1, :cond_3

    .line 45
    .line 46
    if-nez p1, :cond_4

    .line 47
    .line 48
    :cond_3
    move v0, v1

    .line 49
    :cond_4
    const-string p1, "Automatic handling of audio focus is only available for USAGE_MEDIA and USAGE_GAME."

    .line 50
    .line 51
    invoke-static {v0, p1}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_5
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 55
    .line 56
    iget-boolean v0, p1, La8/i1;->l:Z

    .line 57
    .line 58
    iget v1, p1, La8/i1;->n:I

    .line 59
    .line 60
    iget v2, p1, La8/i1;->m:I

    .line 61
    .line 62
    iget p1, p1, La8/i1;->e:I

    .line 63
    .line 64
    invoke-virtual {p2, p1, v0}, La8/e;->d(IZ)I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    invoke-virtual {p0, p1, v1, v2, v0}, La8/q0;->y0(IIIZ)V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public final b(JJLt7/o;Landroid/media/MediaFormat;)V
    .locals 0

    .line 1
    iget-boolean p1, p0, La8/q0;->G:Z

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, La8/q0;->k:Lw7/t;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object p0, p0, Lw7/t;->a:Landroid/os/Handler;

    .line 15
    .line 16
    const/16 p2, 0x25

    .line 17
    .line 18
    invoke-virtual {p0, p2}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    iput-object p0, p1, Lw7/s;->a:Landroid/os/Message;

    .line 23
    .line 24
    invoke-virtual {p1}, Lw7/s;->b()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final b0(ZLw7/e;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, La8/q0;->S:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, La8/q0;->S:Z

    .line 6
    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, La8/q0;->d:[La8/p1;

    .line 10
    .line 11
    array-length p1, p0

    .line 12
    const/4 v0, 0x0

    .line 13
    :goto_0
    if-ge v0, p1, :cond_0

    .line 14
    .line 15
    aget-object v1, p0, v0

    .line 16
    .line 17
    invoke-virtual {v1}, La8/p1;->k()V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v0, v0, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    if-eqz p2, :cond_1

    .line 24
    .line 25
    invoke-virtual {p2}, Lw7/e;->c()Z

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final c(Lh8/z;)V
    .locals 1

    .line 1
    iget-object p0, p0, La8/q0;->k:Lw7/t;

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    invoke-virtual {p0, v0, p1}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Lw7/s;->b()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final c0(La8/m0;)V
    .locals 7

    .line 1
    iget-object v0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, La8/n0;->f(I)V

    .line 5
    .line 6
    .line 7
    iget v0, p1, La8/m0;->c:I

    .line 8
    .line 9
    iget-object v1, p1, La8/m0;->b:Lh8/a1;

    .line 10
    .line 11
    iget-object v2, p1, La8/m0;->a:Ljava/util/ArrayList;

    .line 12
    .line 13
    const/4 v3, -0x1

    .line 14
    if-eq v0, v3, :cond_0

    .line 15
    .line 16
    new-instance v0, La8/p0;

    .line 17
    .line 18
    new-instance v3, La8/n1;

    .line 19
    .line 20
    invoke-direct {v3, v2, v1}, La8/n1;-><init>(Ljava/util/ArrayList;Lh8/a1;)V

    .line 21
    .line 22
    .line 23
    iget v4, p1, La8/m0;->c:I

    .line 24
    .line 25
    iget-wide v5, p1, La8/m0;->d:J

    .line 26
    .line 27
    invoke-direct {v0, v3, v4, v5, v6}, La8/p0;-><init>(Lt7/p0;IJ)V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, La8/q0;->W:La8/p0;

    .line 31
    .line 32
    :cond_0
    iget-object p1, p0, La8/q0;->v:Lac/i;

    .line 33
    .line 34
    iget-object v0, p1, Lac/i;->c:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    const/4 v4, 0x0

    .line 43
    invoke-virtual {p1, v4, v3}, Lac/i;->k(II)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    invoke-virtual {p1, v0, v2, v1}, Lac/i;->a(ILjava/util/ArrayList;Lh8/a1;)Lt7/p0;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-virtual {p0, p1, v4}, La8/q0;->v(Lt7/p0;Z)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method public final d()V
    .locals 7

    .line 1
    iget-object v0, p0, La8/q0;->d:[La8/p1;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    :goto_0
    if-ge v2, v1, :cond_2

    .line 6
    .line 7
    aget-object v3, v0, v2

    .line 8
    .line 9
    iget-boolean v4, p0, La8/q0;->F:Z

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    iget-object v4, p0, La8/q0;->E:La8/q1;

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    const/4 v4, 0x0

    .line 17
    :goto_1
    iget-object v5, v3, La8/p1;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v5, La8/f;

    .line 20
    .line 21
    const/16 v6, 0x12

    .line 22
    .line 23
    invoke-interface {v5, v6, v4}, La8/k1;->a(ILjava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object v3, v3, La8/p1;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v3, La8/f;

    .line 29
    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    invoke-interface {v3, v6, v4}, La8/k1;->a(ILjava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    return-void
.end method

.method public final d0(Z)V
    .locals 1

    .line 1
    iput-boolean p1, p0, La8/q0;->L:Z

    .line 2
    .line 3
    invoke-virtual {p0}, La8/q0;->P()V

    .line 4
    .line 5
    .line 6
    iget-boolean p1, p0, La8/q0;->M:Z

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    iget-object p1, p0, La8/q0;->u:La8/z0;

    .line 11
    .line 12
    iget-object v0, p1, La8/z0;->j:La8/w0;

    .line 13
    .line 14
    iget-object p1, p1, La8/z0;->i:La8/w0;

    .line 15
    .line 16
    if-eq v0, p1, :cond_0

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    invoke-virtual {p0, p1}, La8/q0;->V(Z)V

    .line 20
    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    invoke-virtual {p0, p1}, La8/q0;->u(Z)V

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method public final e()Z
    .locals 4

    .line 1
    iget-boolean v0, p0, La8/q0;->B:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    iget-object p0, p0, La8/q0;->d:[La8/p1;

    .line 8
    .line 9
    array-length v0, p0

    .line 10
    move v2, v1

    .line 11
    :goto_0
    if-ge v2, v0, :cond_2

    .line 12
    .line 13
    aget-object v3, p0, v2

    .line 14
    .line 15
    invoke-virtual {v3}, La8/p1;->f()Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_1

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_2
    return v1
.end method

.method public final e0(Lt7/g0;)V
    .locals 2

    .line 1
    iget-object v0, p0, La8/q0;->k:Lw7/t;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lw7/t;->d(I)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, La8/q0;->q:La8/l;

    .line 9
    .line 10
    invoke-virtual {v0, p1}, La8/l;->d(Lt7/g0;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, La8/l;->c()Lt7/g0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const/4 v0, 0x1

    .line 18
    iget v1, p1, Lt7/g0;->a:F

    .line 19
    .line 20
    invoke-virtual {p0, p1, v1, v0, v0}, La8/q0;->x(Lt7/g0;FZZ)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final f(Lh8/z0;)V
    .locals 1

    .line 1
    check-cast p1, Lh8/z;

    .line 2
    .line 3
    iget-object p0, p0, La8/q0;->k:Lw7/t;

    .line 4
    .line 5
    const/16 v0, 0x9

    .line 6
    .line 7
    invoke-virtual {p0, v0, p1}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Lw7/s;->b()V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final f0(La8/r;)V
    .locals 2

    .line 1
    iput-object p1, p0, La8/q0;->d0:La8/r;

    .line 2
    .line 3
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 4
    .line 5
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 6
    .line 7
    iget-object p0, p0, La8/q0;->u:La8/z0;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    iget-object p1, p0, La8/z0;->q:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-nez p1, :cond_1

    .line 22
    .line 23
    new-instance p1, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    :goto_0
    iget-object v1, p0, La8/z0;->q:Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-ge v0, v1, :cond_0

    .line 36
    .line 37
    iget-object v1, p0, La8/z0;->q:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, La8/w0;

    .line 44
    .line 45
    invoke-virtual {v1}, La8/w0;->i()V

    .line 46
    .line 47
    .line 48
    add-int/lit8 v0, v0, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    iput-object p1, p0, La8/z0;->q:Ljava/util/ArrayList;

    .line 52
    .line 53
    const/4 p1, 0x0

    .line 54
    iput-object p1, p0, La8/z0;->m:La8/w0;

    .line 55
    .line 56
    invoke-virtual {p0}, La8/z0;->k()V

    .line 57
    .line 58
    .line 59
    :cond_1
    return-void
.end method

.method public final g()V
    .locals 1

    .line 1
    invoke-virtual {p0}, La8/q0;->N()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    invoke-virtual {p0, v0}, La8/q0;->V(Z)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final g0(I)V
    .locals 2

    .line 1
    iput p1, p0, La8/q0;->Q:I

    .line 2
    .line 3
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 4
    .line 5
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 6
    .line 7
    iget-object v1, p0, La8/q0;->u:La8/z0;

    .line 8
    .line 9
    iput p1, v1, La8/z0;->g:I

    .line 10
    .line 11
    invoke-virtual {v1, v0}, La8/z0;->r(Lt7/p0;)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    and-int/lit8 v0, p1, 0x1

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-virtual {p0, p1}, La8/q0;->V(Z)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    and-int/lit8 p1, p1, 0x2

    .line 25
    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, La8/q0;->h()V

    .line 29
    .line 30
    .line 31
    :cond_1
    :goto_0
    const/4 p1, 0x0

    .line 32
    invoke-virtual {p0, p1}, La8/q0;->u(Z)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final h()V
    .locals 10

    .line 1
    iget-boolean v0, p0, La8/q0;->B:Z

    .line 2
    .line 3
    if-eqz v0, :cond_7

    .line 4
    .line 5
    invoke-virtual {p0}, La8/q0;->e()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_6

    .line 12
    :cond_0
    iget-object v0, p0, La8/q0;->d:[La8/p1;

    .line 13
    .line 14
    array-length v1, v0

    .line 15
    const/4 v2, 0x0

    .line 16
    move v3, v2

    .line 17
    :goto_0
    if-ge v3, v1, :cond_6

    .line 18
    .line 19
    aget-object v4, v0, v3

    .line 20
    .line 21
    invoke-virtual {v4}, La8/p1;->c()I

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    invoke-virtual {v4}, La8/p1;->f()Z

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    if-nez v6, :cond_1

    .line 30
    .line 31
    goto :goto_5

    .line 32
    :cond_1
    iget v6, v4, La8/p1;->d:I

    .line 33
    .line 34
    const/4 v7, 0x1

    .line 35
    const/4 v8, 0x4

    .line 36
    if-eq v6, v8, :cond_3

    .line 37
    .line 38
    const/4 v9, 0x2

    .line 39
    if-ne v6, v9, :cond_2

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    move v9, v2

    .line 43
    goto :goto_2

    .line 44
    :cond_3
    :goto_1
    move v9, v7

    .line 45
    :goto_2
    if-ne v6, v8, :cond_4

    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_4
    move v7, v2

    .line 49
    :goto_3
    if-eqz v9, :cond_5

    .line 50
    .line 51
    iget-object v6, v4, La8/p1;->e:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v6, La8/f;

    .line 54
    .line 55
    goto :goto_4

    .line 56
    :cond_5
    iget-object v6, v4, La8/p1;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v6, La8/f;

    .line 59
    .line 60
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    :goto_4
    iget-object v8, p0, La8/q0;->q:La8/l;

    .line 64
    .line 65
    invoke-virtual {v4, v6, v8}, La8/p1;->a(La8/f;La8/l;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v4, v9}, La8/p1;->i(Z)V

    .line 69
    .line 70
    .line 71
    iput v7, v4, La8/p1;->d:I

    .line 72
    .line 73
    :goto_5
    iget v6, p0, La8/q0;->V:I

    .line 74
    .line 75
    invoke-virtual {v4}, La8/p1;->c()I

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    sub-int/2addr v5, v4

    .line 80
    sub-int/2addr v6, v5

    .line 81
    iput v6, p0, La8/q0;->V:I

    .line 82
    .line 83
    add-int/lit8 v3, v3, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_6
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    iput-wide v0, p0, La8/q0;->e0:J

    .line 92
    .line 93
    :cond_7
    :goto_6
    return-void
.end method

.method public final h0(Z)V
    .locals 3

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, La8/q0;->G:Z

    .line 5
    .line 6
    iget-object v1, p0, La8/q0;->k:Lw7/t;

    .line 7
    .line 8
    const/16 v2, 0x25

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Lw7/t;->d(I)V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, La8/q0;->H:La8/p0;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0, v1, v0}, La8/q0;->W(La8/p0;Z)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput-object v0, p0, La8/q0;->H:La8/p0;

    .line 22
    .line 23
    :cond_0
    iput-boolean p1, p0, La8/q0;->F:Z

    .line 24
    .line 25
    invoke-virtual {p0}, La8/q0;->d()V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final handleMessage(Landroid/os/Message;)Z
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    const-string v11, "Playback error"

    .line 6
    .line 7
    const-string v12, "ExoPlayerImplInternal"

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    const/16 v3, 0x3e8

    .line 11
    .line 12
    const/4 v4, 0x4

    .line 13
    const/4 v13, 0x0

    .line 14
    const/4 v14, 0x1

    .line 15
    :try_start_0
    iget v5, v0, Landroid/os/Message;->what:I

    .line 16
    .line 17
    const/4 v6, 0x0

    .line 18
    packed-switch v5, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    :pswitch_0
    return v13

    .line 22
    :pswitch_1
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, La8/q1;

    .line 25
    .line 26
    invoke-virtual {v1, v0}, La8/q0;->i0(La8/q1;)V

    .line 27
    .line 28
    .line 29
    goto/16 :goto_f

    .line 30
    .line 31
    :catch_0
    move-exception v0

    .line 32
    goto/16 :goto_5

    .line 33
    .line 34
    :catch_1
    move-exception v0

    .line 35
    goto/16 :goto_6

    .line 36
    .line 37
    :catch_2
    move-exception v0

    .line 38
    goto/16 :goto_7

    .line 39
    .line 40
    :catch_3
    move-exception v0

    .line 41
    goto/16 :goto_8

    .line 42
    .line 43
    :catch_4
    move-exception v0

    .line 44
    goto/16 :goto_b

    .line 45
    .line 46
    :catch_5
    move-exception v0

    .line 47
    goto/16 :goto_c

    .line 48
    .line 49
    :pswitch_2
    iput-boolean v13, v1, La8/q0;->G:Z

    .line 50
    .line 51
    iget-object v0, v1, La8/q0;->H:La8/p0;

    .line 52
    .line 53
    if-eqz v0, :cond_14

    .line 54
    .line 55
    invoke-virtual {v1, v0, v13}, La8/q0;->W(La8/p0;Z)V

    .line 56
    .line 57
    .line 58
    iput-object v6, v1, La8/q0;->H:La8/p0;

    .line 59
    .line 60
    goto/16 :goto_f

    .line 61
    .line 62
    :pswitch_3
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Ljava/lang/Boolean;

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    invoke-virtual {v1, v0}, La8/q0;->h0(Z)V

    .line 71
    .line 72
    .line 73
    goto/16 :goto_f

    .line 74
    .line 75
    :pswitch_4
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v0, Lm8/x;

    .line 78
    .line 79
    invoke-virtual {v1, v0}, La8/q0;->n0(Lm8/x;)V

    .line 80
    .line 81
    .line 82
    goto/16 :goto_f

    .line 83
    .line 84
    :pswitch_5
    invoke-virtual {v1}, La8/q0;->r()V

    .line 85
    .line 86
    .line 87
    goto/16 :goto_f

    .line 88
    .line 89
    :pswitch_6
    iget v0, v0, Landroid/os/Message;->arg1:I

    .line 90
    .line 91
    invoke-virtual {v1, v0}, La8/q0;->q(I)V

    .line 92
    .line 93
    .line 94
    goto/16 :goto_f

    .line 95
    .line 96
    :pswitch_7
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Ljava/lang/Float;

    .line 99
    .line 100
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    invoke-virtual {v1, v0}, La8/q0;->p0(F)V

    .line 105
    .line 106
    .line 107
    goto/16 :goto_f

    .line 108
    .line 109
    :pswitch_8
    iget-object v5, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v5, Lt7/c;

    .line 112
    .line 113
    iget v0, v0, Landroid/os/Message;->arg1:I

    .line 114
    .line 115
    if-eqz v0, :cond_0

    .line 116
    .line 117
    move v0, v14

    .line 118
    goto :goto_0

    .line 119
    :cond_0
    move v0, v13

    .line 120
    :goto_0
    invoke-virtual {v1, v5, v0}, La8/q0;->a0(Lt7/c;Z)V

    .line 121
    .line 122
    .line 123
    goto/16 :goto_f

    .line 124
    .line 125
    :pswitch_9
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v0, Landroid/util/Pair;

    .line 128
    .line 129
    iget-object v5, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 130
    .line 131
    iget-object v0, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v0, Lw7/e;

    .line 134
    .line 135
    invoke-virtual {v1, v5, v0}, La8/q0;->o0(Ljava/lang/Object;Lw7/e;)V

    .line 136
    .line 137
    .line 138
    goto/16 :goto_f

    .line 139
    .line 140
    :pswitch_a
    invoke-virtual {v1}, La8/q0;->J()V

    .line 141
    .line 142
    .line 143
    goto/16 :goto_f

    .line 144
    .line 145
    :pswitch_b
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v0, La8/r;

    .line 148
    .line 149
    invoke-virtual {v1, v0}, La8/q0;->f0(La8/r;)V

    .line 150
    .line 151
    .line 152
    goto/16 :goto_f

    .line 153
    .line 154
    :pswitch_c
    iget v5, v0, Landroid/os/Message;->arg1:I

    .line 155
    .line 156
    iget v6, v0, Landroid/os/Message;->arg2:I

    .line 157
    .line 158
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v0, Ljava/util/List;

    .line 161
    .line 162
    invoke-virtual {v1, v5, v6, v0}, La8/q0;->x0(IILjava/util/List;)V

    .line 163
    .line 164
    .line 165
    goto/16 :goto_f

    .line 166
    .line 167
    :pswitch_d
    invoke-virtual {v1}, La8/q0;->N()V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v1, v14}, La8/q0;->V(Z)V

    .line 171
    .line 172
    .line 173
    goto/16 :goto_f

    .line 174
    .line 175
    :pswitch_e
    invoke-virtual {v1}, La8/q0;->g()V

    .line 176
    .line 177
    .line 178
    goto/16 :goto_f

    .line 179
    .line 180
    :pswitch_f
    iget v0, v0, Landroid/os/Message;->arg1:I

    .line 181
    .line 182
    if-eqz v0, :cond_1

    .line 183
    .line 184
    move v0, v14

    .line 185
    goto :goto_1

    .line 186
    :cond_1
    move v0, v13

    .line 187
    :goto_1
    invoke-virtual {v1, v0}, La8/q0;->d0(Z)V

    .line 188
    .line 189
    .line 190
    goto/16 :goto_f

    .line 191
    .line 192
    :pswitch_10
    invoke-virtual {v1}, La8/q0;->H()V

    .line 193
    .line 194
    .line 195
    goto/16 :goto_f

    .line 196
    .line 197
    :pswitch_11
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v0, Lh8/a1;

    .line 200
    .line 201
    invoke-virtual {v1, v0}, La8/q0;->l0(Lh8/a1;)V

    .line 202
    .line 203
    .line 204
    goto/16 :goto_f

    .line 205
    .line 206
    :pswitch_12
    iget v5, v0, Landroid/os/Message;->arg1:I

    .line 207
    .line 208
    iget v6, v0, Landroid/os/Message;->arg2:I

    .line 209
    .line 210
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v0, Lh8/a1;

    .line 213
    .line 214
    invoke-virtual {v1, v5, v6, v0}, La8/q0;->M(IILh8/a1;)V

    .line 215
    .line 216
    .line 217
    goto/16 :goto_f

    .line 218
    .line 219
    :pswitch_13
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 220
    .line 221
    invoke-static {v0}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v1}, La8/q0;->I()V

    .line 225
    .line 226
    .line 227
    throw v6

    .line 228
    :pswitch_14
    iget-object v5, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast v5, La8/m0;

    .line 231
    .line 232
    iget v0, v0, Landroid/os/Message;->arg1:I

    .line 233
    .line 234
    invoke-virtual {v1, v5, v0}, La8/q0;->a(La8/m0;I)V

    .line 235
    .line 236
    .line 237
    goto/16 :goto_f

    .line 238
    .line 239
    :pswitch_15
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast v0, La8/m0;

    .line 242
    .line 243
    invoke-virtual {v1, v0}, La8/q0;->c0(La8/m0;)V

    .line 244
    .line 245
    .line 246
    goto/16 :goto_f

    .line 247
    .line 248
    :pswitch_16
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast v0, Lt7/g0;

    .line 251
    .line 252
    iget v5, v0, Lt7/g0;->a:F

    .line 253
    .line 254
    invoke-virtual {v1, v0, v5, v14, v13}, La8/q0;->x(Lt7/g0;FZZ)V

    .line 255
    .line 256
    .line 257
    goto/16 :goto_f

    .line 258
    .line 259
    :pswitch_17
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 260
    .line 261
    check-cast v0, La8/l1;

    .line 262
    .line 263
    invoke-virtual {v1, v0}, La8/q0;->Z(La8/l1;)V

    .line 264
    .line 265
    .line 266
    goto/16 :goto_f

    .line 267
    .line 268
    :pswitch_18
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast v0, La8/l1;

    .line 271
    .line 272
    invoke-virtual {v1, v0}, La8/q0;->Y(La8/l1;)V

    .line 273
    .line 274
    .line 275
    goto/16 :goto_f

    .line 276
    .line 277
    :pswitch_19
    iget v5, v0, Landroid/os/Message;->arg1:I

    .line 278
    .line 279
    if-eqz v5, :cond_2

    .line 280
    .line 281
    move v5, v14

    .line 282
    goto :goto_2

    .line 283
    :cond_2
    move v5, v13

    .line 284
    :goto_2
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v0, Lw7/e;

    .line 287
    .line 288
    invoke-virtual {v1, v5, v0}, La8/q0;->b0(ZLw7/e;)V

    .line 289
    .line 290
    .line 291
    goto/16 :goto_f

    .line 292
    .line 293
    :pswitch_1a
    iget v0, v0, Landroid/os/Message;->arg1:I

    .line 294
    .line 295
    if-eqz v0, :cond_3

    .line 296
    .line 297
    move v0, v14

    .line 298
    goto :goto_3

    .line 299
    :cond_3
    move v0, v13

    .line 300
    :goto_3
    invoke-virtual {v1, v0}, La8/q0;->k0(Z)V

    .line 301
    .line 302
    .line 303
    goto/16 :goto_f

    .line 304
    .line 305
    :pswitch_1b
    iget v0, v0, Landroid/os/Message;->arg1:I

    .line 306
    .line 307
    invoke-virtual {v1, v0}, La8/q0;->g0(I)V

    .line 308
    .line 309
    .line 310
    goto/16 :goto_f

    .line 311
    .line 312
    :pswitch_1c
    invoke-virtual {v1}, La8/q0;->N()V

    .line 313
    .line 314
    .line 315
    goto/16 :goto_f

    .line 316
    .line 317
    :pswitch_1d
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 318
    .line 319
    check-cast v0, Lh8/z;

    .line 320
    .line 321
    invoke-virtual {v1, v0}, La8/q0;->s(Lh8/z;)V

    .line 322
    .line 323
    .line 324
    goto/16 :goto_f

    .line 325
    .line 326
    :pswitch_1e
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 327
    .line 328
    check-cast v0, Lh8/z;

    .line 329
    .line 330
    invoke-virtual {v1, v0}, La8/q0;->w(Lh8/z;)V

    .line 331
    .line 332
    .line 333
    goto/16 :goto_f

    .line 334
    .line 335
    :pswitch_1f
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 336
    .line 337
    check-cast v0, Lw7/e;

    .line 338
    .line 339
    invoke-virtual {v1, v0}, La8/q0;->K(Lw7/e;)V

    .line 340
    .line 341
    .line 342
    return v14

    .line 343
    :pswitch_20
    invoke-virtual {v1, v13, v14}, La8/q0;->t0(ZZ)V

    .line 344
    .line 345
    .line 346
    goto/16 :goto_f

    .line 347
    .line 348
    :pswitch_21
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast v0, La8/r1;

    .line 351
    .line 352
    invoke-virtual {v1, v0}, La8/q0;->j0(La8/r1;)V

    .line 353
    .line 354
    .line 355
    goto/16 :goto_f

    .line 356
    .line 357
    :pswitch_22
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 358
    .line 359
    check-cast v0, Lt7/g0;

    .line 360
    .line 361
    invoke-virtual {v1, v0}, La8/q0;->e0(Lt7/g0;)V

    .line 362
    .line 363
    .line 364
    goto/16 :goto_f

    .line 365
    .line 366
    :pswitch_23
    iget-object v0, v0, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 367
    .line 368
    check-cast v0, La8/p0;

    .line 369
    .line 370
    invoke-virtual {v1, v0, v14}, La8/q0;->W(La8/p0;Z)V

    .line 371
    .line 372
    .line 373
    goto/16 :goto_f

    .line 374
    .line 375
    :pswitch_24
    invoke-virtual {v1}, La8/q0;->j()V

    .line 376
    .line 377
    .line 378
    goto/16 :goto_f

    .line 379
    .line 380
    :pswitch_25
    iget v5, v0, Landroid/os/Message;->arg1:I

    .line 381
    .line 382
    if-eqz v5, :cond_4

    .line 383
    .line 384
    move v5, v14

    .line 385
    goto :goto_4

    .line 386
    :cond_4
    move v5, v13

    .line 387
    :goto_4
    iget v0, v0, Landroid/os/Message;->arg2:I

    .line 388
    .line 389
    shr-int/lit8 v6, v0, 0x4

    .line 390
    .line 391
    and-int/lit8 v0, v0, 0xf

    .line 392
    .line 393
    iget-object v7, v1, La8/q0;->J:La8/n0;

    .line 394
    .line 395
    invoke-virtual {v7, v14}, La8/n0;->f(I)V

    .line 396
    .line 397
    .line 398
    iget-object v7, v1, La8/q0;->C:La8/e;

    .line 399
    .line 400
    iget-object v8, v1, La8/q0;->I:La8/i1;

    .line 401
    .line 402
    iget v8, v8, La8/i1;->e:I

    .line 403
    .line 404
    invoke-virtual {v7, v8, v5}, La8/e;->d(IZ)I

    .line 405
    .line 406
    .line 407
    move-result v7

    .line 408
    invoke-virtual {v1, v7, v6, v0, v5}, La8/q0;->y0(IIIZ)V
    :try_end_0
    .catch La8/o; {:try_start_0 .. :try_end_0} :catch_5
    .catch Ld8/d; {:try_start_0 .. :try_end_0} :catch_4
    .catch Lt7/e0; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ly7/i; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 409
    .line 410
    .line 411
    goto/16 :goto_f

    .line 412
    .line 413
    :goto_5
    instance-of v4, v0, Ljava/lang/IllegalStateException;

    .line 414
    .line 415
    if-nez v4, :cond_5

    .line 416
    .line 417
    instance-of v4, v0, Ljava/lang/IllegalArgumentException;

    .line 418
    .line 419
    if-eqz v4, :cond_6

    .line 420
    .line 421
    :cond_5
    const/16 v3, 0x3ec

    .line 422
    .line 423
    :cond_6
    new-instance v4, La8/o;

    .line 424
    .line 425
    invoke-direct {v4, v2, v0, v3}, La8/o;-><init>(ILjava/lang/Exception;I)V

    .line 426
    .line 427
    .line 428
    invoke-static {v12, v11, v4}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {v1, v14, v13}, La8/q0;->t0(ZZ)V

    .line 432
    .line 433
    .line 434
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 435
    .line 436
    invoke-virtual {v0, v4}, La8/i1;->f(La8/o;)La8/i1;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    iput-object v0, v1, La8/q0;->I:La8/i1;

    .line 441
    .line 442
    goto/16 :goto_f

    .line 443
    .line 444
    :goto_6
    const/16 v2, 0x7d0

    .line 445
    .line 446
    invoke-virtual {v1, v0, v2}, La8/q0;->t(Ljava/io/IOException;I)V

    .line 447
    .line 448
    .line 449
    goto/16 :goto_f

    .line 450
    .line 451
    :goto_7
    iget v2, v0, Ly7/i;->d:I

    .line 452
    .line 453
    invoke-virtual {v1, v0, v2}, La8/q0;->t(Ljava/io/IOException;I)V

    .line 454
    .line 455
    .line 456
    goto/16 :goto_f

    .line 457
    .line 458
    :goto_8
    iget-boolean v2, v0, Lt7/e0;->d:Z

    .line 459
    .line 460
    iget v5, v0, Lt7/e0;->e:I

    .line 461
    .line 462
    if-ne v5, v14, :cond_8

    .line 463
    .line 464
    if-eqz v2, :cond_7

    .line 465
    .line 466
    const/16 v2, 0xbb9

    .line 467
    .line 468
    :goto_9
    move v3, v2

    .line 469
    goto :goto_a

    .line 470
    :cond_7
    const/16 v2, 0xbbb

    .line 471
    .line 472
    goto :goto_9

    .line 473
    :cond_8
    if-ne v5, v4, :cond_a

    .line 474
    .line 475
    if-eqz v2, :cond_9

    .line 476
    .line 477
    const/16 v2, 0xbba

    .line 478
    .line 479
    goto :goto_9

    .line 480
    :cond_9
    const/16 v2, 0xbbc

    .line 481
    .line 482
    goto :goto_9

    .line 483
    :cond_a
    :goto_a
    invoke-virtual {v1, v0, v3}, La8/q0;->t(Ljava/io/IOException;I)V

    .line 484
    .line 485
    .line 486
    goto/16 :goto_f

    .line 487
    .line 488
    :goto_b
    iget v2, v0, Ld8/d;->d:I

    .line 489
    .line 490
    invoke-virtual {v1, v0, v2}, La8/q0;->t(Ljava/io/IOException;I)V

    .line 491
    .line 492
    .line 493
    goto/16 :goto_f

    .line 494
    .line 495
    :goto_c
    iget v3, v0, La8/o;->f:I

    .line 496
    .line 497
    iget-object v5, v1, La8/q0;->u:La8/z0;

    .line 498
    .line 499
    if-ne v3, v14, :cond_b

    .line 500
    .line 501
    iget-object v3, v5, La8/z0;->j:La8/w0;

    .line 502
    .line 503
    if-eqz v3, :cond_b

    .line 504
    .line 505
    iget-object v6, v0, La8/o;->k:Lh8/b0;

    .line 506
    .line 507
    if-nez v6, :cond_b

    .line 508
    .line 509
    iget-object v3, v3, La8/w0;->g:La8/x0;

    .line 510
    .line 511
    iget-object v3, v3, La8/x0;->a:Lh8/b0;

    .line 512
    .line 513
    invoke-virtual {v0, v3}, La8/o;->a(Lh8/b0;)La8/o;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    :cond_b
    iget v3, v0, La8/o;->f:I

    .line 518
    .line 519
    iget-object v15, v1, La8/q0;->k:Lw7/t;

    .line 520
    .line 521
    if-ne v3, v14, :cond_d

    .line 522
    .line 523
    iget-object v3, v0, La8/o;->k:Lh8/b0;

    .line 524
    .line 525
    if-eqz v3, :cond_d

    .line 526
    .line 527
    iget v6, v0, La8/o;->h:I

    .line 528
    .line 529
    invoke-virtual {v1, v6, v3}, La8/q0;->A(ILh8/b0;)Z

    .line 530
    .line 531
    .line 532
    move-result v3

    .line 533
    if-eqz v3, :cond_d

    .line 534
    .line 535
    iput-boolean v14, v1, La8/q0;->f0:Z

    .line 536
    .line 537
    invoke-virtual {v1}, La8/q0;->h()V

    .line 538
    .line 539
    .line 540
    invoke-virtual {v5}, La8/z0;->g()La8/w0;

    .line 541
    .line 542
    .line 543
    move-result-object v0

    .line 544
    iget-object v3, v5, La8/z0;->i:La8/w0;

    .line 545
    .line 546
    if-eq v3, v0, :cond_c

    .line 547
    .line 548
    :goto_d
    if-eqz v3, :cond_c

    .line 549
    .line 550
    iget-object v6, v3, La8/w0;->m:La8/w0;

    .line 551
    .line 552
    if-eq v6, v0, :cond_c

    .line 553
    .line 554
    move-object v3, v6

    .line 555
    goto :goto_d

    .line 556
    :cond_c
    invoke-virtual {v5, v3}, La8/z0;->n(La8/w0;)I

    .line 557
    .line 558
    .line 559
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 560
    .line 561
    iget v0, v0, La8/i1;->e:I

    .line 562
    .line 563
    if-eq v0, v4, :cond_14

    .line 564
    .line 565
    invoke-virtual {v1}, La8/q0;->C()V

    .line 566
    .line 567
    .line 568
    invoke-virtual {v15, v2}, Lw7/t;->e(I)Z

    .line 569
    .line 570
    .line 571
    goto/16 :goto_f

    .line 572
    .line 573
    :cond_d
    iget-object v2, v1, La8/q0;->b0:La8/o;

    .line 574
    .line 575
    if-eqz v2, :cond_e

    .line 576
    .line 577
    invoke-virtual {v2, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 578
    .line 579
    .line 580
    iget-object v0, v1, La8/q0;->b0:La8/o;

    .line 581
    .line 582
    :cond_e
    iget v2, v0, La8/o;->f:I

    .line 583
    .line 584
    if-ne v2, v14, :cond_10

    .line 585
    .line 586
    iget-object v2, v5, La8/z0;->i:La8/w0;

    .line 587
    .line 588
    iget-object v3, v5, La8/z0;->j:La8/w0;

    .line 589
    .line 590
    if-eq v2, v3, :cond_10

    .line 591
    .line 592
    :goto_e
    iget-object v2, v5, La8/z0;->i:La8/w0;

    .line 593
    .line 594
    iget-object v3, v5, La8/z0;->j:La8/w0;

    .line 595
    .line 596
    if-eq v2, v3, :cond_f

    .line 597
    .line 598
    invoke-virtual {v5}, La8/z0;->a()La8/w0;

    .line 599
    .line 600
    .line 601
    goto :goto_e

    .line 602
    :cond_f
    invoke-static {v2}, Lw7/a;->h(La8/w0;)V

    .line 603
    .line 604
    .line 605
    invoke-virtual {v1}, La8/q0;->E()V

    .line 606
    .line 607
    .line 608
    iget-object v2, v2, La8/w0;->g:La8/x0;

    .line 609
    .line 610
    iget-object v3, v2, La8/x0;->a:Lh8/b0;

    .line 611
    .line 612
    move-object v5, v3

    .line 613
    iget-wide v3, v2, La8/x0;->b:J

    .line 614
    .line 615
    iget-wide v6, v2, La8/x0;->c:J

    .line 616
    .line 617
    const/4 v9, 0x1

    .line 618
    const/4 v10, 0x0

    .line 619
    move-object v2, v5

    .line 620
    move-wide v5, v6

    .line 621
    move-wide v7, v3

    .line 622
    invoke-virtual/range {v1 .. v10}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 623
    .line 624
    .line 625
    move-result-object v2

    .line 626
    iput-object v2, v1, La8/q0;->I:La8/i1;

    .line 627
    .line 628
    :cond_10
    iget-boolean v2, v0, La8/o;->l:Z

    .line 629
    .line 630
    if-eqz v2, :cond_13

    .line 631
    .line 632
    iget-object v2, v1, La8/q0;->b0:La8/o;

    .line 633
    .line 634
    if-eqz v2, :cond_11

    .line 635
    .line 636
    iget v2, v0, Lt7/f0;->d:I

    .line 637
    .line 638
    const/16 v3, 0x138c

    .line 639
    .line 640
    if-eq v2, v3, :cond_11

    .line 641
    .line 642
    const/16 v3, 0x138b

    .line 643
    .line 644
    if-ne v2, v3, :cond_13

    .line 645
    .line 646
    :cond_11
    const-string v2, "Recoverable renderer error"

    .line 647
    .line 648
    invoke-static {v12, v2, v0}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 649
    .line 650
    .line 651
    iget-object v2, v1, La8/q0;->b0:La8/o;

    .line 652
    .line 653
    if-nez v2, :cond_12

    .line 654
    .line 655
    iput-object v0, v1, La8/q0;->b0:La8/o;

    .line 656
    .line 657
    :cond_12
    const/16 v2, 0x19

    .line 658
    .line 659
    invoke-virtual {v15, v2, v0}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 660
    .line 661
    .line 662
    move-result-object v0

    .line 663
    iget-object v2, v15, Lw7/t;->a:Landroid/os/Handler;

    .line 664
    .line 665
    iget-object v3, v0, Lw7/s;->a:Landroid/os/Message;

    .line 666
    .line 667
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 668
    .line 669
    .line 670
    invoke-virtual {v2, v3}, Landroid/os/Handler;->sendMessageAtFrontOfQueue(Landroid/os/Message;)Z

    .line 671
    .line 672
    .line 673
    invoke-virtual {v0}, Lw7/s;->a()V

    .line 674
    .line 675
    .line 676
    goto :goto_f

    .line 677
    :cond_13
    invoke-static {v12, v11, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 678
    .line 679
    .line 680
    invoke-virtual {v1, v14, v13}, La8/q0;->t0(ZZ)V

    .line 681
    .line 682
    .line 683
    iget-object v2, v1, La8/q0;->I:La8/i1;

    .line 684
    .line 685
    invoke-virtual {v2, v0}, La8/i1;->f(La8/o;)La8/i1;

    .line 686
    .line 687
    .line 688
    move-result-object v0

    .line 689
    iput-object v0, v1, La8/q0;->I:La8/i1;

    .line 690
    .line 691
    :cond_14
    :goto_f
    invoke-virtual {v1}, La8/q0;->E()V

    .line 692
    .line 693
    .line 694
    return v14

    .line 695
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
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
        :pswitch_0
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
    .end packed-switch
.end method

.method public final i(I)V
    .locals 7

    .line 1
    iget-object v0, p0, La8/q0;->d:[La8/p1;

    .line 2
    .line 3
    aget-object v1, v0, p1

    .line 4
    .line 5
    invoke-virtual {v1}, La8/p1;->c()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    aget-object v0, v0, p1

    .line 10
    .line 11
    iget-object v2, v0, La8/p1;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, La8/f;

    .line 14
    .line 15
    iget-object v3, p0, La8/q0;->q:La8/l;

    .line 16
    .line 17
    invoke-virtual {v0, v2, v3}, La8/p1;->a(La8/f;La8/l;)V

    .line 18
    .line 19
    .line 20
    iget-object v2, v0, La8/p1;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v2, La8/f;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    iget v5, v2, La8/f;->k:I

    .line 28
    .line 29
    if-eqz v5, :cond_0

    .line 30
    .line 31
    iget v5, v0, La8/p1;->d:I

    .line 32
    .line 33
    const/4 v6, 0x3

    .line 34
    if-eq v5, v6, :cond_0

    .line 35
    .line 36
    const/4 v5, 0x1

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move v5, v4

    .line 39
    :goto_0
    invoke-virtual {v0, v2, v3}, La8/p1;->a(La8/f;La8/l;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, v4}, La8/p1;->i(Z)V

    .line 43
    .line 44
    .line 45
    if-eqz v5, :cond_1

    .line 46
    .line 47
    iget-object v3, v0, La8/p1;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v3, La8/f;

    .line 50
    .line 51
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    const/16 v5, 0x11

    .line 55
    .line 56
    invoke-interface {v2, v5, v3}, La8/k1;->a(ILjava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    iput v4, v0, La8/p1;->d:I

    .line 60
    .line 61
    invoke-virtual {p0, p1, v4}, La8/q0;->G(IZ)V

    .line 62
    .line 63
    .line 64
    iget p1, p0, La8/q0;->V:I

    .line 65
    .line 66
    sub-int/2addr p1, v1

    .line 67
    iput p1, p0, La8/q0;->V:I

    .line 68
    .line 69
    return-void
.end method

.method public final i0(La8/q1;)V
    .locals 0

    .line 1
    iput-object p1, p0, La8/q0;->E:La8/q1;

    .line 2
    .line 3
    invoke-virtual {p0}, La8/q0;->d()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final j()V
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, La8/q0;->s:Lw7/r;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 9
    .line 10
    .line 11
    move-result-wide v10

    .line 12
    iget-object v1, v0, La8/q0;->k:Lw7/t;

    .line 13
    .line 14
    const/4 v12, 0x2

    .line 15
    invoke-virtual {v1, v12}, Lw7/t;->d(I)V

    .line 16
    .line 17
    .line 18
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 19
    .line 20
    iget-object v1, v1, La8/i1;->a:Lt7/p0;

    .line 21
    .line 22
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    const/4 v13, 0x0

    .line 27
    const-wide v14, -0x7fffffffffffffffL    # -4.9E-324

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    const/4 v8, 0x4

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x1

    .line 35
    if-nez v1, :cond_0

    .line 36
    .line 37
    iget-object v1, v0, La8/q0;->v:Lac/i;

    .line 38
    .line 39
    iget-boolean v1, v1, Lac/i;->a:Z

    .line 40
    .line 41
    if-nez v1, :cond_1

    .line 42
    .line 43
    :cond_0
    move v13, v7

    .line 44
    move-wide/from16 v23, v10

    .line 45
    .line 46
    move-wide/from16 v27, v14

    .line 47
    .line 48
    const/4 v15, 0x3

    .line 49
    move v14, v8

    .line 50
    goto/16 :goto_33

    .line 51
    .line 52
    :cond_1
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 53
    .line 54
    iget-wide v2, v0, La8/q0;->X:J

    .line 55
    .line 56
    invoke-virtual {v1, v2, v3}, La8/z0;->m(J)V

    .line 57
    .line 58
    .line 59
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 60
    .line 61
    iget-object v2, v1, La8/z0;->l:La8/w0;

    .line 62
    .line 63
    if-eqz v2, :cond_3

    .line 64
    .line 65
    iget-object v3, v2, La8/w0;->g:La8/x0;

    .line 66
    .line 67
    iget-boolean v3, v3, La8/x0;->j:Z

    .line 68
    .line 69
    if-nez v3, :cond_2

    .line 70
    .line 71
    invoke-virtual {v2}, La8/w0;->g()Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    if-eqz v2, :cond_2

    .line 76
    .line 77
    iget-object v2, v1, La8/z0;->l:La8/w0;

    .line 78
    .line 79
    iget-object v2, v2, La8/w0;->g:La8/x0;

    .line 80
    .line 81
    iget-wide v2, v2, La8/x0;->e:J

    .line 82
    .line 83
    cmp-long v2, v2, v14

    .line 84
    .line 85
    if-eqz v2, :cond_2

    .line 86
    .line 87
    iget v1, v1, La8/z0;->n:I

    .line 88
    .line 89
    const/16 v2, 0x64

    .line 90
    .line 91
    if-ge v1, v2, :cond_2

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_2
    move-wide/from16 v23, v10

    .line 95
    .line 96
    goto/16 :goto_9

    .line 97
    .line 98
    :cond_3
    :goto_0
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 99
    .line 100
    iget-wide v2, v0, La8/q0;->X:J

    .line 101
    .line 102
    iget-object v4, v0, La8/q0;->I:La8/i1;

    .line 103
    .line 104
    iget-object v5, v1, La8/z0;->l:La8/w0;

    .line 105
    .line 106
    if-nez v5, :cond_4

    .line 107
    .line 108
    iget-object v2, v4, La8/i1;->a:Lt7/p0;

    .line 109
    .line 110
    iget-object v3, v4, La8/i1;->b:Lh8/b0;

    .line 111
    .line 112
    move-wide/from16 v23, v10

    .line 113
    .line 114
    iget-wide v9, v4, La8/i1;->c:J

    .line 115
    .line 116
    iget-wide v4, v4, La8/i1;->s:J

    .line 117
    .line 118
    move-object/from16 v16, v1

    .line 119
    .line 120
    move-object/from16 v17, v2

    .line 121
    .line 122
    move-object/from16 v18, v3

    .line 123
    .line 124
    move-wide/from16 v21, v4

    .line 125
    .line 126
    move-wide/from16 v19, v9

    .line 127
    .line 128
    invoke-virtual/range {v16 .. v22}, La8/z0;->d(Lt7/p0;Lh8/b0;JJ)La8/x0;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    goto :goto_1

    .line 133
    :cond_4
    move-wide/from16 v23, v10

    .line 134
    .line 135
    iget-object v4, v4, La8/i1;->a:Lt7/p0;

    .line 136
    .line 137
    invoke-virtual {v1, v4, v5, v2, v3}, La8/z0;->c(Lt7/p0;La8/w0;J)La8/x0;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    :goto_1
    if-eqz v1, :cond_f

    .line 142
    .line 143
    iget-object v2, v0, La8/q0;->u:La8/z0;

    .line 144
    .line 145
    iget-object v3, v2, La8/z0;->l:La8/w0;

    .line 146
    .line 147
    if-nez v3, :cond_5

    .line 148
    .line 149
    const-wide v3, 0xe8d4a51000L

    .line 150
    .line 151
    .line 152
    .line 153
    .line 154
    :goto_2
    move-wide/from16 v27, v3

    .line 155
    .line 156
    goto :goto_3

    .line 157
    :cond_5
    iget-wide v4, v3, La8/w0;->p:J

    .line 158
    .line 159
    iget-object v3, v3, La8/w0;->g:La8/x0;

    .line 160
    .line 161
    iget-wide v9, v3, La8/x0;->e:J

    .line 162
    .line 163
    add-long/2addr v4, v9

    .line 164
    iget-wide v9, v1, La8/x0;->b:J

    .line 165
    .line 166
    sub-long v3, v4, v9

    .line 167
    .line 168
    goto :goto_2

    .line 169
    :goto_3
    move v3, v6

    .line 170
    :goto_4
    iget-object v4, v2, La8/z0;->q:Ljava/util/ArrayList;

    .line 171
    .line 172
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 173
    .line 174
    .line 175
    move-result v4

    .line 176
    if-ge v3, v4, :cond_8

    .line 177
    .line 178
    iget-object v4, v2, La8/z0;->q:Ljava/util/ArrayList;

    .line 179
    .line 180
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v4

    .line 184
    check-cast v4, La8/w0;

    .line 185
    .line 186
    iget-object v4, v4, La8/w0;->g:La8/x0;

    .line 187
    .line 188
    iget-wide v9, v4, La8/x0;->e:J

    .line 189
    .line 190
    iget-wide v11, v1, La8/x0;->e:J

    .line 191
    .line 192
    cmp-long v5, v9, v14

    .line 193
    .line 194
    if-eqz v5, :cond_6

    .line 195
    .line 196
    cmp-long v5, v9, v11

    .line 197
    .line 198
    if-nez v5, :cond_7

    .line 199
    .line 200
    :cond_6
    iget-wide v9, v4, La8/x0;->b:J

    .line 201
    .line 202
    iget-wide v11, v1, La8/x0;->b:J

    .line 203
    .line 204
    cmp-long v5, v9, v11

    .line 205
    .line 206
    if-nez v5, :cond_7

    .line 207
    .line 208
    iget-object v4, v4, La8/x0;->a:Lh8/b0;

    .line 209
    .line 210
    iget-object v5, v1, La8/x0;->a:Lh8/b0;

    .line 211
    .line 212
    invoke-virtual {v4, v5}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    if-eqz v4, :cond_7

    .line 217
    .line 218
    iget-object v4, v2, La8/z0;->q:Ljava/util/ArrayList;

    .line 219
    .line 220
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v3

    .line 224
    check-cast v3, La8/w0;

    .line 225
    .line 226
    goto :goto_5

    .line 227
    :cond_7
    add-int/lit8 v3, v3, 0x1

    .line 228
    .line 229
    const/4 v12, 0x2

    .line 230
    goto :goto_4

    .line 231
    :cond_8
    move-object v3, v13

    .line 232
    :goto_5
    if-nez v3, :cond_9

    .line 233
    .line 234
    iget-object v3, v2, La8/z0;->e:La8/t;

    .line 235
    .line 236
    iget-object v3, v3, La8/t;->e:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast v3, La8/q0;

    .line 239
    .line 240
    new-instance v25, La8/w0;

    .line 241
    .line 242
    iget-object v4, v3, La8/q0;->e:[La8/f;

    .line 243
    .line 244
    iget-object v5, v3, La8/q0;->g:Lh/w;

    .line 245
    .line 246
    iget-object v9, v3, La8/q0;->i:La8/k;

    .line 247
    .line 248
    iget-object v9, v9, La8/k;->a:Lk8/e;

    .line 249
    .line 250
    iget-object v10, v3, La8/q0;->v:Lac/i;

    .line 251
    .line 252
    iget-object v11, v3, La8/q0;->h:Lj8/s;

    .line 253
    .line 254
    iget-object v3, v3, La8/q0;->d0:La8/r;

    .line 255
    .line 256
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 257
    .line 258
    .line 259
    move-object/from16 v32, v1

    .line 260
    .line 261
    move-object/from16 v26, v4

    .line 262
    .line 263
    move-object/from16 v29, v5

    .line 264
    .line 265
    move-object/from16 v30, v9

    .line 266
    .line 267
    move-object/from16 v31, v10

    .line 268
    .line 269
    move-object/from16 v33, v11

    .line 270
    .line 271
    invoke-direct/range {v25 .. v33}, La8/w0;-><init>([La8/f;JLh/w;Lk8/e;Lac/i;La8/x0;Lj8/s;)V

    .line 272
    .line 273
    .line 274
    move-object/from16 v3, v25

    .line 275
    .line 276
    goto :goto_6

    .line 277
    :cond_9
    move-wide/from16 v4, v27

    .line 278
    .line 279
    iput-object v1, v3, La8/w0;->g:La8/x0;

    .line 280
    .line 281
    iput-wide v4, v3, La8/w0;->p:J

    .line 282
    .line 283
    :goto_6
    iget-object v4, v2, La8/z0;->l:La8/w0;

    .line 284
    .line 285
    if-eqz v4, :cond_b

    .line 286
    .line 287
    iget-object v5, v4, La8/w0;->m:La8/w0;

    .line 288
    .line 289
    if-ne v3, v5, :cond_a

    .line 290
    .line 291
    goto :goto_7

    .line 292
    :cond_a
    invoke-virtual {v4}, La8/w0;->b()V

    .line 293
    .line 294
    .line 295
    iput-object v3, v4, La8/w0;->m:La8/w0;

    .line 296
    .line 297
    invoke-virtual {v4}, La8/w0;->c()V

    .line 298
    .line 299
    .line 300
    goto :goto_7

    .line 301
    :cond_b
    iput-object v3, v2, La8/z0;->i:La8/w0;

    .line 302
    .line 303
    iput-object v3, v2, La8/z0;->j:La8/w0;

    .line 304
    .line 305
    iput-object v3, v2, La8/z0;->k:La8/w0;

    .line 306
    .line 307
    :goto_7
    iput-object v13, v2, La8/z0;->o:Ljava/lang/Object;

    .line 308
    .line 309
    iput-object v3, v2, La8/z0;->l:La8/w0;

    .line 310
    .line 311
    iget v4, v2, La8/z0;->n:I

    .line 312
    .line 313
    add-int/2addr v4, v7

    .line 314
    iput v4, v2, La8/z0;->n:I

    .line 315
    .line 316
    invoke-virtual {v2}, La8/z0;->l()V

    .line 317
    .line 318
    .line 319
    iget-boolean v2, v3, La8/w0;->d:Z

    .line 320
    .line 321
    if-nez v2, :cond_c

    .line 322
    .line 323
    iget-wide v4, v1, La8/x0;->b:J

    .line 324
    .line 325
    iput-boolean v7, v3, La8/w0;->d:Z

    .line 326
    .line 327
    iget-object v2, v3, La8/w0;->a:Ljava/lang/Object;

    .line 328
    .line 329
    invoke-interface {v2, v0, v4, v5}, Lh8/z;->h(Lh8/y;J)V

    .line 330
    .line 331
    .line 332
    goto :goto_8

    .line 333
    :cond_c
    iget-boolean v2, v3, La8/w0;->e:Z

    .line 334
    .line 335
    if-eqz v2, :cond_d

    .line 336
    .line 337
    iget-object v2, v0, La8/q0;->k:Lw7/t;

    .line 338
    .line 339
    const/16 v4, 0x8

    .line 340
    .line 341
    iget-object v5, v3, La8/w0;->a:Ljava/lang/Object;

    .line 342
    .line 343
    invoke-virtual {v2, v4, v5}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 344
    .line 345
    .line 346
    move-result-object v2

    .line 347
    invoke-virtual {v2}, Lw7/s;->b()V

    .line 348
    .line 349
    .line 350
    :cond_d
    :goto_8
    iget-object v2, v0, La8/q0;->u:La8/z0;

    .line 351
    .line 352
    iget-object v2, v2, La8/z0;->i:La8/w0;

    .line 353
    .line 354
    if-ne v2, v3, :cond_e

    .line 355
    .line 356
    iget-wide v1, v1, La8/x0;->b:J

    .line 357
    .line 358
    invoke-virtual {v0, v1, v2}, La8/q0;->Q(J)V

    .line 359
    .line 360
    .line 361
    :cond_e
    invoke-virtual {v0, v6}, La8/q0;->u(Z)V

    .line 362
    .line 363
    .line 364
    :cond_f
    :goto_9
    iget-boolean v1, v0, La8/q0;->P:Z

    .line 365
    .line 366
    if-eqz v1, :cond_10

    .line 367
    .line 368
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 369
    .line 370
    iget-object v1, v1, La8/z0;->l:La8/w0;

    .line 371
    .line 372
    invoke-static {v1}, La8/q0;->z(La8/w0;)Z

    .line 373
    .line 374
    .line 375
    move-result v1

    .line 376
    iput-boolean v1, v0, La8/q0;->P:Z

    .line 377
    .line 378
    invoke-virtual {v0}, La8/q0;->v0()V

    .line 379
    .line 380
    .line 381
    goto :goto_a

    .line 382
    :cond_10
    invoke-virtual {v0}, La8/q0;->C()V

    .line 383
    .line 384
    .line 385
    :goto_a
    iget-object v9, v0, La8/q0;->u:La8/z0;

    .line 386
    .line 387
    iget-boolean v1, v0, La8/q0;->M:Z

    .line 388
    .line 389
    if-nez v1, :cond_18

    .line 390
    .line 391
    iget-boolean v1, v0, La8/q0;->B:Z

    .line 392
    .line 393
    if-eqz v1, :cond_18

    .line 394
    .line 395
    iget-boolean v1, v0, La8/q0;->f0:Z

    .line 396
    .line 397
    if-nez v1, :cond_18

    .line 398
    .line 399
    invoke-virtual {v0}, La8/q0;->e()Z

    .line 400
    .line 401
    .line 402
    move-result v1

    .line 403
    if-eqz v1, :cond_11

    .line 404
    .line 405
    goto/16 :goto_d

    .line 406
    .line 407
    :cond_11
    iget-object v1, v9, La8/z0;->k:La8/w0;

    .line 408
    .line 409
    if-eqz v1, :cond_18

    .line 410
    .line 411
    iget-object v2, v9, La8/z0;->j:La8/w0;

    .line 412
    .line 413
    if-ne v1, v2, :cond_18

    .line 414
    .line 415
    iget-object v1, v1, La8/w0;->m:La8/w0;

    .line 416
    .line 417
    if-eqz v1, :cond_18

    .line 418
    .line 419
    iget-boolean v2, v1, La8/w0;->e:Z

    .line 420
    .line 421
    if-nez v2, :cond_12

    .line 422
    .line 423
    goto/16 :goto_d

    .line 424
    .line 425
    :cond_12
    iput-object v1, v9, La8/z0;->k:La8/w0;

    .line 426
    .line 427
    invoke-virtual {v9}, La8/z0;->l()V

    .line 428
    .line 429
    .line 430
    iget-object v1, v9, La8/z0;->k:La8/w0;

    .line 431
    .line 432
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 433
    .line 434
    .line 435
    iget-object v10, v0, La8/q0;->d:[La8/p1;

    .line 436
    .line 437
    iget-object v1, v9, La8/z0;->k:La8/w0;

    .line 438
    .line 439
    if-nez v1, :cond_13

    .line 440
    .line 441
    goto :goto_d

    .line 442
    :cond_13
    iget-object v11, v1, La8/w0;->o:Lj8/s;

    .line 443
    .line 444
    move v2, v6

    .line 445
    :goto_b
    array-length v3, v10

    .line 446
    if-ge v2, v3, :cond_17

    .line 447
    .line 448
    invoke-virtual {v11, v2}, Lj8/s;->b(I)Z

    .line 449
    .line 450
    .line 451
    move-result v3

    .line 452
    if-eqz v3, :cond_16

    .line 453
    .line 454
    aget-object v3, v10, v2

    .line 455
    .line 456
    iget-object v4, v3, La8/p1;->f:Ljava/lang/Object;

    .line 457
    .line 458
    check-cast v4, La8/f;

    .line 459
    .line 460
    if-eqz v4, :cond_16

    .line 461
    .line 462
    invoke-virtual {v3}, La8/p1;->f()Z

    .line 463
    .line 464
    .line 465
    move-result v3

    .line 466
    if-nez v3, :cond_16

    .line 467
    .line 468
    aget-object v3, v10, v2

    .line 469
    .line 470
    invoke-virtual {v3}, La8/p1;->f()Z

    .line 471
    .line 472
    .line 473
    move-result v4

    .line 474
    xor-int/2addr v4, v7

    .line 475
    invoke-static {v4}, Lw7/a;->j(Z)V

    .line 476
    .line 477
    .line 478
    iget-object v4, v3, La8/p1;->e:Ljava/lang/Object;

    .line 479
    .line 480
    check-cast v4, La8/f;

    .line 481
    .line 482
    invoke-static {v4}, La8/p1;->h(La8/f;)Z

    .line 483
    .line 484
    .line 485
    move-result v4

    .line 486
    if-eqz v4, :cond_14

    .line 487
    .line 488
    const/4 v4, 0x3

    .line 489
    goto :goto_c

    .line 490
    :cond_14
    iget-object v4, v3, La8/p1;->f:Ljava/lang/Object;

    .line 491
    .line 492
    check-cast v4, La8/f;

    .line 493
    .line 494
    if-eqz v4, :cond_15

    .line 495
    .line 496
    iget v4, v4, La8/f;->k:I

    .line 497
    .line 498
    if-eqz v4, :cond_15

    .line 499
    .line 500
    move v4, v8

    .line 501
    goto :goto_c

    .line 502
    :cond_15
    const/4 v4, 0x2

    .line 503
    :goto_c
    iput v4, v3, La8/p1;->d:I

    .line 504
    .line 505
    const/4 v3, 0x0

    .line 506
    invoke-virtual {v1}, La8/w0;->e()J

    .line 507
    .line 508
    .line 509
    move-result-wide v4

    .line 510
    invoke-virtual/range {v0 .. v5}, La8/q0;->k(La8/w0;IZJ)V

    .line 511
    .line 512
    .line 513
    :cond_16
    add-int/lit8 v2, v2, 0x1

    .line 514
    .line 515
    goto :goto_b

    .line 516
    :cond_17
    invoke-virtual {v0}, La8/q0;->e()Z

    .line 517
    .line 518
    .line 519
    move-result v2

    .line 520
    if-eqz v2, :cond_18

    .line 521
    .line 522
    iget-object v2, v1, La8/w0;->a:Ljava/lang/Object;

    .line 523
    .line 524
    invoke-interface {v2}, Lh8/z;->g()J

    .line 525
    .line 526
    .line 527
    move-result-wide v2

    .line 528
    iput-wide v2, v0, La8/q0;->e0:J

    .line 529
    .line 530
    invoke-virtual {v1}, La8/w0;->g()Z

    .line 531
    .line 532
    .line 533
    move-result v2

    .line 534
    if-nez v2, :cond_18

    .line 535
    .line 536
    invoke-virtual {v9, v1}, La8/z0;->n(La8/w0;)I

    .line 537
    .line 538
    .line 539
    invoke-virtual {v0, v6}, La8/q0;->u(Z)V

    .line 540
    .line 541
    .line 542
    invoke-virtual {v0}, La8/q0;->C()V

    .line 543
    .line 544
    .line 545
    :cond_18
    :goto_d
    iget-boolean v9, v0, La8/q0;->B:Z

    .line 546
    .line 547
    iget-object v10, v0, La8/q0;->d:[La8/p1;

    .line 548
    .line 549
    iget-object v12, v0, La8/q0;->u:La8/z0;

    .line 550
    .line 551
    iget-object v1, v12, La8/z0;->j:La8/w0;

    .line 552
    .line 553
    if-nez v1, :cond_19

    .line 554
    .line 555
    :goto_e
    goto/16 :goto_16

    .line 556
    .line 557
    :cond_19
    iget-object v2, v1, La8/w0;->m:La8/w0;

    .line 558
    .line 559
    if-eqz v2, :cond_1a

    .line 560
    .line 561
    iget-boolean v2, v0, La8/q0;->M:Z

    .line 562
    .line 563
    if-eqz v2, :cond_1b

    .line 564
    .line 565
    :cond_1a
    move-wide/from16 v27, v14

    .line 566
    .line 567
    const/4 v14, 0x3

    .line 568
    goto/16 :goto_1a

    .line 569
    .line 570
    :cond_1b
    iget-boolean v2, v1, La8/w0;->e:Z

    .line 571
    .line 572
    if-nez v2, :cond_1c

    .line 573
    .line 574
    goto :goto_e

    .line 575
    :cond_1c
    move v2, v6

    .line 576
    :goto_f
    array-length v3, v10

    .line 577
    if-ge v2, v3, :cond_1d

    .line 578
    .line 579
    aget-object v3, v10, v2

    .line 580
    .line 581
    iget-object v4, v3, La8/p1;->e:Ljava/lang/Object;

    .line 582
    .line 583
    check-cast v4, La8/f;

    .line 584
    .line 585
    invoke-virtual {v3, v1, v4}, La8/p1;->e(La8/w0;La8/f;)Z

    .line 586
    .line 587
    .line 588
    move-result v4

    .line 589
    if-eqz v4, :cond_2b

    .line 590
    .line 591
    iget-object v4, v3, La8/p1;->f:Ljava/lang/Object;

    .line 592
    .line 593
    check-cast v4, La8/f;

    .line 594
    .line 595
    invoke-virtual {v3, v1, v4}, La8/p1;->e(La8/w0;La8/f;)Z

    .line 596
    .line 597
    .line 598
    move-result v3

    .line 599
    if-eqz v3, :cond_2b

    .line 600
    .line 601
    add-int/lit8 v2, v2, 0x1

    .line 602
    .line 603
    goto :goto_f

    .line 604
    :cond_1d
    invoke-virtual {v0}, La8/q0;->e()Z

    .line 605
    .line 606
    .line 607
    move-result v2

    .line 608
    if-eqz v2, :cond_1e

    .line 609
    .line 610
    iget-object v2, v12, La8/z0;->k:La8/w0;

    .line 611
    .line 612
    iget-object v3, v12, La8/z0;->j:La8/w0;

    .line 613
    .line 614
    if-ne v2, v3, :cond_1e

    .line 615
    .line 616
    goto :goto_e

    .line 617
    :cond_1e
    iget-object v2, v1, La8/w0;->m:La8/w0;

    .line 618
    .line 619
    iget-boolean v3, v2, La8/w0;->e:Z

    .line 620
    .line 621
    if-nez v3, :cond_1f

    .line 622
    .line 623
    iget-wide v3, v0, La8/q0;->X:J

    .line 624
    .line 625
    invoke-virtual {v2}, La8/w0;->e()J

    .line 626
    .line 627
    .line 628
    move-result-wide v18

    .line 629
    cmp-long v2, v3, v18

    .line 630
    .line 631
    if-gez v2, :cond_1f

    .line 632
    .line 633
    goto :goto_e

    .line 634
    :cond_1f
    iget-object v11, v1, La8/w0;->o:Lj8/s;

    .line 635
    .line 636
    iget-object v2, v12, La8/z0;->k:La8/w0;

    .line 637
    .line 638
    iget-object v3, v12, La8/z0;->j:La8/w0;

    .line 639
    .line 640
    if-ne v2, v3, :cond_20

    .line 641
    .line 642
    invoke-static {v3}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 643
    .line 644
    .line 645
    iget-object v2, v3, La8/w0;->m:La8/w0;

    .line 646
    .line 647
    iput-object v2, v12, La8/z0;->k:La8/w0;

    .line 648
    .line 649
    :cond_20
    iget-object v2, v12, La8/z0;->j:La8/w0;

    .line 650
    .line 651
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 652
    .line 653
    .line 654
    iget-object v2, v2, La8/w0;->m:La8/w0;

    .line 655
    .line 656
    iput-object v2, v12, La8/z0;->j:La8/w0;

    .line 657
    .line 658
    invoke-virtual {v12}, La8/z0;->l()V

    .line 659
    .line 660
    .line 661
    iget-object v2, v12, La8/z0;->j:La8/w0;

    .line 662
    .line 663
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 664
    .line 665
    .line 666
    iget-object v3, v2, La8/w0;->o:Lj8/s;

    .line 667
    .line 668
    iget-object v4, v0, La8/q0;->I:La8/i1;

    .line 669
    .line 670
    iget-object v4, v4, La8/i1;->a:Lt7/p0;

    .line 671
    .line 672
    iget-object v5, v2, La8/w0;->g:La8/x0;

    .line 673
    .line 674
    iget-object v5, v5, La8/x0;->a:Lh8/b0;

    .line 675
    .line 676
    iget-object v1, v1, La8/w0;->g:La8/x0;

    .line 677
    .line 678
    iget-object v1, v1, La8/x0;->a:Lh8/b0;

    .line 679
    .line 680
    move-object/from16 v18, v2

    .line 681
    .line 682
    move-object v2, v5

    .line 683
    move/from16 v19, v6

    .line 684
    .line 685
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 686
    .line 687
    .line 688
    .line 689
    .line 690
    move/from16 v20, v7

    .line 691
    .line 692
    const/4 v7, 0x0

    .line 693
    move-object/from16 v21, v3

    .line 694
    .line 695
    move-object v3, v4

    .line 696
    move-object v13, v4

    .line 697
    move-object v4, v1

    .line 698
    move-object v1, v13

    .line 699
    move-object/from16 v13, v18

    .line 700
    .line 701
    move/from16 v18, v9

    .line 702
    .line 703
    move-object v9, v13

    .line 704
    move-object/from16 v13, v21

    .line 705
    .line 706
    invoke-virtual/range {v0 .. v7}, La8/q0;->A0(Lt7/p0;Lh8/b0;Lt7/p0;Lh8/b0;JZ)V

    .line 707
    .line 708
    .line 709
    iget-boolean v1, v9, La8/w0;->e:Z

    .line 710
    .line 711
    const/4 v2, -0x2

    .line 712
    if-eqz v1, :cond_2c

    .line 713
    .line 714
    if-eqz v18, :cond_21

    .line 715
    .line 716
    iget-wide v3, v0, La8/q0;->e0:J

    .line 717
    .line 718
    cmp-long v1, v3, v14

    .line 719
    .line 720
    if-nez v1, :cond_22

    .line 721
    .line 722
    :cond_21
    iget-object v1, v9, La8/w0;->a:Ljava/lang/Object;

    .line 723
    .line 724
    invoke-interface {v1}, Lh8/z;->g()J

    .line 725
    .line 726
    .line 727
    move-result-wide v3

    .line 728
    cmp-long v1, v3, v14

    .line 729
    .line 730
    if-eqz v1, :cond_2c

    .line 731
    .line 732
    :cond_22
    iput-wide v14, v0, La8/q0;->e0:J

    .line 733
    .line 734
    if-eqz v18, :cond_23

    .line 735
    .line 736
    iget-boolean v1, v0, La8/q0;->f0:Z

    .line 737
    .line 738
    if-nez v1, :cond_23

    .line 739
    .line 740
    const/4 v6, 0x1

    .line 741
    goto :goto_10

    .line 742
    :cond_23
    const/4 v6, 0x0

    .line 743
    :goto_10
    if-eqz v6, :cond_26

    .line 744
    .line 745
    const/4 v1, 0x0

    .line 746
    :goto_11
    array-length v3, v10

    .line 747
    if-ge v1, v3, :cond_26

    .line 748
    .line 749
    invoke-virtual {v13, v1}, Lj8/s;->b(I)Z

    .line 750
    .line 751
    .line 752
    move-result v3

    .line 753
    iget-object v4, v13, Lj8/s;->c:[Lj8/q;

    .line 754
    .line 755
    if-eqz v3, :cond_25

    .line 756
    .line 757
    aget-object v3, v10, v1

    .line 758
    .line 759
    iget-object v3, v3, La8/p1;->e:Ljava/lang/Object;

    .line 760
    .line 761
    check-cast v3, La8/f;

    .line 762
    .line 763
    iget v3, v3, La8/f;->e:I

    .line 764
    .line 765
    if-ne v3, v2, :cond_24

    .line 766
    .line 767
    goto :goto_12

    .line 768
    :cond_24
    aget-object v3, v4, v1

    .line 769
    .line 770
    invoke-interface {v3}, Lj8/q;->k()Lt7/o;

    .line 771
    .line 772
    .line 773
    move-result-object v3

    .line 774
    iget-object v3, v3, Lt7/o;->n:Ljava/lang/String;

    .line 775
    .line 776
    aget-object v4, v4, v1

    .line 777
    .line 778
    invoke-interface {v4}, Lj8/q;->k()Lt7/o;

    .line 779
    .line 780
    .line 781
    move-result-object v4

    .line 782
    iget-object v4, v4, Lt7/o;->k:Ljava/lang/String;

    .line 783
    .line 784
    invoke-static {v3, v4}, Lt7/d0;->a(Ljava/lang/String;Ljava/lang/String;)Z

    .line 785
    .line 786
    .line 787
    move-result v3

    .line 788
    if-nez v3, :cond_25

    .line 789
    .line 790
    aget-object v3, v10, v1

    .line 791
    .line 792
    invoke-virtual {v3}, La8/p1;->f()Z

    .line 793
    .line 794
    .line 795
    move-result v3

    .line 796
    if-nez v3, :cond_25

    .line 797
    .line 798
    const/4 v6, 0x0

    .line 799
    goto :goto_13

    .line 800
    :cond_25
    :goto_12
    add-int/lit8 v1, v1, 0x1

    .line 801
    .line 802
    goto :goto_11

    .line 803
    :cond_26
    :goto_13
    if-nez v6, :cond_2c

    .line 804
    .line 805
    invoke-virtual {v9}, La8/w0;->e()J

    .line 806
    .line 807
    .line 808
    move-result-wide v1

    .line 809
    array-length v3, v10

    .line 810
    const/4 v6, 0x0

    .line 811
    :goto_14
    if-ge v6, v3, :cond_2a

    .line 812
    .line 813
    aget-object v4, v10, v6

    .line 814
    .line 815
    iget-object v5, v4, La8/p1;->f:Ljava/lang/Object;

    .line 816
    .line 817
    check-cast v5, La8/f;

    .line 818
    .line 819
    iget-object v7, v4, La8/p1;->e:Ljava/lang/Object;

    .line 820
    .line 821
    check-cast v7, La8/f;

    .line 822
    .line 823
    invoke-static {v7}, La8/p1;->h(La8/f;)Z

    .line 824
    .line 825
    .line 826
    move-result v11

    .line 827
    if-eqz v11, :cond_27

    .line 828
    .line 829
    iget v11, v4, La8/p1;->d:I

    .line 830
    .line 831
    if-eq v11, v8, :cond_27

    .line 832
    .line 833
    const/4 v13, 0x2

    .line 834
    if-eq v11, v13, :cond_27

    .line 835
    .line 836
    invoke-static {v7, v1, v2}, La8/p1;->l(La8/f;J)V

    .line 837
    .line 838
    .line 839
    :cond_27
    if-eqz v5, :cond_29

    .line 840
    .line 841
    iget v7, v5, La8/f;->k:I

    .line 842
    .line 843
    if-eqz v7, :cond_28

    .line 844
    .line 845
    const/4 v7, 0x1

    .line 846
    goto :goto_15

    .line 847
    :cond_28
    const/4 v7, 0x0

    .line 848
    :goto_15
    if-eqz v7, :cond_29

    .line 849
    .line 850
    iget v4, v4, La8/p1;->d:I

    .line 851
    .line 852
    const/4 v11, 0x3

    .line 853
    if-eq v4, v11, :cond_29

    .line 854
    .line 855
    invoke-static {v5, v1, v2}, La8/p1;->l(La8/f;J)V

    .line 856
    .line 857
    .line 858
    :cond_29
    add-int/lit8 v6, v6, 0x1

    .line 859
    .line 860
    goto :goto_14

    .line 861
    :cond_2a
    invoke-virtual {v9}, La8/w0;->g()Z

    .line 862
    .line 863
    .line 864
    move-result v1

    .line 865
    if-nez v1, :cond_2b

    .line 866
    .line 867
    invoke-virtual {v12, v9}, La8/z0;->n(La8/w0;)I

    .line 868
    .line 869
    .line 870
    const/4 v1, 0x0

    .line 871
    invoke-virtual {v0, v1}, La8/q0;->u(Z)V

    .line 872
    .line 873
    .line 874
    invoke-virtual {v0}, La8/q0;->C()V

    .line 875
    .line 876
    .line 877
    :cond_2b
    :goto_16
    move-wide/from16 v27, v14

    .line 878
    .line 879
    const/4 v14, 0x3

    .line 880
    goto/16 :goto_1f

    .line 881
    .line 882
    :cond_2c
    move-object v1, v11

    .line 883
    array-length v3, v10

    .line 884
    const/4 v6, 0x0

    .line 885
    :goto_17
    if-ge v6, v3, :cond_2b

    .line 886
    .line 887
    aget-object v4, v10, v6

    .line 888
    .line 889
    move-object/from16 v18, v9

    .line 890
    .line 891
    invoke-virtual/range {v18 .. v18}, La8/w0;->e()J

    .line 892
    .line 893
    .line 894
    move-result-wide v8

    .line 895
    iget-object v5, v4, La8/p1;->e:Ljava/lang/Object;

    .line 896
    .line 897
    check-cast v5, La8/f;

    .line 898
    .line 899
    iget v12, v4, La8/p1;->c:I

    .line 900
    .line 901
    invoke-virtual {v1, v12}, Lj8/s;->b(I)Z

    .line 902
    .line 903
    .line 904
    move-result v17

    .line 905
    invoke-virtual {v13, v12}, Lj8/s;->b(I)Z

    .line 906
    .line 907
    .line 908
    move-result v21

    .line 909
    iget-object v7, v4, La8/p1;->f:Ljava/lang/Object;

    .line 910
    .line 911
    check-cast v7, La8/f;

    .line 912
    .line 913
    if-eqz v7, :cond_2d

    .line 914
    .line 915
    iget v11, v4, La8/p1;->d:I

    .line 916
    .line 917
    move-wide/from16 v27, v14

    .line 918
    .line 919
    const/4 v14, 0x3

    .line 920
    if-eq v11, v14, :cond_2e

    .line 921
    .line 922
    if-nez v11, :cond_2f

    .line 923
    .line 924
    invoke-static {v5}, La8/p1;->h(La8/f;)Z

    .line 925
    .line 926
    .line 927
    move-result v11

    .line 928
    if-eqz v11, :cond_2f

    .line 929
    .line 930
    goto :goto_18

    .line 931
    :cond_2d
    move-wide/from16 v27, v14

    .line 932
    .line 933
    const/4 v14, 0x3

    .line 934
    :cond_2e
    :goto_18
    move-object v7, v5

    .line 935
    :cond_2f
    if-eqz v17, :cond_32

    .line 936
    .line 937
    iget-boolean v11, v7, La8/f;->q:Z

    .line 938
    .line 939
    if-nez v11, :cond_32

    .line 940
    .line 941
    iget v5, v5, La8/f;->e:I

    .line 942
    .line 943
    if-ne v5, v2, :cond_30

    .line 944
    .line 945
    const/4 v5, 0x1

    .line 946
    goto :goto_19

    .line 947
    :cond_30
    const/4 v5, 0x0

    .line 948
    :goto_19
    iget-object v11, v1, Lj8/s;->b:[La8/o1;

    .line 949
    .line 950
    aget-object v11, v11, v12

    .line 951
    .line 952
    iget-object v15, v13, Lj8/s;->b:[La8/o1;

    .line 953
    .line 954
    aget-object v12, v15, v12

    .line 955
    .line 956
    if-eqz v21, :cond_31

    .line 957
    .line 958
    invoke-static {v12, v11}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 959
    .line 960
    .line 961
    move-result v11

    .line 962
    if-eqz v11, :cond_31

    .line 963
    .line 964
    if-nez v5, :cond_31

    .line 965
    .line 966
    invoke-virtual {v4}, La8/p1;->f()Z

    .line 967
    .line 968
    .line 969
    move-result v4

    .line 970
    if-eqz v4, :cond_32

    .line 971
    .line 972
    :cond_31
    invoke-static {v7, v8, v9}, La8/p1;->l(La8/f;J)V

    .line 973
    .line 974
    .line 975
    :cond_32
    add-int/lit8 v6, v6, 0x1

    .line 976
    .line 977
    move-object/from16 v9, v18

    .line 978
    .line 979
    move-wide/from16 v14, v27

    .line 980
    .line 981
    const/4 v8, 0x4

    .line 982
    goto :goto_17

    .line 983
    :goto_1a
    iget-object v2, v1, La8/w0;->g:La8/x0;

    .line 984
    .line 985
    iget-boolean v2, v2, La8/x0;->j:Z

    .line 986
    .line 987
    if-nez v2, :cond_33

    .line 988
    .line 989
    iget-boolean v2, v0, La8/q0;->M:Z

    .line 990
    .line 991
    if-eqz v2, :cond_38

    .line 992
    .line 993
    :cond_33
    array-length v2, v10

    .line 994
    const/4 v6, 0x0

    .line 995
    :goto_1b
    if-ge v6, v2, :cond_38

    .line 996
    .line 997
    aget-object v3, v10, v6

    .line 998
    .line 999
    invoke-virtual {v3, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 1000
    .line 1001
    .line 1002
    move-result-object v4

    .line 1003
    if-eqz v4, :cond_34

    .line 1004
    .line 1005
    const/4 v4, 0x1

    .line 1006
    goto :goto_1c

    .line 1007
    :cond_34
    const/4 v4, 0x0

    .line 1008
    :goto_1c
    if-nez v4, :cond_35

    .line 1009
    .line 1010
    goto :goto_1e

    .line 1011
    :cond_35
    invoke-virtual {v3, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 1012
    .line 1013
    .line 1014
    move-result-object v4

    .line 1015
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1016
    .line 1017
    .line 1018
    invoke-virtual {v4}, La8/f;->l()Z

    .line 1019
    .line 1020
    .line 1021
    move-result v4

    .line 1022
    if-eqz v4, :cond_37

    .line 1023
    .line 1024
    iget-object v4, v1, La8/w0;->g:La8/x0;

    .line 1025
    .line 1026
    iget-wide v4, v4, La8/x0;->e:J

    .line 1027
    .line 1028
    cmp-long v7, v4, v27

    .line 1029
    .line 1030
    if-eqz v7, :cond_36

    .line 1031
    .line 1032
    const-wide/high16 v7, -0x8000000000000000L

    .line 1033
    .line 1034
    cmp-long v7, v4, v7

    .line 1035
    .line 1036
    if-eqz v7, :cond_36

    .line 1037
    .line 1038
    iget-wide v7, v1, La8/w0;->p:J

    .line 1039
    .line 1040
    add-long/2addr v4, v7

    .line 1041
    goto :goto_1d

    .line 1042
    :cond_36
    move-wide/from16 v4, v27

    .line 1043
    .line 1044
    :goto_1d
    invoke-virtual {v3, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v3

    .line 1048
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1049
    .line 1050
    .line 1051
    invoke-static {v3, v4, v5}, La8/p1;->l(La8/f;J)V

    .line 1052
    .line 1053
    .line 1054
    :cond_37
    :goto_1e
    add-int/lit8 v6, v6, 0x1

    .line 1055
    .line 1056
    goto :goto_1b

    .line 1057
    :cond_38
    :goto_1f
    iget-object v6, v0, La8/q0;->u:La8/z0;

    .line 1058
    .line 1059
    iget-object v1, v6, La8/z0;->j:La8/w0;

    .line 1060
    .line 1061
    if-eqz v1, :cond_42

    .line 1062
    .line 1063
    iget-object v2, v6, La8/z0;->i:La8/w0;

    .line 1064
    .line 1065
    if-eq v2, v1, :cond_42

    .line 1066
    .line 1067
    iget-boolean v2, v1, La8/w0;->h:Z

    .line 1068
    .line 1069
    if-eqz v2, :cond_39

    .line 1070
    .line 1071
    goto/16 :goto_25

    .line 1072
    .line 1073
    :cond_39
    iget-object v7, v0, La8/q0;->d:[La8/p1;

    .line 1074
    .line 1075
    iget-object v8, v1, La8/w0;->o:Lj8/s;

    .line 1076
    .line 1077
    const/4 v2, 0x0

    .line 1078
    const/4 v9, 0x1

    .line 1079
    :goto_20
    array-length v3, v7

    .line 1080
    if-ge v2, v3, :cond_3e

    .line 1081
    .line 1082
    aget-object v3, v7, v2

    .line 1083
    .line 1084
    invoke-virtual {v3}, La8/p1;->c()I

    .line 1085
    .line 1086
    .line 1087
    move-result v3

    .line 1088
    aget-object v4, v7, v2

    .line 1089
    .line 1090
    iget-object v5, v0, La8/q0;->q:La8/l;

    .line 1091
    .line 1092
    iget-object v10, v4, La8/p1;->e:Ljava/lang/Object;

    .line 1093
    .line 1094
    check-cast v10, La8/f;

    .line 1095
    .line 1096
    invoke-virtual {v4, v10, v1, v8, v5}, La8/p1;->j(La8/f;La8/w0;Lj8/s;La8/l;)I

    .line 1097
    .line 1098
    .line 1099
    move-result v10

    .line 1100
    iget-object v11, v4, La8/p1;->f:Ljava/lang/Object;

    .line 1101
    .line 1102
    check-cast v11, La8/f;

    .line 1103
    .line 1104
    invoke-virtual {v4, v11, v1, v8, v5}, La8/p1;->j(La8/f;La8/w0;Lj8/s;La8/l;)I

    .line 1105
    .line 1106
    .line 1107
    move-result v4

    .line 1108
    const/4 v5, 0x1

    .line 1109
    if-ne v10, v5, :cond_3a

    .line 1110
    .line 1111
    move v10, v4

    .line 1112
    :cond_3a
    and-int/lit8 v4, v10, 0x2

    .line 1113
    .line 1114
    if-eqz v4, :cond_3c

    .line 1115
    .line 1116
    iget-boolean v4, v0, La8/q0;->U:Z

    .line 1117
    .line 1118
    if-eqz v4, :cond_3c

    .line 1119
    .line 1120
    if-nez v4, :cond_3b

    .line 1121
    .line 1122
    goto :goto_21

    .line 1123
    :cond_3b
    const/4 v4, 0x0

    .line 1124
    iput-boolean v4, v0, La8/q0;->U:Z

    .line 1125
    .line 1126
    iget-object v4, v0, La8/q0;->I:La8/i1;

    .line 1127
    .line 1128
    iget-boolean v4, v4, La8/i1;->p:Z

    .line 1129
    .line 1130
    if-eqz v4, :cond_3c

    .line 1131
    .line 1132
    iget-object v4, v0, La8/q0;->k:Lw7/t;

    .line 1133
    .line 1134
    const/4 v13, 0x2

    .line 1135
    invoke-virtual {v4, v13}, Lw7/t;->e(I)Z

    .line 1136
    .line 1137
    .line 1138
    :cond_3c
    :goto_21
    iget v4, v0, La8/q0;->V:I

    .line 1139
    .line 1140
    aget-object v5, v7, v2

    .line 1141
    .line 1142
    invoke-virtual {v5}, La8/p1;->c()I

    .line 1143
    .line 1144
    .line 1145
    move-result v5

    .line 1146
    sub-int/2addr v3, v5

    .line 1147
    sub-int/2addr v4, v3

    .line 1148
    iput v4, v0, La8/q0;->V:I

    .line 1149
    .line 1150
    and-int/lit8 v3, v10, 0x1

    .line 1151
    .line 1152
    if-eqz v3, :cond_3d

    .line 1153
    .line 1154
    const/4 v3, 0x1

    .line 1155
    goto :goto_22

    .line 1156
    :cond_3d
    const/4 v3, 0x0

    .line 1157
    :goto_22
    and-int/2addr v9, v3

    .line 1158
    add-int/lit8 v2, v2, 0x1

    .line 1159
    .line 1160
    goto :goto_20

    .line 1161
    :cond_3e
    if-eqz v9, :cond_41

    .line 1162
    .line 1163
    const/4 v2, 0x0

    .line 1164
    :goto_23
    array-length v3, v7

    .line 1165
    if-ge v2, v3, :cond_41

    .line 1166
    .line 1167
    invoke-virtual {v8, v2}, Lj8/s;->b(I)Z

    .line 1168
    .line 1169
    .line 1170
    move-result v3

    .line 1171
    if-eqz v3, :cond_40

    .line 1172
    .line 1173
    aget-object v3, v7, v2

    .line 1174
    .line 1175
    invoke-virtual {v3, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v3

    .line 1179
    if-eqz v3, :cond_3f

    .line 1180
    .line 1181
    const/4 v3, 0x1

    .line 1182
    goto :goto_24

    .line 1183
    :cond_3f
    const/4 v3, 0x0

    .line 1184
    :goto_24
    if-nez v3, :cond_40

    .line 1185
    .line 1186
    const/4 v3, 0x0

    .line 1187
    invoke-virtual {v1}, La8/w0;->e()J

    .line 1188
    .line 1189
    .line 1190
    move-result-wide v4

    .line 1191
    invoke-virtual/range {v0 .. v5}, La8/q0;->k(La8/w0;IZJ)V

    .line 1192
    .line 1193
    .line 1194
    :cond_40
    add-int/lit8 v2, v2, 0x1

    .line 1195
    .line 1196
    goto :goto_23

    .line 1197
    :cond_41
    if-eqz v9, :cond_42

    .line 1198
    .line 1199
    iget-object v1, v6, La8/z0;->j:La8/w0;

    .line 1200
    .line 1201
    const/4 v5, 0x1

    .line 1202
    iput-boolean v5, v1, La8/w0;->h:Z

    .line 1203
    .line 1204
    :cond_42
    :goto_25
    iget-object v10, v0, La8/q0;->d:[La8/p1;

    .line 1205
    .line 1206
    iget-object v11, v0, La8/q0;->u:La8/z0;

    .line 1207
    .line 1208
    const/4 v6, 0x0

    .line 1209
    :goto_26
    invoke-virtual {v0}, La8/q0;->q0()Z

    .line 1210
    .line 1211
    .line 1212
    move-result v1

    .line 1213
    if-nez v1, :cond_44

    .line 1214
    .line 1215
    :cond_43
    :goto_27
    move v15, v14

    .line 1216
    const/4 v13, 0x1

    .line 1217
    const/4 v14, 0x4

    .line 1218
    goto/16 :goto_32

    .line 1219
    .line 1220
    :cond_44
    iget-boolean v1, v0, La8/q0;->M:Z

    .line 1221
    .line 1222
    if-eqz v1, :cond_45

    .line 1223
    .line 1224
    goto :goto_27

    .line 1225
    :cond_45
    iget-object v1, v11, La8/z0;->i:La8/w0;

    .line 1226
    .line 1227
    if-nez v1, :cond_46

    .line 1228
    .line 1229
    goto :goto_27

    .line 1230
    :cond_46
    iget-object v1, v1, La8/w0;->m:La8/w0;

    .line 1231
    .line 1232
    if-eqz v1, :cond_43

    .line 1233
    .line 1234
    iget-wide v2, v0, La8/q0;->X:J

    .line 1235
    .line 1236
    invoke-virtual {v1}, La8/w0;->e()J

    .line 1237
    .line 1238
    .line 1239
    move-result-wide v4

    .line 1240
    cmp-long v2, v2, v4

    .line 1241
    .line 1242
    if-ltz v2, :cond_43

    .line 1243
    .line 1244
    iget-boolean v1, v1, La8/w0;->h:Z

    .line 1245
    .line 1246
    if-eqz v1, :cond_43

    .line 1247
    .line 1248
    if-eqz v6, :cond_47

    .line 1249
    .line 1250
    invoke-virtual {v0}, La8/q0;->E()V

    .line 1251
    .line 1252
    .line 1253
    :cond_47
    const/4 v1, 0x0

    .line 1254
    iput-boolean v1, v0, La8/q0;->f0:Z

    .line 1255
    .line 1256
    invoke-virtual {v11}, La8/z0;->a()La8/w0;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v12

    .line 1260
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1261
    .line 1262
    .line 1263
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 1264
    .line 1265
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 1266
    .line 1267
    iget-object v1, v1, Lh8/b0;->a:Ljava/lang/Object;

    .line 1268
    .line 1269
    iget-object v2, v12, La8/w0;->g:La8/x0;

    .line 1270
    .line 1271
    iget-object v2, v2, La8/x0;->a:Lh8/b0;

    .line 1272
    .line 1273
    iget-object v2, v2, Lh8/b0;->a:Ljava/lang/Object;

    .line 1274
    .line 1275
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1276
    .line 1277
    .line 1278
    move-result v1

    .line 1279
    if-eqz v1, :cond_48

    .line 1280
    .line 1281
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 1282
    .line 1283
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 1284
    .line 1285
    iget v2, v1, Lh8/b0;->b:I

    .line 1286
    .line 1287
    const/4 v3, -0x1

    .line 1288
    if-ne v2, v3, :cond_48

    .line 1289
    .line 1290
    iget-object v2, v12, La8/w0;->g:La8/x0;

    .line 1291
    .line 1292
    iget-object v2, v2, La8/x0;->a:Lh8/b0;

    .line 1293
    .line 1294
    iget v4, v2, Lh8/b0;->b:I

    .line 1295
    .line 1296
    if-ne v4, v3, :cond_48

    .line 1297
    .line 1298
    iget v1, v1, Lh8/b0;->e:I

    .line 1299
    .line 1300
    iget v2, v2, Lh8/b0;->e:I

    .line 1301
    .line 1302
    if-eq v1, v2, :cond_48

    .line 1303
    .line 1304
    const/4 v6, 0x1

    .line 1305
    goto :goto_28

    .line 1306
    :cond_48
    const/4 v6, 0x0

    .line 1307
    :goto_28
    iget-object v1, v12, La8/w0;->g:La8/x0;

    .line 1308
    .line 1309
    iget-object v2, v1, La8/x0;->a:Lh8/b0;

    .line 1310
    .line 1311
    move-object v4, v2

    .line 1312
    iget-wide v2, v1, La8/x0;->b:J

    .line 1313
    .line 1314
    iget-wide v7, v1, La8/x0;->c:J

    .line 1315
    .line 1316
    const/16 v20, 0x1

    .line 1317
    .line 1318
    xor-int/lit8 v1, v6, 0x1

    .line 1319
    .line 1320
    const/4 v9, 0x0

    .line 1321
    move-wide/from16 v34, v7

    .line 1322
    .line 1323
    move v8, v1

    .line 1324
    move-object v1, v4

    .line 1325
    move-wide/from16 v4, v34

    .line 1326
    .line 1327
    move-wide v6, v2

    .line 1328
    move v15, v14

    .line 1329
    move/from16 v13, v20

    .line 1330
    .line 1331
    const/4 v14, 0x4

    .line 1332
    invoke-virtual/range {v0 .. v9}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v1

    .line 1336
    iput-object v1, v0, La8/q0;->I:La8/i1;

    .line 1337
    .line 1338
    invoke-virtual {v0}, La8/q0;->P()V

    .line 1339
    .line 1340
    .line 1341
    invoke-virtual {v0}, La8/q0;->z0()V

    .line 1342
    .line 1343
    .line 1344
    invoke-virtual {v0}, La8/q0;->e()Z

    .line 1345
    .line 1346
    .line 1347
    move-result v1

    .line 1348
    if-eqz v1, :cond_4f

    .line 1349
    .line 1350
    iget-object v1, v11, La8/z0;->k:La8/w0;

    .line 1351
    .line 1352
    if-ne v12, v1, :cond_4f

    .line 1353
    .line 1354
    array-length v1, v10

    .line 1355
    const/4 v6, 0x0

    .line 1356
    :goto_29
    if-ge v6, v1, :cond_4f

    .line 1357
    .line 1358
    aget-object v2, v10, v6

    .line 1359
    .line 1360
    iget v3, v2, La8/p1;->d:I

    .line 1361
    .line 1362
    if-eq v3, v15, :cond_4a

    .line 1363
    .line 1364
    if-ne v3, v14, :cond_49

    .line 1365
    .line 1366
    goto :goto_2a

    .line 1367
    :cond_49
    const/4 v4, 0x2

    .line 1368
    if-ne v3, v4, :cond_4e

    .line 1369
    .line 1370
    const/4 v4, 0x0

    .line 1371
    iput v4, v2, La8/p1;->d:I

    .line 1372
    .line 1373
    goto :goto_2e

    .line 1374
    :cond_4a
    :goto_2a
    if-ne v3, v14, :cond_4b

    .line 1375
    .line 1376
    move v3, v13

    .line 1377
    goto :goto_2b

    .line 1378
    :cond_4b
    const/4 v3, 0x0

    .line 1379
    :goto_2b
    iget-object v4, v2, La8/p1;->e:Ljava/lang/Object;

    .line 1380
    .line 1381
    check-cast v4, La8/f;

    .line 1382
    .line 1383
    iget-object v5, v2, La8/p1;->f:Ljava/lang/Object;

    .line 1384
    .line 1385
    check-cast v5, La8/f;

    .line 1386
    .line 1387
    const/16 v7, 0x11

    .line 1388
    .line 1389
    if-eqz v3, :cond_4c

    .line 1390
    .line 1391
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1392
    .line 1393
    .line 1394
    invoke-interface {v5, v7, v4}, La8/k1;->a(ILjava/lang/Object;)V

    .line 1395
    .line 1396
    .line 1397
    goto :goto_2c

    .line 1398
    :cond_4c
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1399
    .line 1400
    .line 1401
    invoke-interface {v4, v7, v5}, La8/k1;->a(ILjava/lang/Object;)V

    .line 1402
    .line 1403
    .line 1404
    :goto_2c
    iget v3, v2, La8/p1;->d:I

    .line 1405
    .line 1406
    if-ne v3, v14, :cond_4d

    .line 1407
    .line 1408
    const/4 v3, 0x0

    .line 1409
    goto :goto_2d

    .line 1410
    :cond_4d
    move v3, v13

    .line 1411
    :goto_2d
    iput v3, v2, La8/p1;->d:I

    .line 1412
    .line 1413
    :cond_4e
    :goto_2e
    add-int/lit8 v6, v6, 0x1

    .line 1414
    .line 1415
    goto :goto_29

    .line 1416
    :cond_4f
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 1417
    .line 1418
    iget v1, v1, La8/i1;->e:I

    .line 1419
    .line 1420
    if-ne v1, v15, :cond_50

    .line 1421
    .line 1422
    invoke-virtual {v0}, La8/q0;->s0()V

    .line 1423
    .line 1424
    .line 1425
    :cond_50
    iget-object v1, v11, La8/z0;->i:La8/w0;

    .line 1426
    .line 1427
    iget-object v1, v1, La8/w0;->o:Lj8/s;

    .line 1428
    .line 1429
    const/4 v6, 0x0

    .line 1430
    :goto_2f
    array-length v2, v10

    .line 1431
    if-ge v6, v2, :cond_55

    .line 1432
    .line 1433
    invoke-virtual {v1, v6}, Lj8/s;->b(I)Z

    .line 1434
    .line 1435
    .line 1436
    move-result v2

    .line 1437
    if-nez v2, :cond_51

    .line 1438
    .line 1439
    goto :goto_31

    .line 1440
    :cond_51
    aget-object v2, v10, v6

    .line 1441
    .line 1442
    iget-object v3, v2, La8/p1;->f:Ljava/lang/Object;

    .line 1443
    .line 1444
    check-cast v3, La8/f;

    .line 1445
    .line 1446
    iget-object v2, v2, La8/p1;->e:Ljava/lang/Object;

    .line 1447
    .line 1448
    check-cast v2, La8/f;

    .line 1449
    .line 1450
    invoke-static {v2}, La8/p1;->h(La8/f;)Z

    .line 1451
    .line 1452
    .line 1453
    move-result v4

    .line 1454
    if-eqz v4, :cond_52

    .line 1455
    .line 1456
    invoke-virtual {v2}, La8/f;->h()V

    .line 1457
    .line 1458
    .line 1459
    goto :goto_31

    .line 1460
    :cond_52
    if-eqz v3, :cond_54

    .line 1461
    .line 1462
    iget v2, v3, La8/f;->k:I

    .line 1463
    .line 1464
    if-eqz v2, :cond_53

    .line 1465
    .line 1466
    move v2, v13

    .line 1467
    goto :goto_30

    .line 1468
    :cond_53
    const/4 v2, 0x0

    .line 1469
    :goto_30
    if-eqz v2, :cond_54

    .line 1470
    .line 1471
    invoke-virtual {v3}, La8/f;->h()V

    .line 1472
    .line 1473
    .line 1474
    :cond_54
    :goto_31
    add-int/lit8 v6, v6, 0x1

    .line 1475
    .line 1476
    goto :goto_2f

    .line 1477
    :cond_55
    move v6, v13

    .line 1478
    move v14, v15

    .line 1479
    goto/16 :goto_26

    .line 1480
    .line 1481
    :goto_32
    iget-object v1, v0, La8/q0;->d0:La8/r;

    .line 1482
    .line 1483
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1484
    .line 1485
    .line 1486
    :goto_33
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 1487
    .line 1488
    iget v1, v1, La8/i1;->e:I

    .line 1489
    .line 1490
    if-eq v1, v13, :cond_8d

    .line 1491
    .line 1492
    if-ne v1, v14, :cond_56

    .line 1493
    .line 1494
    goto/16 :goto_4f

    .line 1495
    .line 1496
    :cond_56
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 1497
    .line 1498
    iget-object v1, v1, La8/z0;->i:La8/w0;

    .line 1499
    .line 1500
    if-nez v1, :cond_57

    .line 1501
    .line 1502
    move-wide/from16 v2, v23

    .line 1503
    .line 1504
    invoke-virtual {v0, v2, v3}, La8/q0;->U(J)V

    .line 1505
    .line 1506
    .line 1507
    return-void

    .line 1508
    :cond_57
    move-wide/from16 v2, v23

    .line 1509
    .line 1510
    const-string v4, "doSomeWork"

    .line 1511
    .line 1512
    invoke-static {v4}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 1513
    .line 1514
    .line 1515
    invoke-virtual {v0}, La8/q0;->z0()V

    .line 1516
    .line 1517
    .line 1518
    iget-boolean v4, v1, La8/w0;->e:Z

    .line 1519
    .line 1520
    if-eqz v4, :cond_64

    .line 1521
    .line 1522
    iget-object v4, v0, La8/q0;->s:Lw7/r;

    .line 1523
    .line 1524
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1525
    .line 1526
    .line 1527
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 1528
    .line 1529
    .line 1530
    move-result-wide v4

    .line 1531
    invoke-static {v4, v5}, Lw7/w;->D(J)J

    .line 1532
    .line 1533
    .line 1534
    move-result-wide v4

    .line 1535
    iput-wide v4, v0, La8/q0;->Y:J

    .line 1536
    .line 1537
    iget-object v4, v1, La8/w0;->a:Ljava/lang/Object;

    .line 1538
    .line 1539
    iget-object v5, v0, La8/q0;->I:La8/i1;

    .line 1540
    .line 1541
    iget-wide v5, v5, La8/i1;->s:J

    .line 1542
    .line 1543
    iget-wide v7, v0, La8/q0;->p:J

    .line 1544
    .line 1545
    sub-long/2addr v5, v7

    .line 1546
    invoke-interface {v4, v5, v6}, Lh8/z;->l(J)V

    .line 1547
    .line 1548
    .line 1549
    move v4, v13

    .line 1550
    move v7, v4

    .line 1551
    const/4 v6, 0x0

    .line 1552
    :goto_34
    iget-object v5, v0, La8/q0;->d:[La8/p1;

    .line 1553
    .line 1554
    array-length v8, v5

    .line 1555
    if-ge v6, v8, :cond_65

    .line 1556
    .line 1557
    aget-object v5, v5, v6

    .line 1558
    .line 1559
    invoke-virtual {v5}, La8/p1;->c()I

    .line 1560
    .line 1561
    .line 1562
    move-result v8

    .line 1563
    if-nez v8, :cond_58

    .line 1564
    .line 1565
    const/4 v8, 0x0

    .line 1566
    invoke-virtual {v0, v6, v8}, La8/q0;->G(IZ)V

    .line 1567
    .line 1568
    .line 1569
    goto/16 :goto_3c

    .line 1570
    .line 1571
    :cond_58
    iget-wide v8, v0, La8/q0;->X:J

    .line 1572
    .line 1573
    iget-wide v10, v0, La8/q0;->Y:J

    .line 1574
    .line 1575
    iget-object v12, v5, La8/p1;->f:Ljava/lang/Object;

    .line 1576
    .line 1577
    check-cast v12, La8/f;

    .line 1578
    .line 1579
    iget-object v13, v5, La8/p1;->e:Ljava/lang/Object;

    .line 1580
    .line 1581
    check-cast v13, La8/f;

    .line 1582
    .line 1583
    invoke-static {v13}, La8/p1;->h(La8/f;)Z

    .line 1584
    .line 1585
    .line 1586
    move-result v17

    .line 1587
    if-eqz v17, :cond_59

    .line 1588
    .line 1589
    invoke-virtual {v13, v8, v9, v10, v11}, La8/f;->y(JJ)V

    .line 1590
    .line 1591
    .line 1592
    :cond_59
    if-eqz v12, :cond_5b

    .line 1593
    .line 1594
    iget v13, v12, La8/f;->k:I

    .line 1595
    .line 1596
    if-eqz v13, :cond_5a

    .line 1597
    .line 1598
    const/4 v13, 0x1

    .line 1599
    goto :goto_35

    .line 1600
    :cond_5a
    const/4 v13, 0x0

    .line 1601
    :goto_35
    if-eqz v13, :cond_5b

    .line 1602
    .line 1603
    invoke-virtual {v12, v8, v9, v10, v11}, La8/f;->y(JJ)V

    .line 1604
    .line 1605
    .line 1606
    :cond_5b
    if-eqz v7, :cond_5f

    .line 1607
    .line 1608
    iget-object v7, v5, La8/p1;->f:Ljava/lang/Object;

    .line 1609
    .line 1610
    check-cast v7, La8/f;

    .line 1611
    .line 1612
    iget-object v8, v5, La8/p1;->e:Ljava/lang/Object;

    .line 1613
    .line 1614
    check-cast v8, La8/f;

    .line 1615
    .line 1616
    invoke-static {v8}, La8/p1;->h(La8/f;)Z

    .line 1617
    .line 1618
    .line 1619
    move-result v9

    .line 1620
    if-eqz v9, :cond_5c

    .line 1621
    .line 1622
    invoke-virtual {v8}, La8/f;->m()Z

    .line 1623
    .line 1624
    .line 1625
    move-result v8

    .line 1626
    goto :goto_36

    .line 1627
    :cond_5c
    const/4 v8, 0x1

    .line 1628
    :goto_36
    if-eqz v7, :cond_5e

    .line 1629
    .line 1630
    iget v9, v7, La8/f;->k:I

    .line 1631
    .line 1632
    if-eqz v9, :cond_5d

    .line 1633
    .line 1634
    const/4 v9, 0x1

    .line 1635
    goto :goto_37

    .line 1636
    :cond_5d
    const/4 v9, 0x0

    .line 1637
    :goto_37
    if-eqz v9, :cond_5e

    .line 1638
    .line 1639
    invoke-virtual {v7}, La8/f;->m()Z

    .line 1640
    .line 1641
    .line 1642
    move-result v7

    .line 1643
    and-int/2addr v8, v7

    .line 1644
    :cond_5e
    if-eqz v8, :cond_5f

    .line 1645
    .line 1646
    const/4 v7, 0x1

    .line 1647
    goto :goto_38

    .line 1648
    :cond_5f
    const/4 v7, 0x0

    .line 1649
    :goto_38
    invoke-virtual {v5, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 1650
    .line 1651
    .line 1652
    move-result-object v5

    .line 1653
    if-eqz v5, :cond_61

    .line 1654
    .line 1655
    invoke-virtual {v5}, La8/f;->l()Z

    .line 1656
    .line 1657
    .line 1658
    move-result v8

    .line 1659
    if-nez v8, :cond_61

    .line 1660
    .line 1661
    invoke-virtual {v5}, La8/f;->o()Z

    .line 1662
    .line 1663
    .line 1664
    move-result v8

    .line 1665
    if-nez v8, :cond_61

    .line 1666
    .line 1667
    invoke-virtual {v5}, La8/f;->m()Z

    .line 1668
    .line 1669
    .line 1670
    move-result v5

    .line 1671
    if-eqz v5, :cond_60

    .line 1672
    .line 1673
    goto :goto_39

    .line 1674
    :cond_60
    const/4 v5, 0x0

    .line 1675
    goto :goto_3a

    .line 1676
    :cond_61
    :goto_39
    const/4 v5, 0x1

    .line 1677
    :goto_3a
    invoke-virtual {v0, v6, v5}, La8/q0;->G(IZ)V

    .line 1678
    .line 1679
    .line 1680
    if-eqz v4, :cond_62

    .line 1681
    .line 1682
    if-eqz v5, :cond_62

    .line 1683
    .line 1684
    const/4 v4, 0x1

    .line 1685
    goto :goto_3b

    .line 1686
    :cond_62
    const/4 v4, 0x0

    .line 1687
    :goto_3b
    if-nez v5, :cond_63

    .line 1688
    .line 1689
    invoke-virtual {v0, v6}, La8/q0;->F(I)V

    .line 1690
    .line 1691
    .line 1692
    :cond_63
    :goto_3c
    add-int/lit8 v6, v6, 0x1

    .line 1693
    .line 1694
    const/4 v13, 0x1

    .line 1695
    goto/16 :goto_34

    .line 1696
    .line 1697
    :cond_64
    iget-object v4, v1, La8/w0;->a:Ljava/lang/Object;

    .line 1698
    .line 1699
    invoke-interface {v4}, Lh8/z;->k()V

    .line 1700
    .line 1701
    .line 1702
    const/4 v4, 0x1

    .line 1703
    const/4 v7, 0x1

    .line 1704
    :cond_65
    iget-object v5, v1, La8/w0;->g:La8/x0;

    .line 1705
    .line 1706
    iget-wide v5, v5, La8/x0;->e:J

    .line 1707
    .line 1708
    if-eqz v7, :cond_67

    .line 1709
    .line 1710
    iget-boolean v7, v1, La8/w0;->e:Z

    .line 1711
    .line 1712
    if-eqz v7, :cond_67

    .line 1713
    .line 1714
    cmp-long v7, v5, v27

    .line 1715
    .line 1716
    if-eqz v7, :cond_66

    .line 1717
    .line 1718
    iget-object v7, v0, La8/q0;->I:La8/i1;

    .line 1719
    .line 1720
    iget-wide v7, v7, La8/i1;->s:J

    .line 1721
    .line 1722
    cmp-long v5, v5, v7

    .line 1723
    .line 1724
    if-gtz v5, :cond_67

    .line 1725
    .line 1726
    :cond_66
    const/4 v6, 0x1

    .line 1727
    goto :goto_3d

    .line 1728
    :cond_67
    const/4 v6, 0x0

    .line 1729
    :goto_3d
    if-eqz v6, :cond_68

    .line 1730
    .line 1731
    iget-boolean v5, v0, La8/q0;->M:Z

    .line 1732
    .line 1733
    if-eqz v5, :cond_68

    .line 1734
    .line 1735
    const/4 v8, 0x0

    .line 1736
    iput-boolean v8, v0, La8/q0;->M:Z

    .line 1737
    .line 1738
    iget-object v5, v0, La8/q0;->I:La8/i1;

    .line 1739
    .line 1740
    iget v5, v5, La8/i1;->n:I

    .line 1741
    .line 1742
    iget-object v7, v0, La8/q0;->J:La8/n0;

    .line 1743
    .line 1744
    invoke-virtual {v7, v8}, La8/n0;->f(I)V

    .line 1745
    .line 1746
    .line 1747
    iget-object v7, v0, La8/q0;->C:La8/e;

    .line 1748
    .line 1749
    iget-object v9, v0, La8/q0;->I:La8/i1;

    .line 1750
    .line 1751
    iget v9, v9, La8/i1;->e:I

    .line 1752
    .line 1753
    invoke-virtual {v7, v9, v8}, La8/e;->d(IZ)I

    .line 1754
    .line 1755
    .line 1756
    move-result v7

    .line 1757
    const/4 v9, 0x5

    .line 1758
    invoke-virtual {v0, v7, v5, v9, v8}, La8/q0;->y0(IIIZ)V

    .line 1759
    .line 1760
    .line 1761
    :cond_68
    if-eqz v6, :cond_6a

    .line 1762
    .line 1763
    iget-object v5, v1, La8/w0;->g:La8/x0;

    .line 1764
    .line 1765
    iget-boolean v5, v5, La8/x0;->j:Z

    .line 1766
    .line 1767
    if-eqz v5, :cond_6a

    .line 1768
    .line 1769
    invoke-virtual {v0, v14}, La8/q0;->m0(I)V

    .line 1770
    .line 1771
    .line 1772
    invoke-virtual {v0}, La8/q0;->u0()V

    .line 1773
    .line 1774
    .line 1775
    :cond_69
    const/4 v5, 0x1

    .line 1776
    goto/16 :goto_47

    .line 1777
    .line 1778
    :cond_6a
    iget-object v5, v0, La8/q0;->I:La8/i1;

    .line 1779
    .line 1780
    iget v6, v5, La8/i1;->e:I

    .line 1781
    .line 1782
    const/4 v13, 0x2

    .line 1783
    if-ne v6, v13, :cond_76

    .line 1784
    .line 1785
    iget-object v6, v0, La8/q0;->u:La8/z0;

    .line 1786
    .line 1787
    iget v7, v0, La8/q0;->V:I

    .line 1788
    .line 1789
    if-nez v7, :cond_6b

    .line 1790
    .line 1791
    invoke-virtual {v0}, La8/q0;->B()Z

    .line 1792
    .line 1793
    .line 1794
    move-result v6

    .line 1795
    goto/16 :goto_43

    .line 1796
    .line 1797
    :cond_6b
    if-nez v4, :cond_6d

    .line 1798
    .line 1799
    :cond_6c
    const/4 v6, 0x0

    .line 1800
    goto/16 :goto_43

    .line 1801
    .line 1802
    :cond_6d
    iget-boolean v7, v5, La8/i1;->g:Z

    .line 1803
    .line 1804
    if-nez v7, :cond_6f

    .line 1805
    .line 1806
    :cond_6e
    :goto_3e
    const/4 v6, 0x1

    .line 1807
    goto/16 :goto_43

    .line 1808
    .line 1809
    :cond_6f
    iget-object v7, v6, La8/z0;->i:La8/w0;

    .line 1810
    .line 1811
    iget-object v5, v5, La8/i1;->a:Lt7/p0;

    .line 1812
    .line 1813
    iget-object v7, v7, La8/w0;->g:La8/x0;

    .line 1814
    .line 1815
    iget-object v7, v7, La8/x0;->a:Lh8/b0;

    .line 1816
    .line 1817
    invoke-virtual {v0, v5, v7}, La8/q0;->r0(Lt7/p0;Lh8/b0;)Z

    .line 1818
    .line 1819
    .line 1820
    move-result v5

    .line 1821
    if-eqz v5, :cond_70

    .line 1822
    .line 1823
    iget-object v5, v0, La8/q0;->w:La8/i;

    .line 1824
    .line 1825
    iget-wide v7, v5, La8/i;->h:J

    .line 1826
    .line 1827
    goto :goto_3f

    .line 1828
    :cond_70
    move-wide/from16 v7, v27

    .line 1829
    .line 1830
    :goto_3f
    iget-object v5, v6, La8/z0;->l:La8/w0;

    .line 1831
    .line 1832
    invoke-virtual {v5}, La8/w0;->g()Z

    .line 1833
    .line 1834
    .line 1835
    move-result v6

    .line 1836
    if-eqz v6, :cond_71

    .line 1837
    .line 1838
    iget-object v6, v5, La8/w0;->g:La8/x0;

    .line 1839
    .line 1840
    iget-boolean v6, v6, La8/x0;->j:Z

    .line 1841
    .line 1842
    if-eqz v6, :cond_71

    .line 1843
    .line 1844
    const/4 v6, 0x1

    .line 1845
    goto :goto_40

    .line 1846
    :cond_71
    const/4 v6, 0x0

    .line 1847
    :goto_40
    iget-object v9, v5, La8/w0;->g:La8/x0;

    .line 1848
    .line 1849
    iget-object v9, v9, La8/x0;->a:Lh8/b0;

    .line 1850
    .line 1851
    invoke-virtual {v9}, Lh8/b0;->b()Z

    .line 1852
    .line 1853
    .line 1854
    move-result v9

    .line 1855
    if-eqz v9, :cond_72

    .line 1856
    .line 1857
    iget-boolean v9, v5, La8/w0;->e:Z

    .line 1858
    .line 1859
    if-nez v9, :cond_72

    .line 1860
    .line 1861
    const/4 v9, 0x1

    .line 1862
    goto :goto_41

    .line 1863
    :cond_72
    const/4 v9, 0x0

    .line 1864
    :goto_41
    if-nez v6, :cond_6e

    .line 1865
    .line 1866
    if-eqz v9, :cond_73

    .line 1867
    .line 1868
    goto :goto_3e

    .line 1869
    :cond_73
    invoke-virtual {v5}, La8/w0;->d()J

    .line 1870
    .line 1871
    .line 1872
    move-result-wide v5

    .line 1873
    invoke-virtual {v0, v5, v6}, La8/q0;->p(J)J

    .line 1874
    .line 1875
    .line 1876
    move-result-wide v5

    .line 1877
    iget-object v9, v0, La8/q0;->i:La8/k;

    .line 1878
    .line 1879
    iget-object v10, v0, La8/q0;->I:La8/i1;

    .line 1880
    .line 1881
    iget-object v10, v10, La8/i1;->a:Lt7/p0;

    .line 1882
    .line 1883
    iget-object v10, v0, La8/q0;->q:La8/l;

    .line 1884
    .line 1885
    invoke-virtual {v10}, La8/l;->c()Lt7/g0;

    .line 1886
    .line 1887
    .line 1888
    move-result-object v10

    .line 1889
    iget v10, v10, Lt7/g0;->a:F

    .line 1890
    .line 1891
    iget-object v11, v0, La8/q0;->I:La8/i1;

    .line 1892
    .line 1893
    iget-boolean v11, v11, La8/i1;->l:Z

    .line 1894
    .line 1895
    iget-boolean v11, v0, La8/q0;->N:Z

    .line 1896
    .line 1897
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1898
    .line 1899
    .line 1900
    invoke-static {v5, v6, v10}, Lw7/w;->t(JF)J

    .line 1901
    .line 1902
    .line 1903
    move-result-wide v5

    .line 1904
    if-eqz v11, :cond_74

    .line 1905
    .line 1906
    iget-wide v10, v9, La8/k;->e:J

    .line 1907
    .line 1908
    goto :goto_42

    .line 1909
    :cond_74
    iget-wide v10, v9, La8/k;->d:J

    .line 1910
    .line 1911
    :goto_42
    cmp-long v12, v7, v27

    .line 1912
    .line 1913
    if-eqz v12, :cond_75

    .line 1914
    .line 1915
    const-wide/16 v12, 0x2

    .line 1916
    .line 1917
    div-long/2addr v7, v12

    .line 1918
    invoke-static {v7, v8, v10, v11}, Ljava/lang/Math;->min(JJ)J

    .line 1919
    .line 1920
    .line 1921
    move-result-wide v10

    .line 1922
    :cond_75
    const-wide/16 v7, 0x0

    .line 1923
    .line 1924
    cmp-long v7, v10, v7

    .line 1925
    .line 1926
    if-lez v7, :cond_6e

    .line 1927
    .line 1928
    cmp-long v5, v5, v10

    .line 1929
    .line 1930
    if-gez v5, :cond_6e

    .line 1931
    .line 1932
    iget-object v5, v9, La8/k;->a:Lk8/e;

    .line 1933
    .line 1934
    monitor-enter v5

    .line 1935
    :try_start_0
    iget v6, v5, Lk8/e;->d:I

    .line 1936
    .line 1937
    iget v7, v5, Lk8/e;->b:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1938
    .line 1939
    mul-int/2addr v6, v7

    .line 1940
    monitor-exit v5

    .line 1941
    invoke-virtual {v9}, La8/k;->b()I

    .line 1942
    .line 1943
    .line 1944
    move-result v5

    .line 1945
    if-lt v6, v5, :cond_6c

    .line 1946
    .line 1947
    goto/16 :goto_3e

    .line 1948
    .line 1949
    :catchall_0
    move-exception v0

    .line 1950
    :try_start_1
    monitor-exit v5
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 1951
    throw v0

    .line 1952
    :goto_43
    if-eqz v6, :cond_76

    .line 1953
    .line 1954
    invoke-virtual {v0, v15}, La8/q0;->m0(I)V

    .line 1955
    .line 1956
    .line 1957
    const/4 v4, 0x0

    .line 1958
    iput-object v4, v0, La8/q0;->b0:La8/o;

    .line 1959
    .line 1960
    invoke-virtual {v0}, La8/q0;->q0()Z

    .line 1961
    .line 1962
    .line 1963
    move-result v4

    .line 1964
    if-eqz v4, :cond_69

    .line 1965
    .line 1966
    const/4 v4, 0x0

    .line 1967
    invoke-virtual {v0, v4, v4}, La8/q0;->B0(ZZ)V

    .line 1968
    .line 1969
    .line 1970
    iget-object v4, v0, La8/q0;->q:La8/l;

    .line 1971
    .line 1972
    const/4 v5, 0x1

    .line 1973
    iput-boolean v5, v4, La8/l;->e:Z

    .line 1974
    .line 1975
    iget-object v4, v4, La8/l;->f:Ljava/lang/Object;

    .line 1976
    .line 1977
    check-cast v4, La8/s1;

    .line 1978
    .line 1979
    invoke-virtual {v4}, La8/s1;->f()V

    .line 1980
    .line 1981
    .line 1982
    invoke-virtual {v0}, La8/q0;->s0()V

    .line 1983
    .line 1984
    .line 1985
    goto :goto_47

    .line 1986
    :cond_76
    const/4 v5, 0x1

    .line 1987
    iget-object v6, v0, La8/q0;->I:La8/i1;

    .line 1988
    .line 1989
    iget v6, v6, La8/i1;->e:I

    .line 1990
    .line 1991
    if-ne v6, v15, :cond_7f

    .line 1992
    .line 1993
    iget v6, v0, La8/q0;->V:I

    .line 1994
    .line 1995
    if-nez v6, :cond_77

    .line 1996
    .line 1997
    invoke-virtual {v0}, La8/q0;->B()Z

    .line 1998
    .line 1999
    .line 2000
    move-result v4

    .line 2001
    if-eqz v4, :cond_78

    .line 2002
    .line 2003
    goto :goto_47

    .line 2004
    :cond_77
    if-nez v4, :cond_7f

    .line 2005
    .line 2006
    :cond_78
    invoke-virtual {v0}, La8/q0;->q0()Z

    .line 2007
    .line 2008
    .line 2009
    move-result v4

    .line 2010
    const/4 v8, 0x0

    .line 2011
    invoke-virtual {v0, v4, v8}, La8/q0;->B0(ZZ)V

    .line 2012
    .line 2013
    .line 2014
    const/4 v13, 0x2

    .line 2015
    invoke-virtual {v0, v13}, La8/q0;->m0(I)V

    .line 2016
    .line 2017
    .line 2018
    iget-boolean v4, v0, La8/q0;->N:Z

    .line 2019
    .line 2020
    if-eqz v4, :cond_7e

    .line 2021
    .line 2022
    iget-object v4, v0, La8/q0;->u:La8/z0;

    .line 2023
    .line 2024
    iget-object v4, v4, La8/z0;->i:La8/w0;

    .line 2025
    .line 2026
    :goto_44
    if-eqz v4, :cond_7b

    .line 2027
    .line 2028
    iget-object v6, v4, La8/w0;->o:Lj8/s;

    .line 2029
    .line 2030
    iget-object v6, v6, Lj8/s;->c:[Lj8/q;

    .line 2031
    .line 2032
    array-length v7, v6

    .line 2033
    const/4 v8, 0x0

    .line 2034
    :goto_45
    if-ge v8, v7, :cond_7a

    .line 2035
    .line 2036
    aget-object v9, v6, v8

    .line 2037
    .line 2038
    if-eqz v9, :cond_79

    .line 2039
    .line 2040
    invoke-interface {v9}, Lj8/q;->l()V

    .line 2041
    .line 2042
    .line 2043
    :cond_79
    add-int/lit8 v8, v8, 0x1

    .line 2044
    .line 2045
    goto :goto_45

    .line 2046
    :cond_7a
    iget-object v4, v4, La8/w0;->m:La8/w0;

    .line 2047
    .line 2048
    goto :goto_44

    .line 2049
    :cond_7b
    iget-object v4, v0, La8/q0;->w:La8/i;

    .line 2050
    .line 2051
    iget-wide v6, v4, La8/i;->h:J

    .line 2052
    .line 2053
    cmp-long v8, v6, v27

    .line 2054
    .line 2055
    if-nez v8, :cond_7c

    .line 2056
    .line 2057
    goto :goto_46

    .line 2058
    :cond_7c
    iget-wide v8, v4, La8/i;->b:J

    .line 2059
    .line 2060
    add-long/2addr v6, v8

    .line 2061
    iput-wide v6, v4, La8/i;->h:J

    .line 2062
    .line 2063
    iget-wide v8, v4, La8/i;->g:J

    .line 2064
    .line 2065
    cmp-long v10, v8, v27

    .line 2066
    .line 2067
    if-eqz v10, :cond_7d

    .line 2068
    .line 2069
    cmp-long v6, v6, v8

    .line 2070
    .line 2071
    if-lez v6, :cond_7d

    .line 2072
    .line 2073
    iput-wide v8, v4, La8/i;->h:J

    .line 2074
    .line 2075
    :cond_7d
    move-wide/from16 v6, v27

    .line 2076
    .line 2077
    iput-wide v6, v4, La8/i;->l:J

    .line 2078
    .line 2079
    :cond_7e
    :goto_46
    invoke-virtual {v0}, La8/q0;->u0()V

    .line 2080
    .line 2081
    .line 2082
    :cond_7f
    :goto_47
    iget-object v4, v0, La8/q0;->I:La8/i1;

    .line 2083
    .line 2084
    iget v4, v4, La8/i1;->e:I

    .line 2085
    .line 2086
    const/4 v13, 0x2

    .line 2087
    if-ne v4, v13, :cond_83

    .line 2088
    .line 2089
    const/4 v6, 0x0

    .line 2090
    :goto_48
    iget-object v4, v0, La8/q0;->d:[La8/p1;

    .line 2091
    .line 2092
    array-length v7, v4

    .line 2093
    if-ge v6, v7, :cond_82

    .line 2094
    .line 2095
    aget-object v4, v4, v6

    .line 2096
    .line 2097
    invoke-virtual {v4, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 2098
    .line 2099
    .line 2100
    move-result-object v4

    .line 2101
    if-eqz v4, :cond_80

    .line 2102
    .line 2103
    move v4, v5

    .line 2104
    goto :goto_49

    .line 2105
    :cond_80
    const/4 v4, 0x0

    .line 2106
    :goto_49
    if-eqz v4, :cond_81

    .line 2107
    .line 2108
    invoke-virtual {v0, v6}, La8/q0;->F(I)V

    .line 2109
    .line 2110
    .line 2111
    :cond_81
    add-int/lit8 v6, v6, 0x1

    .line 2112
    .line 2113
    goto :goto_48

    .line 2114
    :cond_82
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 2115
    .line 2116
    iget-boolean v4, v1, La8/i1;->g:Z

    .line 2117
    .line 2118
    if-nez v4, :cond_83

    .line 2119
    .line 2120
    iget-wide v6, v1, La8/i1;->r:J

    .line 2121
    .line 2122
    const-wide/32 v8, 0x7a120

    .line 2123
    .line 2124
    .line 2125
    cmp-long v1, v6, v8

    .line 2126
    .line 2127
    if-gez v1, :cond_83

    .line 2128
    .line 2129
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 2130
    .line 2131
    iget-object v1, v1, La8/z0;->l:La8/w0;

    .line 2132
    .line 2133
    invoke-static {v1}, La8/q0;->z(La8/w0;)Z

    .line 2134
    .line 2135
    .line 2136
    move-result v1

    .line 2137
    if-eqz v1, :cond_83

    .line 2138
    .line 2139
    invoke-virtual {v0}, La8/q0;->q0()Z

    .line 2140
    .line 2141
    .line 2142
    move-result v1

    .line 2143
    if-eqz v1, :cond_83

    .line 2144
    .line 2145
    move v6, v5

    .line 2146
    goto :goto_4a

    .line 2147
    :cond_83
    const/4 v6, 0x0

    .line 2148
    :goto_4a
    if-nez v6, :cond_84

    .line 2149
    .line 2150
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 2151
    .line 2152
    .line 2153
    .line 2154
    .line 2155
    iput-wide v6, v0, La8/q0;->c0:J

    .line 2156
    .line 2157
    goto :goto_4b

    .line 2158
    :cond_84
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 2159
    .line 2160
    .line 2161
    .line 2162
    .line 2163
    iget-wide v8, v0, La8/q0;->c0:J

    .line 2164
    .line 2165
    cmp-long v1, v8, v6

    .line 2166
    .line 2167
    if-nez v1, :cond_85

    .line 2168
    .line 2169
    iget-object v1, v0, La8/q0;->s:Lw7/r;

    .line 2170
    .line 2171
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2172
    .line 2173
    .line 2174
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2175
    .line 2176
    .line 2177
    move-result-wide v6

    .line 2178
    iput-wide v6, v0, La8/q0;->c0:J

    .line 2179
    .line 2180
    goto :goto_4b

    .line 2181
    :cond_85
    iget-object v1, v0, La8/q0;->s:Lw7/r;

    .line 2182
    .line 2183
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2184
    .line 2185
    .line 2186
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2187
    .line 2188
    .line 2189
    move-result-wide v6

    .line 2190
    iget-wide v8, v0, La8/q0;->c0:J

    .line 2191
    .line 2192
    sub-long/2addr v6, v8

    .line 2193
    const-wide/16 v8, 0xfa0

    .line 2194
    .line 2195
    cmp-long v1, v6, v8

    .line 2196
    .line 2197
    if-gez v1, :cond_8c

    .line 2198
    .line 2199
    :goto_4b
    invoke-virtual {v0}, La8/q0;->q0()Z

    .line 2200
    .line 2201
    .line 2202
    move-result v1

    .line 2203
    if-eqz v1, :cond_86

    .line 2204
    .line 2205
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 2206
    .line 2207
    iget v1, v1, La8/i1;->e:I

    .line 2208
    .line 2209
    if-ne v1, v15, :cond_86

    .line 2210
    .line 2211
    move v6, v5

    .line 2212
    goto :goto_4c

    .line 2213
    :cond_86
    const/4 v6, 0x0

    .line 2214
    :goto_4c
    iget-boolean v1, v0, La8/q0;->U:Z

    .line 2215
    .line 2216
    if-eqz v1, :cond_87

    .line 2217
    .line 2218
    iget-boolean v1, v0, La8/q0;->T:Z

    .line 2219
    .line 2220
    if-eqz v1, :cond_87

    .line 2221
    .line 2222
    if-eqz v6, :cond_87

    .line 2223
    .line 2224
    goto :goto_4d

    .line 2225
    :cond_87
    const/4 v5, 0x0

    .line 2226
    :goto_4d
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 2227
    .line 2228
    iget-boolean v4, v1, La8/i1;->p:Z

    .line 2229
    .line 2230
    if-eq v4, v5, :cond_88

    .line 2231
    .line 2232
    invoke-virtual {v1, v5}, La8/i1;->i(Z)La8/i1;

    .line 2233
    .line 2234
    .line 2235
    move-result-object v1

    .line 2236
    iput-object v1, v0, La8/q0;->I:La8/i1;

    .line 2237
    .line 2238
    :cond_88
    const/4 v4, 0x0

    .line 2239
    iput-boolean v4, v0, La8/q0;->T:Z

    .line 2240
    .line 2241
    if-nez v5, :cond_8b

    .line 2242
    .line 2243
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 2244
    .line 2245
    iget v1, v1, La8/i1;->e:I

    .line 2246
    .line 2247
    if-ne v1, v14, :cond_89

    .line 2248
    .line 2249
    goto :goto_4e

    .line 2250
    :cond_89
    if-nez v6, :cond_8a

    .line 2251
    .line 2252
    const/4 v13, 0x2

    .line 2253
    if-eq v1, v13, :cond_8a

    .line 2254
    .line 2255
    if-ne v1, v15, :cond_8b

    .line 2256
    .line 2257
    iget v1, v0, La8/q0;->V:I

    .line 2258
    .line 2259
    if-eqz v1, :cond_8b

    .line 2260
    .line 2261
    :cond_8a
    invoke-virtual {v0, v2, v3}, La8/q0;->U(J)V

    .line 2262
    .line 2263
    .line 2264
    :cond_8b
    :goto_4e
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 2265
    .line 2266
    .line 2267
    return-void

    .line 2268
    :cond_8c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2269
    .line 2270
    const-string v1, "Playback stuck buffering and not loading"

    .line 2271
    .line 2272
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2273
    .line 2274
    .line 2275
    throw v0

    .line 2276
    :cond_8d
    :goto_4f
    return-void
.end method

.method public final j0(La8/r1;)V
    .locals 0

    .line 1
    iput-object p1, p0, La8/q0;->D:La8/r1;

    .line 2
    .line 3
    return-void
.end method

.method public final k(La8/w0;IZJ)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, La8/q0;->d:[La8/p1;

    .line 6
    .line 7
    aget-object v10, v2, p2

    .line 8
    .line 9
    invoke-virtual {v10}, La8/p1;->g()Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    iget-object v3, v10, La8/p1;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, La8/f;

    .line 16
    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    goto/16 :goto_a

    .line 20
    .line 21
    :cond_0
    iget-object v2, v0, La8/q0;->u:La8/z0;

    .line 22
    .line 23
    iget-object v2, v2, La8/z0;->i:La8/w0;

    .line 24
    .line 25
    const/4 v4, 0x1

    .line 26
    if-ne v1, v2, :cond_1

    .line 27
    .line 28
    move v12, v4

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 v12, 0x0

    .line 31
    :goto_0
    iget-object v2, v1, La8/w0;->o:Lj8/s;

    .line 32
    .line 33
    iget-object v5, v2, Lj8/s;->b:[La8/o1;

    .line 34
    .line 35
    aget-object v5, v5, p2

    .line 36
    .line 37
    iget-object v2, v2, Lj8/s;->c:[Lj8/q;

    .line 38
    .line 39
    aget-object v2, v2, p2

    .line 40
    .line 41
    invoke-virtual {v0}, La8/q0;->q0()Z

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-eqz v6, :cond_2

    .line 46
    .line 47
    iget-object v6, v0, La8/q0;->I:La8/i1;

    .line 48
    .line 49
    iget v6, v6, La8/i1;->e:I

    .line 50
    .line 51
    const/4 v7, 0x3

    .line 52
    if-ne v6, v7, :cond_2

    .line 53
    .line 54
    move v13, v4

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    const/4 v13, 0x0

    .line 57
    :goto_1
    if-nez p3, :cond_3

    .line 58
    .line 59
    if-eqz v13, :cond_3

    .line 60
    .line 61
    move v14, v4

    .line 62
    goto :goto_2

    .line 63
    :cond_3
    const/4 v14, 0x0

    .line 64
    :goto_2
    iget v6, v0, La8/q0;->V:I

    .line 65
    .line 66
    add-int/2addr v6, v4

    .line 67
    iput v6, v0, La8/q0;->V:I

    .line 68
    .line 69
    iget-object v6, v1, La8/w0;->c:[Lh8/y0;

    .line 70
    .line 71
    aget-object v6, v6, p2

    .line 72
    .line 73
    iget-wide v7, v1, La8/w0;->p:J

    .line 74
    .line 75
    iget-object v9, v1, La8/w0;->g:La8/x0;

    .line 76
    .line 77
    iget-object v9, v9, La8/x0;->a:Lh8/b0;

    .line 78
    .line 79
    iget-object v15, v10, La8/p1;->f:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v15, La8/f;

    .line 82
    .line 83
    if-eqz v2, :cond_4

    .line 84
    .line 85
    invoke-interface {v2}, Lj8/q;->length()I

    .line 86
    .line 87
    .line 88
    move-result v16

    .line 89
    move/from16 v11, v16

    .line 90
    .line 91
    :goto_3
    move-object/from16 v17, v3

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_4
    const/4 v11, 0x0

    .line 95
    goto :goto_3

    .line 96
    :goto_4
    new-array v3, v11, [Lt7/o;

    .line 97
    .line 98
    const/4 v4, 0x0

    .line 99
    :goto_5
    if-ge v4, v11, :cond_5

    .line 100
    .line 101
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 102
    .line 103
    .line 104
    invoke-interface {v2, v4}, Lj8/q;->a(I)Lt7/o;

    .line 105
    .line 106
    .line 107
    move-result-object v18

    .line 108
    aput-object v18, v3, v4

    .line 109
    .line 110
    add-int/lit8 v4, v4, 0x1

    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_5
    iget v2, v10, La8/p1;->d:I

    .line 114
    .line 115
    iget-object v11, v0, La8/q0;->q:La8/l;

    .line 116
    .line 117
    if-eqz v2, :cond_6

    .line 118
    .line 119
    const/4 v4, 0x2

    .line 120
    if-eq v2, v4, :cond_6

    .line 121
    .line 122
    const/4 v4, 0x4

    .line 123
    if-ne v2, v4, :cond_7

    .line 124
    .line 125
    :cond_6
    move-object v4, v6

    .line 126
    const/4 v2, 0x1

    .line 127
    goto :goto_7

    .line 128
    :cond_7
    const/4 v2, 0x1

    .line 129
    iput-boolean v2, v10, La8/p1;->b:Z

    .line 130
    .line 131
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    iget v4, v15, La8/f;->k:I

    .line 135
    .line 136
    if-nez v4, :cond_8

    .line 137
    .line 138
    move v4, v2

    .line 139
    goto :goto_6

    .line 140
    :cond_8
    const/4 v4, 0x0

    .line 141
    :goto_6
    invoke-static {v4}, Lw7/a;->j(Z)V

    .line 142
    .line 143
    .line 144
    iput-object v5, v15, La8/f;->g:La8/o1;

    .line 145
    .line 146
    iput-object v9, v15, La8/f;->t:Lh8/b0;

    .line 147
    .line 148
    iput v2, v15, La8/f;->k:I

    .line 149
    .line 150
    invoke-virtual {v15, v14, v12}, La8/f;->q(ZZ)V

    .line 151
    .line 152
    .line 153
    move-object v4, v6

    .line 154
    move-object v2, v15

    .line 155
    move-wide/from16 v5, p4

    .line 156
    .line 157
    invoke-virtual/range {v2 .. v9}, La8/f;->z([Lt7/o;Lh8/y0;JJLh8/b0;)V

    .line 158
    .line 159
    .line 160
    move-wide v3, v5

    .line 161
    const/4 v5, 0x0

    .line 162
    iput-boolean v5, v2, La8/f;->q:Z

    .line 163
    .line 164
    iput-wide v3, v2, La8/f;->o:J

    .line 165
    .line 166
    iput-wide v3, v2, La8/f;->p:J

    .line 167
    .line 168
    invoke-virtual {v2, v3, v4, v14}, La8/f;->r(JZ)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v11, v2}, La8/l;->f(La8/f;)V

    .line 172
    .line 173
    .line 174
    goto :goto_9

    .line 175
    :goto_7
    iput-boolean v2, v10, La8/p1;->a:Z

    .line 176
    .line 177
    move-object/from16 v6, v17

    .line 178
    .line 179
    iget v15, v6, La8/f;->k:I

    .line 180
    .line 181
    if-nez v15, :cond_9

    .line 182
    .line 183
    move v15, v2

    .line 184
    goto :goto_8

    .line 185
    :cond_9
    const/4 v15, 0x0

    .line 186
    :goto_8
    invoke-static {v15}, Lw7/a;->j(Z)V

    .line 187
    .line 188
    .line 189
    iput-object v5, v6, La8/f;->g:La8/o1;

    .line 190
    .line 191
    iput-object v9, v6, La8/f;->t:Lh8/b0;

    .line 192
    .line 193
    iput v2, v6, La8/f;->k:I

    .line 194
    .line 195
    invoke-virtual {v6, v14, v12}, La8/f;->q(ZZ)V

    .line 196
    .line 197
    .line 198
    move-object v2, v6

    .line 199
    move-wide/from16 v5, p4

    .line 200
    .line 201
    invoke-virtual/range {v2 .. v9}, La8/f;->z([Lt7/o;Lh8/y0;JJLh8/b0;)V

    .line 202
    .line 203
    .line 204
    const/4 v3, 0x0

    .line 205
    iput-boolean v3, v2, La8/f;->q:Z

    .line 206
    .line 207
    iput-wide v5, v2, La8/f;->o:J

    .line 208
    .line 209
    iput-wide v5, v2, La8/f;->p:J

    .line 210
    .line 211
    invoke-virtual {v2, v5, v6, v14}, La8/f;->r(JZ)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v11, v2}, La8/l;->f(La8/f;)V

    .line 215
    .line 216
    .line 217
    :goto_9
    new-instance v2, La8/l0;

    .line 218
    .line 219
    invoke-direct {v2, v0}, La8/l0;-><init>(La8/q0;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v10, v1}, La8/p1;->d(La8/w0;)La8/f;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 227
    .line 228
    .line 229
    const/16 v1, 0xb

    .line 230
    .line 231
    invoke-interface {v0, v1, v2}, La8/k1;->a(ILjava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    if-eqz v13, :cond_a

    .line 235
    .line 236
    if-eqz v12, :cond_a

    .line 237
    .line 238
    invoke-virtual {v10}, La8/p1;->m()V

    .line 239
    .line 240
    .line 241
    :cond_a
    :goto_a
    return-void
.end method

.method public final k0(Z)V
    .locals 2

    .line 1
    iput-boolean p1, p0, La8/q0;->R:Z

    .line 2
    .line 3
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 4
    .line 5
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 6
    .line 7
    iget-object v1, p0, La8/q0;->u:La8/z0;

    .line 8
    .line 9
    iput-boolean p1, v1, La8/z0;->h:Z

    .line 10
    .line 11
    invoke-virtual {v1, v0}, La8/z0;->r(Lt7/p0;)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    and-int/lit8 v0, p1, 0x1

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-virtual {p0, p1}, La8/q0;->V(Z)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    and-int/lit8 p1, p1, 0x2

    .line 25
    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, La8/q0;->h()V

    .line 29
    .line 30
    .line 31
    :cond_1
    :goto_0
    const/4 p1, 0x0

    .line 32
    invoke-virtual {p0, p1}, La8/q0;->u(Z)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final l([ZJ)V
    .locals 8

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v2, v0, La8/z0;->j:La8/w0;

    .line 4
    .line 5
    iget-object v0, v2, La8/w0;->o:Lj8/s;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    move v3, v1

    .line 9
    :goto_0
    iget-object v7, p0, La8/q0;->d:[La8/p1;

    .line 10
    .line 11
    array-length v4, v7

    .line 12
    if-ge v3, v4, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0, v3}, Lj8/s;->b(I)Z

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    if-nez v4, :cond_0

    .line 19
    .line 20
    aget-object v4, v7, v3

    .line 21
    .line 22
    invoke-virtual {v4}, La8/p1;->k()V

    .line 23
    .line 24
    .line 25
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    move v3, v1

    .line 29
    :goto_1
    array-length v1, v7

    .line 30
    if-ge v3, v1, :cond_4

    .line 31
    .line 32
    invoke-virtual {v0, v3}, Lj8/s;->b(I)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_2

    .line 37
    .line 38
    aget-object v1, v7, v3

    .line 39
    .line 40
    invoke-virtual {v1, v2}, La8/p1;->d(La8/w0;)La8/f;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    if-eqz v1, :cond_3

    .line 45
    .line 46
    :cond_2
    move-object v1, p0

    .line 47
    move-wide v5, p2

    .line 48
    goto :goto_2

    .line 49
    :cond_3
    aget-boolean v4, p1, v3

    .line 50
    .line 51
    move-object v1, p0

    .line 52
    move-wide v5, p2

    .line 53
    invoke-virtual/range {v1 .. v6}, La8/q0;->k(La8/w0;IZJ)V

    .line 54
    .line 55
    .line 56
    :goto_2
    add-int/lit8 v3, v3, 0x1

    .line 57
    .line 58
    move-object p0, v1

    .line 59
    move-wide p2, v5

    .line 60
    goto :goto_1

    .line 61
    :cond_4
    return-void
.end method

.method public final l0(Lh8/a1;)V
    .locals 6

    .line 1
    iget-object v0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, La8/n0;->f(I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, La8/q0;->v:Lac/i;

    .line 8
    .line 9
    iget-object v1, v0, Lac/i;->c:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    iget-object v2, p1, Lh8/a1;->b:[I

    .line 18
    .line 19
    array-length v2, v2

    .line 20
    if-eq v2, v1, :cond_0

    .line 21
    .line 22
    new-instance v2, Lh8/a1;

    .line 23
    .line 24
    new-instance v3, Ljava/util/Random;

    .line 25
    .line 26
    iget-object p1, p1, Lh8/a1;->a:Ljava/util/Random;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/util/Random;->nextLong()J

    .line 29
    .line 30
    .line 31
    move-result-wide v4

    .line 32
    invoke-direct {v3, v4, v5}, Ljava/util/Random;-><init>(J)V

    .line 33
    .line 34
    .line 35
    invoke-direct {v2, v3}, Lh8/a1;-><init>(Ljava/util/Random;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2, v1}, Lh8/a1;->a(I)Lh8/a1;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    :cond_0
    iput-object p1, v0, Lac/i;->k:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-virtual {v0}, Lac/i;->c()Lt7/p0;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    const/4 v0, 0x0

    .line 49
    invoke-virtual {p0, p1, v0}, La8/q0;->v(Lt7/p0;Z)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public final m(Lt7/p0;Ljava/lang/Object;J)J
    .locals 3

    .line 1
    iget-object v0, p0, La8/q0;->o:Lt7/n0;

    .line 2
    .line 3
    invoke-virtual {p1, p2, v0}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    iget p2, p2, Lt7/n0;->c:I

    .line 8
    .line 9
    iget-object p0, p0, La8/q0;->n:Lt7/o0;

    .line 10
    .line 11
    invoke-virtual {p1, p2, p0}, Lt7/p0;->n(ILt7/o0;)V

    .line 12
    .line 13
    .line 14
    iget-wide p1, p0, Lt7/o0;->e:J

    .line 15
    .line 16
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    cmp-long p1, p1, v1

    .line 22
    .line 23
    if-eqz p1, :cond_2

    .line 24
    .line 25
    invoke-virtual {p0}, Lt7/o0;->a()Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p1, :cond_2

    .line 30
    .line 31
    iget-boolean p1, p0, Lt7/o0;->h:Z

    .line 32
    .line 33
    if-nez p1, :cond_0

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_0
    iget-wide p1, p0, Lt7/o0;->f:J

    .line 37
    .line 38
    cmp-long v1, p1, v1

    .line 39
    .line 40
    if-nez v1, :cond_1

    .line 41
    .line 42
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 43
    .line 44
    .line 45
    move-result-wide p1

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 48
    .line 49
    .line 50
    move-result-wide v1

    .line 51
    add-long/2addr p1, v1

    .line 52
    :goto_0
    iget-wide v1, p0, Lt7/o0;->e:J

    .line 53
    .line 54
    sub-long/2addr p1, v1

    .line 55
    invoke-static {p1, p2}, Lw7/w;->D(J)J

    .line 56
    .line 57
    .line 58
    move-result-wide p0

    .line 59
    iget-wide v0, v0, Lt7/n0;->e:J

    .line 60
    .line 61
    add-long/2addr p3, v0

    .line 62
    sub-long/2addr p0, p3

    .line 63
    return-wide p0

    .line 64
    :cond_2
    :goto_1
    return-wide v1
.end method

.method public final m0(I)V
    .locals 3

    .line 1
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 2
    .line 3
    iget v1, v0, La8/i1;->e:I

    .line 4
    .line 5
    if-eq v1, p1, :cond_2

    .line 6
    .line 7
    const/4 v1, 0x2

    .line 8
    if-eq p1, v1, :cond_0

    .line 9
    .line 10
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    iput-wide v1, p0, La8/q0;->c0:J

    .line 16
    .line 17
    :cond_0
    const/4 v1, 0x3

    .line 18
    if-eq p1, v1, :cond_1

    .line 19
    .line 20
    iget-boolean v1, v0, La8/i1;->p:Z

    .line 21
    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-virtual {v0, v1}, La8/i1;->i(Z)La8/i1;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, La8/q0;->I:La8/i1;

    .line 30
    .line 31
    :cond_1
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 32
    .line 33
    invoke-virtual {v0, p1}, La8/i1;->h(I)La8/i1;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iput-object p1, p0, La8/q0;->I:La8/i1;

    .line 38
    .line 39
    :cond_2
    return-void
.end method

.method public final n(La8/w0;)J
    .locals 8

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const-wide/16 p0, 0x0

    .line 4
    .line 5
    return-wide p0

    .line 6
    :cond_0
    iget-wide v0, p1, La8/w0;->p:J

    .line 7
    .line 8
    iget-boolean v2, p1, La8/w0;->e:Z

    .line 9
    .line 10
    if-nez v2, :cond_1

    .line 11
    .line 12
    return-wide v0

    .line 13
    :cond_1
    const/4 v2, 0x0

    .line 14
    :goto_0
    iget-object v3, p0, La8/q0;->d:[La8/p1;

    .line 15
    .line 16
    array-length v4, v3

    .line 17
    if-ge v2, v4, :cond_4

    .line 18
    .line 19
    aget-object v4, v3, v2

    .line 20
    .line 21
    invoke-virtual {v4, p1}, La8/p1;->d(La8/w0;)La8/f;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    if-eqz v4, :cond_3

    .line 26
    .line 27
    aget-object v3, v3, v2

    .line 28
    .line 29
    invoke-virtual {v3, p1}, La8/p1;->d(La8/w0;)La8/f;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    iget-wide v3, v3, La8/f;->p:J

    .line 37
    .line 38
    const-wide/high16 v5, -0x8000000000000000L

    .line 39
    .line 40
    cmp-long v7, v3, v5

    .line 41
    .line 42
    if-nez v7, :cond_2

    .line 43
    .line 44
    return-wide v5

    .line 45
    :cond_2
    invoke-static {v3, v4, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 46
    .line 47
    .line 48
    move-result-wide v0

    .line 49
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_4
    return-wide v0
.end method

.method public final n0(Lm8/x;)V
    .locals 6

    .line 1
    iget-object p0, p0, La8/q0;->d:[La8/p1;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    if-ge v1, v0, :cond_2

    .line 6
    .line 7
    aget-object v2, p0, v1

    .line 8
    .line 9
    iget-object v3, v2, La8/p1;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, La8/f;

    .line 12
    .line 13
    iget v4, v3, La8/f;->e:I

    .line 14
    .line 15
    const/4 v5, 0x2

    .line 16
    if-eq v4, v5, :cond_0

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    const/4 v4, 0x7

    .line 20
    invoke-interface {v3, v4, p1}, La8/k1;->a(ILjava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object v2, v2, La8/p1;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v2, La8/f;

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    invoke-interface {v2, v4, p1}, La8/k1;->a(ILjava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    return-void
.end method

.method public final o(Lt7/p0;)Landroid/util/Pair;
    .locals 9

    .line 1
    invoke-virtual {p1}, Lt7/p0;->p()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-wide/16 v1, 0x0

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, La8/i1;->u:Lh8/b0;

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-static {p0, p1}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    iget-boolean v0, p0, La8/q0;->R:Z

    .line 21
    .line 22
    invoke-virtual {p1, v0}, Lt7/p0;->a(Z)I

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    iget-object v5, p0, La8/q0;->o:Lt7/n0;

    .line 27
    .line 28
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    iget-object v4, p0, La8/q0;->n:Lt7/o0;

    .line 34
    .line 35
    move-object v3, p1

    .line 36
    invoke-virtual/range {v3 .. v8}, Lt7/p0;->i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 41
    .line 42
    iget-object v4, p1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-virtual {v0, v3, v4, v1, v2}, La8/z0;->p(Lt7/p0;Ljava/lang/Object;J)Lh8/b0;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iget-object p1, p1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p1, Ljava/lang/Long;

    .line 51
    .line 52
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 53
    .line 54
    .line 55
    move-result-wide v4

    .line 56
    invoke-virtual {v0}, Lh8/b0;->b()Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_1

    .line 61
    .line 62
    iget-object p1, v0, Lh8/b0;->a:Ljava/lang/Object;

    .line 63
    .line 64
    iget-object p0, p0, La8/q0;->o:Lt7/n0;

    .line 65
    .line 66
    invoke-virtual {v3, p1, p0}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 67
    .line 68
    .line 69
    iget p1, v0, Lh8/b0;->c:I

    .line 70
    .line 71
    iget v3, v0, Lh8/b0;->b:I

    .line 72
    .line 73
    invoke-virtual {p0, v3}, Lt7/n0;->e(I)I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    if-ne p1, v3, :cond_2

    .line 78
    .line 79
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_1
    move-wide v1, v4

    .line 86
    :cond_2
    :goto_0
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    invoke-static {v0, p0}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0
.end method

.method public final o0(Ljava/lang/Object;Lw7/e;)V
    .locals 8

    .line 1
    iget-object v0, p0, La8/q0;->d:[La8/p1;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    :goto_0
    const/4 v3, 0x2

    .line 6
    if-ge v2, v1, :cond_3

    .line 7
    .line 8
    aget-object v4, v0, v2

    .line 9
    .line 10
    iget-object v5, v4, La8/p1;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v5, La8/f;

    .line 13
    .line 14
    iget v6, v5, La8/f;->e:I

    .line 15
    .line 16
    if-eq v6, v3, :cond_0

    .line 17
    .line 18
    goto :goto_2

    .line 19
    :cond_0
    iget v3, v4, La8/p1;->d:I

    .line 20
    .line 21
    const/4 v6, 0x4

    .line 22
    const/4 v7, 0x1

    .line 23
    if-eq v3, v6, :cond_2

    .line 24
    .line 25
    if-ne v3, v7, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    invoke-interface {v5, v7, p1}, La8/k1;->a(ILjava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    :goto_1
    iget-object v3, v4, La8/p1;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v3, La8/f;

    .line 35
    .line 36
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-interface {v3, v7, p1}, La8/k1;->a(ILjava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_3
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 46
    .line 47
    iget p1, p1, La8/i1;->e:I

    .line 48
    .line 49
    const/4 v0, 0x3

    .line 50
    if-eq p1, v0, :cond_4

    .line 51
    .line 52
    if-ne p1, v3, :cond_5

    .line 53
    .line 54
    :cond_4
    iget-object p0, p0, La8/q0;->k:Lw7/t;

    .line 55
    .line 56
    invoke-virtual {p0, v3}, Lw7/t;->e(I)Z

    .line 57
    .line 58
    .line 59
    :cond_5
    if-eqz p2, :cond_6

    .line 60
    .line 61
    invoke-virtual {p2}, Lw7/e;->c()Z

    .line 62
    .line 63
    .line 64
    :cond_6
    return-void
.end method

.method public final p(J)J
    .locals 7

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->l:La8/w0;

    .line 4
    .line 5
    const-wide/16 v1, 0x0

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    return-wide v1

    .line 10
    :cond_0
    iget-wide v3, p0, La8/q0;->X:J

    .line 11
    .line 12
    iget-wide v5, v0, La8/w0;->p:J

    .line 13
    .line 14
    sub-long/2addr v3, v5

    .line 15
    sub-long/2addr p1, v3

    .line 16
    invoke-static {v1, v2, p1, p2}, Ljava/lang/Math;->max(JJ)J

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    return-wide p0
.end method

.method public final p0(F)V
    .locals 6

    .line 1
    iput p1, p0, La8/q0;->g0:F

    .line 2
    .line 3
    iget-object v0, p0, La8/q0;->C:La8/e;

    .line 4
    .line 5
    iget v0, v0, La8/e;->g:F

    .line 6
    .line 7
    mul-float/2addr p1, v0

    .line 8
    iget-object p0, p0, La8/q0;->d:[La8/p1;

    .line 9
    .line 10
    array-length v0, p0

    .line 11
    const/4 v1, 0x0

    .line 12
    :goto_0
    if-ge v1, v0, :cond_2

    .line 13
    .line 14
    aget-object v2, p0, v1

    .line 15
    .line 16
    iget-object v3, v2, La8/p1;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v3, La8/f;

    .line 19
    .line 20
    iget v4, v3, La8/f;->e:I

    .line 21
    .line 22
    const/4 v5, 0x1

    .line 23
    if-eq v4, v5, :cond_0

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    const/4 v5, 0x2

    .line 31
    invoke-interface {v3, v5, v4}, La8/k1;->a(ILjava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object v2, v2, La8/p1;->f:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v2, La8/f;

    .line 37
    .line 38
    if-eqz v2, :cond_1

    .line 39
    .line 40
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    invoke-interface {v2, v5, v3}, La8/k1;->a(ILjava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    return-void
.end method

.method public final q(I)V
    .locals 3

    .line 1
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 2
    .line 3
    iget-boolean v1, v0, La8/i1;->l:Z

    .line 4
    .line 5
    iget v2, v0, La8/i1;->n:I

    .line 6
    .line 7
    iget v0, v0, La8/i1;->m:I

    .line 8
    .line 9
    invoke-virtual {p0, p1, v2, v0, v1}, La8/q0;->y0(IIIZ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final q0()Z
    .locals 1

    .line 1
    iget-object p0, p0, La8/q0;->I:La8/i1;

    .line 2
    .line 3
    iget-boolean v0, p0, La8/i1;->l:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget p0, p0, La8/i1;->n:I

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final r()V
    .locals 1

    .line 1
    iget v0, p0, La8/q0;->g0:F

    .line 2
    .line 3
    invoke-virtual {p0, v0}, La8/q0;->p0(F)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final r0(Lt7/p0;Lh8/b0;)Z
    .locals 2

    .line 1
    invoke-virtual {p2}, Lh8/b0;->b()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Lt7/p0;->p()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object p2, p2, Lh8/b0;->a:Ljava/lang/Object;

    .line 15
    .line 16
    iget-object v0, p0, La8/q0;->o:Lt7/n0;

    .line 17
    .line 18
    invoke-virtual {p1, p2, v0}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    iget p2, p2, Lt7/n0;->c:I

    .line 23
    .line 24
    iget-object p0, p0, La8/q0;->n:Lt7/o0;

    .line 25
    .line 26
    invoke-virtual {p1, p2, p0}, Lt7/p0;->n(ILt7/o0;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Lt7/o0;->a()Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_1

    .line 34
    .line 35
    iget-boolean p1, p0, Lt7/o0;->h:Z

    .line 36
    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    iget-wide p0, p0, Lt7/o0;->e:J

    .line 40
    .line 41
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    cmp-long p0, p0, v0

    .line 47
    .line 48
    if-eqz p0, :cond_1

    .line 49
    .line 50
    const/4 p0, 0x1

    .line 51
    return p0

    .line 52
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 53
    return p0
.end method

.method public final s(Lh8/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v1, v0, La8/z0;->l:La8/w0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, v1, La8/w0;->a:Ljava/lang/Object;

    .line 8
    .line 9
    if-ne v1, p1, :cond_0

    .line 10
    .line 11
    iget-wide v1, p0, La8/q0;->X:J

    .line 12
    .line 13
    invoke-virtual {v0, v1, v2}, La8/z0;->m(J)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, La8/q0;->C()V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    iget-object v0, v0, La8/z0;->m:La8/w0;

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    iget-object v0, v0, La8/w0;->a:Ljava/lang/Object;

    .line 25
    .line 26
    if-ne v0, p1, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, La8/q0;->D()V

    .line 29
    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public final s0()V
    .locals 4

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->i:La8/w0;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_2

    .line 8
    :cond_0
    iget-object v0, v0, La8/w0;->o:Lj8/s;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    :goto_0
    iget-object v2, p0, La8/q0;->d:[La8/p1;

    .line 12
    .line 13
    array-length v3, v2

    .line 14
    if-ge v1, v3, :cond_2

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lj8/s;->b(I)Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-nez v3, :cond_1

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_1
    aget-object v2, v2, v1

    .line 24
    .line 25
    invoke-virtual {v2}, La8/p1;->m()V

    .line 26
    .line 27
    .line 28
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_2
    :goto_2
    return-void
.end method

.method public final t(Ljava/io/IOException;I)V
    .locals 2

    .line 1
    new-instance v0, La8/o;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p1, p2}, La8/o;-><init>(ILjava/lang/Exception;I)V

    .line 5
    .line 6
    .line 7
    iget-object p1, p0, La8/q0;->u:La8/z0;

    .line 8
    .line 9
    iget-object p1, p1, La8/z0;->i:La8/w0;

    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    iget-object p1, p1, La8/w0;->g:La8/x0;

    .line 14
    .line 15
    iget-object p1, p1, La8/x0;->a:Lh8/b0;

    .line 16
    .line 17
    invoke-virtual {v0, p1}, La8/o;->a(Lh8/b0;)La8/o;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    :cond_0
    const-string p1, "ExoPlayerImplInternal"

    .line 22
    .line 23
    const-string p2, "Playback error"

    .line 24
    .line 25
    invoke-static {p1, p2, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, v1, v1}, La8/q0;->t0(ZZ)V

    .line 29
    .line 30
    .line 31
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 32
    .line 33
    invoke-virtual {p1, v0}, La8/i1;->f(La8/o;)La8/i1;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iput-object p1, p0, La8/q0;->I:La8/i1;

    .line 38
    .line 39
    return-void
.end method

.method public final t0(ZZ)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-nez p1, :cond_1

    .line 4
    .line 5
    iget-boolean p1, p0, La8/q0;->S:Z

    .line 6
    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move p1, v0

    .line 11
    goto :goto_1

    .line 12
    :cond_1
    :goto_0
    move p1, v1

    .line 13
    :goto_1
    invoke-virtual {p0, p1, v0, v1, v0}, La8/q0;->O(ZZZZ)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p0, La8/q0;->J:La8/n0;

    .line 17
    .line 18
    invoke-virtual {p1, p2}, La8/n0;->f(I)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, La8/q0;->i:La8/k;

    .line 22
    .line 23
    iget-object p2, p1, La8/k;->h:Ljava/util/HashMap;

    .line 24
    .line 25
    iget-object v0, p0, La8/q0;->y:Lb8/k;

    .line 26
    .line 27
    invoke-virtual {p2, v0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    if-eqz p2, :cond_2

    .line 32
    .line 33
    invoke-virtual {p1}, La8/k;->d()V

    .line 34
    .line 35
    .line 36
    :cond_2
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 37
    .line 38
    iget-boolean p1, p1, La8/i1;->l:Z

    .line 39
    .line 40
    iget-object p2, p0, La8/q0;->C:La8/e;

    .line 41
    .line 42
    invoke-virtual {p2, v1, p1}, La8/e;->d(IZ)I

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v1}, La8/q0;->m0(I)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public final u(Z)V
    .locals 5

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->l:La8/w0;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, La8/q0;->I:La8/i1;

    .line 8
    .line 9
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v1, v0, La8/w0;->g:La8/x0;

    .line 13
    .line 14
    iget-object v1, v1, La8/x0;->a:Lh8/b0;

    .line 15
    .line 16
    :goto_0
    iget-object v2, p0, La8/q0;->I:La8/i1;

    .line 17
    .line 18
    iget-object v2, v2, La8/i1;->k:Lh8/b0;

    .line 19
    .line 20
    invoke-virtual {v2, v1}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    iget-object v3, p0, La8/q0;->I:La8/i1;

    .line 27
    .line 28
    invoke-virtual {v3, v1}, La8/i1;->c(Lh8/b0;)La8/i1;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    iput-object v1, p0, La8/q0;->I:La8/i1;

    .line 33
    .line 34
    :cond_1
    iget-object v1, p0, La8/q0;->I:La8/i1;

    .line 35
    .line 36
    if-nez v0, :cond_2

    .line 37
    .line 38
    iget-wide v3, v1, La8/i1;->s:J

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    invoke-virtual {v0}, La8/w0;->d()J

    .line 42
    .line 43
    .line 44
    move-result-wide v3

    .line 45
    :goto_1
    iput-wide v3, v1, La8/i1;->q:J

    .line 46
    .line 47
    iget-object v1, p0, La8/q0;->I:La8/i1;

    .line 48
    .line 49
    iget-wide v3, v1, La8/i1;->q:J

    .line 50
    .line 51
    invoke-virtual {p0, v3, v4}, La8/q0;->p(J)J

    .line 52
    .line 53
    .line 54
    move-result-wide v3

    .line 55
    iput-wide v3, v1, La8/i1;->r:J

    .line 56
    .line 57
    if-eqz v2, :cond_3

    .line 58
    .line 59
    if-eqz p1, :cond_4

    .line 60
    .line 61
    :cond_3
    if-eqz v0, :cond_4

    .line 62
    .line 63
    iget-boolean p1, v0, La8/w0;->e:Z

    .line 64
    .line 65
    if-eqz p1, :cond_4

    .line 66
    .line 67
    iget-object p1, v0, La8/w0;->o:Lj8/s;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, La8/q0;->w0(Lj8/s;)V

    .line 70
    .line 71
    .line 72
    :cond_4
    return-void
.end method

.method public final u0()V
    .locals 5

    .line 1
    iget-object v0, p0, La8/q0;->q:La8/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-boolean v1, v0, La8/l;->e:Z

    .line 5
    .line 6
    iget-object v0, v0, La8/l;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, La8/s1;

    .line 9
    .line 10
    iget-boolean v2, v0, La8/s1;->e:Z

    .line 11
    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, La8/s1;->e()J

    .line 15
    .line 16
    .line 17
    move-result-wide v2

    .line 18
    invoke-virtual {v0, v2, v3}, La8/s1;->a(J)V

    .line 19
    .line 20
    .line 21
    iput-boolean v1, v0, La8/s1;->e:Z

    .line 22
    .line 23
    :cond_0
    iget-object p0, p0, La8/q0;->d:[La8/p1;

    .line 24
    .line 25
    array-length v0, p0

    .line 26
    :goto_0
    if-ge v1, v0, :cond_3

    .line 27
    .line 28
    aget-object v2, p0, v1

    .line 29
    .line 30
    iget-object v3, v2, La8/p1;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v3, La8/f;

    .line 33
    .line 34
    iget-object v2, v2, La8/p1;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v2, La8/f;

    .line 37
    .line 38
    invoke-static {v2}, La8/p1;->h(La8/f;)Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    if-eqz v4, :cond_1

    .line 43
    .line 44
    invoke-static {v2}, La8/p1;->b(La8/f;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    if-eqz v3, :cond_2

    .line 48
    .line 49
    iget v2, v3, La8/f;->k:I

    .line 50
    .line 51
    if-eqz v2, :cond_2

    .line 52
    .line 53
    invoke-static {v3}, La8/p1;->b(La8/f;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    return-void
.end method

.method public final v(Lt7/p0;Z)V
    .locals 35

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 4
    .line 5
    iget-object v3, v1, La8/q0;->W:La8/p0;

    .line 6
    .line 7
    iget-object v9, v1, La8/q0;->u:La8/z0;

    .line 8
    .line 9
    iget v4, v1, La8/q0;->Q:I

    .line 10
    .line 11
    iget-boolean v5, v1, La8/q0;->R:Z

    .line 12
    .line 13
    iget-object v2, v1, La8/q0;->n:Lt7/o0;

    .line 14
    .line 15
    iget-object v8, v1, La8/q0;->o:Lt7/n0;

    .line 16
    .line 17
    invoke-virtual/range {p1 .. p1}, Lt7/p0;->p()Z

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    const/4 v12, 0x4

    .line 22
    const/4 v15, -0x1

    .line 23
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    if-eqz v6, :cond_0

    .line 29
    .line 30
    new-instance v18, La8/o0;

    .line 31
    .line 32
    sget-object v19, La8/i1;->u:Lh8/b0;

    .line 33
    .line 34
    const/16 v25, 0x1

    .line 35
    .line 36
    const/16 v26, 0x0

    .line 37
    .line 38
    const-wide/16 v20, 0x0

    .line 39
    .line 40
    const-wide v22, -0x7fffffffffffffffL    # -4.9E-324

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    const/16 v24, 0x0

    .line 46
    .line 47
    invoke-direct/range {v18 .. v26}, La8/o0;-><init>(Lh8/b0;JJZZZ)V

    .line 48
    .line 49
    .line 50
    move-object/from16 v2, p1

    .line 51
    .line 52
    move-object/from16 v10, v18

    .line 53
    .line 54
    goto/16 :goto_16

    .line 55
    .line 56
    :cond_0
    iget-object v14, v0, La8/i1;->b:Lh8/b0;

    .line 57
    .line 58
    iget-object v6, v14, Lh8/b0;->a:Ljava/lang/Object;

    .line 59
    .line 60
    iget-object v7, v0, La8/i1;->a:Lt7/p0;

    .line 61
    .line 62
    invoke-virtual {v7}, Lt7/p0;->p()Z

    .line 63
    .line 64
    .line 65
    move-result v19

    .line 66
    if-nez v19, :cond_2

    .line 67
    .line 68
    iget-object v13, v14, Lh8/b0;->a:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-virtual {v7, v13, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    iget-boolean v7, v7, Lt7/n0;->f:Z

    .line 75
    .line 76
    if-eqz v7, :cond_1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_1
    const/4 v13, 0x0

    .line 80
    goto :goto_1

    .line 81
    :cond_2
    :goto_0
    const/4 v13, 0x1

    .line 82
    :goto_1
    iget-object v7, v0, La8/i1;->b:Lh8/b0;

    .line 83
    .line 84
    invoke-virtual {v7}, Lh8/b0;->b()Z

    .line 85
    .line 86
    .line 87
    move-result v7

    .line 88
    if-nez v7, :cond_4

    .line 89
    .line 90
    if-eqz v13, :cond_3

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_3
    iget-wide v10, v0, La8/i1;->s:J

    .line 94
    .line 95
    :goto_2
    move-wide/from16 v22, v10

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_4
    :goto_3
    iget-wide v10, v0, La8/i1;->c:J

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :goto_4
    if-eqz v3, :cond_8

    .line 102
    .line 103
    move-object v7, v6

    .line 104
    move v6, v5

    .line 105
    move v5, v4

    .line 106
    const/4 v4, 0x1

    .line 107
    move-object v10, v7

    .line 108
    const/4 v11, 0x0

    .line 109
    move-object v7, v2

    .line 110
    move-object/from16 v2, p1

    .line 111
    .line 112
    invoke-static/range {v2 .. v8}, La8/q0;->S(Lt7/p0;La8/p0;ZIZLt7/o0;Lt7/n0;)Landroid/util/Pair;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    if-nez v4, :cond_5

    .line 117
    .line 118
    invoke-virtual {v2, v6}, Lt7/p0;->a(Z)I

    .line 119
    .line 120
    .line 121
    move-result v3

    .line 122
    move v5, v3

    .line 123
    move-object v6, v10

    .line 124
    move/from16 v24, v11

    .line 125
    .line 126
    move-wide/from16 v3, v22

    .line 127
    .line 128
    const/4 v10, 0x1

    .line 129
    goto :goto_7

    .line 130
    :cond_5
    iget-wide v5, v3, La8/p0;->c:J

    .line 131
    .line 132
    cmp-long v3, v5, v16

    .line 133
    .line 134
    if-nez v3, :cond_6

    .line 135
    .line 136
    iget-object v3, v4, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 137
    .line 138
    invoke-virtual {v2, v3, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 139
    .line 140
    .line 141
    move-result-object v3

    .line 142
    iget v3, v3, Lt7/n0;->c:I

    .line 143
    .line 144
    move v5, v3

    .line 145
    move-object v6, v10

    .line 146
    move v10, v11

    .line 147
    move-wide/from16 v3, v22

    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_6
    iget-object v6, v4, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 151
    .line 152
    iget-object v3, v4, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v3, Ljava/lang/Long;

    .line 155
    .line 156
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 157
    .line 158
    .line 159
    move-result-wide v3

    .line 160
    move v5, v15

    .line 161
    const/4 v10, 0x1

    .line 162
    :goto_5
    iget v11, v0, La8/i1;->e:I

    .line 163
    .line 164
    if-ne v11, v12, :cond_7

    .line 165
    .line 166
    const/4 v11, 0x1

    .line 167
    goto :goto_6

    .line 168
    :cond_7
    const/4 v11, 0x0

    .line 169
    :goto_6
    move/from16 v24, v10

    .line 170
    .line 171
    const/4 v10, 0x0

    .line 172
    :goto_7
    move-wide/from16 v20, v3

    .line 173
    .line 174
    move-object v3, v7

    .line 175
    move/from16 v31, v10

    .line 176
    .line 177
    move/from16 v30, v11

    .line 178
    .line 179
    move/from16 v32, v24

    .line 180
    .line 181
    const-wide/16 v10, 0x0

    .line 182
    .line 183
    goto/16 :goto_e

    .line 184
    .line 185
    :cond_8
    move-object v7, v2

    .line 186
    move-object v10, v6

    .line 187
    move-object/from16 v2, p1

    .line 188
    .line 189
    move v6, v5

    .line 190
    move v5, v4

    .line 191
    iget-object v3, v0, La8/i1;->a:Lt7/p0;

    .line 192
    .line 193
    invoke-virtual {v3}, Lt7/p0;->p()Z

    .line 194
    .line 195
    .line 196
    move-result v3

    .line 197
    if-eqz v3, :cond_9

    .line 198
    .line 199
    invoke-virtual {v2, v6}, Lt7/p0;->a(Z)I

    .line 200
    .line 201
    .line 202
    move-result v5

    .line 203
    move-object v3, v7

    .line 204
    move-object v6, v10

    .line 205
    :goto_8
    move-wide/from16 v20, v22

    .line 206
    .line 207
    const-wide/16 v10, 0x0

    .line 208
    .line 209
    :goto_9
    const/16 v30, 0x0

    .line 210
    .line 211
    const/16 v31, 0x0

    .line 212
    .line 213
    :goto_a
    const/16 v32, 0x0

    .line 214
    .line 215
    goto/16 :goto_e

    .line 216
    .line 217
    :cond_9
    invoke-virtual {v2, v10}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 218
    .line 219
    .line 220
    move-result v3

    .line 221
    if-ne v3, v15, :cond_b

    .line 222
    .line 223
    move-object v3, v7

    .line 224
    iget-object v7, v0, La8/i1;->a:Lt7/p0;

    .line 225
    .line 226
    move-object v4, v8

    .line 227
    move-object v8, v2

    .line 228
    move-object v2, v3

    .line 229
    move-object v3, v4

    .line 230
    move v4, v5

    .line 231
    move v5, v6

    .line 232
    move-object v6, v10

    .line 233
    invoke-static/range {v2 .. v8}, La8/q0;->T(Lt7/o0;Lt7/n0;IZLjava/lang/Object;Lt7/p0;Lt7/p0;)I

    .line 234
    .line 235
    .line 236
    move-result v4

    .line 237
    move-object/from16 v33, v3

    .line 238
    .line 239
    move-object v3, v2

    .line 240
    move-object v2, v8

    .line 241
    move-object/from16 v8, v33

    .line 242
    .line 243
    if-ne v4, v15, :cond_a

    .line 244
    .line 245
    invoke-virtual {v2, v5}, Lt7/p0;->a(Z)I

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    const/4 v7, 0x1

    .line 250
    :goto_b
    move v5, v4

    .line 251
    goto :goto_c

    .line 252
    :cond_a
    const/4 v7, 0x0

    .line 253
    goto :goto_b

    .line 254
    :goto_c
    move/from16 v31, v7

    .line 255
    .line 256
    move-wide/from16 v20, v22

    .line 257
    .line 258
    const-wide/16 v10, 0x0

    .line 259
    .line 260
    const/16 v30, 0x0

    .line 261
    .line 262
    goto :goto_a

    .line 263
    :cond_b
    move-object v3, v7

    .line 264
    move-object v6, v10

    .line 265
    cmp-long v4, v22, v16

    .line 266
    .line 267
    if-nez v4, :cond_c

    .line 268
    .line 269
    invoke-virtual {v2, v6, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 270
    .line 271
    .line 272
    move-result-object v4

    .line 273
    iget v5, v4, Lt7/n0;->c:I

    .line 274
    .line 275
    goto :goto_8

    .line 276
    :cond_c
    if-eqz v13, :cond_f

    .line 277
    .line 278
    iget-object v4, v0, La8/i1;->a:Lt7/p0;

    .line 279
    .line 280
    iget-object v5, v14, Lh8/b0;->a:Ljava/lang/Object;

    .line 281
    .line 282
    invoke-virtual {v4, v5, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 283
    .line 284
    .line 285
    iget-object v4, v0, La8/i1;->a:Lt7/p0;

    .line 286
    .line 287
    iget v5, v8, Lt7/n0;->c:I

    .line 288
    .line 289
    const-wide/16 v10, 0x0

    .line 290
    .line 291
    invoke-virtual {v4, v5, v3, v10, v11}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 292
    .line 293
    .line 294
    move-result-object v4

    .line 295
    iget v4, v4, Lt7/o0;->m:I

    .line 296
    .line 297
    iget-object v5, v0, La8/i1;->a:Lt7/p0;

    .line 298
    .line 299
    iget-object v7, v14, Lh8/b0;->a:Ljava/lang/Object;

    .line 300
    .line 301
    invoke-virtual {v5, v7}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 302
    .line 303
    .line 304
    move-result v5

    .line 305
    if-ne v4, v5, :cond_d

    .line 306
    .line 307
    iget-wide v4, v8, Lt7/n0;->e:J

    .line 308
    .line 309
    add-long v4, v22, v4

    .line 310
    .line 311
    invoke-virtual {v2, v6, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 312
    .line 313
    .line 314
    move-result-object v6

    .line 315
    iget v6, v6, Lt7/n0;->c:I

    .line 316
    .line 317
    move-wide/from16 v33, v4

    .line 318
    .line 319
    move v5, v6

    .line 320
    move-wide/from16 v6, v33

    .line 321
    .line 322
    move-object v4, v8

    .line 323
    invoke-virtual/range {v2 .. v7}, Lt7/p0;->i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;

    .line 324
    .line 325
    .line 326
    move-result-object v5

    .line 327
    iget-object v6, v5, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 328
    .line 329
    iget-object v4, v5, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 330
    .line 331
    check-cast v4, Ljava/lang/Long;

    .line 332
    .line 333
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 334
    .line 335
    .line 336
    move-result-wide v4

    .line 337
    goto :goto_d

    .line 338
    :cond_d
    invoke-virtual {v2, v6, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 339
    .line 340
    .line 341
    move-result-object v4

    .line 342
    iget-wide v4, v4, Lt7/n0;->d:J

    .line 343
    .line 344
    cmp-long v4, v4, v16

    .line 345
    .line 346
    if-eqz v4, :cond_e

    .line 347
    .line 348
    iget-wide v4, v8, Lt7/n0;->d:J

    .line 349
    .line 350
    const-wide/16 v20, 0x1

    .line 351
    .line 352
    sub-long v26, v4, v20

    .line 353
    .line 354
    const-wide/16 v24, 0x0

    .line 355
    .line 356
    invoke-static/range {v22 .. v27}, Lw7/w;->h(JJJ)J

    .line 357
    .line 358
    .line 359
    move-result-wide v4

    .line 360
    goto :goto_d

    .line 361
    :cond_e
    move-wide/from16 v4, v22

    .line 362
    .line 363
    :goto_d
    move-wide/from16 v20, v4

    .line 364
    .line 365
    move v5, v15

    .line 366
    const/16 v30, 0x0

    .line 367
    .line 368
    const/16 v31, 0x0

    .line 369
    .line 370
    const/16 v32, 0x1

    .line 371
    .line 372
    goto :goto_e

    .line 373
    :cond_f
    const-wide/16 v10, 0x0

    .line 374
    .line 375
    move v5, v15

    .line 376
    move-wide/from16 v20, v22

    .line 377
    .line 378
    goto/16 :goto_9

    .line 379
    .line 380
    :goto_e
    if-eq v5, v15, :cond_10

    .line 381
    .line 382
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 383
    .line 384
    .line 385
    .line 386
    .line 387
    move-object v4, v8

    .line 388
    invoke-virtual/range {v2 .. v7}, Lt7/p0;->i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;

    .line 389
    .line 390
    .line 391
    move-result-object v3

    .line 392
    iget-object v6, v3, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 393
    .line 394
    iget-object v3, v3, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast v3, Ljava/lang/Long;

    .line 397
    .line 398
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 399
    .line 400
    .line 401
    move-result-wide v20

    .line 402
    move-wide/from16 v28, v16

    .line 403
    .line 404
    move-wide/from16 v3, v20

    .line 405
    .line 406
    goto :goto_f

    .line 407
    :cond_10
    move-wide/from16 v3, v20

    .line 408
    .line 409
    move-wide/from16 v28, v3

    .line 410
    .line 411
    :goto_f
    invoke-virtual {v9, v2, v6, v3, v4}, La8/z0;->p(Lt7/p0;Ljava/lang/Object;J)Lh8/b0;

    .line 412
    .line 413
    .line 414
    move-result-object v5

    .line 415
    iget v7, v5, Lh8/b0;->e:I

    .line 416
    .line 417
    if-eq v7, v15, :cond_12

    .line 418
    .line 419
    iget v9, v14, Lh8/b0;->e:I

    .line 420
    .line 421
    if-eq v9, v15, :cond_11

    .line 422
    .line 423
    if-lt v7, v9, :cond_11

    .line 424
    .line 425
    goto :goto_10

    .line 426
    :cond_11
    const/4 v7, 0x0

    .line 427
    goto :goto_11

    .line 428
    :cond_12
    :goto_10
    const/4 v7, 0x1

    .line 429
    :goto_11
    iget-object v9, v14, Lh8/b0;->a:Ljava/lang/Object;

    .line 430
    .line 431
    invoke-virtual {v9, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 432
    .line 433
    .line 434
    move-result v9

    .line 435
    if-eqz v9, :cond_13

    .line 436
    .line 437
    invoke-virtual {v14}, Lh8/b0;->b()Z

    .line 438
    .line 439
    .line 440
    move-result v9

    .line 441
    if-nez v9, :cond_13

    .line 442
    .line 443
    invoke-virtual {v5}, Lh8/b0;->b()Z

    .line 444
    .line 445
    .line 446
    move-result v9

    .line 447
    if-nez v9, :cond_13

    .line 448
    .line 449
    if-eqz v7, :cond_13

    .line 450
    .line 451
    const/4 v7, 0x1

    .line 452
    goto :goto_12

    .line 453
    :cond_13
    const/4 v7, 0x0

    .line 454
    :goto_12
    invoke-virtual {v2, v6, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 455
    .line 456
    .line 457
    move-result-object v6

    .line 458
    if-nez v13, :cond_16

    .line 459
    .line 460
    cmp-long v9, v22, v28

    .line 461
    .line 462
    if-nez v9, :cond_16

    .line 463
    .line 464
    iget-object v9, v14, Lh8/b0;->a:Ljava/lang/Object;

    .line 465
    .line 466
    iget v13, v14, Lh8/b0;->b:I

    .line 467
    .line 468
    iget-object v10, v5, Lh8/b0;->a:Ljava/lang/Object;

    .line 469
    .line 470
    invoke-virtual {v9, v10}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 471
    .line 472
    .line 473
    move-result v9

    .line 474
    if-nez v9, :cond_14

    .line 475
    .line 476
    goto :goto_13

    .line 477
    :cond_14
    invoke-virtual {v14}, Lh8/b0;->b()Z

    .line 478
    .line 479
    .line 480
    move-result v9

    .line 481
    if-eqz v9, :cond_15

    .line 482
    .line 483
    invoke-virtual {v6, v13}, Lt7/n0;->g(I)Z

    .line 484
    .line 485
    .line 486
    :cond_15
    invoke-virtual {v5}, Lh8/b0;->b()Z

    .line 487
    .line 488
    .line 489
    move-result v9

    .line 490
    if-eqz v9, :cond_16

    .line 491
    .line 492
    iget v9, v5, Lh8/b0;->b:I

    .line 493
    .line 494
    invoke-virtual {v6, v9}, Lt7/n0;->g(I)Z

    .line 495
    .line 496
    .line 497
    :cond_16
    :goto_13
    if-nez v7, :cond_17

    .line 498
    .line 499
    goto :goto_14

    .line 500
    :cond_17
    move-object v5, v14

    .line 501
    :goto_14
    invoke-virtual {v5}, Lh8/b0;->b()Z

    .line 502
    .line 503
    .line 504
    move-result v6

    .line 505
    if-eqz v6, :cond_18

    .line 506
    .line 507
    invoke-virtual {v5, v14}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 508
    .line 509
    .line 510
    move-result v3

    .line 511
    if-eqz v3, :cond_19

    .line 512
    .line 513
    iget-wide v3, v0, La8/i1;->s:J

    .line 514
    .line 515
    :cond_18
    move-wide/from16 v26, v3

    .line 516
    .line 517
    goto :goto_15

    .line 518
    :cond_19
    iget-object v0, v5, Lh8/b0;->a:Ljava/lang/Object;

    .line 519
    .line 520
    invoke-virtual {v2, v0, v8}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 521
    .line 522
    .line 523
    iget v0, v5, Lh8/b0;->c:I

    .line 524
    .line 525
    iget v3, v5, Lh8/b0;->b:I

    .line 526
    .line 527
    invoke-virtual {v8, v3}, Lt7/n0;->e(I)I

    .line 528
    .line 529
    .line 530
    move-result v3

    .line 531
    if-ne v0, v3, :cond_1a

    .line 532
    .line 533
    iget-object v0, v8, Lt7/n0;->g:Lt7/b;

    .line 534
    .line 535
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 536
    .line 537
    .line 538
    :cond_1a
    const-wide/16 v26, 0x0

    .line 539
    .line 540
    :goto_15
    new-instance v24, La8/o0;

    .line 541
    .line 542
    move-object/from16 v25, v5

    .line 543
    .line 544
    invoke-direct/range {v24 .. v32}, La8/o0;-><init>(Lh8/b0;JJZZZ)V

    .line 545
    .line 546
    .line 547
    move-object/from16 v10, v24

    .line 548
    .line 549
    :goto_16
    iget-object v11, v10, La8/o0;->a:Lh8/b0;

    .line 550
    .line 551
    iget-wide v13, v10, La8/o0;->c:J

    .line 552
    .line 553
    iget-boolean v6, v10, La8/o0;->d:Z

    .line 554
    .line 555
    iget-wide v3, v10, La8/o0;->b:J

    .line 556
    .line 557
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 558
    .line 559
    iget-object v0, v0, La8/i1;->b:Lh8/b0;

    .line 560
    .line 561
    invoke-virtual {v0, v11}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 562
    .line 563
    .line 564
    move-result v0

    .line 565
    if-eqz v0, :cond_1c

    .line 566
    .line 567
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 568
    .line 569
    iget-wide v7, v0, La8/i1;->s:J

    .line 570
    .line 571
    cmp-long v0, v3, v7

    .line 572
    .line 573
    if-eqz v0, :cond_1b

    .line 574
    .line 575
    goto :goto_17

    .line 576
    :cond_1b
    const/16 v22, 0x0

    .line 577
    .line 578
    goto :goto_18

    .line 579
    :cond_1c
    :goto_17
    const/16 v22, 0x1

    .line 580
    .line 581
    :goto_18
    const/16 v23, 0x3

    .line 582
    .line 583
    :try_start_0
    iget-boolean v0, v10, La8/o0;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 584
    .line 585
    if-eqz v0, :cond_1e

    .line 586
    .line 587
    :try_start_1
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 588
    .line 589
    iget v0, v0, La8/i1;->e:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 590
    .line 591
    const/4 v8, 0x1

    .line 592
    if-eq v0, v8, :cond_1d

    .line 593
    .line 594
    :try_start_2
    invoke-virtual {v1, v12}, La8/q0;->m0(I)V

    .line 595
    .line 596
    .line 597
    :cond_1d
    const/4 v9, 0x0

    .line 598
    goto :goto_1a

    .line 599
    :catchall_0
    move-exception v0

    .line 600
    :goto_19
    move-object v12, v11

    .line 601
    move-object v11, v2

    .line 602
    move-object v2, v12

    .line 603
    move-wide/from16 v20, v3

    .line 604
    .line 605
    move/from16 v25, v8

    .line 606
    .line 607
    const/4 v12, 0x2

    .line 608
    goto/16 :goto_2e

    .line 609
    .line 610
    :goto_1a
    invoke-virtual {v1, v9, v9, v9, v8}, La8/q0;->O(ZZZZ)V

    .line 611
    .line 612
    .line 613
    goto :goto_1b

    .line 614
    :catchall_1
    move-exception v0

    .line 615
    const/4 v8, 0x1

    .line 616
    goto :goto_19

    .line 617
    :cond_1e
    const/4 v8, 0x1

    .line 618
    :goto_1b
    iget-object v0, v1, La8/q0;->d:[La8/p1;

    .line 619
    .line 620
    array-length v9, v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 621
    const/4 v5, 0x0

    .line 622
    :goto_1c
    if-ge v5, v9, :cond_21

    .line 623
    .line 624
    :try_start_3
    aget-object v7, v0, v5

    .line 625
    .line 626
    iget-object v8, v7, La8/p1;->e:Ljava/lang/Object;

    .line 627
    .line 628
    check-cast v8, La8/f;

    .line 629
    .line 630
    iget-object v12, v8, La8/f;->s:Lt7/p0;

    .line 631
    .line 632
    invoke-static {v12, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 633
    .line 634
    .line 635
    move-result v12

    .line 636
    if-nez v12, :cond_1f

    .line 637
    .line 638
    iput-object v2, v8, La8/f;->s:Lt7/p0;

    .line 639
    .line 640
    :cond_1f
    iget-object v7, v7, La8/p1;->f:Ljava/lang/Object;

    .line 641
    .line 642
    check-cast v7, La8/f;

    .line 643
    .line 644
    if-eqz v7, :cond_20

    .line 645
    .line 646
    iget-object v8, v7, La8/f;->s:Lt7/p0;

    .line 647
    .line 648
    invoke-static {v8, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 649
    .line 650
    .line 651
    move-result v8

    .line 652
    if-nez v8, :cond_20

    .line 653
    .line 654
    iput-object v2, v7, La8/f;->s:Lt7/p0;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 655
    .line 656
    :cond_20
    add-int/lit8 v5, v5, 0x1

    .line 657
    .line 658
    const/4 v8, 0x1

    .line 659
    const/4 v12, 0x4

    .line 660
    goto :goto_1c

    .line 661
    :goto_1d
    move-object v12, v11

    .line 662
    move-object v11, v2

    .line 663
    move-object v2, v12

    .line 664
    move-wide/from16 v20, v3

    .line 665
    .line 666
    const/4 v12, 0x2

    .line 667
    const/16 v25, 0x1

    .line 668
    .line 669
    goto/16 :goto_2e

    .line 670
    .line 671
    :catchall_2
    move-exception v0

    .line 672
    goto :goto_1d

    .line 673
    :cond_21
    if-nez v22, :cond_27

    .line 674
    .line 675
    :try_start_4
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 676
    .line 677
    iget-object v0, v0, La8/z0;->j:La8/w0;

    .line 678
    .line 679
    if-nez v0, :cond_22

    .line 680
    .line 681
    const-wide/16 v6, 0x0

    .line 682
    .line 683
    goto :goto_1e

    .line 684
    :cond_22
    invoke-virtual {v1, v0}, La8/q0;->n(La8/w0;)J

    .line 685
    .line 686
    .line 687
    move-result-wide v5

    .line 688
    move-wide v6, v5

    .line 689
    :goto_1e
    invoke-virtual {v1}, La8/q0;->e()Z

    .line 690
    .line 691
    .line 692
    move-result v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_7

    .line 693
    if-eqz v0, :cond_24

    .line 694
    .line 695
    :try_start_5
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 696
    .line 697
    iget-object v0, v0, La8/z0;->k:La8/w0;

    .line 698
    .line 699
    if-nez v0, :cond_23

    .line 700
    .line 701
    goto :goto_1f

    .line 702
    :cond_23
    invoke-virtual {v1, v0}, La8/q0;->n(La8/w0;)J

    .line 703
    .line 704
    .line 705
    move-result-wide v8
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 706
    goto :goto_20

    .line 707
    :cond_24
    :goto_1f
    const-wide/16 v8, 0x0

    .line 708
    .line 709
    :goto_20
    :try_start_6
    iget-object v2, v1, La8/q0;->u:La8/z0;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 710
    .line 711
    move-wide/from16 v20, v3

    .line 712
    .line 713
    :try_start_7
    iget-wide v4, v1, La8/q0;->X:J
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 714
    .line 715
    move-object/from16 v3, p1

    .line 716
    .line 717
    const/4 v12, 0x2

    .line 718
    const/16 v25, 0x1

    .line 719
    .line 720
    :try_start_8
    invoke-virtual/range {v2 .. v9}, La8/z0;->s(Lt7/p0;JJJ)I

    .line 721
    .line 722
    .line 723
    move-result v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 724
    move-object v8, v3

    .line 725
    and-int/lit8 v2, v0, 0x1

    .line 726
    .line 727
    if-eqz v2, :cond_25

    .line 728
    .line 729
    const/4 v9, 0x0

    .line 730
    :try_start_9
    invoke-virtual {v1, v9}, La8/q0;->V(Z)V

    .line 731
    .line 732
    .line 733
    goto :goto_23

    .line 734
    :catchall_3
    move-exception v0

    .line 735
    :goto_21
    move-object v2, v11

    .line 736
    :goto_22
    move-object v11, v8

    .line 737
    goto/16 :goto_2e

    .line 738
    .line 739
    :cond_25
    and-int/2addr v0, v12

    .line 740
    if-eqz v0, :cond_26

    .line 741
    .line 742
    invoke-virtual {v1}, La8/q0;->h()V

    .line 743
    .line 744
    .line 745
    :cond_26
    :goto_23
    move-object v2, v11

    .line 746
    goto/16 :goto_29

    .line 747
    .line 748
    :catchall_4
    move-exception v0

    .line 749
    move-object v8, v3

    .line 750
    goto :goto_21

    .line 751
    :catchall_5
    move-exception v0

    .line 752
    move-object/from16 v8, p1

    .line 753
    .line 754
    :goto_24
    const/4 v12, 0x2

    .line 755
    const/16 v25, 0x1

    .line 756
    .line 757
    goto :goto_21

    .line 758
    :catchall_6
    move-exception v0

    .line 759
    move-object/from16 v8, p1

    .line 760
    .line 761
    :goto_25
    move-wide/from16 v20, v3

    .line 762
    .line 763
    goto :goto_24

    .line 764
    :catchall_7
    move-exception v0

    .line 765
    move-object v8, v2

    .line 766
    goto :goto_25

    .line 767
    :cond_27
    move-object v8, v2

    .line 768
    move-wide/from16 v20, v3

    .line 769
    .line 770
    const/4 v12, 0x2

    .line 771
    const/16 v25, 0x1

    .line 772
    .line 773
    invoke-virtual {v8}, Lt7/p0;->p()Z

    .line 774
    .line 775
    .line 776
    move-result v0

    .line 777
    if-nez v0, :cond_26

    .line 778
    .line 779
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 780
    .line 781
    iget-object v0, v0, La8/z0;->i:La8/w0;

    .line 782
    .line 783
    :goto_26
    if-eqz v0, :cond_29

    .line 784
    .line 785
    iget-object v2, v0, La8/w0;->g:La8/x0;

    .line 786
    .line 787
    iget-object v2, v2, La8/x0;->a:Lh8/b0;

    .line 788
    .line 789
    invoke-virtual {v2, v11}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 790
    .line 791
    .line 792
    move-result v2

    .line 793
    if-eqz v2, :cond_28

    .line 794
    .line 795
    iget-object v2, v1, La8/q0;->u:La8/z0;

    .line 796
    .line 797
    iget-object v3, v0, La8/w0;->g:La8/x0;

    .line 798
    .line 799
    invoke-virtual {v2, v8, v3}, La8/z0;->h(Lt7/p0;La8/x0;)La8/x0;

    .line 800
    .line 801
    .line 802
    move-result-object v2

    .line 803
    iput-object v2, v0, La8/w0;->g:La8/x0;

    .line 804
    .line 805
    invoke-virtual {v0}, La8/w0;->k()V

    .line 806
    .line 807
    .line 808
    :cond_28
    iget-object v0, v0, La8/w0;->m:La8/w0;
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 809
    .line 810
    goto :goto_26

    .line 811
    :cond_29
    :try_start_a
    iget-object v0, v1, La8/q0;->u:La8/z0;

    .line 812
    .line 813
    iget-object v2, v0, La8/z0;->i:La8/w0;

    .line 814
    .line 815
    iget-object v0, v0, La8/z0;->j:La8/w0;
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_9

    .line 816
    .line 817
    if-eq v2, v0, :cond_2a

    .line 818
    .line 819
    move/from16 v5, v25

    .line 820
    .line 821
    :goto_27
    move-object v2, v11

    .line 822
    move-wide/from16 v3, v20

    .line 823
    .line 824
    goto :goto_28

    .line 825
    :cond_2a
    const/4 v5, 0x0

    .line 826
    goto :goto_27

    .line 827
    :goto_28
    :try_start_b
    invoke-virtual/range {v1 .. v6}, La8/q0;->X(Lh8/b0;JZZ)J

    .line 828
    .line 829
    .line 830
    move-result-wide v3
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_8

    .line 831
    move-wide/from16 v20, v3

    .line 832
    .line 833
    goto :goto_29

    .line 834
    :catchall_8
    move-exception v0

    .line 835
    move-wide/from16 v20, v3

    .line 836
    .line 837
    goto :goto_22

    .line 838
    :catchall_9
    move-exception v0

    .line 839
    goto :goto_21

    .line 840
    :goto_29
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 841
    .line 842
    iget-object v4, v0, La8/i1;->a:Lt7/p0;

    .line 843
    .line 844
    iget-object v5, v0, La8/i1;->b:Lh8/b0;

    .line 845
    .line 846
    iget-boolean v0, v10, La8/o0;->f:Z

    .line 847
    .line 848
    if-eqz v0, :cond_2b

    .line 849
    .line 850
    move-wide/from16 v6, v20

    .line 851
    .line 852
    goto :goto_2a

    .line 853
    :cond_2b
    move-wide/from16 v6, v16

    .line 854
    .line 855
    :goto_2a
    const/4 v8, 0x0

    .line 856
    move-object v3, v2

    .line 857
    move-object/from16 v2, p1

    .line 858
    .line 859
    invoke-virtual/range {v1 .. v8}, La8/q0;->A0(Lt7/p0;Lh8/b0;Lt7/p0;Lh8/b0;JZ)V

    .line 860
    .line 861
    .line 862
    move-object v11, v2

    .line 863
    move-object v2, v3

    .line 864
    if-nez v22, :cond_2c

    .line 865
    .line 866
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 867
    .line 868
    iget-wide v3, v0, La8/i1;->c:J

    .line 869
    .line 870
    cmp-long v0, v13, v3

    .line 871
    .line 872
    if-eqz v0, :cond_2f

    .line 873
    .line 874
    :cond_2c
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 875
    .line 876
    iget-object v3, v0, La8/i1;->b:Lh8/b0;

    .line 877
    .line 878
    iget-object v3, v3, Lh8/b0;->a:Ljava/lang/Object;

    .line 879
    .line 880
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 881
    .line 882
    if-eqz v22, :cond_2d

    .line 883
    .line 884
    if-eqz p2, :cond_2d

    .line 885
    .line 886
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 887
    .line 888
    .line 889
    move-result v4

    .line 890
    if-nez v4, :cond_2d

    .line 891
    .line 892
    iget-object v4, v1, La8/q0;->o:Lt7/n0;

    .line 893
    .line 894
    invoke-virtual {v0, v3, v4}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 895
    .line 896
    .line 897
    move-result-object v0

    .line 898
    iget-boolean v0, v0, Lt7/n0;->f:Z

    .line 899
    .line 900
    if-nez v0, :cond_2d

    .line 901
    .line 902
    move/from16 v9, v25

    .line 903
    .line 904
    goto :goto_2b

    .line 905
    :cond_2d
    const/4 v9, 0x0

    .line 906
    :goto_2b
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 907
    .line 908
    iget-wide v7, v0, La8/i1;->d:J

    .line 909
    .line 910
    invoke-virtual {v11, v3}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 911
    .line 912
    .line 913
    move-result v0

    .line 914
    if-ne v0, v15, :cond_2e

    .line 915
    .line 916
    const/4 v10, 0x4

    .line 917
    :goto_2c
    move-wide v5, v13

    .line 918
    move-wide/from16 v3, v20

    .line 919
    .line 920
    goto :goto_2d

    .line 921
    :cond_2e
    move/from16 v10, v23

    .line 922
    .line 923
    goto :goto_2c

    .line 924
    :goto_2d
    invoke-virtual/range {v1 .. v10}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 925
    .line 926
    .line 927
    move-result-object v0

    .line 928
    iput-object v0, v1, La8/q0;->I:La8/i1;

    .line 929
    .line 930
    :cond_2f
    invoke-virtual {v1}, La8/q0;->P()V

    .line 931
    .line 932
    .line 933
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 934
    .line 935
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 936
    .line 937
    invoke-virtual {v1, v11, v0}, La8/q0;->R(Lt7/p0;Lt7/p0;)V

    .line 938
    .line 939
    .line 940
    iget-object v0, v1, La8/q0;->I:La8/i1;

    .line 941
    .line 942
    invoke-virtual {v0, v11}, La8/i1;->j(Lt7/p0;)La8/i1;

    .line 943
    .line 944
    .line 945
    move-result-object v0

    .line 946
    iput-object v0, v1, La8/q0;->I:La8/i1;

    .line 947
    .line 948
    invoke-virtual {v11}, Lt7/p0;->p()Z

    .line 949
    .line 950
    .line 951
    move-result v0

    .line 952
    if-nez v0, :cond_30

    .line 953
    .line 954
    const/4 v2, 0x0

    .line 955
    iput-object v2, v1, La8/q0;->W:La8/p0;

    .line 956
    .line 957
    :cond_30
    const/4 v9, 0x0

    .line 958
    invoke-virtual {v1, v9}, La8/q0;->u(Z)V

    .line 959
    .line 960
    .line 961
    iget-object v0, v1, La8/q0;->k:Lw7/t;

    .line 962
    .line 963
    invoke-virtual {v0, v12}, Lw7/t;->e(I)Z

    .line 964
    .line 965
    .line 966
    return-void

    .line 967
    :goto_2e
    iget-object v3, v1, La8/q0;->I:La8/i1;

    .line 968
    .line 969
    iget-object v4, v3, La8/i1;->a:Lt7/p0;

    .line 970
    .line 971
    iget-object v5, v3, La8/i1;->b:Lh8/b0;

    .line 972
    .line 973
    iget-boolean v3, v10, La8/o0;->f:Z

    .line 974
    .line 975
    if-eqz v3, :cond_31

    .line 976
    .line 977
    move-wide/from16 v6, v20

    .line 978
    .line 979
    goto :goto_2f

    .line 980
    :cond_31
    move-wide/from16 v6, v16

    .line 981
    .line 982
    :goto_2f
    const/4 v8, 0x0

    .line 983
    move-object v3, v2

    .line 984
    move-object v2, v11

    .line 985
    invoke-virtual/range {v1 .. v8}, La8/q0;->A0(Lt7/p0;Lh8/b0;Lt7/p0;Lh8/b0;JZ)V

    .line 986
    .line 987
    .line 988
    move-object v2, v3

    .line 989
    if-nez v22, :cond_32

    .line 990
    .line 991
    iget-object v3, v1, La8/q0;->I:La8/i1;

    .line 992
    .line 993
    iget-wide v3, v3, La8/i1;->c:J

    .line 994
    .line 995
    cmp-long v3, v13, v3

    .line 996
    .line 997
    if-eqz v3, :cond_35

    .line 998
    .line 999
    :cond_32
    iget-object v3, v1, La8/q0;->I:La8/i1;

    .line 1000
    .line 1001
    iget-object v4, v3, La8/i1;->b:Lh8/b0;

    .line 1002
    .line 1003
    iget-object v4, v4, Lh8/b0;->a:Ljava/lang/Object;

    .line 1004
    .line 1005
    iget-object v3, v3, La8/i1;->a:Lt7/p0;

    .line 1006
    .line 1007
    if-eqz v22, :cond_33

    .line 1008
    .line 1009
    if-eqz p2, :cond_33

    .line 1010
    .line 1011
    invoke-virtual {v3}, Lt7/p0;->p()Z

    .line 1012
    .line 1013
    .line 1014
    move-result v5

    .line 1015
    if-nez v5, :cond_33

    .line 1016
    .line 1017
    iget-object v5, v1, La8/q0;->o:Lt7/n0;

    .line 1018
    .line 1019
    invoke-virtual {v3, v4, v5}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 1020
    .line 1021
    .line 1022
    move-result-object v3

    .line 1023
    iget-boolean v3, v3, Lt7/n0;->f:Z

    .line 1024
    .line 1025
    if-nez v3, :cond_33

    .line 1026
    .line 1027
    move/from16 v9, v25

    .line 1028
    .line 1029
    goto :goto_30

    .line 1030
    :cond_33
    const/4 v9, 0x0

    .line 1031
    :goto_30
    iget-object v3, v1, La8/q0;->I:La8/i1;

    .line 1032
    .line 1033
    iget-wide v7, v3, La8/i1;->d:J

    .line 1034
    .line 1035
    invoke-virtual {v11, v4}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 1036
    .line 1037
    .line 1038
    move-result v3

    .line 1039
    if-ne v3, v15, :cond_34

    .line 1040
    .line 1041
    const/4 v10, 0x4

    .line 1042
    :goto_31
    move-wide v5, v13

    .line 1043
    move-wide/from16 v3, v20

    .line 1044
    .line 1045
    goto :goto_32

    .line 1046
    :cond_34
    move/from16 v10, v23

    .line 1047
    .line 1048
    goto :goto_31

    .line 1049
    :goto_32
    invoke-virtual/range {v1 .. v10}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 1050
    .line 1051
    .line 1052
    move-result-object v2

    .line 1053
    iput-object v2, v1, La8/q0;->I:La8/i1;

    .line 1054
    .line 1055
    :cond_35
    invoke-virtual {v1}, La8/q0;->P()V

    .line 1056
    .line 1057
    .line 1058
    iget-object v2, v1, La8/q0;->I:La8/i1;

    .line 1059
    .line 1060
    iget-object v2, v2, La8/i1;->a:Lt7/p0;

    .line 1061
    .line 1062
    invoke-virtual {v1, v11, v2}, La8/q0;->R(Lt7/p0;Lt7/p0;)V

    .line 1063
    .line 1064
    .line 1065
    iget-object v2, v1, La8/q0;->I:La8/i1;

    .line 1066
    .line 1067
    invoke-virtual {v2, v11}, La8/i1;->j(Lt7/p0;)La8/i1;

    .line 1068
    .line 1069
    .line 1070
    move-result-object v2

    .line 1071
    iput-object v2, v1, La8/q0;->I:La8/i1;

    .line 1072
    .line 1073
    invoke-virtual {v11}, Lt7/p0;->p()Z

    .line 1074
    .line 1075
    .line 1076
    move-result v2

    .line 1077
    if-nez v2, :cond_36

    .line 1078
    .line 1079
    const/4 v2, 0x0

    .line 1080
    iput-object v2, v1, La8/q0;->W:La8/p0;

    .line 1081
    .line 1082
    :cond_36
    const/4 v9, 0x0

    .line 1083
    invoke-virtual {v1, v9}, La8/q0;->u(Z)V

    .line 1084
    .line 1085
    .line 1086
    iget-object v1, v1, La8/q0;->k:Lw7/t;

    .line 1087
    .line 1088
    invoke-virtual {v1, v12}, Lw7/t;->e(I)Z

    .line 1089
    .line 1090
    .line 1091
    throw v0
.end method

.method public final v0()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->l:La8/w0;

    .line 4
    .line 5
    iget-boolean v1, p0, La8/q0;->P:Z

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, v0, La8/w0;->a:Ljava/lang/Object;

    .line 12
    .line 13
    invoke-interface {v0}, Lh8/z0;->e()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    :goto_0
    const/4 v0, 0x1

    .line 23
    :goto_1
    iget-object v1, p0, La8/q0;->I:La8/i1;

    .line 24
    .line 25
    iget-boolean v2, v1, La8/i1;->g:Z

    .line 26
    .line 27
    if-eq v0, v2, :cond_2

    .line 28
    .line 29
    invoke-virtual {v1, v0}, La8/i1;->b(Z)La8/i1;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object v0, p0, La8/q0;->I:La8/i1;

    .line 34
    .line 35
    :cond_2
    return-void
.end method

.method public final w(Lh8/z;)V
    .locals 12

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v1, v0, La8/z0;->l:La8/w0;

    .line 4
    .line 5
    iget-object v2, p0, La8/q0;->q:La8/l;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    iget-object v4, v1, La8/w0;->a:Ljava/lang/Object;

    .line 11
    .line 12
    if-ne v4, p1, :cond_2

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget-boolean p1, v1, La8/w0;->e:Z

    .line 18
    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    invoke-virtual {v2}, La8/l;->c()Lt7/g0;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iget p1, p1, Lt7/g0;->a:F

    .line 26
    .line 27
    iget-object v2, p0, La8/q0;->I:La8/i1;

    .line 28
    .line 29
    iget-object v4, v2, La8/i1;->a:Lt7/p0;

    .line 30
    .line 31
    iget-boolean v2, v2, La8/i1;->l:Z

    .line 32
    .line 33
    invoke-virtual {v1, p1, v4, v2}, La8/w0;->f(FLt7/p0;Z)V

    .line 34
    .line 35
    .line 36
    :cond_0
    iget-object p1, v1, La8/w0;->o:Lj8/s;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, La8/q0;->w0(Lj8/s;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, v0, La8/z0;->i:La8/w0;

    .line 42
    .line 43
    if-ne v1, p1, :cond_1

    .line 44
    .line 45
    iget-object p1, v1, La8/w0;->g:La8/x0;

    .line 46
    .line 47
    iget-wide v4, p1, La8/x0;->b:J

    .line 48
    .line 49
    invoke-virtual {p0, v4, v5}, La8/q0;->Q(J)V

    .line 50
    .line 51
    .line 52
    iget-object p1, p0, La8/q0;->d:[La8/p1;

    .line 53
    .line 54
    array-length p1, p1

    .line 55
    new-array p1, p1, [Z

    .line 56
    .line 57
    iget-object v0, v0, La8/z0;->j:La8/w0;

    .line 58
    .line 59
    invoke-virtual {v0}, La8/w0;->e()J

    .line 60
    .line 61
    .line 62
    move-result-wide v4

    .line 63
    invoke-virtual {p0, p1, v4, v5}, La8/q0;->l([ZJ)V

    .line 64
    .line 65
    .line 66
    iput-boolean v3, v1, La8/w0;->h:Z

    .line 67
    .line 68
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 69
    .line 70
    iget-object v3, p1, La8/i1;->b:Lh8/b0;

    .line 71
    .line 72
    iget-object v0, v1, La8/w0;->g:La8/x0;

    .line 73
    .line 74
    iget-wide v4, v0, La8/x0;->b:J

    .line 75
    .line 76
    iget-wide v6, p1, La8/i1;->c:J

    .line 77
    .line 78
    const/4 v10, 0x0

    .line 79
    const/4 v11, 0x5

    .line 80
    move-wide v8, v4

    .line 81
    move-object v2, p0

    .line 82
    invoke-virtual/range {v2 .. v11}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    move-object v1, v2

    .line 87
    iput-object p0, v1, La8/q0;->I:La8/i1;

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_1
    move-object v1, p0

    .line 91
    :goto_0
    invoke-virtual {v1}, La8/q0;->C()V

    .line 92
    .line 93
    .line 94
    return-void

    .line 95
    :cond_2
    move-object v1, p0

    .line 96
    const/4 p0, 0x0

    .line 97
    :goto_1
    iget-object v4, v0, La8/z0;->q:Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    if-ge p0, v4, :cond_4

    .line 104
    .line 105
    iget-object v4, v0, La8/z0;->q:Ljava/util/ArrayList;

    .line 106
    .line 107
    invoke-virtual {v4, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    check-cast v4, La8/w0;

    .line 112
    .line 113
    iget-object v5, v4, La8/w0;->a:Ljava/lang/Object;

    .line 114
    .line 115
    if-ne v5, p1, :cond_3

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_3
    add-int/lit8 p0, p0, 0x1

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_4
    const/4 v4, 0x0

    .line 122
    :goto_2
    if-eqz v4, :cond_5

    .line 123
    .line 124
    iget-boolean p0, v4, La8/w0;->e:Z

    .line 125
    .line 126
    xor-int/2addr p0, v3

    .line 127
    invoke-static {p0}, Lw7/a;->j(Z)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2}, La8/l;->c()Lt7/g0;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    iget p0, p0, Lt7/g0;->a:F

    .line 135
    .line 136
    iget-object v2, v1, La8/q0;->I:La8/i1;

    .line 137
    .line 138
    iget-object v3, v2, La8/i1;->a:Lt7/p0;

    .line 139
    .line 140
    iget-boolean v2, v2, La8/i1;->l:Z

    .line 141
    .line 142
    invoke-virtual {v4, p0, v3, v2}, La8/w0;->f(FLt7/p0;Z)V

    .line 143
    .line 144
    .line 145
    iget-object p0, v0, La8/z0;->m:La8/w0;

    .line 146
    .line 147
    if-eqz p0, :cond_5

    .line 148
    .line 149
    iget-object p0, p0, La8/w0;->a:Ljava/lang/Object;

    .line 150
    .line 151
    if-ne p0, p1, :cond_5

    .line 152
    .line 153
    invoke-virtual {v1}, La8/q0;->D()V

    .line 154
    .line 155
    .line 156
    :cond_5
    return-void
.end method

.method public final w0(Lj8/s;)V
    .locals 8

    .line 1
    iget-object v0, p0, La8/q0;->u:La8/z0;

    .line 2
    .line 3
    iget-object v0, v0, La8/z0;->l:La8/w0;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, La8/w0;->d()J

    .line 9
    .line 10
    .line 11
    move-result-wide v1

    .line 12
    invoke-virtual {p0, v1, v2}, La8/q0;->p(J)J

    .line 13
    .line 14
    .line 15
    iget-object v1, p0, La8/q0;->I:La8/i1;

    .line 16
    .line 17
    iget-object v1, v1, La8/i1;->a:Lt7/p0;

    .line 18
    .line 19
    iget-object v0, v0, La8/w0;->g:La8/x0;

    .line 20
    .line 21
    iget-object v0, v0, La8/x0;->a:Lh8/b0;

    .line 22
    .line 23
    invoke-virtual {p0, v1, v0}, La8/q0;->r0(Lt7/p0;Lh8/b0;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    iget-object v0, p0, La8/q0;->w:La8/i;

    .line 30
    .line 31
    iget-wide v0, v0, La8/i;->h:J

    .line 32
    .line 33
    :cond_0
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 34
    .line 35
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 36
    .line 37
    iget-object v0, p0, La8/q0;->q:La8/l;

    .line 38
    .line 39
    invoke-virtual {v0}, La8/l;->c()Lt7/g0;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    iget v0, v0, Lt7/g0;->a:F

    .line 44
    .line 45
    iget-object v0, p0, La8/q0;->I:La8/i1;

    .line 46
    .line 47
    iget-boolean v0, v0, La8/i1;->l:Z

    .line 48
    .line 49
    iget-object p1, p1, Lj8/s;->c:[Lj8/q;

    .line 50
    .line 51
    iget-object v0, p0, La8/q0;->i:La8/k;

    .line 52
    .line 53
    iget-object v1, v0, La8/k;->h:Ljava/util/HashMap;

    .line 54
    .line 55
    iget-object p0, p0, La8/q0;->y:Lb8/k;

    .line 56
    .line 57
    invoke-virtual {v1, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    check-cast p0, La8/j;

    .line 62
    .line 63
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    iget v1, v0, La8/k;->f:I

    .line 67
    .line 68
    const/4 v2, -0x1

    .line 69
    if-ne v1, v2, :cond_3

    .line 70
    .line 71
    array-length v1, p1

    .line 72
    const/4 v2, 0x0

    .line 73
    move v3, v2

    .line 74
    move v4, v3

    .line 75
    :goto_0
    const/high16 v5, 0xc80000

    .line 76
    .line 77
    if-ge v3, v1, :cond_2

    .line 78
    .line 79
    aget-object v6, p1, v3

    .line 80
    .line 81
    if-eqz v6, :cond_1

    .line 82
    .line 83
    invoke-interface {v6}, Lj8/q;->g()Lt7/q0;

    .line 84
    .line 85
    .line 86
    move-result-object v6

    .line 87
    iget v6, v6, Lt7/q0;->c:I

    .line 88
    .line 89
    const/high16 v7, 0x20000

    .line 90
    .line 91
    packed-switch v6, :pswitch_data_0

    .line 92
    .line 93
    .line 94
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 95
    .line 96
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :pswitch_0
    move v5, v7

    .line 101
    goto :goto_1

    .line 102
    :pswitch_1
    const/high16 v5, 0x1900000

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :pswitch_2
    const/high16 v5, 0x7d00000

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :pswitch_3
    const/high16 v5, 0x89a0000

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :pswitch_4
    move v5, v2

    .line 112
    :goto_1
    :pswitch_5
    add-int/2addr v4, v5

    .line 113
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_2
    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    :cond_3
    iput v1, p0, La8/j;->b:I

    .line 121
    .line 122
    invoke-virtual {v0}, La8/k;->d()V

    .line 123
    .line 124
    .line 125
    return-void

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch -0x2
        :pswitch_4
        :pswitch_5
        :pswitch_3
        :pswitch_5
        :pswitch_2
        :pswitch_0
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final x(Lt7/g0;FZZ)V
    .locals 4

    .line 1
    if-eqz p3, :cond_1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p3, p0, La8/q0;->J:La8/n0;

    .line 6
    .line 7
    const/4 p4, 0x1

    .line 8
    invoke-virtual {p3, p4}, La8/n0;->f(I)V

    .line 9
    .line 10
    .line 11
    :cond_0
    iget-object p3, p0, La8/q0;->I:La8/i1;

    .line 12
    .line 13
    invoke-virtual {p3, p1}, La8/i1;->g(Lt7/g0;)La8/i1;

    .line 14
    .line 15
    .line 16
    move-result-object p3

    .line 17
    iput-object p3, p0, La8/q0;->I:La8/i1;

    .line 18
    .line 19
    :cond_1
    iget p3, p1, Lt7/g0;->a:F

    .line 20
    .line 21
    iget-object p4, p0, La8/q0;->u:La8/z0;

    .line 22
    .line 23
    iget-object p4, p4, La8/z0;->i:La8/w0;

    .line 24
    .line 25
    :goto_0
    const/4 v0, 0x0

    .line 26
    if-eqz p4, :cond_4

    .line 27
    .line 28
    iget-object v1, p4, La8/w0;->o:Lj8/s;

    .line 29
    .line 30
    iget-object v1, v1, Lj8/s;->c:[Lj8/q;

    .line 31
    .line 32
    array-length v2, v1

    .line 33
    :goto_1
    if-ge v0, v2, :cond_3

    .line 34
    .line 35
    aget-object v3, v1, v0

    .line 36
    .line 37
    if-eqz v3, :cond_2

    .line 38
    .line 39
    invoke-interface {v3, p3}, Lj8/q;->d(F)V

    .line 40
    .line 41
    .line 42
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_3
    iget-object p4, p4, La8/w0;->m:La8/w0;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_4
    iget-object p0, p0, La8/q0;->d:[La8/p1;

    .line 49
    .line 50
    array-length p3, p0

    .line 51
    :goto_2
    if-ge v0, p3, :cond_6

    .line 52
    .line 53
    aget-object p4, p0, v0

    .line 54
    .line 55
    iget v1, p1, Lt7/g0;->a:F

    .line 56
    .line 57
    iget-object v2, p4, La8/p1;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v2, La8/f;

    .line 60
    .line 61
    invoke-virtual {v2, p2, v1}, La8/f;->A(FF)V

    .line 62
    .line 63
    .line 64
    iget-object p4, p4, La8/p1;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p4, La8/f;

    .line 67
    .line 68
    if-eqz p4, :cond_5

    .line 69
    .line 70
    invoke-virtual {p4, p2, v1}, La8/f;->A(FF)V

    .line 71
    .line 72
    .line 73
    :cond_5
    add-int/lit8 v0, v0, 0x1

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_6
    return-void
.end method

.method public final x0(IILjava/util/List;)V
    .locals 6

    .line 1
    iget-object v0, p0, La8/q0;->J:La8/n0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, La8/n0;->f(I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, La8/q0;->v:Lac/i;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-object v2, v0, Lac/i;->c:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ljava/util/ArrayList;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    if-ltz p1, :cond_0

    .line 18
    .line 19
    if-gt p1, p2, :cond_0

    .line 20
    .line 21
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-gt p2, v4, :cond_0

    .line 26
    .line 27
    move v4, v1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v4, v3

    .line 30
    :goto_0
    invoke-static {v4}, Lw7/a;->c(Z)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    sub-int v5, p2, p1

    .line 38
    .line 39
    if-ne v4, v5, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move v1, v3

    .line 43
    :goto_1
    invoke-static {v1}, Lw7/a;->c(Z)V

    .line 44
    .line 45
    .line 46
    move v1, p1

    .line 47
    :goto_2
    if-ge v1, p2, :cond_2

    .line 48
    .line 49
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    check-cast v4, La8/h1;

    .line 54
    .line 55
    iget-object v4, v4, La8/h1;->a:Lh8/w;

    .line 56
    .line 57
    sub-int v5, v1, p1

    .line 58
    .line 59
    invoke-interface {p3, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    check-cast v5, Lt7/x;

    .line 64
    .line 65
    invoke-virtual {v4, v5}, Lh8/w;->r(Lt7/x;)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v1, v1, 0x1

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_2
    invoke-virtual {v0}, Lac/i;->c()Lt7/p0;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    invoke-virtual {p0, p1, v3}, La8/q0;->v(Lt7/p0;Z)V

    .line 76
    .line 77
    .line 78
    return-void
.end method

.method public final y(Lh8/b0;JJJZI)La8/i1;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-wide/from16 v4, p4

    .line 6
    .line 7
    move/from16 v2, p9

    .line 8
    .line 9
    iget-boolean v3, v0, La8/q0;->a0:Z

    .line 10
    .line 11
    const/4 v7, 0x0

    .line 12
    if-nez v3, :cond_1

    .line 13
    .line 14
    iget-object v3, v0, La8/q0;->I:La8/i1;

    .line 15
    .line 16
    iget-wide v8, v3, La8/i1;->s:J

    .line 17
    .line 18
    cmp-long v3, p2, v8

    .line 19
    .line 20
    if-nez v3, :cond_1

    .line 21
    .line 22
    iget-object v3, v0, La8/q0;->I:La8/i1;

    .line 23
    .line 24
    iget-object v3, v3, La8/i1;->b:Lh8/b0;

    .line 25
    .line 26
    invoke-virtual {v1, v3}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-nez v3, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v3, v7

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    :goto_0
    const/4 v3, 0x1

    .line 36
    :goto_1
    iput-boolean v3, v0, La8/q0;->a0:Z

    .line 37
    .line 38
    invoke-virtual {v0}, La8/q0;->P()V

    .line 39
    .line 40
    .line 41
    iget-object v3, v0, La8/q0;->I:La8/i1;

    .line 42
    .line 43
    iget-object v8, v3, La8/i1;->h:Lh8/e1;

    .line 44
    .line 45
    iget-object v9, v3, La8/i1;->i:Lj8/s;

    .line 46
    .line 47
    iget-object v10, v3, La8/i1;->j:Ljava/util/List;

    .line 48
    .line 49
    iget-object v11, v0, La8/q0;->v:Lac/i;

    .line 50
    .line 51
    iget-boolean v11, v11, Lac/i;->a:Z

    .line 52
    .line 53
    if-eqz v11, :cond_10

    .line 54
    .line 55
    iget-object v3, v0, La8/q0;->u:La8/z0;

    .line 56
    .line 57
    iget-object v3, v3, La8/z0;->i:La8/w0;

    .line 58
    .line 59
    if-nez v3, :cond_2

    .line 60
    .line 61
    sget-object v8, Lh8/e1;->d:Lh8/e1;

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_2
    iget-object v8, v3, La8/w0;->n:Lh8/e1;

    .line 65
    .line 66
    :goto_2
    if-nez v3, :cond_3

    .line 67
    .line 68
    iget-object v9, v0, La8/q0;->h:Lj8/s;

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_3
    iget-object v9, v3, La8/w0;->o:Lj8/s;

    .line 72
    .line 73
    :goto_3
    iget-object v10, v9, Lj8/s;->c:[Lj8/q;

    .line 74
    .line 75
    new-instance v11, Lhr/e0;

    .line 76
    .line 77
    const/4 v12, 0x4

    .line 78
    invoke-direct {v11, v12}, Lhr/b0;-><init>(I)V

    .line 79
    .line 80
    .line 81
    array-length v12, v10

    .line 82
    move v13, v7

    .line 83
    move v14, v13

    .line 84
    :goto_4
    if-ge v13, v12, :cond_6

    .line 85
    .line 86
    aget-object v15, v10, v13

    .line 87
    .line 88
    if-eqz v15, :cond_5

    .line 89
    .line 90
    invoke-interface {v15, v7}, Lj8/q;->a(I)Lt7/o;

    .line 91
    .line 92
    .line 93
    move-result-object v15

    .line 94
    iget-object v15, v15, Lt7/o;->l:Lt7/c0;

    .line 95
    .line 96
    if-nez v15, :cond_4

    .line 97
    .line 98
    new-instance v15, Lt7/c0;

    .line 99
    .line 100
    new-array v6, v7, [Lt7/b0;

    .line 101
    .line 102
    invoke-direct {v15, v6}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v11, v15}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_4
    invoke-virtual {v11, v15}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    const/4 v14, 0x1

    .line 113
    :cond_5
    :goto_5
    add-int/lit8 v13, v13, 0x1

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_6
    if-eqz v14, :cond_7

    .line 117
    .line 118
    invoke-virtual {v11}, Lhr/e0;->i()Lhr/x0;

    .line 119
    .line 120
    .line 121
    move-result-object v6

    .line 122
    :goto_6
    move-object v10, v6

    .line 123
    goto :goto_7

    .line 124
    :cond_7
    sget-object v6, Lhr/h0;->e:Lhr/f0;

    .line 125
    .line 126
    sget-object v6, Lhr/x0;->h:Lhr/x0;

    .line 127
    .line 128
    goto :goto_6

    .line 129
    :goto_7
    if-eqz v3, :cond_8

    .line 130
    .line 131
    iget-object v6, v3, La8/w0;->g:La8/x0;

    .line 132
    .line 133
    iget-wide v11, v6, La8/x0;->c:J

    .line 134
    .line 135
    cmp-long v11, v11, v4

    .line 136
    .line 137
    if-eqz v11, :cond_8

    .line 138
    .line 139
    invoke-virtual {v6, v4, v5}, La8/x0;->a(J)La8/x0;

    .line 140
    .line 141
    .line 142
    move-result-object v6

    .line 143
    iput-object v6, v3, La8/w0;->g:La8/x0;

    .line 144
    .line 145
    :cond_8
    iget-object v3, v0, La8/q0;->d:[La8/p1;

    .line 146
    .line 147
    iget-object v6, v0, La8/q0;->u:La8/z0;

    .line 148
    .line 149
    iget-object v11, v6, La8/z0;->i:La8/w0;

    .line 150
    .line 151
    iget-object v6, v6, La8/z0;->j:La8/w0;

    .line 152
    .line 153
    if-eq v11, v6, :cond_9

    .line 154
    .line 155
    goto :goto_b

    .line 156
    :cond_9
    if-eqz v11, :cond_f

    .line 157
    .line 158
    iget-object v6, v11, La8/w0;->o:Lj8/s;

    .line 159
    .line 160
    move v11, v7

    .line 161
    move v12, v11

    .line 162
    :goto_8
    array-length v13, v3

    .line 163
    if-ge v11, v13, :cond_c

    .line 164
    .line 165
    invoke-virtual {v6, v11}, Lj8/s;->b(I)Z

    .line 166
    .line 167
    .line 168
    move-result v13

    .line 169
    if-eqz v13, :cond_b

    .line 170
    .line 171
    aget-object v13, v3, v11

    .line 172
    .line 173
    iget-object v13, v13, La8/p1;->e:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast v13, La8/f;

    .line 176
    .line 177
    iget v13, v13, La8/f;->e:I

    .line 178
    .line 179
    const/4 v14, 0x1

    .line 180
    if-eq v13, v14, :cond_a

    .line 181
    .line 182
    move v14, v7

    .line 183
    goto :goto_9

    .line 184
    :cond_a
    iget-object v13, v6, Lj8/s;->b:[La8/o1;

    .line 185
    .line 186
    aget-object v13, v13, v11

    .line 187
    .line 188
    iget v13, v13, La8/o1;->a:I

    .line 189
    .line 190
    if-eqz v13, :cond_b

    .line 191
    .line 192
    const/4 v12, 0x1

    .line 193
    :cond_b
    add-int/lit8 v11, v11, 0x1

    .line 194
    .line 195
    goto :goto_8

    .line 196
    :cond_c
    const/4 v14, 0x1

    .line 197
    :goto_9
    if-eqz v12, :cond_d

    .line 198
    .line 199
    if-eqz v14, :cond_d

    .line 200
    .line 201
    const/4 v14, 0x1

    .line 202
    goto :goto_a

    .line 203
    :cond_d
    move v14, v7

    .line 204
    :goto_a
    iget-boolean v3, v0, La8/q0;->U:Z

    .line 205
    .line 206
    if-ne v14, v3, :cond_e

    .line 207
    .line 208
    goto :goto_b

    .line 209
    :cond_e
    iput-boolean v14, v0, La8/q0;->U:Z

    .line 210
    .line 211
    if-nez v14, :cond_f

    .line 212
    .line 213
    iget-object v3, v0, La8/q0;->I:La8/i1;

    .line 214
    .line 215
    iget-boolean v3, v3, La8/i1;->p:Z

    .line 216
    .line 217
    if-eqz v3, :cond_f

    .line 218
    .line 219
    iget-object v3, v0, La8/q0;->k:Lw7/t;

    .line 220
    .line 221
    const/4 v6, 0x2

    .line 222
    invoke-virtual {v3, v6}, Lw7/t;->e(I)Z

    .line 223
    .line 224
    .line 225
    :cond_f
    :goto_b
    move-object v11, v9

    .line 226
    move-object v12, v10

    .line 227
    move-object v10, v8

    .line 228
    goto :goto_c

    .line 229
    :cond_10
    iget-object v3, v3, La8/i1;->b:Lh8/b0;

    .line 230
    .line 231
    invoke-virtual {v1, v3}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    move-result v3

    .line 235
    if-nez v3, :cond_f

    .line 236
    .line 237
    sget-object v8, Lh8/e1;->d:Lh8/e1;

    .line 238
    .line 239
    iget-object v9, v0, La8/q0;->h:Lj8/s;

    .line 240
    .line 241
    sget-object v10, Lhr/x0;->h:Lhr/x0;

    .line 242
    .line 243
    goto :goto_b

    .line 244
    :goto_c
    if-eqz p8, :cond_13

    .line 245
    .line 246
    iget-object v3, v0, La8/q0;->J:La8/n0;

    .line 247
    .line 248
    iget-boolean v6, v3, La8/n0;->e:Z

    .line 249
    .line 250
    if-eqz v6, :cond_12

    .line 251
    .line 252
    iget v6, v3, La8/n0;->c:I

    .line 253
    .line 254
    const/4 v8, 0x5

    .line 255
    if-eq v6, v8, :cond_12

    .line 256
    .line 257
    if-ne v2, v8, :cond_11

    .line 258
    .line 259
    const/4 v6, 0x1

    .line 260
    goto :goto_d

    .line 261
    :cond_11
    move v6, v7

    .line 262
    :goto_d
    invoke-static {v6}, Lw7/a;->c(Z)V

    .line 263
    .line 264
    .line 265
    goto :goto_e

    .line 266
    :cond_12
    const/4 v14, 0x1

    .line 267
    iput-boolean v14, v3, La8/n0;->d:Z

    .line 268
    .line 269
    iput-boolean v14, v3, La8/n0;->e:Z

    .line 270
    .line 271
    iput v2, v3, La8/n0;->c:I

    .line 272
    .line 273
    :cond_13
    :goto_e
    iget-object v2, v0, La8/q0;->I:La8/i1;

    .line 274
    .line 275
    iget-wide v6, v2, La8/i1;->q:J

    .line 276
    .line 277
    invoke-virtual {v0, v6, v7}, La8/q0;->p(J)J

    .line 278
    .line 279
    .line 280
    move-result-wide v8

    .line 281
    move-wide/from16 v6, p6

    .line 282
    .line 283
    move-object v0, v2

    .line 284
    move-wide/from16 v2, p2

    .line 285
    .line 286
    invoke-virtual/range {v0 .. v12}, La8/i1;->d(Lh8/b0;JJJJLh8/e1;Lj8/s;Ljava/util/List;)La8/i1;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    return-object v0
.end method

.method public final y0(IIIZ)V
    .locals 6

    .line 1
    const/4 v0, -0x1

    .line 2
    const/4 v1, 0x1

    .line 3
    const/4 v2, 0x0

    .line 4
    if-eqz p4, :cond_0

    .line 5
    .line 6
    if-eq p1, v0, :cond_0

    .line 7
    .line 8
    move p4, v1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move p4, v2

    .line 11
    :goto_0
    const/4 v3, 0x2

    .line 12
    if-ne p1, v0, :cond_1

    .line 13
    .line 14
    move p3, v3

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    if-ne p3, v3, :cond_2

    .line 17
    .line 18
    move p3, v1

    .line 19
    :cond_2
    :goto_1
    if-nez p1, :cond_3

    .line 20
    .line 21
    move p2, v1

    .line 22
    goto :goto_2

    .line 23
    :cond_3
    if-ne p2, v1, :cond_4

    .line 24
    .line 25
    move p2, v2

    .line 26
    :cond_4
    :goto_2
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 27
    .line 28
    iget-boolean v0, p1, La8/i1;->l:Z

    .line 29
    .line 30
    if-ne v0, p4, :cond_5

    .line 31
    .line 32
    iget v0, p1, La8/i1;->n:I

    .line 33
    .line 34
    if-ne v0, p2, :cond_5

    .line 35
    .line 36
    iget v0, p1, La8/i1;->m:I

    .line 37
    .line 38
    if-ne v0, p3, :cond_5

    .line 39
    .line 40
    goto :goto_5

    .line 41
    :cond_5
    invoke-virtual {p1, p3, p2, p4}, La8/i1;->e(IIZ)La8/i1;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iput-object p1, p0, La8/q0;->I:La8/i1;

    .line 46
    .line 47
    invoke-virtual {p0, v2, v2}, La8/q0;->B0(ZZ)V

    .line 48
    .line 49
    .line 50
    iget-object p1, p0, La8/q0;->u:La8/z0;

    .line 51
    .line 52
    iget-object p2, p1, La8/z0;->i:La8/w0;

    .line 53
    .line 54
    :goto_3
    if-eqz p2, :cond_8

    .line 55
    .line 56
    iget-object p3, p2, La8/w0;->o:Lj8/s;

    .line 57
    .line 58
    iget-object p3, p3, Lj8/s;->c:[Lj8/q;

    .line 59
    .line 60
    array-length v0, p3

    .line 61
    move v4, v2

    .line 62
    :goto_4
    if-ge v4, v0, :cond_7

    .line 63
    .line 64
    aget-object v5, p3, v4

    .line 65
    .line 66
    if-eqz v5, :cond_6

    .line 67
    .line 68
    invoke-interface {v5, p4}, Lj8/q;->h(Z)V

    .line 69
    .line 70
    .line 71
    :cond_6
    add-int/lit8 v4, v4, 0x1

    .line 72
    .line 73
    goto :goto_4

    .line 74
    :cond_7
    iget-object p2, p2, La8/w0;->m:La8/w0;

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_8
    invoke-virtual {p0}, La8/q0;->q0()Z

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    if-nez p2, :cond_a

    .line 82
    .line 83
    invoke-virtual {p0}, La8/q0;->u0()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0}, La8/q0;->z0()V

    .line 87
    .line 88
    .line 89
    iget-object p2, p0, La8/q0;->I:La8/i1;

    .line 90
    .line 91
    iget-boolean p3, p2, La8/i1;->p:Z

    .line 92
    .line 93
    if-eqz p3, :cond_9

    .line 94
    .line 95
    invoke-virtual {p2, v2}, La8/i1;->i(Z)La8/i1;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    iput-object p2, p0, La8/q0;->I:La8/i1;

    .line 100
    .line 101
    :cond_9
    iget-wide p2, p0, La8/q0;->X:J

    .line 102
    .line 103
    invoke-virtual {p1, p2, p3}, La8/z0;->m(J)V

    .line 104
    .line 105
    .line 106
    return-void

    .line 107
    :cond_a
    iget-object p1, p0, La8/q0;->I:La8/i1;

    .line 108
    .line 109
    iget p1, p1, La8/i1;->e:I

    .line 110
    .line 111
    const/4 p2, 0x3

    .line 112
    iget-object p3, p0, La8/q0;->k:Lw7/t;

    .line 113
    .line 114
    if-ne p1, p2, :cond_b

    .line 115
    .line 116
    iget-object p1, p0, La8/q0;->q:La8/l;

    .line 117
    .line 118
    iput-boolean v1, p1, La8/l;->e:Z

    .line 119
    .line 120
    iget-object p1, p1, La8/l;->f:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast p1, La8/s1;

    .line 123
    .line 124
    invoke-virtual {p1}, La8/s1;->f()V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0}, La8/q0;->s0()V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p3, v3}, Lw7/t;->e(I)Z

    .line 131
    .line 132
    .line 133
    return-void

    .line 134
    :cond_b
    if-ne p1, v3, :cond_c

    .line 135
    .line 136
    invoke-virtual {p3, v3}, Lw7/t;->e(I)Z

    .line 137
    .line 138
    .line 139
    :cond_c
    :goto_5
    return-void
.end method

.method public final z0()V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 4
    .line 5
    iget-object v1, v1, La8/z0;->i:La8/w0;

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto/16 :goto_d

    .line 10
    .line 11
    :cond_0
    iget-boolean v2, v1, La8/w0;->e:Z

    .line 12
    .line 13
    const-wide v10, -0x7fffffffffffffffL    # -4.9E-324

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    if-eqz v2, :cond_1

    .line 19
    .line 20
    iget-object v2, v1, La8/w0;->a:Ljava/lang/Object;

    .line 21
    .line 22
    invoke-interface {v2}, Lh8/z;->g()J

    .line 23
    .line 24
    .line 25
    move-result-wide v2

    .line 26
    goto :goto_0

    .line 27
    :cond_1
    move-wide v2, v10

    .line 28
    :goto_0
    cmp-long v4, v2, v10

    .line 29
    .line 30
    const/4 v12, 0x2

    .line 31
    const/16 v13, 0x10

    .line 32
    .line 33
    const/4 v14, 0x1

    .line 34
    const/4 v15, 0x0

    .line 35
    if-eqz v4, :cond_3

    .line 36
    .line 37
    invoke-virtual {v1}, La8/w0;->g()Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-nez v4, :cond_2

    .line 42
    .line 43
    iget-object v4, v0, La8/q0;->u:La8/z0;

    .line 44
    .line 45
    invoke-virtual {v4, v1}, La8/z0;->n(La8/w0;)I

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, v15}, La8/q0;->u(Z)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, La8/q0;->C()V

    .line 52
    .line 53
    .line 54
    :cond_2
    invoke-virtual {v0, v2, v3}, La8/q0;->Q(J)V

    .line 55
    .line 56
    .line 57
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 58
    .line 59
    iget-wide v4, v1, La8/i1;->s:J

    .line 60
    .line 61
    cmp-long v1, v2, v4

    .line 62
    .line 63
    if-eqz v1, :cond_13

    .line 64
    .line 65
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 66
    .line 67
    iget-object v4, v1, La8/i1;->b:Lh8/b0;

    .line 68
    .line 69
    iget-wide v5, v1, La8/i1;->c:J

    .line 70
    .line 71
    const/4 v8, 0x1

    .line 72
    const/4 v9, 0x5

    .line 73
    move-object v1, v4

    .line 74
    move-wide v4, v5

    .line 75
    move-wide v6, v2

    .line 76
    invoke-virtual/range {v0 .. v9}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    iput-object v1, v0, La8/q0;->I:La8/i1;

    .line 81
    .line 82
    goto/16 :goto_7

    .line 83
    .line 84
    :cond_3
    iget-object v2, v0, La8/q0;->q:La8/l;

    .line 85
    .line 86
    iget-object v3, v0, La8/q0;->u:La8/z0;

    .line 87
    .line 88
    iget-object v3, v3, La8/z0;->j:La8/w0;

    .line 89
    .line 90
    if-eq v1, v3, :cond_4

    .line 91
    .line 92
    move v3, v14

    .line 93
    goto :goto_1

    .line 94
    :cond_4
    move v3, v15

    .line 95
    :goto_1
    iget-object v4, v2, La8/l;->f:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v4, La8/s1;

    .line 98
    .line 99
    iget-object v5, v2, La8/l;->h:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v5, La8/f;

    .line 102
    .line 103
    if-eqz v5, :cond_9

    .line 104
    .line 105
    invoke-virtual {v5}, La8/f;->m()Z

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    if-nez v5, :cond_9

    .line 110
    .line 111
    if-eqz v3, :cond_5

    .line 112
    .line 113
    iget-object v5, v2, La8/l;->h:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v5, La8/f;

    .line 116
    .line 117
    iget v5, v5, La8/f;->k:I

    .line 118
    .line 119
    if-ne v5, v12, :cond_9

    .line 120
    .line 121
    :cond_5
    iget-object v5, v2, La8/l;->h:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v5, La8/f;

    .line 124
    .line 125
    invoke-virtual {v5}, La8/f;->o()Z

    .line 126
    .line 127
    .line 128
    move-result v5

    .line 129
    if-nez v5, :cond_6

    .line 130
    .line 131
    if-nez v3, :cond_9

    .line 132
    .line 133
    iget-object v3, v2, La8/l;->h:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v3, La8/f;

    .line 136
    .line 137
    invoke-virtual {v3}, La8/f;->l()Z

    .line 138
    .line 139
    .line 140
    move-result v3

    .line 141
    if-eqz v3, :cond_6

    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_6
    iget-object v3, v2, La8/l;->i:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v3, La8/v0;

    .line 147
    .line 148
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    invoke-interface {v3}, La8/v0;->e()J

    .line 152
    .line 153
    .line 154
    move-result-wide v5

    .line 155
    iget-boolean v7, v2, La8/l;->d:Z

    .line 156
    .line 157
    if-eqz v7, :cond_8

    .line 158
    .line 159
    invoke-virtual {v4}, La8/s1;->e()J

    .line 160
    .line 161
    .line 162
    move-result-wide v7

    .line 163
    cmp-long v7, v5, v7

    .line 164
    .line 165
    if-gez v7, :cond_7

    .line 166
    .line 167
    iget-boolean v3, v4, La8/s1;->e:Z

    .line 168
    .line 169
    if-eqz v3, :cond_a

    .line 170
    .line 171
    invoke-virtual {v4}, La8/s1;->e()J

    .line 172
    .line 173
    .line 174
    move-result-wide v5

    .line 175
    invoke-virtual {v4, v5, v6}, La8/s1;->a(J)V

    .line 176
    .line 177
    .line 178
    iput-boolean v15, v4, La8/s1;->e:Z

    .line 179
    .line 180
    goto :goto_3

    .line 181
    :cond_7
    iput-boolean v15, v2, La8/l;->d:Z

    .line 182
    .line 183
    iget-boolean v7, v2, La8/l;->e:Z

    .line 184
    .line 185
    if-eqz v7, :cond_8

    .line 186
    .line 187
    invoke-virtual {v4}, La8/s1;->f()V

    .line 188
    .line 189
    .line 190
    :cond_8
    invoke-virtual {v4, v5, v6}, La8/s1;->a(J)V

    .line 191
    .line 192
    .line 193
    invoke-interface {v3}, La8/v0;->c()Lt7/g0;

    .line 194
    .line 195
    .line 196
    move-result-object v3

    .line 197
    iget-object v5, v4, La8/s1;->h:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v5, Lt7/g0;

    .line 200
    .line 201
    invoke-virtual {v3, v5}, Lt7/g0;->equals(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v5

    .line 205
    if-nez v5, :cond_a

    .line 206
    .line 207
    invoke-virtual {v4, v3}, La8/s1;->d(Lt7/g0;)V

    .line 208
    .line 209
    .line 210
    iget-object v4, v2, La8/l;->g:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v4, La8/q0;

    .line 213
    .line 214
    iget-object v4, v4, La8/q0;->k:Lw7/t;

    .line 215
    .line 216
    invoke-virtual {v4, v13, v3}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 217
    .line 218
    .line 219
    move-result-object v3

    .line 220
    invoke-virtual {v3}, Lw7/s;->b()V

    .line 221
    .line 222
    .line 223
    goto :goto_3

    .line 224
    :cond_9
    :goto_2
    iput-boolean v14, v2, La8/l;->d:Z

    .line 225
    .line 226
    iget-boolean v3, v2, La8/l;->e:Z

    .line 227
    .line 228
    if-eqz v3, :cond_a

    .line 229
    .line 230
    invoke-virtual {v4}, La8/s1;->f()V

    .line 231
    .line 232
    .line 233
    :cond_a
    :goto_3
    invoke-virtual {v2}, La8/l;->e()J

    .line 234
    .line 235
    .line 236
    move-result-wide v2

    .line 237
    iput-wide v2, v0, La8/q0;->X:J

    .line 238
    .line 239
    iget-wide v4, v1, La8/w0;->p:J

    .line 240
    .line 241
    sub-long/2addr v2, v4

    .line 242
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 243
    .line 244
    iget-wide v4, v1, La8/i1;->s:J

    .line 245
    .line 246
    iget-object v1, v0, La8/q0;->r:Ljava/util/ArrayList;

    .line 247
    .line 248
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 249
    .line 250
    .line 251
    move-result v1

    .line 252
    if-nez v1, :cond_11

    .line 253
    .line 254
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 255
    .line 256
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 257
    .line 258
    invoke-virtual {v1}, Lh8/b0;->b()Z

    .line 259
    .line 260
    .line 261
    move-result v1

    .line 262
    if-eqz v1, :cond_b

    .line 263
    .line 264
    goto :goto_6

    .line 265
    :cond_b
    iget-boolean v1, v0, La8/q0;->a0:Z

    .line 266
    .line 267
    if-eqz v1, :cond_c

    .line 268
    .line 269
    iput-boolean v15, v0, La8/q0;->a0:Z

    .line 270
    .line 271
    :cond_c
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 272
    .line 273
    iget-object v4, v1, La8/i1;->a:Lt7/p0;

    .line 274
    .line 275
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 276
    .line 277
    iget-object v1, v1, Lh8/b0;->a:Ljava/lang/Object;

    .line 278
    .line 279
    invoke-virtual {v4, v1}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 280
    .line 281
    .line 282
    iget v1, v0, La8/q0;->Z:I

    .line 283
    .line 284
    iget-object v4, v0, La8/q0;->r:Ljava/util/ArrayList;

    .line 285
    .line 286
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 287
    .line 288
    .line 289
    move-result v4

    .line 290
    invoke-static {v1, v4}, Ljava/lang/Math;->min(II)I

    .line 291
    .line 292
    .line 293
    move-result v1

    .line 294
    if-lez v1, :cond_e

    .line 295
    .line 296
    iget-object v4, v0, La8/q0;->r:Ljava/util/ArrayList;

    .line 297
    .line 298
    add-int/lit8 v5, v1, -0x1

    .line 299
    .line 300
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v4

    .line 304
    if-nez v4, :cond_d

    .line 305
    .line 306
    goto :goto_4

    .line 307
    :cond_d
    new-instance v0, Ljava/lang/ClassCastException;

    .line 308
    .line 309
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 310
    .line 311
    .line 312
    throw v0

    .line 313
    :cond_e
    :goto_4
    iget-object v4, v0, La8/q0;->r:Ljava/util/ArrayList;

    .line 314
    .line 315
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 316
    .line 317
    .line 318
    move-result v4

    .line 319
    if-ge v1, v4, :cond_10

    .line 320
    .line 321
    iget-object v4, v0, La8/q0;->r:Ljava/util/ArrayList;

    .line 322
    .line 323
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v4

    .line 327
    if-nez v4, :cond_f

    .line 328
    .line 329
    goto :goto_5

    .line 330
    :cond_f
    new-instance v0, Ljava/lang/ClassCastException;

    .line 331
    .line 332
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 333
    .line 334
    .line 335
    throw v0

    .line 336
    :cond_10
    :goto_5
    iput v1, v0, La8/q0;->Z:I

    .line 337
    .line 338
    :cond_11
    :goto_6
    iget-object v1, v0, La8/q0;->q:La8/l;

    .line 339
    .line 340
    invoke-virtual {v1}, La8/l;->b()Z

    .line 341
    .line 342
    .line 343
    move-result v1

    .line 344
    if-eqz v1, :cond_12

    .line 345
    .line 346
    iget-object v1, v0, La8/q0;->J:La8/n0;

    .line 347
    .line 348
    iget-boolean v1, v1, La8/n0;->e:Z

    .line 349
    .line 350
    xor-int/lit8 v8, v1, 0x1

    .line 351
    .line 352
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 353
    .line 354
    iget-object v4, v1, La8/i1;->b:Lh8/b0;

    .line 355
    .line 356
    iget-wide v5, v1, La8/i1;->c:J

    .line 357
    .line 358
    const/4 v9, 0x6

    .line 359
    move-object v1, v4

    .line 360
    move-wide v4, v5

    .line 361
    move-wide v6, v2

    .line 362
    invoke-virtual/range {v0 .. v9}, La8/q0;->y(Lh8/b0;JJJZI)La8/i1;

    .line 363
    .line 364
    .line 365
    move-result-object v1

    .line 366
    iput-object v1, v0, La8/q0;->I:La8/i1;

    .line 367
    .line 368
    goto :goto_7

    .line 369
    :cond_12
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 370
    .line 371
    iput-wide v2, v1, La8/i1;->s:J

    .line 372
    .line 373
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 374
    .line 375
    .line 376
    move-result-wide v2

    .line 377
    iput-wide v2, v1, La8/i1;->t:J

    .line 378
    .line 379
    :cond_13
    :goto_7
    iget-object v1, v0, La8/q0;->u:La8/z0;

    .line 380
    .line 381
    iget-object v1, v1, La8/z0;->l:La8/w0;

    .line 382
    .line 383
    iget-object v2, v0, La8/q0;->I:La8/i1;

    .line 384
    .line 385
    invoke-virtual {v1}, La8/w0;->d()J

    .line 386
    .line 387
    .line 388
    move-result-wide v3

    .line 389
    iput-wide v3, v2, La8/i1;->q:J

    .line 390
    .line 391
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 392
    .line 393
    iget-wide v2, v1, La8/i1;->q:J

    .line 394
    .line 395
    invoke-virtual {v0, v2, v3}, La8/q0;->p(J)J

    .line 396
    .line 397
    .line 398
    move-result-wide v2

    .line 399
    iput-wide v2, v1, La8/i1;->r:J

    .line 400
    .line 401
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 402
    .line 403
    iget-boolean v2, v1, La8/i1;->l:Z

    .line 404
    .line 405
    if-eqz v2, :cond_1d

    .line 406
    .line 407
    iget v2, v1, La8/i1;->e:I

    .line 408
    .line 409
    const/4 v3, 0x3

    .line 410
    if-ne v2, v3, :cond_1d

    .line 411
    .line 412
    iget-object v2, v1, La8/i1;->a:Lt7/p0;

    .line 413
    .line 414
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 415
    .line 416
    invoke-virtual {v0, v2, v1}, La8/q0;->r0(Lt7/p0;Lh8/b0;)Z

    .line 417
    .line 418
    .line 419
    move-result v1

    .line 420
    if-eqz v1, :cond_1d

    .line 421
    .line 422
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 423
    .line 424
    iget-object v2, v1, La8/i1;->o:Lt7/g0;

    .line 425
    .line 426
    iget v2, v2, Lt7/g0;->a:F

    .line 427
    .line 428
    const/high16 v4, 0x3f800000    # 1.0f

    .line 429
    .line 430
    cmpl-float v2, v2, v4

    .line 431
    .line 432
    if-nez v2, :cond_1d

    .line 433
    .line 434
    iget-object v2, v0, La8/q0;->w:La8/i;

    .line 435
    .line 436
    iget-object v5, v1, La8/i1;->a:Lt7/p0;

    .line 437
    .line 438
    iget-object v6, v1, La8/i1;->b:Lh8/b0;

    .line 439
    .line 440
    iget-object v6, v6, Lh8/b0;->a:Ljava/lang/Object;

    .line 441
    .line 442
    iget-wide v7, v1, La8/i1;->s:J

    .line 443
    .line 444
    invoke-virtual {v0, v5, v6, v7, v8}, La8/q0;->m(Lt7/p0;Ljava/lang/Object;J)J

    .line 445
    .line 446
    .line 447
    move-result-wide v5

    .line 448
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 449
    .line 450
    iget-wide v7, v1, La8/i1;->r:J

    .line 451
    .line 452
    move-wide/from16 v16, v10

    .line 453
    .line 454
    iget-wide v10, v2, La8/i;->c:J

    .line 455
    .line 456
    cmp-long v1, v10, v16

    .line 457
    .line 458
    if-nez v1, :cond_14

    .line 459
    .line 460
    goto/16 :goto_c

    .line 461
    .line 462
    :cond_14
    sub-long v7, v5, v7

    .line 463
    .line 464
    iget-wide v9, v2, La8/i;->m:J

    .line 465
    .line 466
    cmp-long v1, v9, v16

    .line 467
    .line 468
    if-nez v1, :cond_15

    .line 469
    .line 470
    iput-wide v7, v2, La8/i;->m:J

    .line 471
    .line 472
    const-wide/16 v7, 0x0

    .line 473
    .line 474
    iput-wide v7, v2, La8/i;->n:J

    .line 475
    .line 476
    goto :goto_8

    .line 477
    :cond_15
    long-to-float v1, v9

    .line 478
    const v9, 0x3f7fbe77    # 0.999f

    .line 479
    .line 480
    .line 481
    mul-float/2addr v1, v9

    .line 482
    long-to-float v10, v7

    .line 483
    const v11, 0x3a831200    # 9.999871E-4f

    .line 484
    .line 485
    .line 486
    mul-float/2addr v10, v11

    .line 487
    add-float/2addr v10, v1

    .line 488
    move v1, v9

    .line 489
    float-to-long v9, v10

    .line 490
    invoke-static {v7, v8, v9, v10}, Ljava/lang/Math;->max(JJ)J

    .line 491
    .line 492
    .line 493
    move-result-wide v9

    .line 494
    iput-wide v9, v2, La8/i;->m:J

    .line 495
    .line 496
    sub-long/2addr v7, v9

    .line 497
    invoke-static {v7, v8}, Ljava/lang/Math;->abs(J)J

    .line 498
    .line 499
    .line 500
    move-result-wide v7

    .line 501
    iget-wide v9, v2, La8/i;->n:J

    .line 502
    .line 503
    long-to-float v9, v9

    .line 504
    mul-float/2addr v9, v1

    .line 505
    long-to-float v1, v7

    .line 506
    mul-float/2addr v11, v1

    .line 507
    add-float/2addr v11, v9

    .line 508
    float-to-long v7, v11

    .line 509
    iput-wide v7, v2, La8/i;->n:J

    .line 510
    .line 511
    :goto_8
    iget-wide v7, v2, La8/i;->l:J

    .line 512
    .line 513
    cmp-long v1, v7, v16

    .line 514
    .line 515
    if-eqz v1, :cond_16

    .line 516
    .line 517
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 518
    .line 519
    .line 520
    move-result-wide v9

    .line 521
    const-wide/16 v18, 0x3e8

    .line 522
    .line 523
    iget-wide v7, v2, La8/i;->l:J

    .line 524
    .line 525
    sub-long/2addr v9, v7

    .line 526
    cmp-long v1, v9, v18

    .line 527
    .line 528
    if-gez v1, :cond_17

    .line 529
    .line 530
    iget v4, v2, La8/i;->k:F

    .line 531
    .line 532
    goto/16 :goto_c

    .line 533
    .line 534
    :cond_16
    const-wide/16 v18, 0x3e8

    .line 535
    .line 536
    :cond_17
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 537
    .line 538
    .line 539
    move-result-wide v7

    .line 540
    iput-wide v7, v2, La8/i;->l:J

    .line 541
    .line 542
    iget-wide v7, v2, La8/i;->m:J

    .line 543
    .line 544
    const-wide/16 v20, 0x3

    .line 545
    .line 546
    iget-wide v9, v2, La8/i;->n:J

    .line 547
    .line 548
    mul-long v9, v9, v20

    .line 549
    .line 550
    add-long v24, v9, v7

    .line 551
    .line 552
    iget-wide v7, v2, La8/i;->h:J

    .line 553
    .line 554
    cmp-long v1, v7, v24

    .line 555
    .line 556
    if-lez v1, :cond_1a

    .line 557
    .line 558
    invoke-static/range {v18 .. v19}, Lw7/w;->D(J)J

    .line 559
    .line 560
    .line 561
    move-result-wide v8

    .line 562
    iget v1, v2, La8/i;->k:F

    .line 563
    .line 564
    sub-float/2addr v1, v4

    .line 565
    long-to-float v8, v8

    .line 566
    mul-float/2addr v1, v8

    .line 567
    float-to-long v9, v1

    .line 568
    iget v1, v2, La8/i;->i:F

    .line 569
    .line 570
    sub-float/2addr v1, v4

    .line 571
    mul-float/2addr v1, v8

    .line 572
    const v11, 0x33d6bf95    # 1.0E-7f

    .line 573
    .line 574
    .line 575
    float-to-long v7, v1

    .line 576
    add-long/2addr v9, v7

    .line 577
    iget-wide v7, v2, La8/i;->e:J

    .line 578
    .line 579
    move/from16 v18, v11

    .line 580
    .line 581
    move v1, v12

    .line 582
    iget-wide v11, v2, La8/i;->h:J

    .line 583
    .line 584
    sub-long/2addr v11, v9

    .line 585
    new-array v9, v3, [J

    .line 586
    .line 587
    aput-wide v24, v9, v15

    .line 588
    .line 589
    aput-wide v7, v9, v14

    .line 590
    .line 591
    aput-wide v11, v9, v1

    .line 592
    .line 593
    aget-wide v7, v9, v15

    .line 594
    .line 595
    :goto_9
    if-ge v14, v3, :cond_19

    .line 596
    .line 597
    aget-wide v10, v9, v14

    .line 598
    .line 599
    cmp-long v1, v10, v7

    .line 600
    .line 601
    if-lez v1, :cond_18

    .line 602
    .line 603
    move-wide v7, v10

    .line 604
    :cond_18
    add-int/lit8 v14, v14, 0x1

    .line 605
    .line 606
    goto :goto_9

    .line 607
    :cond_19
    iput-wide v7, v2, La8/i;->h:J

    .line 608
    .line 609
    goto :goto_a

    .line 610
    :cond_1a
    const v18, 0x33d6bf95    # 1.0E-7f

    .line 611
    .line 612
    .line 613
    iget v1, v2, La8/i;->k:F

    .line 614
    .line 615
    sub-float/2addr v1, v4

    .line 616
    const/4 v3, 0x0

    .line 617
    invoke-static {v3, v1}, Ljava/lang/Math;->max(FF)F

    .line 618
    .line 619
    .line 620
    move-result v1

    .line 621
    div-float v1, v1, v18

    .line 622
    .line 623
    float-to-long v7, v1

    .line 624
    sub-long v20, v5, v7

    .line 625
    .line 626
    iget-wide v7, v2, La8/i;->h:J

    .line 627
    .line 628
    move-wide/from16 v22, v7

    .line 629
    .line 630
    invoke-static/range {v20 .. v25}, Lw7/w;->h(JJJ)J

    .line 631
    .line 632
    .line 633
    move-result-wide v7

    .line 634
    iput-wide v7, v2, La8/i;->h:J

    .line 635
    .line 636
    iget-wide v9, v2, La8/i;->g:J

    .line 637
    .line 638
    cmp-long v1, v9, v16

    .line 639
    .line 640
    if-eqz v1, :cond_1b

    .line 641
    .line 642
    cmp-long v1, v7, v9

    .line 643
    .line 644
    if-lez v1, :cond_1b

    .line 645
    .line 646
    iput-wide v9, v2, La8/i;->h:J

    .line 647
    .line 648
    :cond_1b
    :goto_a
    iget-wide v7, v2, La8/i;->h:J

    .line 649
    .line 650
    sub-long/2addr v5, v7

    .line 651
    invoke-static {v5, v6}, Ljava/lang/Math;->abs(J)J

    .line 652
    .line 653
    .line 654
    move-result-wide v7

    .line 655
    iget-wide v9, v2, La8/i;->a:J

    .line 656
    .line 657
    cmp-long v1, v7, v9

    .line 658
    .line 659
    if-gez v1, :cond_1c

    .line 660
    .line 661
    iput v4, v2, La8/i;->k:F

    .line 662
    .line 663
    goto :goto_b

    .line 664
    :cond_1c
    long-to-float v1, v5

    .line 665
    mul-float v7, v18, v1

    .line 666
    .line 667
    add-float/2addr v7, v4

    .line 668
    iget v1, v2, La8/i;->j:F

    .line 669
    .line 670
    iget v3, v2, La8/i;->i:F

    .line 671
    .line 672
    invoke-static {v7, v1, v3}, Lw7/w;->f(FFF)F

    .line 673
    .line 674
    .line 675
    move-result v1

    .line 676
    iput v1, v2, La8/i;->k:F

    .line 677
    .line 678
    :goto_b
    iget v4, v2, La8/i;->k:F

    .line 679
    .line 680
    :goto_c
    iget-object v1, v0, La8/q0;->q:La8/l;

    .line 681
    .line 682
    invoke-virtual {v1}, La8/l;->c()Lt7/g0;

    .line 683
    .line 684
    .line 685
    move-result-object v1

    .line 686
    iget v1, v1, Lt7/g0;->a:F

    .line 687
    .line 688
    cmpl-float v1, v1, v4

    .line 689
    .line 690
    if-eqz v1, :cond_1d

    .line 691
    .line 692
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 693
    .line 694
    iget-object v1, v1, La8/i1;->o:Lt7/g0;

    .line 695
    .line 696
    new-instance v2, Lt7/g0;

    .line 697
    .line 698
    iget v1, v1, Lt7/g0;->b:F

    .line 699
    .line 700
    invoke-direct {v2, v4, v1}, Lt7/g0;-><init>(FF)V

    .line 701
    .line 702
    .line 703
    iget-object v1, v0, La8/q0;->k:Lw7/t;

    .line 704
    .line 705
    invoke-virtual {v1, v13}, Lw7/t;->d(I)V

    .line 706
    .line 707
    .line 708
    iget-object v1, v0, La8/q0;->q:La8/l;

    .line 709
    .line 710
    invoke-virtual {v1, v2}, La8/l;->d(Lt7/g0;)V

    .line 711
    .line 712
    .line 713
    iget-object v1, v0, La8/q0;->I:La8/i1;

    .line 714
    .line 715
    iget-object v1, v1, La8/i1;->o:Lt7/g0;

    .line 716
    .line 717
    iget-object v2, v0, La8/q0;->q:La8/l;

    .line 718
    .line 719
    invoke-virtual {v2}, La8/l;->c()Lt7/g0;

    .line 720
    .line 721
    .line 722
    move-result-object v2

    .line 723
    iget v2, v2, Lt7/g0;->a:F

    .line 724
    .line 725
    invoke-virtual {v0, v1, v2, v15, v15}, La8/q0;->x(Lt7/g0;FZZ)V

    .line 726
    .line 727
    .line 728
    :cond_1d
    :goto_d
    return-void
.end method
