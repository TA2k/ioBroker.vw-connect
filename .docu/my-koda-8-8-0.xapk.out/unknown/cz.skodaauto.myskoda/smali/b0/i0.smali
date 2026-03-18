.class public final Lb0/i0;
.super Lb0/z1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final y:Lb0/g0;


# instance fields
.field public final p:Ljava/lang/Object;

.field public q:Lb0/l0;

.field public r:Ljava/util/concurrent/Executor;

.field public s:Lb0/d0;

.field public t:Landroid/graphics/Rect;

.field public u:Landroid/graphics/Matrix;

.field public v:Lh0/v1;

.field public w:Lb0/u1;

.field public x:Lh0/w1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lb0/g0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lb0/i0;->y:Lb0/g0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lh0/x0;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lb0/z1;-><init>(Lh0/o2;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lb0/i0;->p:Ljava/lang/Object;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final A(Landroid/graphics/Rect;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 2
    .line 3
    iget-object v0, p0, Lb0/i0;->p:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Lb0/i0;->q:Lb0/l0;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    invoke-virtual {v1, p1}, Lb0/l0;->j(Landroid/graphics/Rect;)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    :goto_0
    iput-object p1, p0, Lb0/i0;->t:Landroid/graphics/Rect;

    .line 17
    .line 18
    monitor-exit v0

    .line 19
    return-void

    .line 20
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    throw p0
.end method

.method public final D(Lh0/x0;Lh0/k;)Lh0/v1;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    invoke-static {}, Llp/k1;->a()V

    .line 8
    .line 9
    .line 10
    iget-object v3, v2, Lh0/k;->a:Landroid/util/Size;

    .line 11
    .line 12
    invoke-static {}, Llp/hb;->b()Lj0/e;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    sget-object v5, Ll0/l;->i1:Lh0/g;

    .line 17
    .line 18
    invoke-interface {v1, v5, v4}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    check-cast v4, Ljava/util/concurrent/Executor;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    iget-object v5, v0, Lb0/z1;->g:Lh0/o2;

    .line 28
    .line 29
    check-cast v5, Lh0/x0;

    .line 30
    .line 31
    sget-object v6, Lh0/x0;->e:Lh0/g;

    .line 32
    .line 33
    const/4 v7, 0x0

    .line 34
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 35
    .line 36
    .line 37
    move-result-object v8

    .line 38
    invoke-interface {v5, v6, v8}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    check-cast v5, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    const/4 v6, 0x1

    .line 49
    if-ne v5, v6, :cond_0

    .line 50
    .line 51
    iget-object v5, v0, Lb0/z1;->g:Lh0/o2;

    .line 52
    .line 53
    check-cast v5, Lh0/x0;

    .line 54
    .line 55
    sget-object v8, Lh0/x0;->f:Lh0/g;

    .line 56
    .line 57
    const/4 v9, 0x6

    .line 58
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 59
    .line 60
    .line 61
    move-result-object v9

    .line 62
    invoke-interface {v5, v8, v9}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Ljava/lang/Integer;

    .line 67
    .line 68
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    goto :goto_0

    .line 73
    :cond_0
    const/4 v5, 0x4

    .line 74
    :goto_0
    sget-object v8, Lh0/x0;->g:Lh0/g;

    .line 75
    .line 76
    const/4 v9, 0x0

    .line 77
    invoke-interface {v1, v8, v9}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v8

    .line 81
    if-nez v8, :cond_11

    .line 82
    .line 83
    new-instance v8, Lb0/n1;

    .line 84
    .line 85
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 86
    .line 87
    .line 88
    move-result v10

    .line 89
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 90
    .line 91
    .line 92
    move-result v11

    .line 93
    iget-object v12, v0, Lb0/z1;->g:Lh0/o2;

    .line 94
    .line 95
    invoke-interface {v12}, Lh0/z0;->l()I

    .line 96
    .line 97
    .line 98
    move-result v12

    .line 99
    invoke-static {v10, v11, v12, v5}, Ljp/u1;->e(IIII)Lcom/google/android/gms/internal/measurement/i4;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    invoke-direct {v8, v5}, Lb0/n1;-><init>(Lh0/c1;)V

    .line 104
    .line 105
    .line 106
    iget-object v5, v0, Lb0/i0;->p:Ljava/lang/Object;

    .line 107
    .line 108
    monitor-enter v5

    .line 109
    :try_start_0
    invoke-virtual {v0}, Lb0/i0;->F()V

    .line 110
    .line 111
    .line 112
    iget-object v10, v0, Lb0/i0;->q:Lb0/l0;

    .line 113
    .line 114
    monitor-exit v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 115
    invoke-virtual {v0}, Lb0/z1;->c()Lh0/b0;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    if-eqz v5, :cond_1

    .line 120
    .line 121
    invoke-virtual {v0}, Lb0/z1;->c()Lh0/b0;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    iget-object v11, v0, Lb0/z1;->g:Lh0/o2;

    .line 126
    .line 127
    check-cast v11, Lh0/x0;

    .line 128
    .line 129
    sget-object v12, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 130
    .line 131
    sget-object v13, Lh0/x0;->j:Lh0/g;

    .line 132
    .line 133
    invoke-interface {v11, v13, v12}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v11

    .line 137
    check-cast v11, Ljava/lang/Boolean;

    .line 138
    .line 139
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 140
    .line 141
    .line 142
    move-result v11

    .line 143
    if-eqz v11, :cond_1

    .line 144
    .line 145
    invoke-virtual {v0, v5, v7}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 146
    .line 147
    .line 148
    move-result v5

    .line 149
    rem-int/lit16 v5, v5, 0xb4

    .line 150
    .line 151
    if-eqz v5, :cond_1

    .line 152
    .line 153
    move v5, v6

    .line 154
    goto :goto_1

    .line 155
    :cond_1
    move v5, v7

    .line 156
    :goto_1
    if-eqz v5, :cond_2

    .line 157
    .line 158
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 159
    .line 160
    .line 161
    move-result v11

    .line 162
    goto :goto_2

    .line 163
    :cond_2
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 164
    .line 165
    .line 166
    move-result v11

    .line 167
    :goto_2
    if-eqz v5, :cond_3

    .line 168
    .line 169
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 170
    .line 171
    .line 172
    move-result v5

    .line 173
    goto :goto_3

    .line 174
    :cond_3
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 175
    .line 176
    .line 177
    move-result v5

    .line 178
    :goto_3
    invoke-virtual {v0}, Lb0/i0;->E()I

    .line 179
    .line 180
    .line 181
    move-result v12

    .line 182
    const/4 v13, 0x2

    .line 183
    const/16 v14, 0x23

    .line 184
    .line 185
    if-ne v12, v13, :cond_4

    .line 186
    .line 187
    move v12, v6

    .line 188
    goto :goto_4

    .line 189
    :cond_4
    move v12, v14

    .line 190
    :goto_4
    iget-object v15, v0, Lb0/z1;->g:Lh0/o2;

    .line 191
    .line 192
    invoke-interface {v15}, Lh0/z0;->l()I

    .line 193
    .line 194
    .line 195
    move-result v15

    .line 196
    if-ne v15, v14, :cond_5

    .line 197
    .line 198
    invoke-virtual {v0}, Lb0/i0;->E()I

    .line 199
    .line 200
    .line 201
    move-result v15

    .line 202
    if-ne v15, v13, :cond_5

    .line 203
    .line 204
    move v13, v6

    .line 205
    goto :goto_5

    .line 206
    :cond_5
    move v13, v7

    .line 207
    :goto_5
    iget-object v15, v0, Lb0/z1;->g:Lh0/o2;

    .line 208
    .line 209
    invoke-interface {v15}, Lh0/z0;->l()I

    .line 210
    .line 211
    .line 212
    move-result v15

    .line 213
    if-ne v15, v14, :cond_6

    .line 214
    .line 215
    invoke-virtual {v0}, Lb0/i0;->E()I

    .line 216
    .line 217
    .line 218
    move-result v15

    .line 219
    const/4 v6, 0x3

    .line 220
    if-ne v15, v6, :cond_6

    .line 221
    .line 222
    const/4 v6, 0x1

    .line 223
    goto :goto_6

    .line 224
    :cond_6
    move v6, v7

    .line 225
    :goto_6
    iget-object v15, v0, Lb0/z1;->g:Lh0/o2;

    .line 226
    .line 227
    invoke-interface {v15}, Lh0/z0;->l()I

    .line 228
    .line 229
    .line 230
    move-result v15

    .line 231
    if-ne v15, v14, :cond_9

    .line 232
    .line 233
    invoke-virtual {v0}, Lb0/z1;->c()Lh0/b0;

    .line 234
    .line 235
    .line 236
    move-result-object v14

    .line 237
    if-eqz v14, :cond_7

    .line 238
    .line 239
    invoke-virtual {v0}, Lb0/z1;->c()Lh0/b0;

    .line 240
    .line 241
    .line 242
    move-result-object v14

    .line 243
    invoke-virtual {v0, v14, v7}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 244
    .line 245
    .line 246
    move-result v14

    .line 247
    if-nez v14, :cond_8

    .line 248
    .line 249
    :cond_7
    sget-object v14, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 250
    .line 251
    iget-object v15, v0, Lb0/z1;->g:Lh0/o2;

    .line 252
    .line 253
    check-cast v15, Lh0/x0;

    .line 254
    .line 255
    sget-object v7, Lh0/x0;->i:Lh0/g;

    .line 256
    .line 257
    invoke-interface {v15, v7, v9}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v7

    .line 261
    check-cast v7, Ljava/lang/Boolean;

    .line 262
    .line 263
    invoke-virtual {v14, v7}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    move-result v7

    .line 267
    if-eqz v7, :cond_9

    .line 268
    .line 269
    :cond_8
    const/16 v16, 0x1

    .line 270
    .line 271
    goto :goto_7

    .line 272
    :cond_9
    const/16 v16, 0x0

    .line 273
    .line 274
    :goto_7
    if-nez v13, :cond_a

    .line 275
    .line 276
    if-eqz v16, :cond_b

    .line 277
    .line 278
    if-nez v6, :cond_b

    .line 279
    .line 280
    :cond_a
    new-instance v9, Lb0/n1;

    .line 281
    .line 282
    invoke-virtual {v8}, Lb0/n1;->f()I

    .line 283
    .line 284
    .line 285
    move-result v6

    .line 286
    invoke-static {v11, v5, v12, v6}, Ljp/u1;->e(IIII)Lcom/google/android/gms/internal/measurement/i4;

    .line 287
    .line 288
    .line 289
    move-result-object v5

    .line 290
    invoke-direct {v9, v5}, Lb0/n1;-><init>(Lh0/c1;)V

    .line 291
    .line 292
    .line 293
    :cond_b
    if-eqz v9, :cond_c

    .line 294
    .line 295
    iget-object v5, v10, Lb0/l0;->w:Ljava/lang/Object;

    .line 296
    .line 297
    monitor-enter v5

    .line 298
    :try_start_1
    iput-object v9, v10, Lb0/l0;->k:Lb0/n1;

    .line 299
    .line 300
    monitor-exit v5

    .line 301
    goto :goto_8

    .line 302
    :catchall_0
    move-exception v0

    .line 303
    monitor-exit v5
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 304
    throw v0

    .line 305
    :cond_c
    :goto_8
    iget-object v6, v0, Lb0/i0;->p:Ljava/lang/Object;

    .line 306
    .line 307
    monitor-enter v6

    .line 308
    :try_start_2
    invoke-virtual {v0}, Lb0/z1;->c()Lh0/b0;

    .line 309
    .line 310
    .line 311
    move-result-object v5

    .line 312
    if-eqz v5, :cond_d

    .line 313
    .line 314
    iget-object v7, v0, Lb0/i0;->q:Lb0/l0;

    .line 315
    .line 316
    const/4 v11, 0x0

    .line 317
    invoke-virtual {v0, v5, v11}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 318
    .line 319
    .line 320
    move-result v5

    .line 321
    iput v5, v7, Lb0/l0;->e:I

    .line 322
    .line 323
    goto :goto_9

    .line 324
    :catchall_1
    move-exception v0

    .line 325
    goto :goto_a

    .line 326
    :cond_d
    :goto_9
    monitor-exit v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 327
    invoke-virtual {v8, v10, v4}, Lb0/n1;->g(Lh0/b1;Ljava/util/concurrent/Executor;)V

    .line 328
    .line 329
    .line 330
    iget-object v4, v2, Lh0/k;->a:Landroid/util/Size;

    .line 331
    .line 332
    invoke-static {v1, v4}, Lh0/v1;->d(Lh0/o2;Landroid/util/Size;)Lh0/v1;

    .line 333
    .line 334
    .line 335
    move-result-object v1

    .line 336
    iget-object v4, v2, Lh0/k;->f:Lh0/q0;

    .line 337
    .line 338
    if-eqz v4, :cond_e

    .line 339
    .line 340
    iget-object v5, v1, Lh0/u1;->b:Lb0/n1;

    .line 341
    .line 342
    invoke-virtual {v5, v4}, Lb0/n1;->i(Lh0/q0;)V

    .line 343
    .line 344
    .line 345
    :cond_e
    iget-object v4, v0, Lb0/i0;->w:Lb0/u1;

    .line 346
    .line 347
    if-eqz v4, :cond_f

    .line 348
    .line 349
    invoke-virtual {v4}, Lh0/t0;->a()V

    .line 350
    .line 351
    .line 352
    :cond_f
    new-instance v4, Lb0/u1;

    .line 353
    .line 354
    invoke-virtual {v8}, Lb0/n1;->getSurface()Landroid/view/Surface;

    .line 355
    .line 356
    .line 357
    move-result-object v5

    .line 358
    iget-object v6, v0, Lb0/z1;->g:Lh0/o2;

    .line 359
    .line 360
    invoke-interface {v6}, Lh0/z0;->l()I

    .line 361
    .line 362
    .line 363
    move-result v6

    .line 364
    invoke-direct {v4, v5, v3, v6}, Lb0/u1;-><init>(Landroid/view/Surface;Landroid/util/Size;I)V

    .line 365
    .line 366
    .line 367
    iput-object v4, v0, Lb0/i0;->w:Lb0/u1;

    .line 368
    .line 369
    iget-object v3, v4, Lh0/t0;->e:Ly4/k;

    .line 370
    .line 371
    invoke-static {v3}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 372
    .line 373
    .line 374
    move-result-object v3

    .line 375
    new-instance v4, La8/z;

    .line 376
    .line 377
    const/4 v5, 0x6

    .line 378
    invoke-direct {v4, v5, v8, v9}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 379
    .line 380
    .line 381
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 382
    .line 383
    .line 384
    move-result-object v5

    .line 385
    invoke-interface {v3, v5, v4}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 386
    .line 387
    .line 388
    iget v3, v2, Lh0/k;->d:I

    .line 389
    .line 390
    iput v3, v1, Lh0/u1;->h:I

    .line 391
    .line 392
    invoke-virtual {v0, v1, v2}, Lb0/z1;->a(Lh0/v1;Lh0/k;)V

    .line 393
    .line 394
    .line 395
    iget-object v3, v0, Lb0/i0;->w:Lb0/u1;

    .line 396
    .line 397
    iget-object v2, v2, Lh0/k;->c:Lb0/y;

    .line 398
    .line 399
    const/4 v4, -0x1

    .line 400
    invoke-virtual {v1, v3, v2, v4}, Lh0/v1;->b(Lh0/t0;Lb0/y;I)V

    .line 401
    .line 402
    .line 403
    iget-object v2, v0, Lb0/i0;->x:Lh0/w1;

    .line 404
    .line 405
    if-eqz v2, :cond_10

    .line 406
    .line 407
    invoke-virtual {v2}, Lh0/w1;->b()V

    .line 408
    .line 409
    .line 410
    :cond_10
    new-instance v2, Lh0/w1;

    .line 411
    .line 412
    new-instance v3, Lb0/c0;

    .line 413
    .line 414
    invoke-direct {v3, v0, v10}, Lb0/c0;-><init>(Lb0/i0;Lb0/l0;)V

    .line 415
    .line 416
    .line 417
    invoke-direct {v2, v3}, Lh0/w1;-><init>(Lh0/x1;)V

    .line 418
    .line 419
    .line 420
    iput-object v2, v0, Lb0/i0;->x:Lh0/w1;

    .line 421
    .line 422
    iput-object v2, v1, Lh0/u1;->f:Lh0/w1;

    .line 423
    .line 424
    return-object v1

    .line 425
    :goto_a
    :try_start_3
    monitor-exit v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 426
    throw v0

    .line 427
    :catchall_2
    move-exception v0

    .line 428
    :try_start_4
    monitor-exit v5
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 429
    throw v0

    .line 430
    :cond_11
    new-instance v0, Ljava/lang/ClassCastException;

    .line 431
    .line 432
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 433
    .line 434
    .line 435
    throw v0
.end method

.method public final E()I
    .locals 2

    .line 1
    iget-object p0, p0, Lb0/z1;->g:Lh0/o2;

    .line 2
    .line 3
    check-cast p0, Lh0/x0;

    .line 4
    .line 5
    sget-object v0, Lh0/x0;->h:Lh0/g;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {p0, v0, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/lang/Integer;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0
.end method

.method public final F()V
    .locals 6

    .line 1
    iget-object v0, p0, Lb0/i0;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lb0/z1;->g:Lh0/o2;

    .line 5
    .line 6
    check-cast v1, Lh0/x0;

    .line 7
    .line 8
    sget-object v2, Lh0/x0;->e:Lh0/g;

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    invoke-interface {v1, v2, v4}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    const/4 v4, 0x1

    .line 26
    if-ne v2, v4, :cond_0

    .line 27
    .line 28
    new-instance v1, Lb0/m0;

    .line 29
    .line 30
    invoke-direct {v1}, Lb0/l0;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v1, p0, Lb0/i0;->q:Lb0/l0;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    goto/16 :goto_4

    .line 38
    .line 39
    :cond_0
    new-instance v2, Lb0/p0;

    .line 40
    .line 41
    invoke-static {}, Llp/hb;->b()Lj0/e;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    sget-object v5, Ll0/l;->i1:Lh0/g;

    .line 46
    .line 47
    invoke-interface {v1, v5, v4}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Ljava/util/concurrent/Executor;

    .line 52
    .line 53
    invoke-direct {v2, v1}, Lb0/p0;-><init>(Ljava/util/concurrent/Executor;)V

    .line 54
    .line 55
    .line 56
    iput-object v2, p0, Lb0/i0;->q:Lb0/l0;

    .line 57
    .line 58
    :goto_0
    iget-object v1, p0, Lb0/i0;->q:Lb0/l0;

    .line 59
    .line 60
    invoke-virtual {p0}, Lb0/i0;->E()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    iput v2, v1, Lb0/l0;->g:I

    .line 65
    .line 66
    iget-object v1, p0, Lb0/i0;->q:Lb0/l0;

    .line 67
    .line 68
    iget-object v2, p0, Lb0/z1;->g:Lh0/o2;

    .line 69
    .line 70
    check-cast v2, Lh0/x0;

    .line 71
    .line 72
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 73
    .line 74
    sget-object v5, Lh0/x0;->j:Lh0/g;

    .line 75
    .line 76
    invoke-interface {v2, v5, v4}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    check-cast v2, Ljava/lang/Boolean;

    .line 81
    .line 82
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    iput-boolean v2, v1, Lb0/l0;->h:Z

    .line 87
    .line 88
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    iget-object v2, p0, Lb0/z1;->g:Lh0/o2;

    .line 93
    .line 94
    check-cast v2, Lh0/x0;

    .line 95
    .line 96
    sget-object v4, Lh0/x0;->i:Lh0/g;

    .line 97
    .line 98
    const/4 v5, 0x0

    .line 99
    invoke-interface {v2, v4, v5}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    check-cast v2, Ljava/lang/Boolean;

    .line 104
    .line 105
    if-eqz v1, :cond_1

    .line 106
    .line 107
    invoke-interface {v1}, Lh0/b0;->l()Lh0/z;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    invoke-interface {v4}, Lh0/z;->j()Ld01/x;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    const-class v5, Landroidx/camera/core/internal/compat/quirk/OnePixelShiftQuirk;

    .line 116
    .line 117
    invoke-virtual {v4, v5}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 118
    .line 119
    .line 120
    move-result v4

    .line 121
    goto :goto_1

    .line 122
    :cond_1
    move v4, v3

    .line 123
    :goto_1
    iget-object v5, p0, Lb0/i0;->q:Lb0/l0;

    .line 124
    .line 125
    if-nez v2, :cond_2

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 129
    .line 130
    .line 131
    move-result v4

    .line 132
    :goto_2
    iput-boolean v4, v5, Lb0/l0;->i:Z

    .line 133
    .line 134
    if-eqz v1, :cond_3

    .line 135
    .line 136
    iget-object v2, p0, Lb0/i0;->q:Lb0/l0;

    .line 137
    .line 138
    invoke-virtual {p0, v1, v3}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    iput v1, v2, Lb0/l0;->e:I

    .line 143
    .line 144
    :cond_3
    iget-object v1, p0, Lb0/i0;->t:Landroid/graphics/Rect;

    .line 145
    .line 146
    if-eqz v1, :cond_4

    .line 147
    .line 148
    iget-object v2, p0, Lb0/i0;->q:Lb0/l0;

    .line 149
    .line 150
    invoke-virtual {v2, v1}, Lb0/l0;->j(Landroid/graphics/Rect;)V

    .line 151
    .line 152
    .line 153
    :cond_4
    iget-object v1, p0, Lb0/i0;->u:Landroid/graphics/Matrix;

    .line 154
    .line 155
    if-eqz v1, :cond_5

    .line 156
    .line 157
    iget-object v2, p0, Lb0/i0;->q:Lb0/l0;

    .line 158
    .line 159
    invoke-virtual {v2, v1}, Lb0/l0;->i(Landroid/graphics/Matrix;)V

    .line 160
    .line 161
    .line 162
    :cond_5
    iget-object v1, p0, Lb0/i0;->r:Ljava/util/concurrent/Executor;

    .line 163
    .line 164
    if-eqz v1, :cond_6

    .line 165
    .line 166
    iget-object v2, p0, Lb0/i0;->s:Lb0/d0;

    .line 167
    .line 168
    if-eqz v2, :cond_6

    .line 169
    .line 170
    iget-object p0, p0, Lb0/i0;->q:Lb0/l0;

    .line 171
    .line 172
    iget-object v3, p0, Lb0/l0;->w:Ljava/lang/Object;

    .line 173
    .line 174
    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 175
    :try_start_1
    iput-object v2, p0, Lb0/l0;->d:Lb0/d0;

    .line 176
    .line 177
    iput-object v1, p0, Lb0/l0;->j:Ljava/util/concurrent/Executor;

    .line 178
    .line 179
    monitor-exit v3

    .line 180
    goto :goto_3

    .line 181
    :catchall_1
    move-exception p0

    .line 182
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 183
    :try_start_2
    throw p0

    .line 184
    :cond_6
    :goto_3
    monitor-exit v0

    .line 185
    return-void

    .line 186
    :goto_4
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 187
    throw p0
.end method

.method public final G(Ljava/util/concurrent/Executor;Lb0/d0;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lb0/i0;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lb0/i0;->q:Lb0/l0;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    new-instance v2, La8/t;

    .line 9
    .line 10
    const/16 v3, 0x8

    .line 11
    .line 12
    invoke-direct {v2, p2, v3}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    iget-object v3, v1, Lb0/l0;->w:Ljava/lang/Object;

    .line 16
    .line 17
    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 18
    :try_start_1
    iput-object v2, v1, Lb0/l0;->d:Lb0/d0;

    .line 19
    .line 20
    iput-object p1, v1, Lb0/l0;->j:Ljava/util/concurrent/Executor;

    .line 21
    .line 22
    monitor-exit v3

    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    :try_start_2
    throw p0

    .line 27
    :catchall_1
    move-exception p0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    :goto_0
    iget-object v1, p0, Lb0/i0;->s:Lb0/d0;

    .line 30
    .line 31
    if-nez v1, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0}, Lb0/z1;->o()V

    .line 34
    .line 35
    .line 36
    :cond_1
    iput-object p1, p0, Lb0/i0;->r:Ljava/util/concurrent/Executor;

    .line 37
    .line 38
    iput-object p2, p0, Lb0/i0;->s:Lb0/d0;

    .line 39
    .line 40
    monitor-exit v0

    .line 41
    return-void

    .line 42
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 43
    throw p0
.end method

.method public final f(ZLh0/r2;)Lh0/o2;
    .locals 3

    .line 1
    sget-object v0, Lb0/i0;->y:Lb0/g0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v0, Lb0/g0;->a:Lh0/x0;

    .line 7
    .line 8
    invoke-interface {v0}, Lh0/o2;->J()Lh0/q2;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-interface {p2, v1, v2}, Lh0/r2;->a(Lh0/q2;I)Lh0/q0;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-static {p2, v0}, Lh0/q0;->w(Lh0/q0;Lh0/q0;)Lh0/n1;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    :cond_0
    if-nez p2, :cond_1

    .line 24
    .line 25
    const/4 p0, 0x0

    .line 26
    return-object p0

    .line 27
    :cond_1
    invoke-virtual {p0, p2}, Lb0/i0;->l(Lh0/q0;)Lh0/n2;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lb0/f0;

    .line 32
    .line 33
    new-instance p1, Lh0/x0;

    .line 34
    .line 35
    iget-object p0, p0, Lb0/f0;->b:Lh0/j1;

    .line 36
    .line 37
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-direct {p1, p0}, Lh0/x0;-><init>(Lh0/n1;)V

    .line 42
    .line 43
    .line 44
    return-object p1
.end method

.method public final l(Lh0/q0;)Lh0/n2;
    .locals 1

    .line 1
    new-instance p0, Lb0/f0;

    .line 2
    .line 3
    invoke-static {p1}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-direct {p0, p1, v0}, Lb0/f0;-><init>(Lh0/j1;I)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public final t(Lh0/z;Lh0/n2;)Lh0/o2;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/i0;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    invoke-interface {p2}, Lh0/n2;->b()Lh0/o2;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :catchall_0
    move-exception p1

    .line 11
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 12
    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lb0/z1;->g()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "ImageAnalysis:"

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final w(Lh0/q0;)Lh0/k;
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/i0;->v:Lh0/v1;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lh0/v1;->a(Lh0/q0;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb0/i0;->v:Lh0/v1;

    .line 7
    .line 8
    invoke-virtual {v0}, Lh0/v1;->c()Lh0/z1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    aget-object v0, v0, v2

    .line 24
    .line 25
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0}, Lb0/z1;->C(Ljava/util/List;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lb0/z1;->h:Lh0/k;

    .line 39
    .line 40
    invoke-virtual {p0}, Lh0/k;->b()Lss/b;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    iput-object p1, p0, Lss/b;->j:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-virtual {p0}, Lss/b;->c()Lh0/k;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method

.method public final x(Lh0/k;Lh0/k;)Lh0/k;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onSuggestedStreamSpecUpdated: primaryStreamSpec = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, ", secondaryStreamSpec "

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    const-string v0, "ImageAnalysis"

    .line 24
    .line 25
    invoke-static {v0, p2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object p2, p0, Lb0/z1;->g:Lh0/o2;

    .line 29
    .line 30
    check-cast p2, Lh0/x0;

    .line 31
    .line 32
    invoke-virtual {p0}, Lb0/z1;->e()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p2, p1}, Lb0/i0;->D(Lh0/x0;Lh0/k;)Lh0/v1;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    iput-object p2, p0, Lb0/i0;->v:Lh0/v1;

    .line 40
    .line 41
    invoke-virtual {p2}, Lh0/v1;->c()Lh0/z1;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    new-instance v0, Ljava/util/ArrayList;

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 53
    .line 54
    .line 55
    const/4 v1, 0x0

    .line 56
    aget-object p2, p2, v1

    .line 57
    .line 58
    invoke-static {p2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    invoke-virtual {p0, p2}, Lb0/z1;->C(Ljava/util/List;)V

    .line 69
    .line 70
    .line 71
    return-object p1
.end method

.method public final y()V
    .locals 4

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lb0/i0;->x:Lh0/w1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Lb0/i0;->x:Lh0/w1;

    .line 13
    .line 14
    :cond_0
    iget-object v0, p0, Lb0/i0;->w:Lb0/u1;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0}, Lh0/t0;->a()V

    .line 19
    .line 20
    .line 21
    iput-object v1, p0, Lb0/i0;->w:Lb0/u1;

    .line 22
    .line 23
    :cond_1
    iget-object v0, p0, Lb0/i0;->p:Ljava/lang/Object;

    .line 24
    .line 25
    monitor-enter v0

    .line 26
    :try_start_0
    iget-object v2, p0, Lb0/i0;->q:Lb0/l0;

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    iput-boolean v3, v2, Lb0/l0;->x:Z

    .line 30
    .line 31
    invoke-virtual {v2}, Lb0/l0;->d()V

    .line 32
    .line 33
    .line 34
    iput-object v1, p0, Lb0/i0;->q:Lb0/l0;

    .line 35
    .line 36
    monitor-exit v0

    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    throw p0
.end method

.method public final z(Landroid/graphics/Matrix;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Lb0/z1;->z(Landroid/graphics/Matrix;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lb0/i0;->p:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object v1, p0, Lb0/i0;->q:Lb0/l0;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1, p1}, Lb0/l0;->i(Landroid/graphics/Matrix;)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    :goto_0
    iput-object p1, p0, Lb0/i0;->u:Landroid/graphics/Matrix;

    .line 18
    .line 19
    monitor-exit v0

    .line 20
    return-void

    .line 21
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method
