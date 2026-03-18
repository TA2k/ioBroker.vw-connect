.class public final Lu/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/b0;


# instance fields
.field public A:Z

.field public B:Z

.field public C:Z

.field public D:Lu/x0;

.field public final E:Lu/x0;

.field public final F:Lin/z1;

.field public final G:Ljava/util/HashSet;

.field public H:Lh0/t;

.field public final I:Ljava/lang/Object;

.field public J:Z

.field public final K:Lu/q0;

.field public final L:Lpv/g;

.field public final M:Lu/c1;

.field public final N:Lb81/b;

.field public volatile O:I

.field public final d:Lb81/c;

.field public final e:Lv/d;

.field public final f:Lj0/h;

.field public final g:Lj0/c;

.field public final h:Lgw0/c;

.field public final i:Lb81/c;

.field public final j:Lu/m;

.field public final k:Lu/x;

.field public final l:Lu/z;

.field public m:Landroid/hardware/camera2/CameraDevice;

.field public n:I

.field public o:Lu/p0;

.field public final p:Ljava/util/concurrent/atomic/AtomicInteger;

.field public q:Lcom/google/common/util/concurrent/ListenableFuture;

.field public r:Ly4/h;

.field public final s:Ljava/util/LinkedHashMap;

.field public t:I

.field public final u:Lu/u;

.field public final v:Lz/a;

.field public final w:Lh0/k0;

.field public final x:Lb0/w;

.field public final y:Z

.field public final z:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Lv/d;Ljava/lang/String;Lu/z;Lz/a;Lh0/k0;Ljava/util/concurrent/Executor;Landroid/os/Handler;Lu/q0;JLb0/w;)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v6, p2

    .line 4
    .line 5
    move-object/from16 v7, p3

    .line 6
    .line 7
    move-object/from16 v8, p4

    .line 8
    .line 9
    move-object/from16 v9, p6

    .line 10
    .line 11
    move-object/from16 v10, p8

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x3

    .line 17
    iput v0, v1, Lu/y;->O:I

    .line 18
    .line 19
    new-instance v11, Lgw0/c;

    .line 20
    .line 21
    const/16 v0, 0x15

    .line 22
    .line 23
    invoke-direct {v11, v0}, Lgw0/c;-><init>(I)V

    .line 24
    .line 25
    .line 26
    iput-object v11, v1, Lu/y;->h:Lgw0/c;

    .line 27
    .line 28
    const/4 v12, 0x0

    .line 29
    iput v12, v1, Lu/y;->n:I

    .line 30
    .line 31
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 32
    .line 33
    invoke-direct {v0, v12}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 34
    .line 35
    .line 36
    iput-object v0, v1, Lu/y;->p:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 37
    .line 38
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 39
    .line 40
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 41
    .line 42
    .line 43
    iput-object v0, v1, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 44
    .line 45
    iput v12, v1, Lu/y;->t:I

    .line 46
    .line 47
    iput-boolean v12, v1, Lu/y;->A:Z

    .line 48
    .line 49
    iput-boolean v12, v1, Lu/y;->B:Z

    .line 50
    .line 51
    const/4 v13, 0x1

    .line 52
    iput-boolean v13, v1, Lu/y;->C:Z

    .line 53
    .line 54
    new-instance v0, Ljava/util/HashSet;

    .line 55
    .line 56
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 57
    .line 58
    .line 59
    iput-object v0, v1, Lu/y;->G:Ljava/util/HashSet;

    .line 60
    .line 61
    sget-object v0, Lh0/w;->a:Lh0/v;

    .line 62
    .line 63
    iput-object v0, v1, Lu/y;->H:Lh0/t;

    .line 64
    .line 65
    new-instance v0, Ljava/lang/Object;

    .line 66
    .line 67
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 68
    .line 69
    .line 70
    iput-object v0, v1, Lu/y;->I:Ljava/lang/Object;

    .line 71
    .line 72
    iput-boolean v12, v1, Lu/y;->J:Z

    .line 73
    .line 74
    new-instance v0, Lb81/b;

    .line 75
    .line 76
    invoke-direct {v0, v1}, Lb81/b;-><init>(Lu/y;)V

    .line 77
    .line 78
    .line 79
    iput-object v0, v1, Lu/y;->N:Lb81/b;

    .line 80
    .line 81
    iput-object v6, v1, Lu/y;->e:Lv/d;

    .line 82
    .line 83
    move-object/from16 v0, p5

    .line 84
    .line 85
    iput-object v0, v1, Lu/y;->v:Lz/a;

    .line 86
    .line 87
    iput-object v9, v1, Lu/y;->w:Lh0/k0;

    .line 88
    .line 89
    new-instance v3, Lj0/c;

    .line 90
    .line 91
    invoke-direct {v3, v10}, Lj0/c;-><init>(Landroid/os/Handler;)V

    .line 92
    .line 93
    .line 94
    iput-object v3, v1, Lu/y;->g:Lj0/c;

    .line 95
    .line 96
    new-instance v2, Lj0/h;

    .line 97
    .line 98
    move-object/from16 v0, p7

    .line 99
    .line 100
    invoke-direct {v2, v0}, Lj0/h;-><init>(Ljava/util/concurrent/Executor;)V

    .line 101
    .line 102
    .line 103
    iput-object v2, v1, Lu/y;->f:Lj0/h;

    .line 104
    .line 105
    new-instance v0, Lu/x;

    .line 106
    .line 107
    move-wide/from16 v4, p10

    .line 108
    .line 109
    invoke-direct/range {v0 .. v5}, Lu/x;-><init>(Lu/y;Lj0/h;Lj0/c;J)V

    .line 110
    .line 111
    .line 112
    move-object v14, v1

    .line 113
    iput-object v0, v14, Lu/y;->k:Lu/x;

    .line 114
    .line 115
    new-instance v0, Lb81/c;

    .line 116
    .line 117
    invoke-direct {v0, v7}, Lb81/c;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    iput-object v0, v14, Lu/y;->d:Lb81/c;

    .line 121
    .line 122
    sget-object v0, Lh0/a0;->g:Lh0/a0;

    .line 123
    .line 124
    iget-object v1, v11, Lgw0/c;->e:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v1, Landroidx/lifecycle/i0;

    .line 127
    .line 128
    new-instance v4, Lh0/h1;

    .line 129
    .line 130
    invoke-direct {v4, v0}, Lh0/h1;-><init>(Lh0/a0;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v1, v4}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    new-instance v11, Lb81/c;

    .line 137
    .line 138
    invoke-direct {v11, v9}, Lb81/c;-><init>(Lh0/k0;)V

    .line 139
    .line 140
    .line 141
    iput-object v11, v14, Lu/y;->i:Lb81/c;

    .line 142
    .line 143
    new-instance v15, Lu/x0;

    .line 144
    .line 145
    invoke-direct {v15}, Ljava/lang/Object;-><init>()V

    .line 146
    .line 147
    .line 148
    new-instance v0, Ljava/lang/Object;

    .line 149
    .line 150
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 151
    .line 152
    .line 153
    iput-object v0, v15, Lu/x0;->b:Ljava/lang/Object;

    .line 154
    .line 155
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 156
    .line 157
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 158
    .line 159
    .line 160
    iput-object v0, v15, Lu/x0;->c:Ljava/lang/Object;

    .line 161
    .line 162
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 163
    .line 164
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 165
    .line 166
    .line 167
    iput-object v0, v15, Lu/x0;->d:Ljava/lang/Object;

    .line 168
    .line 169
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 170
    .line 171
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 172
    .line 173
    .line 174
    iput-object v0, v15, Lu/x0;->e:Ljava/lang/Object;

    .line 175
    .line 176
    new-instance v0, Lu/j0;

    .line 177
    .line 178
    invoke-direct {v0, v15}, Lu/j0;-><init>(Lu/x0;)V

    .line 179
    .line 180
    .line 181
    iput-object v0, v15, Lu/x0;->f:Ljava/lang/Object;

    .line 182
    .line 183
    iput-object v2, v15, Lu/x0;->a:Ljava/lang/Object;

    .line 184
    .line 185
    iput-object v15, v14, Lu/y;->E:Lu/x0;

    .line 186
    .line 187
    move-object/from16 v0, p9

    .line 188
    .line 189
    iput-object v0, v14, Lu/y;->K:Lu/q0;

    .line 190
    .line 191
    move-object/from16 v0, p12

    .line 192
    .line 193
    iput-object v0, v14, Lu/y;->x:Lb0/w;

    .line 194
    .line 195
    :try_start_0
    invoke-virtual/range {p2 .. p3}, Lv/d;->a(Ljava/lang/String;)Lv/b;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    new-instance v0, Lu/m;

    .line 200
    .line 201
    new-instance v4, Lro/f;

    .line 202
    .line 203
    const/4 v5, 0x2

    .line 204
    invoke-direct {v4, v14, v5}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 205
    .line 206
    .line 207
    iget-object v5, v8, Lu/z;->h:Ld01/x;

    .line 208
    .line 209
    move-object/from16 v16, v3

    .line 210
    .line 211
    move-object v3, v2

    .line 212
    move-object/from16 v2, v16

    .line 213
    .line 214
    invoke-direct/range {v0 .. v5}, Lu/m;-><init>(Lv/b;Lj0/c;Lj0/h;Lro/f;Ld01/x;)V

    .line 215
    .line 216
    .line 217
    move-object/from16 v16, v3

    .line 218
    .line 219
    move-object v3, v2

    .line 220
    move-object/from16 v2, v16

    .line 221
    .line 222
    iput-object v0, v14, Lu/y;->j:Lu/m;

    .line 223
    .line 224
    iput-object v8, v14, Lu/y;->l:Lu/z;

    .line 225
    .line 226
    invoke-virtual {v8, v0}, Lu/z;->a(Lu/m;)V

    .line 227
    .line 228
    .line 229
    iget-object v0, v11, Lb81/c;->f:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast v0, Landroidx/lifecycle/i0;

    .line 232
    .line 233
    iget-object v4, v8, Lu/z;->f:Li0/e;

    .line 234
    .line 235
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 236
    .line 237
    .line 238
    const-string v5, "liveDataSource"

    .line 239
    .line 240
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    iget-object v5, v4, Li0/e;->o:Landroidx/lifecycle/g0;

    .line 244
    .line 245
    if-eqz v5, :cond_0

    .line 246
    .line 247
    iget-object v11, v4, Li0/e;->l:Lo/f;

    .line 248
    .line 249
    invoke-virtual {v11, v5}, Lo/f;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v5

    .line 253
    check-cast v5, Landroidx/lifecycle/h0;

    .line 254
    .line 255
    if-eqz v5, :cond_0

    .line 256
    .line 257
    invoke-virtual {v5}, Landroidx/lifecycle/h0;->b()V

    .line 258
    .line 259
    .line 260
    :cond_0
    iput-object v0, v4, Li0/e;->o:Landroidx/lifecycle/g0;

    .line 261
    .line 262
    new-instance v5, Lh0/h0;

    .line 263
    .line 264
    const/16 v11, 0x8

    .line 265
    .line 266
    invoke-direct {v5, v11, v4, v0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    invoke-static {v5}, Llp/k1;->d(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Lv/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 270
    .line 271
    .line 272
    invoke-static {v1}, Lpv/g;->d(Lv/b;)Lpv/g;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    iput-object v0, v14, Lu/y;->L:Lpv/g;

    .line 277
    .line 278
    invoke-virtual {v14}, Lu/y;->C()Lu/p0;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    iput-object v0, v14, Lu/y;->o:Lu/p0;

    .line 283
    .line 284
    new-instance v0, Lin/z1;

    .line 285
    .line 286
    iget-object v1, v8, Lu/z;->h:Ld01/x;

    .line 287
    .line 288
    sget-object v4, Lx/a;->a:Ld01/x;

    .line 289
    .line 290
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 291
    .line 292
    .line 293
    iput-object v2, v0, Lin/z1;->a:Ljava/lang/Object;

    .line 294
    .line 295
    iput-object v3, v0, Lin/z1;->b:Ljava/lang/Object;

    .line 296
    .line 297
    iput-object v10, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 298
    .line 299
    iput-object v15, v0, Lin/z1;->d:Ljava/lang/Object;

    .line 300
    .line 301
    iput-object v1, v0, Lin/z1;->e:Ljava/lang/Object;

    .line 302
    .line 303
    iput-object v4, v0, Lin/z1;->f:Ljava/lang/Object;

    .line 304
    .line 305
    iput-object v0, v14, Lu/y;->F:Lin/z1;

    .line 306
    .line 307
    iget-object v0, v8, Lu/z;->h:Ld01/x;

    .line 308
    .line 309
    const-class v1, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraOutputConfigNullPointerQuirk;

    .line 310
    .line 311
    invoke-virtual {v0, v1}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 312
    .line 313
    .line 314
    move-result v1

    .line 315
    if-nez v1, :cond_1

    .line 316
    .line 317
    const-class v1, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionStuckWhenCreatingBeforeClosingCameraQuirk;

    .line 318
    .line 319
    invoke-virtual {v0, v1}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 320
    .line 321
    .line 322
    move-result v0

    .line 323
    if-eqz v0, :cond_2

    .line 324
    .line 325
    :cond_1
    move v12, v13

    .line 326
    :cond_2
    iput-boolean v12, v14, Lu/y;->y:Z

    .line 327
    .line 328
    iget-object v0, v8, Lu/z;->h:Ld01/x;

    .line 329
    .line 330
    const-class v1, Landroidx/camera/camera2/internal/compat/quirk/LegacyCameraSurfaceCleanupQuirk;

    .line 331
    .line 332
    invoke-virtual {v0, v1}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 333
    .line 334
    .line 335
    move-result v0

    .line 336
    iput-boolean v0, v14, Lu/y;->z:Z

    .line 337
    .line 338
    new-instance v0, Lu/u;

    .line 339
    .line 340
    invoke-direct {v0, v14, v7}, Lu/u;-><init>(Lu/y;Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    iput-object v0, v14, Lu/y;->u:Lu/u;

    .line 344
    .line 345
    new-instance v1, Lt1/j0;

    .line 346
    .line 347
    const/4 v3, 0x3

    .line 348
    invoke-direct {v1, v14, v3}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 349
    .line 350
    .line 351
    const-string v3, "Camera is already registered: "

    .line 352
    .line 353
    iget-object v4, v9, Lh0/k0;->b:Ljava/lang/Object;

    .line 354
    .line 355
    monitor-enter v4

    .line 356
    :try_start_1
    iget-object v5, v9, Lh0/k0;->e:Ljava/util/HashMap;

    .line 357
    .line 358
    invoke-virtual {v5, v14}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 359
    .line 360
    .line 361
    move-result v5

    .line 362
    xor-int/2addr v5, v13

    .line 363
    new-instance v8, Ljava/lang/StringBuilder;

    .line 364
    .line 365
    invoke-direct {v8, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {v8, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 369
    .line 370
    .line 371
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object v3

    .line 375
    invoke-static {v3, v5}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 376
    .line 377
    .line 378
    iget-object v3, v9, Lh0/k0;->e:Ljava/util/HashMap;

    .line 379
    .line 380
    new-instance v5, Lh0/j0;

    .line 381
    .line 382
    invoke-direct {v5, v2, v1, v0}, Lh0/j0;-><init>(Lj0/h;Lt1/j0;Lu/u;)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v3, v14, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 389
    iget-object v1, v6, Lv/d;->a:Lv/e;

    .line 390
    .line 391
    iget-object v1, v1, Lh/w;->b:Ljava/lang/Object;

    .line 392
    .line 393
    check-cast v1, Landroid/hardware/camera2/CameraManager;

    .line 394
    .line 395
    invoke-virtual {v1, v2, v0}, Landroid/hardware/camera2/CameraManager;->registerAvailabilityCallback(Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraManager$AvailabilityCallback;)V

    .line 396
    .line 397
    .line 398
    new-instance v0, Lu/c1;

    .line 399
    .line 400
    new-instance v1, Lgv/a;

    .line 401
    .line 402
    const/16 v2, 0xe

    .line 403
    .line 404
    invoke-direct {v1, v2}, Lgv/a;-><init>(I)V

    .line 405
    .line 406
    .line 407
    sget-object v2, Ld0/b;->u0:Lfv/b;

    .line 408
    .line 409
    move-object/from16 p5, p1

    .line 410
    .line 411
    move-object/from16 p4, v0

    .line 412
    .line 413
    move-object/from16 p8, v1

    .line 414
    .line 415
    move-object/from16 p9, v2

    .line 416
    .line 417
    move-object/from16 p7, v6

    .line 418
    .line 419
    move-object/from16 p6, v7

    .line 420
    .line 421
    invoke-direct/range {p4 .. p9}, Lu/c1;-><init>(Landroid/content/Context;Ljava/lang/String;Lv/d;Lu/e;Ld0/b;)V

    .line 422
    .line 423
    .line 424
    iput-object v0, v14, Lu/y;->M:Lu/c1;

    .line 425
    .line 426
    return-void

    .line 427
    :catchall_0
    move-exception v0

    .line 428
    :try_start_2
    monitor-exit v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 429
    throw v0

    .line 430
    :catch_0
    move-exception v0

    .line 431
    new-instance v1, Lb0/s;

    .line 432
    .line 433
    invoke-direct {v1, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 434
    .line 435
    .line 436
    throw v1
.end method

.method public static A(Lb0/z1;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lb0/z1;->g()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public static y(I)Ljava/lang/String;
    .locals 1

    .line 1
    if-eqz p0, :cond_5

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p0, v0, :cond_4

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    if-eq p0, v0, :cond_3

    .line 8
    .line 9
    const/4 v0, 0x3

    .line 10
    if-eq p0, v0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x5

    .line 16
    if-eq p0, v0, :cond_0

    .line 17
    .line 18
    const-string p0, "UNKNOWN ERROR"

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    const-string p0, "ERROR_CAMERA_SERVICE"

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_1
    const-string p0, "ERROR_CAMERA_DEVICE"

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_2
    const-string p0, "ERROR_CAMERA_DISABLED"

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_3
    const-string p0, "ERROR_MAX_CAMERAS_IN_USE"

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_4
    const-string p0, "ERROR_CAMERA_IN_USE"

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_5
    const-string p0, "ERROR_NONE"

    .line 37
    .line 38
    return-object p0
.end method

.method public static z(Lu/x0;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MeteringRepeating"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method


# virtual methods
.method public final B(Lu/x0;)Z
    .locals 28

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    new-instance v4, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    iget-object v2, v1, Lu/y;->I:Ljava/lang/Object;

    .line 14
    .line 15
    monitor-enter v2

    .line 16
    :try_start_0
    iget-object v3, v1, Lu/y;->v:Lz/a;

    .line 17
    .line 18
    invoke-virtual {v3}, Lz/a;->b()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const/4 v5, 0x2

    .line 23
    const/4 v10, 0x0

    .line 24
    if-ne v3, v5, :cond_0

    .line 25
    .line 26
    monitor-exit v2

    .line 27
    const/4 v14, 0x1

    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    goto/16 :goto_6

    .line 31
    .line 32
    :cond_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    move v14, v10

    .line 34
    :goto_0
    iget-object v2, v1, Lu/y;->d:Lb81/c;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    new-instance v3, Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 42
    .line 43
    .line 44
    iget-object v2, v2, Lb81/c;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v2, Ljava/util/LinkedHashMap;

    .line 47
    .line 48
    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    :cond_1
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_2

    .line 61
    .line 62
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Ljava/util/Map$Entry;

    .line 67
    .line 68
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    check-cast v6, Lh0/l2;

    .line 73
    .line 74
    iget-boolean v6, v6, Lh0/l2;->e:Z

    .line 75
    .line 76
    if-eqz v6, :cond_1

    .line 77
    .line 78
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    check-cast v5, Lh0/l2;

    .line 83
    .line 84
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_2
    invoke-static {v3}, Ljava/util/Collections;->unmodifiableCollection(Ljava/util/Collection;)Ljava/util/Collection;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    :cond_3
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    if-eqz v3, :cond_7

    .line 101
    .line 102
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    check-cast v3, Lh0/l2;

    .line 107
    .line 108
    iget-object v5, v3, Lh0/l2;->d:Ljava/util/List;

    .line 109
    .line 110
    if-eqz v5, :cond_4

    .line 111
    .line 112
    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    sget-object v6, Lh0/q2;->i:Lh0/q2;

    .line 117
    .line 118
    if-ne v5, v6, :cond_4

    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_4
    iget-object v5, v3, Lh0/l2;->c:Lh0/k;

    .line 122
    .line 123
    if-eqz v5, :cond_5

    .line 124
    .line 125
    iget-object v5, v3, Lh0/l2;->d:Ljava/util/List;

    .line 126
    .line 127
    if-nez v5, :cond_6

    .line 128
    .line 129
    :cond_5
    const/16 v16, 0x1

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_6
    iget-object v5, v3, Lh0/l2;->a:Lh0/z1;

    .line 133
    .line 134
    iget-object v6, v3, Lh0/l2;->b:Lh0/o2;

    .line 135
    .line 136
    invoke-virtual {v5}, Lh0/z1;->b()Ljava/util/List;

    .line 137
    .line 138
    .line 139
    move-result-object v5

    .line 140
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result v7

    .line 148
    if-eqz v7, :cond_3

    .line 149
    .line 150
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v7

    .line 154
    check-cast v7, Lh0/t0;

    .line 155
    .line 156
    iget-object v8, v1, Lu/y;->M:Lu/c1;

    .line 157
    .line 158
    invoke-interface {v6}, Lh0/z0;->l()I

    .line 159
    .line 160
    .line 161
    move-result v11

    .line 162
    iget-object v12, v7, Lh0/t0;->h:Landroid/util/Size;

    .line 163
    .line 164
    invoke-interface {v6}, Lh0/o2;->H()Lh0/c2;

    .line 165
    .line 166
    .line 167
    move-result-object v16

    .line 168
    invoke-virtual {v8, v11}, Lu/c1;->l(I)Lh0/l;

    .line 169
    .line 170
    .line 171
    move-result-object v13

    .line 172
    sget-object v15, Lh0/f2;->e:Lh0/f2;

    .line 173
    .line 174
    sget-object v8, Lh0/h2;->e:Lh0/c2;

    .line 175
    .line 176
    invoke-static/range {v11 .. v16}, Lkp/aa;->d(ILandroid/util/Size;Lh0/l;ILh0/f2;Lh0/c2;)Lh0/h2;

    .line 177
    .line 178
    .line 179
    move-result-object v18

    .line 180
    invoke-interface {v6}, Lh0/z0;->l()I

    .line 181
    .line 182
    .line 183
    move-result v19

    .line 184
    iget-object v7, v7, Lh0/t0;->h:Landroid/util/Size;

    .line 185
    .line 186
    iget-object v8, v3, Lh0/l2;->c:Lh0/k;

    .line 187
    .line 188
    iget-object v11, v8, Lh0/k;->c:Lb0/y;

    .line 189
    .line 190
    iget-object v12, v3, Lh0/l2;->d:Ljava/util/List;

    .line 191
    .line 192
    iget-object v13, v8, Lh0/k;->f:Lh0/q0;

    .line 193
    .line 194
    iget v15, v8, Lh0/k;->d:I

    .line 195
    .line 196
    iget-object v8, v8, Lh0/k;->e:Landroid/util/Range;

    .line 197
    .line 198
    const/16 v16, 0x1

    .line 199
    .line 200
    sget-object v9, Lh0/o2;->W0:Lh0/g;

    .line 201
    .line 202
    move/from16 v27, v10

    .line 203
    .line 204
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 205
    .line 206
    invoke-interface {v6, v9, v10}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v9

    .line 210
    check-cast v9, Ljava/lang/Boolean;

    .line 211
    .line 212
    invoke-static {v9}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 216
    .line 217
    .line 218
    move-result v26

    .line 219
    new-instance v17, Lh0/e;

    .line 220
    .line 221
    move-object/from16 v20, v7

    .line 222
    .line 223
    move-object/from16 v25, v8

    .line 224
    .line 225
    move-object/from16 v21, v11

    .line 226
    .line 227
    move-object/from16 v22, v12

    .line 228
    .line 229
    move-object/from16 v23, v13

    .line 230
    .line 231
    move/from16 v24, v15

    .line 232
    .line 233
    invoke-direct/range {v17 .. v26}, Lh0/e;-><init>(Lh0/h2;ILandroid/util/Size;Lb0/y;Ljava/util/List;Lh0/q0;ILandroid/util/Range;Z)V

    .line 234
    .line 235
    .line 236
    move-object/from16 v7, v17

    .line 237
    .line 238
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    move/from16 v10, v27

    .line 242
    .line 243
    goto :goto_3

    .line 244
    :goto_4
    const-string v0, "Camera2CameraImpl"

    .line 245
    .line 246
    new-instance v1, Ljava/lang/StringBuilder;

    .line 247
    .line 248
    const-string v2, "Invalid stream spec or capture types in "

    .line 249
    .line 250
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 257
    .line 258
    .line 259
    move-result-object v1

    .line 260
    invoke-static {v0, v1}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    goto :goto_5

    .line 264
    :cond_7
    move/from16 v27, v10

    .line 265
    .line 266
    const/16 v16, 0x1

    .line 267
    .line 268
    new-instance v5, Ljava/util/HashMap;

    .line 269
    .line 270
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 271
    .line 272
    .line 273
    iget-object v2, v0, Lu/x0;->c:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast v2, Lu/w0;

    .line 276
    .line 277
    iget-object v0, v0, Lu/x0;->d:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v0, Landroid/util/Size;

    .line 280
    .line 281
    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 282
    .line 283
    .line 284
    move-result-object v0

    .line 285
    invoke-virtual {v5, v2, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    :try_start_1
    iget-object v2, v1, Lu/y;->M:Lu/c1;

    .line 289
    .line 290
    const/4 v7, 0x0

    .line 291
    const/4 v8, 0x0

    .line 292
    const/4 v6, 0x0

    .line 293
    move v3, v14

    .line 294
    invoke-virtual/range {v2 .. v8}, Lu/c1;->j(ILjava/util/ArrayList;Ljava/util/HashMap;ZZZ)Lh0/i2;
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0

    .line 295
    .line 296
    .line 297
    const-string v0, "Surface combination with metering repeating supported!"

    .line 298
    .line 299
    const/4 v2, 0x0

    .line 300
    invoke-virtual {v1, v0, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 301
    .line 302
    .line 303
    iget-object v0, v1, Lu/y;->x:Lb0/w;

    .line 304
    .line 305
    if-eqz v0, :cond_8

    .line 306
    .line 307
    iget-object v0, v0, Lb0/w;->d:Lh0/n1;

    .line 308
    .line 309
    sget-object v1, Lb0/w;->p:Lh0/g;

    .line 310
    .line 311
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 312
    .line 313
    invoke-virtual {v0, v1, v2}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    check-cast v0, Ljava/lang/Boolean;

    .line 318
    .line 319
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 320
    .line 321
    .line 322
    move-result v0

    .line 323
    if-nez v0, :cond_8

    .line 324
    .line 325
    goto :goto_5

    .line 326
    :cond_8
    return v27

    .line 327
    :catch_0
    move-exception v0

    .line 328
    const-string v2, "Surface combination with metering repeating  not supported!"

    .line 329
    .line 330
    invoke-virtual {v1, v2, v0}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 331
    .line 332
    .line 333
    :goto_5
    return v16

    .line 334
    :goto_6
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 335
    throw v0
.end method

.method public final C()Lu/p0;
    .locals 4

    .line 1
    iget-object v0, p0, Lu/y;->I:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lu/y;->x:Lb0/w;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    sget-object v2, La0/g;->a:Lh0/g;

    .line 10
    .line 11
    iget-object v1, v1, Lb0/w;->d:Lh0/n1;

    .line 12
    .line 13
    sget-object v2, La0/g;->a:Lh0/g;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-virtual {v1, v2, v3}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    :goto_0
    new-instance v1, Lu/p0;

    .line 23
    .line 24
    iget-object v2, p0, Lu/y;->L:Lpv/g;

    .line 25
    .line 26
    iget-object p0, p0, Lu/y;->l:Lu/z;

    .line 27
    .line 28
    iget-object p0, p0, Lu/z;->h:Ld01/x;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-direct {v1, v2, p0, v3}, Lu/p0;-><init>(Lpv/g;Ld01/x;Z)V

    .line 32
    .line 33
    .line 34
    monitor-exit v0

    .line 35
    return-object v1

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    throw p0
.end method

.method public final D(Z)V
    .locals 7

    .line 1
    const-string v0, "Unable to open camera due to "

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lu/y;->k:Lu/x;

    .line 6
    .line 7
    iget-object p1, p1, Lu/x;->e:Las/e;

    .line 8
    .line 9
    const-wide/16 v1, -0x1

    .line 10
    .line 11
    iput-wide v1, p1, Las/e;->b:J

    .line 12
    .line 13
    :cond_0
    iget-object p1, p0, Lu/y;->k:Lu/x;

    .line 14
    .line 15
    invoke-virtual {p1}, Lu/x;->a()Z

    .line 16
    .line 17
    .line 18
    iget-object p1, p0, Lu/y;->N:Lb81/b;

    .line 19
    .line 20
    invoke-virtual {p1}, Lb81/b;->j()V

    .line 21
    .line 22
    .line 23
    const-string p1, "Opening camera."

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    invoke-virtual {p0, p1, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    const/16 p1, 0x9

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lu/y;->G(I)V

    .line 32
    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    :try_start_0
    iget-object v3, p0, Lu/y;->e:Lv/d;

    .line 36
    .line 37
    iget-object v4, p0, Lu/y;->l:Lu/z;

    .line 38
    .line 39
    iget-object v4, v4, Lu/z;->a:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v5, p0, Lu/y;->f:Lj0/h;

    .line 42
    .line 43
    invoke-virtual {p0}, Lu/y;->v()Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    iget-object v3, v3, Lv/d;->a:Lv/e;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catch Lv/a; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_1

    .line 50
    .line 51
    .line 52
    :try_start_1
    iget-object v3, v3, Lh/w;->b:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v3, Landroid/hardware/camera2/CameraManager;

    .line 55
    .line 56
    invoke-virtual {v3, v4, v5, v6}, Landroid/hardware/camera2/CameraManager;->openCamera(Ljava/lang/String;Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraDevice$StateCallback;)V
    :try_end_1
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Lv/a; {:try_start_1 .. :try_end_1} :catch_3
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :catch_0
    move-exception v3

    .line 61
    :try_start_2
    new-instance v4, Lv/a;

    .line 62
    .line 63
    invoke-direct {v4, v3}, Lv/a;-><init>(Landroid/hardware/camera2/CameraAccessException;)V

    .line 64
    .line 65
    .line 66
    throw v4
    :try_end_2
    .catch Lv/a; {:try_start_2 .. :try_end_2} :catch_3
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_1

    .line 67
    :catch_1
    move-exception p1

    .line 68
    goto :goto_0

    .line 69
    :catch_2
    move-exception p1

    .line 70
    goto :goto_1

    .line 71
    :catch_3
    move-exception v3

    .line 72
    goto :goto_2

    .line 73
    :goto_0
    const-string v0, "Unexpected error occurred when opening camera."

    .line 74
    .line 75
    invoke-virtual {p0, v0, p1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 76
    .line 77
    .line 78
    new-instance p1, Lb0/e;

    .line 79
    .line 80
    const/4 v0, 0x6

    .line 81
    invoke-direct {p1, v0, v1}, Lb0/e;-><init>(ILjava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    const/4 v0, 0x5

    .line 85
    invoke-virtual {p0, v0, p1, v2}, Lu/y;->H(ILb0/e;Z)V

    .line 86
    .line 87
    .line 88
    goto :goto_3

    .line 89
    :goto_1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 90
    .line 91
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-virtual {p0, p1, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 106
    .line 107
    .line 108
    const/16 p1, 0x8

    .line 109
    .line 110
    invoke-virtual {p0, p1}, Lu/y;->G(I)V

    .line 111
    .line 112
    .line 113
    iget-object p0, p0, Lu/y;->k:Lu/x;

    .line 114
    .line 115
    invoke-virtual {p0}, Lu/x;->b()V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :goto_2
    new-instance v4, Ljava/lang/StringBuilder;

    .line 120
    .line 121
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v3}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 136
    .line 137
    .line 138
    iget v0, v3, Lv/a;->d:I

    .line 139
    .line 140
    const/16 v4, 0x2711

    .line 141
    .line 142
    if-eq v0, v4, :cond_2

    .line 143
    .line 144
    iget-object p0, p0, Lu/y;->N:Lb81/b;

    .line 145
    .line 146
    iget-object v0, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v0, Lu/y;

    .line 149
    .line 150
    iget v0, v0, Lu/y;->O:I

    .line 151
    .line 152
    if-eq v0, p1, :cond_1

    .line 153
    .line 154
    iget-object p0, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast p0, Lu/y;

    .line 157
    .line 158
    const-string p1, "Don\'t need the onError timeout handler."

    .line 159
    .line 160
    invoke-virtual {p0, p1, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 161
    .line 162
    .line 163
    goto :goto_3

    .line 164
    :cond_1
    iget-object p1, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p1, Lu/y;

    .line 167
    .line 168
    const-string v0, "Camera waiting for onError."

    .line 169
    .line 170
    invoke-virtual {p1, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0}, Lb81/b;->j()V

    .line 174
    .line 175
    .line 176
    new-instance p1, Lrn/i;

    .line 177
    .line 178
    invoke-direct {p1, p0}, Lrn/i;-><init>(Lb81/b;)V

    .line 179
    .line 180
    .line 181
    iput-object p1, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_2
    new-instance p1, Lb0/e;

    .line 185
    .line 186
    const/4 v0, 0x7

    .line 187
    invoke-direct {p1, v0, v3}, Lb0/e;-><init>(ILjava/lang/Throwable;)V

    .line 188
    .line 189
    .line 190
    const/4 v0, 0x3

    .line 191
    invoke-virtual {p0, v0, p1, v2}, Lu/y;->H(ILb0/e;Z)V

    .line 192
    .line 193
    .line 194
    :goto_3
    return-void
.end method

.method public final E()V
    .locals 13

    .line 1
    iget v0, p0, Lu/y;->O:I

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    move v0, v3

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v2

    .line 12
    :goto_0
    const/4 v1, 0x0

    .line 13
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lu/y;->d:Lb81/c;

    .line 17
    .line 18
    invoke-virtual {v0}, Lb81/c;->n()Lh0/y1;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0}, Lh0/y1;->c()Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    const-string v0, "Unable to create capture session due to conflicting configurations"

    .line 29
    .line 30
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_1
    iget-object v4, p0, Lu/y;->w:Lh0/k0;

    .line 35
    .line 36
    iget-object v5, p0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 37
    .line 38
    invoke-virtual {v5}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    iget-object v6, p0, Lu/y;->v:Lz/a;

    .line 43
    .line 44
    iget-object v7, p0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 45
    .line 46
    invoke-virtual {v7}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    invoke-virtual {v6, v7}, Lz/a;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v6

    .line 54
    invoke-virtual {v4, v5, v6}, Lh0/k0;->e(Ljava/lang/String;Ljava/lang/String;)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-nez v4, :cond_2

    .line 59
    .line 60
    new-instance v0, Ljava/lang/StringBuilder;

    .line 61
    .line 62
    const-string v2, "Unable to create capture session in camera operating mode = "

    .line 63
    .line 64
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iget-object v2, p0, Lu/y;->v:Lz/a;

    .line 68
    .line 69
    invoke-virtual {v2}, Lz/a;->b()I

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_2
    new-instance v1, Ljava/util/HashMap;

    .line 85
    .line 86
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 87
    .line 88
    .line 89
    iget-object v4, p0, Lu/y;->d:Lb81/c;

    .line 90
    .line 91
    invoke-virtual {v4}, Lb81/c;->p()Ljava/util/Collection;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    iget-object v5, p0, Lu/y;->d:Lb81/c;

    .line 96
    .line 97
    invoke-virtual {v5}, Lb81/c;->r()Ljava/util/Collection;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    const-string v6, "getSurfaces(...)"

    .line 102
    .line 103
    const-string v7, "StreamUseCaseUtil"

    .line 104
    .line 105
    sget-object v8, Lu/b1;->a:Lh0/g;

    .line 106
    .line 107
    const-string v9, "sessionConfigs"

    .line 108
    .line 109
    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string v9, "useCaseConfigs"

    .line 113
    .line 114
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    new-instance v9, Ljava/util/ArrayList;

    .line 118
    .line 119
    invoke-direct {v9, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 120
    .line 121
    .line 122
    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object v5

    .line 126
    :cond_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 127
    .line 128
    .line 129
    move-result v10

    .line 130
    if-eqz v10, :cond_7

    .line 131
    .line 132
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v10

    .line 136
    check-cast v10, Lh0/z1;

    .line 137
    .line 138
    iget-object v11, v10, Lh0/z1;->g:Lh0/o0;

    .line 139
    .line 140
    iget-object v11, v11, Lh0/o0;->b:Lh0/n1;

    .line 141
    .line 142
    iget-object v11, v11, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 143
    .line 144
    invoke-virtual {v11, v8}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v11

    .line 148
    if-eqz v11, :cond_4

    .line 149
    .line 150
    invoke-virtual {v10}, Lh0/z1;->b()Ljava/util/List;

    .line 151
    .line 152
    .line 153
    move-result-object v11

    .line 154
    invoke-interface {v11}, Ljava/util/List;->size()I

    .line 155
    .line 156
    .line 157
    move-result v11

    .line 158
    if-eq v11, v3, :cond_4

    .line 159
    .line 160
    const-string v2, "SessionConfig has stream use case but also contains %d surfaces, abort populateSurfaceToStreamUseCaseMapping()."

    .line 161
    .line 162
    invoke-virtual {v10}, Lh0/z1;->b()Ljava/util/List;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 171
    .line 172
    .line 173
    move-result-object v4

    .line 174
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v4

    .line 178
    invoke-static {v4, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v3

    .line 182
    invoke-static {v2, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    invoke-static {v7, v2}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    goto/16 :goto_3

    .line 190
    .line 191
    :cond_4
    iget-object v10, v10, Lh0/z1;->g:Lh0/o0;

    .line 192
    .line 193
    iget-object v10, v10, Lh0/o0;->b:Lh0/n1;

    .line 194
    .line 195
    iget-object v10, v10, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 196
    .line 197
    invoke-virtual {v10, v8}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v10

    .line 201
    if-eqz v10, :cond_3

    .line 202
    .line 203
    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 204
    .line 205
    .line 206
    move-result-object v4

    .line 207
    move v5, v2

    .line 208
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 209
    .line 210
    .line 211
    move-result v10

    .line 212
    if-eqz v10, :cond_7

    .line 213
    .line 214
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v10

    .line 218
    check-cast v10, Lh0/z1;

    .line 219
    .line 220
    invoke-virtual {v9, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v11

    .line 224
    check-cast v11, Lh0/o2;

    .line 225
    .line 226
    invoke-interface {v11}, Lh0/o2;->J()Lh0/q2;

    .line 227
    .line 228
    .line 229
    move-result-object v11

    .line 230
    sget-object v12, Lh0/q2;->i:Lh0/q2;

    .line 231
    .line 232
    if-ne v11, v12, :cond_5

    .line 233
    .line 234
    invoke-virtual {v10}, Lh0/z1;->b()Ljava/util/List;

    .line 235
    .line 236
    .line 237
    move-result-object v11

    .line 238
    invoke-static {v11, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    check-cast v11, Ljava/util/Collection;

    .line 242
    .line 243
    invoke-interface {v11}, Ljava/util/Collection;->isEmpty()Z

    .line 244
    .line 245
    .line 246
    move-result v11

    .line 247
    xor-int/2addr v11, v3

    .line 248
    const-string v12, "MeteringRepeating should contain a surface"

    .line 249
    .line 250
    invoke-static {v12, v11}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v10}, Lh0/z1;->b()Ljava/util/List;

    .line 254
    .line 255
    .line 256
    move-result-object v10

    .line 257
    invoke-interface {v10, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v10

    .line 261
    const-wide/16 v11, 0x1

    .line 262
    .line 263
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 264
    .line 265
    .line 266
    move-result-object v11

    .line 267
    invoke-virtual {v1, v10, v11}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    goto :goto_2

    .line 271
    :cond_5
    iget-object v11, v10, Lh0/z1;->g:Lh0/o0;

    .line 272
    .line 273
    iget-object v11, v11, Lh0/o0;->b:Lh0/n1;

    .line 274
    .line 275
    iget-object v11, v11, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 276
    .line 277
    invoke-virtual {v11, v8}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 278
    .line 279
    .line 280
    move-result v11

    .line 281
    if-eqz v11, :cond_6

    .line 282
    .line 283
    invoke-virtual {v10}, Lh0/z1;->b()Ljava/util/List;

    .line 284
    .line 285
    .line 286
    move-result-object v11

    .line 287
    invoke-static {v11, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    check-cast v11, Ljava/util/Collection;

    .line 291
    .line 292
    invoke-interface {v11}, Ljava/util/Collection;->isEmpty()Z

    .line 293
    .line 294
    .line 295
    move-result v11

    .line 296
    if-nez v11, :cond_6

    .line 297
    .line 298
    invoke-virtual {v10}, Lh0/z1;->b()Ljava/util/List;

    .line 299
    .line 300
    .line 301
    move-result-object v11

    .line 302
    invoke-interface {v11, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v11

    .line 306
    iget-object v10, v10, Lh0/z1;->g:Lh0/o0;

    .line 307
    .line 308
    iget-object v10, v10, Lh0/o0;->b:Lh0/n1;

    .line 309
    .line 310
    invoke-virtual {v10, v8}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v10

    .line 314
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {v1, v11, v10}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    :cond_6
    :goto_2
    add-int/lit8 v5, v5, 0x1

    .line 321
    .line 322
    goto :goto_1

    .line 323
    :cond_7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 324
    .line 325
    const-string v3, "populateSurfaceToStreamUseCaseMapping() - streamUseCaseMap = "

    .line 326
    .line 327
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v2

    .line 337
    invoke-static {v7, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    :goto_3
    iget-object v2, p0, Lu/y;->o:Lu/p0;

    .line 341
    .line 342
    iget-object v3, v2, Lu/p0;->a:Ljava/lang/Object;

    .line 343
    .line 344
    monitor-enter v3

    .line 345
    :try_start_0
    iput-object v1, v2, Lu/p0;->m:Ljava/util/HashMap;

    .line 346
    .line 347
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 348
    iget-object v1, p0, Lu/y;->o:Lu/p0;

    .line 349
    .line 350
    invoke-virtual {v0}, Lh0/y1;->b()Lh0/z1;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    iget-object v2, p0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 355
    .line 356
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 357
    .line 358
    .line 359
    iget-object v3, p0, Lu/y;->F:Lin/z1;

    .line 360
    .line 361
    new-instance v4, Lu/g1;

    .line 362
    .line 363
    iget-object v5, v3, Lin/z1;->e:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast v5, Ld01/x;

    .line 366
    .line 367
    iget-object v6, v3, Lin/z1;->f:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v6, Ld01/x;

    .line 370
    .line 371
    iget-object v7, v3, Lin/z1;->d:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v7, Lu/x0;

    .line 374
    .line 375
    iget-object v8, v3, Lin/z1;->a:Ljava/lang/Object;

    .line 376
    .line 377
    check-cast v8, Lj0/h;

    .line 378
    .line 379
    iget-object v9, v3, Lin/z1;->b:Ljava/lang/Object;

    .line 380
    .line 381
    check-cast v9, Lj0/c;

    .line 382
    .line 383
    iget-object v3, v3, Lin/z1;->c:Ljava/lang/Object;

    .line 384
    .line 385
    move-object v10, v3

    .line 386
    check-cast v10, Landroid/os/Handler;

    .line 387
    .line 388
    invoke-direct/range {v4 .. v10}, Lu/g1;-><init>(Ld01/x;Ld01/x;Lu/x0;Lj0/h;Lj0/c;Landroid/os/Handler;)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v1, v0, v2, v4}, Lu/p0;->m(Lh0/z1;Landroid/hardware/camera2/CameraDevice;Lu/g1;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    new-instance v2, Lb81/a;

    .line 396
    .line 397
    const/16 v3, 0x18

    .line 398
    .line 399
    const/4 v4, 0x0

    .line 400
    invoke-direct {v2, p0, v1, v4, v3}, Lb81/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 401
    .line 402
    .line 403
    iget-object p0, p0, Lu/y;->f:Lj0/h;

    .line 404
    .line 405
    new-instance v1, Lk0/g;

    .line 406
    .line 407
    const/4 v3, 0x0

    .line 408
    invoke-direct {v1, v3, v0, v2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 409
    .line 410
    .line 411
    invoke-interface {v0, p0, v1}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 412
    .line 413
    .line 414
    return-void

    .line 415
    :catchall_0
    move-exception v0

    .line 416
    move-object p0, v0

    .line 417
    :try_start_1
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 418
    throw p0
.end method

.method public final F()V
    .locals 6

    .line 1
    iget-object v0, p0, Lu/y;->o:Lu/p0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    const/4 v2, 0x0

    .line 10
    invoke-static {v2, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 11
    .line 12
    .line 13
    const-string v0, "Resetting Capture Session"

    .line 14
    .line 15
    invoke-virtual {p0, v0, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lu/y;->o:Lu/p0;

    .line 19
    .line 20
    iget-object v3, v0, Lu/p0;->a:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter v3

    .line 23
    :try_start_0
    iget-object v4, v0, Lu/p0;->f:Lh0/z1;

    .line 24
    .line 25
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 26
    iget-object v5, v0, Lu/p0;->a:Ljava/lang/Object;

    .line 27
    .line 28
    monitor-enter v5

    .line 29
    :try_start_1
    iget-object v3, v0, Lu/p0;->b:Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-static {v3}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    monitor-exit v5
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    invoke-virtual {p0}, Lu/y;->C()Lu/p0;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    iput-object v5, p0, Lu/y;->o:Lu/p0;

    .line 41
    .line 42
    invoke-virtual {v5, v4}, Lu/p0;->o(Lh0/z1;)V

    .line 43
    .line 44
    .line 45
    iget-object v4, p0, Lu/y;->o:Lu/p0;

    .line 46
    .line 47
    invoke-virtual {v4, v3}, Lu/p0;->k(Ljava/util/List;)V

    .line 48
    .line 49
    .line 50
    iget v3, p0, Lu/y;->O:I

    .line 51
    .line 52
    invoke-static {v3}, Lu/w;->o(I)I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    const/16 v4, 0x9

    .line 57
    .line 58
    if-eq v3, v4, :cond_1

    .line 59
    .line 60
    new-instance v3, Ljava/lang/StringBuilder;

    .line 61
    .line 62
    const-string v4, "Skipping Capture Session state check due to current camera state: "

    .line 63
    .line 64
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iget v4, p0, Lu/y;->O:I

    .line 68
    .line 69
    invoke-static {v4}, Lu/w;->p(I)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v4, " and previous session status: "

    .line 77
    .line 78
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0}, Lu/p0;->i()Z

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    invoke-virtual {p0, v3, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_1
    iget-boolean v3, p0, Lu/y;->y:Z

    .line 97
    .line 98
    if-eqz v3, :cond_2

    .line 99
    .line 100
    invoke-virtual {v0}, Lu/p0;->i()Z

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    if-eqz v3, :cond_2

    .line 105
    .line 106
    const-string v3, "Close camera before creating new session"

    .line 107
    .line 108
    invoke-virtual {p0, v3, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 109
    .line 110
    .line 111
    const/4 v3, 0x7

    .line 112
    invoke-virtual {p0, v3}, Lu/y;->G(I)V

    .line 113
    .line 114
    .line 115
    :cond_2
    :goto_1
    iget-boolean v3, p0, Lu/y;->z:Z

    .line 116
    .line 117
    if-eqz v3, :cond_3

    .line 118
    .line 119
    invoke-virtual {v0}, Lu/p0;->i()Z

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    if-eqz v3, :cond_3

    .line 124
    .line 125
    const-string v3, "ConfigAndClose is required when close the camera."

    .line 126
    .line 127
    invoke-virtual {p0, v3, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 128
    .line 129
    .line 130
    iput-boolean v1, p0, Lu/y;->A:Z

    .line 131
    .line 132
    :cond_3
    invoke-virtual {v0}, Lu/p0;->b()V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0}, Lu/p0;->n()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    iget v3, p0, Lu/y;->O:I

    .line 140
    .line 141
    invoke-static {v3}, Lu/w;->n(I)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    const-string v4, "Releasing session in state "

    .line 146
    .line 147
    invoke-virtual {v4, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    invoke-virtual {p0, v3, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 152
    .line 153
    .line 154
    iget-object v2, p0, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 155
    .line 156
    invoke-interface {v2, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    new-instance v2, Lvp/y1;

    .line 160
    .line 161
    const/16 v3, 0x17

    .line 162
    .line 163
    invoke-direct {v2, v3, p0, v0}, Lvp/y1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    new-instance v0, Lk0/g;

    .line 171
    .line 172
    const/4 v3, 0x0

    .line 173
    invoke-direct {v0, v3, v1, v2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    invoke-interface {v1, p0, v0}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 177
    .line 178
    .line 179
    return-void

    .line 180
    :catchall_0
    move-exception p0

    .line 181
    :try_start_2
    monitor-exit v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 182
    throw p0

    .line 183
    :catchall_1
    move-exception p0

    .line 184
    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 185
    throw p0
.end method

.method public final G(I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    invoke-virtual {p0, p1, v0, v1}, Lu/y;->H(ILb0/e;Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final H(ILb0/e;Z)V
    .locals 9

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Transitioning camera internal state: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lu/y;->O:I

    .line 9
    .line 10
    invoke-static {v1}, Lu/w;->p(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, " --> "

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, Lu/w;->p(I)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    const-string v0, "]"

    .line 38
    .line 39
    invoke-static {}, Lab/a;->a()Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    const/4 v3, 0x0

    .line 44
    const/4 v4, 0x1

    .line 45
    if-eqz v2, :cond_2

    .line 46
    .line 47
    new-instance v2, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v5, "CX:C2State["

    .line 50
    .line 51
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-static {p1}, Lu/w;->o(I)I

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    invoke-static {v2}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    int-to-long v5, v5

    .line 73
    invoke-static {v2, v5, v6}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 74
    .line 75
    .line 76
    if-eqz p2, :cond_0

    .line 77
    .line 78
    iget v2, p0, Lu/y;->t:I

    .line 79
    .line 80
    add-int/2addr v2, v4

    .line 81
    iput v2, p0, Lu/y;->t:I

    .line 82
    .line 83
    :cond_0
    iget v2, p0, Lu/y;->t:I

    .line 84
    .line 85
    if-lez v2, :cond_2

    .line 86
    .line 87
    new-instance v2, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string v5, "CX:C2StateErrorCode["

    .line 90
    .line 91
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    if-eqz p2, :cond_1

    .line 105
    .line 106
    iget v2, p2, Lb0/e;->a:I

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_1
    move v2, v3

    .line 110
    :goto_0
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    int-to-long v5, v2

    .line 115
    invoke-static {v0, v5, v6}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 116
    .line 117
    .line 118
    :cond_2
    iput p1, p0, Lu/y;->O:I

    .line 119
    .line 120
    invoke-static {p1}, Lu/w;->o(I)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    packed-switch v0, :pswitch_data_0

    .line 125
    .line 126
    .line 127
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 128
    .line 129
    invoke-static {p1}, Lu/w;->p(I)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    const-string p2, "Unknown state: "

    .line 134
    .line 135
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p0

    .line 143
    :pswitch_0
    sget-object p1, Lh0/a0;->l:Lh0/a0;

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :pswitch_1
    sget-object p1, Lh0/a0;->k:Lh0/a0;

    .line 147
    .line 148
    goto :goto_1

    .line 149
    :pswitch_2
    sget-object p1, Lh0/a0;->j:Lh0/a0;

    .line 150
    .line 151
    goto :goto_1

    .line 152
    :pswitch_3
    sget-object p1, Lh0/a0;->i:Lh0/a0;

    .line 153
    .line 154
    goto :goto_1

    .line 155
    :pswitch_4
    sget-object p1, Lh0/a0;->h:Lh0/a0;

    .line 156
    .line 157
    goto :goto_1

    .line 158
    :pswitch_5
    sget-object p1, Lh0/a0;->g:Lh0/a0;

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :pswitch_6
    sget-object p1, Lh0/a0;->f:Lh0/a0;

    .line 162
    .line 163
    goto :goto_1

    .line 164
    :pswitch_7
    sget-object p1, Lh0/a0;->e:Lh0/a0;

    .line 165
    .line 166
    :goto_1
    iget-object v0, p0, Lu/y;->w:Lh0/k0;

    .line 167
    .line 168
    iget-object v2, v0, Lh0/k0;->b:Ljava/lang/Object;

    .line 169
    .line 170
    monitor-enter v2

    .line 171
    :try_start_0
    iget v5, v0, Lh0/k0;->f:I

    .line 172
    .line 173
    sget-object v6, Lh0/a0;->e:Lh0/a0;

    .line 174
    .line 175
    if-ne p1, v6, :cond_4

    .line 176
    .line 177
    iget-object v3, v0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 178
    .line 179
    invoke-virtual {v3, p0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v3

    .line 183
    check-cast v3, Lh0/j0;

    .line 184
    .line 185
    if-eqz v3, :cond_3

    .line 186
    .line 187
    invoke-virtual {v0}, Lh0/k0;->b()V

    .line 188
    .line 189
    .line 190
    iget-object v3, v3, Lh0/j0;->a:Lh0/a0;

    .line 191
    .line 192
    goto :goto_2

    .line 193
    :cond_3
    move-object v3, v1

    .line 194
    goto :goto_2

    .line 195
    :cond_4
    iget-object v6, v0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 196
    .line 197
    invoke-virtual {v6, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v6

    .line 201
    check-cast v6, Lh0/j0;

    .line 202
    .line 203
    const-string v7, "Cannot update state of camera which has not yet been registered. Register with CameraStateRegistry.registerCamera()"

    .line 204
    .line 205
    invoke-static {v6, v7}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    iget-object v7, v6, Lh0/j0;->a:Lh0/a0;

    .line 209
    .line 210
    iput-object p1, v6, Lh0/j0;->a:Lh0/a0;

    .line 211
    .line 212
    sget-object v6, Lh0/a0;->j:Lh0/a0;

    .line 213
    .line 214
    if-ne p1, v6, :cond_7

    .line 215
    .line 216
    iget-boolean v8, p1, Lh0/a0;->d:Z

    .line 217
    .line 218
    if-nez v8, :cond_5

    .line 219
    .line 220
    if-ne v7, v6, :cond_6

    .line 221
    .line 222
    :cond_5
    move v3, v4

    .line 223
    :cond_6
    const-string v6, "Cannot mark camera as opening until camera was successful at calling CameraStateRegistry.tryOpenCamera()"

    .line 224
    .line 225
    invoke-static {v6, v3}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 226
    .line 227
    .line 228
    :cond_7
    if-eq v7, p1, :cond_8

    .line 229
    .line 230
    invoke-static {p0, p1}, Lh0/k0;->c(Lu/y;Lh0/a0;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v0}, Lh0/k0;->b()V

    .line 234
    .line 235
    .line 236
    :cond_8
    move-object v3, v7

    .line 237
    :goto_2
    if-ne v3, p1, :cond_9

    .line 238
    .line 239
    monitor-exit v2

    .line 240
    goto/16 :goto_6

    .line 241
    .line 242
    :catchall_0
    move-exception p0

    .line 243
    goto/16 :goto_7

    .line 244
    .line 245
    :cond_9
    iget-object v3, v0, Lh0/k0;->d:Lz/a;

    .line 246
    .line 247
    invoke-virtual {v3}, Lz/a;->b()I

    .line 248
    .line 249
    .line 250
    move-result v3

    .line 251
    const/4 v6, 0x2

    .line 252
    if-ne v3, v6, :cond_a

    .line 253
    .line 254
    sget-object v3, Lh0/a0;->l:Lh0/a0;

    .line 255
    .line 256
    if-ne p1, v3, :cond_a

    .line 257
    .line 258
    invoke-virtual {p0}, Lu/y;->l()Lh0/z;

    .line 259
    .line 260
    .line 261
    move-result-object v3

    .line 262
    invoke-interface {v3}, Lh0/z;->f()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    iget-object v6, v0, Lh0/k0;->d:Lz/a;

    .line 267
    .line 268
    invoke-virtual {v6, v3}, Lz/a;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v3

    .line 272
    if-eqz v3, :cond_a

    .line 273
    .line 274
    invoke-virtual {v0, v3}, Lh0/k0;->a(Ljava/lang/String;)Lh0/j0;

    .line 275
    .line 276
    .line 277
    move-result-object v3

    .line 278
    goto :goto_3

    .line 279
    :cond_a
    move-object v3, v1

    .line 280
    :goto_3
    if-ge v5, v4, :cond_c

    .line 281
    .line 282
    iget v4, v0, Lh0/k0;->f:I

    .line 283
    .line 284
    if-lez v4, :cond_c

    .line 285
    .line 286
    new-instance v1, Ljava/util/HashMap;

    .line 287
    .line 288
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 289
    .line 290
    .line 291
    iget-object v0, v0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 292
    .line 293
    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 298
    .line 299
    .line 300
    move-result-object v0

    .line 301
    :cond_b
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 302
    .line 303
    .line 304
    move-result v4

    .line 305
    if-eqz v4, :cond_d

    .line 306
    .line 307
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v4

    .line 311
    check-cast v4, Ljava/util/Map$Entry;

    .line 312
    .line 313
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v5

    .line 317
    check-cast v5, Lh0/j0;

    .line 318
    .line 319
    iget-object v5, v5, Lh0/j0;->a:Lh0/a0;

    .line 320
    .line 321
    sget-object v6, Lh0/a0;->h:Lh0/a0;

    .line 322
    .line 323
    if-ne v5, v6, :cond_b

    .line 324
    .line 325
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v5

    .line 329
    check-cast v5, Lb0/k;

    .line 330
    .line 331
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v4

    .line 335
    check-cast v4, Lh0/j0;

    .line 336
    .line 337
    invoke-virtual {v1, v5, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    goto :goto_4

    .line 341
    :cond_c
    sget-object v4, Lh0/a0;->h:Lh0/a0;

    .line 342
    .line 343
    if-ne p1, v4, :cond_d

    .line 344
    .line 345
    iget v4, v0, Lh0/k0;->f:I

    .line 346
    .line 347
    if-lez v4, :cond_d

    .line 348
    .line 349
    new-instance v1, Ljava/util/HashMap;

    .line 350
    .line 351
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 352
    .line 353
    .line 354
    iget-object v0, v0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 355
    .line 356
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    check-cast v0, Lh0/j0;

    .line 361
    .line 362
    invoke-virtual {v1, p0, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    :cond_d
    if-eqz v1, :cond_e

    .line 366
    .line 367
    if-nez p3, :cond_e

    .line 368
    .line 369
    invoke-interface {v1, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    :cond_e
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 373
    if-eqz v1, :cond_f

    .line 374
    .line 375
    invoke-interface {v1}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 376
    .line 377
    .line 378
    move-result-object p3

    .line 379
    invoke-interface {p3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 380
    .line 381
    .line 382
    move-result-object p3

    .line 383
    :goto_5
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 384
    .line 385
    .line 386
    move-result v0

    .line 387
    if-eqz v0, :cond_f

    .line 388
    .line 389
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    check-cast v0, Lh0/j0;

    .line 394
    .line 395
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 396
    .line 397
    .line 398
    :try_start_1
    iget-object v1, v0, Lh0/j0;->b:Lj0/h;

    .line 399
    .line 400
    iget-object v0, v0, Lh0/j0;->d:Lu/u;

    .line 401
    .line 402
    new-instance v2, La0/d;

    .line 403
    .line 404
    const/16 v4, 0x14

    .line 405
    .line 406
    invoke-direct {v2, v0, v4}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 407
    .line 408
    .line 409
    invoke-virtual {v1, v2}, Lj0/h;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_1 .. :try_end_1} :catch_0

    .line 410
    .line 411
    .line 412
    goto :goto_5

    .line 413
    :catch_0
    move-exception v0

    .line 414
    const-string v1, "CameraStateRegistry"

    .line 415
    .line 416
    const-string v2, "Unable to notify camera to open."

    .line 417
    .line 418
    invoke-static {v1, v2, v0}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 419
    .line 420
    .line 421
    goto :goto_5

    .line 422
    :cond_f
    if-eqz v3, :cond_10

    .line 423
    .line 424
    :try_start_2
    iget-object p3, v3, Lh0/j0;->b:Lj0/h;

    .line 425
    .line 426
    iget-object v0, v3, Lh0/j0;->c:Lt1/j0;

    .line 427
    .line 428
    new-instance v1, La0/d;

    .line 429
    .line 430
    const/16 v2, 0x15

    .line 431
    .line 432
    invoke-direct {v1, v0, v2}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {p3, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V
    :try_end_2
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_2 .. :try_end_2} :catch_1

    .line 436
    .line 437
    .line 438
    goto :goto_6

    .line 439
    :catch_1
    move-exception p3

    .line 440
    const-string v0, "CameraStateRegistry"

    .line 441
    .line 442
    const-string v1, "Unable to notify camera to configure."

    .line 443
    .line 444
    invoke-static {v0, v1, p3}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 445
    .line 446
    .line 447
    :cond_10
    :goto_6
    iget-object p3, p0, Lu/y;->h:Lgw0/c;

    .line 448
    .line 449
    iget-object p3, p3, Lgw0/c;->e:Ljava/lang/Object;

    .line 450
    .line 451
    check-cast p3, Landroidx/lifecycle/i0;

    .line 452
    .line 453
    new-instance v0, Lh0/h1;

    .line 454
    .line 455
    invoke-direct {v0, p1}, Lh0/h1;-><init>(Lh0/a0;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {p3, v0}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 459
    .line 460
    .line 461
    iget-object p0, p0, Lu/y;->i:Lb81/c;

    .line 462
    .line 463
    invoke-virtual {p0, p1, p2}, Lb81/c;->x(Lh0/a0;Lb0/e;)V

    .line 464
    .line 465
    .line 466
    return-void

    .line 467
    :goto_7
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 468
    throw p0

    .line 469
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final I(Ljava/util/ArrayList;)Ljava/util/ArrayList;
    .locals 11

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_3

    .line 15
    .line 16
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lb0/z1;

    .line 21
    .line 22
    iget-boolean v2, p0, Lu/y;->C:Z

    .line 23
    .line 24
    invoke-static {v1}, Lu/y;->A(Lb0/z1;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    iget-object v2, v1, Lb0/z1;->n:Lh0/z1;

    .line 35
    .line 36
    :goto_1
    move-object v6, v2

    .line 37
    goto :goto_2

    .line 38
    :cond_0
    iget-object v2, v1, Lb0/z1;->o:Lh0/z1;

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :goto_2
    iget-object v7, v1, Lb0/z1;->g:Lh0/o2;

    .line 42
    .line 43
    iget-object v9, v1, Lb0/z1;->h:Lh0/k;

    .line 44
    .line 45
    const/4 v2, 0x0

    .line 46
    if-eqz v9, :cond_1

    .line 47
    .line 48
    iget-object v3, v9, Lh0/k;->a:Landroid/util/Size;

    .line 49
    .line 50
    move-object v8, v3

    .line 51
    goto :goto_3

    .line 52
    :cond_1
    move-object v8, v2

    .line 53
    :goto_3
    invoke-virtual {v1}, Lb0/z1;->c()Lh0/b0;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    if-nez v3, :cond_2

    .line 58
    .line 59
    :goto_4
    move-object v10, v2

    .line 60
    goto :goto_5

    .line 61
    :cond_2
    invoke-static {v1}, Lt0/e;->H(Lb0/z1;)Ljava/util/ArrayList;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    goto :goto_4

    .line 66
    :goto_5
    new-instance v3, Lu/b;

    .line 67
    .line 68
    invoke-direct/range {v3 .. v10}, Lu/b;-><init>(Ljava/lang/String;Ljava/lang/Class;Lh0/z1;Lh0/o2;Landroid/util/Size;Lh0/k;Ljava/util/ArrayList;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_3
    return-object v0
.end method

.method public final J(Ljava/util/ArrayList;)V
    .locals 14

    .line 1
    iget-object v0, p0, Lu/y;->d:Lb81/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb81/c;->p()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    new-instance v1, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    const/4 v2, 0x0

    .line 21
    move-object v3, v2

    .line 22
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    const/4 v5, 0x1

    .line 27
    if-eqz v4, :cond_2

    .line 28
    .line 29
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    check-cast v4, Lu/b;

    .line 34
    .line 35
    iget-object v6, p0, Lu/y;->d:Lb81/c;

    .line 36
    .line 37
    iget-object v7, v4, Lu/b;->a:Ljava/lang/String;

    .line 38
    .line 39
    invoke-virtual {v6, v7}, Lb81/c;->s(Ljava/lang/String;)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-nez v6, :cond_0

    .line 44
    .line 45
    iget-object v7, p0, Lu/y;->d:Lb81/c;

    .line 46
    .line 47
    iget-object v8, v4, Lu/b;->a:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v9, v4, Lu/b;->c:Lh0/z1;

    .line 50
    .line 51
    iget-object v10, v4, Lu/b;->d:Lh0/o2;

    .line 52
    .line 53
    iget-object v11, v4, Lu/b;->f:Lh0/k;

    .line 54
    .line 55
    iget-object v12, v4, Lu/b;->g:Ljava/util/List;

    .line 56
    .line 57
    iget-object v6, v7, Lb81/c;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v6, Ljava/util/LinkedHashMap;

    .line 60
    .line 61
    invoke-virtual {v6, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v13

    .line 65
    check-cast v13, Lh0/l2;

    .line 66
    .line 67
    if-nez v13, :cond_1

    .line 68
    .line 69
    new-instance v13, Lh0/l2;

    .line 70
    .line 71
    invoke-direct {v13, v9, v10, v11, v12}, Lh0/l2;-><init>(Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;)V

    .line 72
    .line 73
    .line 74
    invoke-interface {v6, v8, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    :cond_1
    iput-boolean v5, v13, Lh0/l2;->e:Z

    .line 78
    .line 79
    invoke-virtual/range {v7 .. v12}, Lb81/c;->y(Ljava/lang/String;Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;)V

    .line 80
    .line 81
    .line 82
    iget-object v5, v4, Lu/b;->a:Ljava/lang/String;

    .line 83
    .line 84
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    iget-object v5, v4, Lu/b;->b:Ljava/lang/Class;

    .line 88
    .line 89
    const-class v6, Lb0/k1;

    .line 90
    .line 91
    if-ne v5, v6, :cond_0

    .line 92
    .line 93
    iget-object v4, v4, Lu/b;->e:Landroid/util/Size;

    .line 94
    .line 95
    if-eqz v4, :cond_0

    .line 96
    .line 97
    new-instance v3, Landroid/util/Rational;

    .line 98
    .line 99
    invoke-virtual {v4}, Landroid/util/Size;->getWidth()I

    .line 100
    .line 101
    .line 102
    move-result v5

    .line 103
    invoke-virtual {v4}, Landroid/util/Size;->getHeight()I

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    invoke-direct {v3, v5, v4}, Landroid/util/Rational;-><init>(II)V

    .line 108
    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_2
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    if-eqz p1, :cond_3

    .line 116
    .line 117
    goto/16 :goto_4

    .line 118
    .line 119
    :cond_3
    new-instance p1, Ljava/lang/StringBuilder;

    .line 120
    .line 121
    const-string v4, "Use cases ["

    .line 122
    .line 123
    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const-string v4, ", "

    .line 127
    .line 128
    invoke-static {v4, v1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const-string v1, "] now ATTACHED"

    .line 136
    .line 137
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-virtual {p0, p1, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 145
    .line 146
    .line 147
    if-eqz v0, :cond_4

    .line 148
    .line 149
    iget-object p1, p0, Lu/y;->j:Lu/m;

    .line 150
    .line 151
    invoke-virtual {p1, v5}, Lu/m;->m(Z)V

    .line 152
    .line 153
    .line 154
    iget-object p1, p0, Lu/y;->j:Lu/m;

    .line 155
    .line 156
    iget-object v1, p1, Lu/m;->d:Ljava/lang/Object;

    .line 157
    .line 158
    monitor-enter v1

    .line 159
    :try_start_0
    iget v0, p1, Lu/m;->q:I

    .line 160
    .line 161
    add-int/2addr v0, v5

    .line 162
    iput v0, p1, Lu/m;->q:I

    .line 163
    .line 164
    monitor-exit v1

    .line 165
    goto :goto_1

    .line 166
    :catchall_0
    move-exception v0

    .line 167
    move-object p0, v0

    .line 168
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 169
    throw p0

    .line 170
    :cond_4
    :goto_1
    invoke-virtual {p0}, Lu/y;->s()V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0}, Lu/y;->O()V

    .line 174
    .line 175
    .line 176
    invoke-virtual {p0}, Lu/y;->N()V

    .line 177
    .line 178
    .line 179
    invoke-virtual {p0}, Lu/y;->M()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {p0}, Lu/y;->F()V

    .line 183
    .line 184
    .line 185
    iget p1, p0, Lu/y;->O:I

    .line 186
    .line 187
    const/16 v0, 0xa

    .line 188
    .line 189
    if-ne p1, v0, :cond_5

    .line 190
    .line 191
    invoke-virtual {p0}, Lu/y;->E()V

    .line 192
    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_5
    iget p1, p0, Lu/y;->O:I

    .line 196
    .line 197
    invoke-static {p1}, Lu/w;->o(I)I

    .line 198
    .line 199
    .line 200
    move-result p1

    .line 201
    const/4 v1, 0x2

    .line 202
    const/4 v4, 0x0

    .line 203
    if-eq p1, v1, :cond_8

    .line 204
    .line 205
    const/4 v1, 0x3

    .line 206
    if-eq p1, v1, :cond_8

    .line 207
    .line 208
    const/4 v1, 0x4

    .line 209
    if-eq p1, v1, :cond_8

    .line 210
    .line 211
    const/4 v1, 0x5

    .line 212
    if-eq p1, v1, :cond_6

    .line 213
    .line 214
    iget p1, p0, Lu/y;->O:I

    .line 215
    .line 216
    invoke-static {p1}, Lu/w;->p(I)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object p1

    .line 220
    const-string v0, "open() ignored due to being in state: "

    .line 221
    .line 222
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object p1

    .line 226
    invoke-virtual {p0, p1, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 227
    .line 228
    .line 229
    goto :goto_3

    .line 230
    :cond_6
    const/16 p1, 0x8

    .line 231
    .line 232
    invoke-virtual {p0, p1}, Lu/y;->G(I)V

    .line 233
    .line 234
    .line 235
    iget-object p1, p0, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 236
    .line 237
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 238
    .line 239
    .line 240
    move-result p1

    .line 241
    if-nez p1, :cond_9

    .line 242
    .line 243
    iget-boolean p1, p0, Lu/y;->B:Z

    .line 244
    .line 245
    if-nez p1, :cond_9

    .line 246
    .line 247
    iget p1, p0, Lu/y;->n:I

    .line 248
    .line 249
    if-nez p1, :cond_9

    .line 250
    .line 251
    iget-object p1, p0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 252
    .line 253
    if-eqz p1, :cond_7

    .line 254
    .line 255
    goto :goto_2

    .line 256
    :cond_7
    move v5, v4

    .line 257
    :goto_2
    const-string p1, "Camera Device should be open if session close is not complete"

    .line 258
    .line 259
    invoke-static {p1, v5}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {p0, v0}, Lu/y;->G(I)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {p0}, Lu/y;->E()V

    .line 266
    .line 267
    .line 268
    goto :goto_3

    .line 269
    :cond_8
    invoke-virtual {p0, v4}, Lu/y;->K(Z)V

    .line 270
    .line 271
    .line 272
    :cond_9
    :goto_3
    if-eqz v3, :cond_a

    .line 273
    .line 274
    iget-object p0, p0, Lu/y;->j:Lu/m;

    .line 275
    .line 276
    iget-object p0, p0, Lu/m;->h:Lu/r0;

    .line 277
    .line 278
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 279
    .line 280
    .line 281
    :cond_a
    :goto_4
    return-void
.end method

.method public final K(Z)V
    .locals 2

    .line 1
    const-string v0, "Attempting to force open the camera."

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lu/y;->w:Lh0/k0;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lh0/k0;->d(Lu/y;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    const-string p1, "No cameras available. Waiting for available camera before opening camera."

    .line 16
    .line 17
    invoke-virtual {p0, p1, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 18
    .line 19
    .line 20
    const/4 p1, 0x4

    .line 21
    invoke-virtual {p0, p1}, Lu/y;->G(I)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    invoke-virtual {p0, p1}, Lu/y;->D(Z)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final L(Z)V
    .locals 2

    .line 1
    const-string v0, "Attempting to open the camera."

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lu/y;->u:Lu/u;

    .line 8
    .line 9
    iget-boolean v0, v0, Lu/u;->b:Z

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Lu/y;->w:Lh0/k0;

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Lh0/k0;->d(Lu/y;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lu/y;->D(Z)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    const-string p1, "No cameras available. Waiting for available camera before opening camera."

    .line 26
    .line 27
    invoke-virtual {p0, p1, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    const/4 p1, 0x4

    .line 31
    invoke-virtual {p0, p1}, Lu/y;->G(I)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final M()V
    .locals 4

    .line 1
    iget-object v0, p0, Lu/y;->d:Lb81/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb81/c;->m()Lh0/y1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Lh0/y1;->c()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    iget-object v2, p0, Lu/y;->j:Lu/m;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0}, Lh0/y1;->b()Lh0/z1;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    iget-object v1, v1, Lh0/z1;->g:Lh0/o0;

    .line 20
    .line 21
    iget v1, v1, Lh0/o0;->c:I

    .line 22
    .line 23
    iput v1, v2, Lu/m;->w:I

    .line 24
    .line 25
    iget-object v3, v2, Lu/m;->h:Lu/r0;

    .line 26
    .line 27
    iput v1, v3, Lu/r0;->c:I

    .line 28
    .line 29
    iget-object v1, v2, Lu/m;->o:Lip/v;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v2}, Lu/m;->j()Lh0/z1;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v0, v1}, Lh0/y1;->a(Lh0/z1;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Lh0/y1;->b()Lh0/z1;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iget-object p0, p0, Lu/y;->o:Lu/p0;

    .line 46
    .line 47
    invoke-virtual {p0, v0}, Lu/p0;->o(Lh0/z1;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_0
    const/4 v0, 0x1

    .line 52
    iput v0, v2, Lu/m;->w:I

    .line 53
    .line 54
    iget-object v1, v2, Lu/m;->h:Lu/r0;

    .line 55
    .line 56
    iput v0, v1, Lu/r0;->c:I

    .line 57
    .line 58
    iget-object v0, v2, Lu/m;->o:Lip/v;

    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    iget-object p0, p0, Lu/y;->o:Lu/p0;

    .line 64
    .line 65
    invoke-virtual {v2}, Lu/m;->j()Lh0/z1;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-virtual {p0, v0}, Lu/p0;->o(Lh0/z1;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final N()V
    .locals 2

    .line 1
    iget-object v0, p0, Lu/y;->l:Lu/z;

    .line 2
    .line 3
    iget-object v0, v0, Lu/z;->b:Lv/b;

    .line 4
    .line 5
    invoke-static {v0}, Lb6/f;->j(Lv/b;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v0, p0, Lu/y;->d:Lb81/c;

    .line 13
    .line 14
    invoke-virtual {v0}, Lb81/c;->m()Lh0/y1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Lh0/y1;->c()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    invoke-virtual {v0}, Lh0/y1;->b()Lh0/z1;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iget-object v0, v0, Lh0/z1;->g:Lh0/o0;

    .line 29
    .line 30
    invoke-virtual {v0}, Lh0/o0;->a()Landroid/util/Range;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v0}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    check-cast v0, Ljava/lang/Integer;

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    const/16 v1, 0x1e

    .line 45
    .line 46
    iget-object p0, p0, Lu/y;->j:Lu/m;

    .line 47
    .line 48
    if-le v0, v1, :cond_1

    .line 49
    .line 50
    const/4 v0, 0x1

    .line 51
    invoke-virtual {p0, v0}, Lu/m;->n(Z)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    const/4 v0, 0x0

    .line 56
    invoke-virtual {p0, v0}, Lu/m;->n(Z)V

    .line 57
    .line 58
    .line 59
    :cond_2
    :goto_0
    return-void
.end method

.method public final O()V
    .locals 5

    .line 1
    iget-object v0, p0, Lu/y;->d:Lb81/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb81/c;->r()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const/4 v1, 0x0

    .line 12
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Lh0/o2;

    .line 23
    .line 24
    sget-object v3, Lh0/o2;->X0:Lh0/g;

    .line 25
    .line 26
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-interface {v2, v3, v4}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Ljava/lang/Boolean;

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    or-int/2addr v1, v2

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    iget-object p0, p0, Lu/y;->j:Lu/m;

    .line 41
    .line 42
    iget-object p0, p0, Lu/m;->m:Lu/l1;

    .line 43
    .line 44
    iget-boolean v0, p0, Lu/l1;->d:Z

    .line 45
    .line 46
    if-eq v0, v1, :cond_1

    .line 47
    .line 48
    if-eqz v1, :cond_1

    .line 49
    .line 50
    invoke-virtual {p0}, Lu/l1;->b()V

    .line 51
    .line 52
    .line 53
    :cond_1
    iput-boolean v1, p0, Lu/l1;->d:Z

    .line 54
    .line 55
    return-void
.end method

.method public final b()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 2

    .line 1
    new-instance v0, Lu/p;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, p0, v1}, Lu/p;-><init>(Lu/y;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final c()Lh0/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/y;->h:Lgw0/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()V
    .locals 2

    .line 1
    new-instance v0, Lu/o;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lu/o;-><init>(Lu/y;I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lu/y;->f:Lj0/h;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final e(Lb0/z1;)V
    .locals 2

    .line 1
    invoke-static {p1}, Lu/y;->A(Lb0/z1;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v0, Lno/nordicsemi/android/ble/o0;

    .line 6
    .line 7
    const/16 v1, 0x10

    .line 8
    .line 9
    invoke-direct {v0, v1, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lu/y;->f:Lj0/h;

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final f(Lb0/z1;)V
    .locals 9

    .line 1
    iget-boolean v0, p0, Lu/y;->C:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p1, Lb0/z1;->n:Lh0/z1;

    .line 6
    .line 7
    :goto_0
    move-object v4, v0

    .line 8
    goto :goto_1

    .line 9
    :cond_0
    iget-object v0, p1, Lb0/z1;->o:Lh0/z1;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :goto_1
    iget-object v5, p1, Lb0/z1;->g:Lh0/o2;

    .line 13
    .line 14
    iget-object v6, p1, Lb0/z1;->h:Lh0/k;

    .line 15
    .line 16
    invoke-virtual {p1}, Lb0/z1;->c()Lh0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    :goto_2
    move-object v7, v0

    .line 24
    goto :goto_3

    .line 25
    :cond_1
    invoke-static {p1}, Lt0/e;->H(Lb0/z1;)Ljava/util/ArrayList;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    goto :goto_2

    .line 30
    :goto_3
    invoke-static {p1}, Lu/y;->A(Lb0/z1;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    new-instance v1, Lu/s;

    .line 35
    .line 36
    const/4 v8, 0x2

    .line 37
    move-object v2, p0

    .line 38
    invoke-direct/range {v1 .. v8}, Lu/s;-><init>(Lu/y;Ljava/lang/String;Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;I)V

    .line 39
    .line 40
    .line 41
    iget-object p0, v2, Lu/y;->f:Lj0/h;

    .line 42
    .line 43
    invoke-virtual {p0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final g()Lh0/y;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/y;->j:Lu/m;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Lh0/t;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/y;->H:Lh0/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(Lh0/t;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    sget-object p1, Lh0/w;->a:Lh0/v;

    .line 5
    .line 6
    :goto_0
    invoke-interface {p1}, Lh0/t;->r()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lu/y;->H:Lh0/t;

    .line 10
    .line 11
    iget-object p0, p0, Lu/y;->I:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter p0

    .line 14
    :try_start_0
    monitor-exit p0

    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception p1

    .line 17
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    throw p1
.end method

.method public final j(Z)V
    .locals 2

    .line 1
    new-instance v0, La0/b;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p0, p1, v1}, La0/b;-><init>(Ljava/lang/Object;ZI)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lu/y;->f:Lj0/h;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final k(Ljava/util/Collection;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lu/y;->j:Lu/m;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v1, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    iget-object p1, v0, Lu/m;->d:Ljava/lang/Object;

    .line 16
    .line 17
    monitor-enter p1

    .line 18
    :try_start_0
    iget v2, v0, Lu/m;->q:I

    .line 19
    .line 20
    add-int/lit8 v2, v2, 0x1

    .line 21
    .line 22
    iput v2, v0, Lu/m;->q:I

    .line 23
    .line 24
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    new-instance p1, Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 28
    .line 29
    .line 30
    iget-object v2, p0, Lu/y;->G:Ljava/util/HashSet;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_2

    .line 41
    .line 42
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    check-cast v3, Lb0/z1;

    .line 47
    .line 48
    invoke-static {v3}, Lu/y;->A(Lb0/z1;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    invoke-virtual {v2, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    if-eqz v5, :cond_1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_1
    invoke-virtual {v2, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    invoke-virtual {v3}, Lb0/z1;->u()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v3}, Lb0/z1;->s()V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    new-instance p1, Ljava/util/ArrayList;

    .line 70
    .line 71
    invoke-virtual {p0, v1}, Lu/y;->I(Ljava/util/ArrayList;)Ljava/util/ArrayList;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 76
    .line 77
    .line 78
    :try_start_1
    iget-object v1, p0, Lu/y;->f:Lj0/h;

    .line 79
    .line 80
    new-instance v2, Lu/r;

    .line 81
    .line 82
    const/4 v3, 0x0

    .line 83
    invoke-direct {v2, p0, p1, v3}, Lu/r;-><init>(Lu/y;Ljava/util/ArrayList;I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1, v2}, Lj0/h;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_1 .. :try_end_1} :catch_0

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :catch_0
    move-exception p1

    .line 91
    const-string v1, "Unable to attach use cases."

    .line 92
    .line 93
    invoke-virtual {p0, v1, p1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0}, Lu/m;->i()V

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :catchall_0
    move-exception p0

    .line 101
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 102
    throw p0
.end method

.method public final l()Lh0/z;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/y;->l:Lu/z;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m(Lb0/z1;)V
    .locals 8

    .line 1
    invoke-static {p1}, Lu/y;->A(Lb0/z1;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v2

    .line 5
    iget-boolean v0, p0, Lu/y;->C:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p1, Lb0/z1;->n:Lh0/z1;

    .line 10
    .line 11
    :goto_0
    move-object v3, v0

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    iget-object v0, p1, Lb0/z1;->o:Lh0/z1;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :goto_1
    iget-object v4, p1, Lb0/z1;->g:Lh0/o2;

    .line 17
    .line 18
    iget-object v5, p1, Lb0/z1;->h:Lh0/k;

    .line 19
    .line 20
    invoke-virtual {p1}, Lb0/z1;->c()Lh0/b0;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    const/4 p1, 0x0

    .line 27
    :goto_2
    move-object v6, p1

    .line 28
    goto :goto_3

    .line 29
    :cond_1
    invoke-static {p1}, Lt0/e;->H(Lb0/z1;)Ljava/util/ArrayList;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    goto :goto_2

    .line 34
    :goto_3
    new-instance v0, Lu/s;

    .line 35
    .line 36
    const/4 v7, 0x1

    .line 37
    move-object v1, p0

    .line 38
    invoke-direct/range {v0 .. v7}, Lu/s;-><init>(Lu/y;Ljava/lang/String;Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;I)V

    .line 39
    .line 40
    .line 41
    iget-object p0, v1, Lu/y;->f:Lj0/h;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final o(Ljava/util/ArrayList;)V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p1, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {p0, v0}, Lu/y;->I(Ljava/util/ArrayList;)Ljava/util/ArrayList;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 20
    .line 21
    .line 22
    new-instance v1, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Lb0/z1;

    .line 42
    .line 43
    invoke-static {v1}, Lu/y;->A(Lb0/z1;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    iget-object v3, p0, Lu/y;->G:Ljava/util/HashSet;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-nez v4, :cond_1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    invoke-virtual {v1}, Lb0/z1;->v()V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v2}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    new-instance v0, Lu/r;

    .line 64
    .line 65
    const/4 v1, 0x1

    .line 66
    invoke-direct {v0, p0, p1, v1}, Lu/r;-><init>(Lu/y;Ljava/util/ArrayList;I)V

    .line 67
    .line 68
    .line 69
    iget-object p0, p0, Lu/y;->f:Lj0/h;

    .line 70
    .line 71
    invoke-virtual {p0, v0}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public final q(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lu/y;->C:Z

    .line 2
    .line 3
    return-void
.end method

.method public final r(Lb0/z1;)V
    .locals 8

    .line 1
    invoke-static {p1}, Lu/y;->A(Lb0/z1;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v2

    .line 5
    iget-boolean v0, p0, Lu/y;->C:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p1, Lb0/z1;->n:Lh0/z1;

    .line 10
    .line 11
    :goto_0
    move-object v3, v0

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    iget-object v0, p1, Lb0/z1;->o:Lh0/z1;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :goto_1
    iget-object v4, p1, Lb0/z1;->g:Lh0/o2;

    .line 17
    .line 18
    iget-object v5, p1, Lb0/z1;->h:Lh0/k;

    .line 19
    .line 20
    invoke-virtual {p1}, Lb0/z1;->c()Lh0/b0;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    const/4 p1, 0x0

    .line 27
    :goto_2
    move-object v6, p1

    .line 28
    goto :goto_3

    .line 29
    :cond_1
    invoke-static {p1}, Lt0/e;->H(Lb0/z1;)Ljava/util/ArrayList;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    goto :goto_2

    .line 34
    :goto_3
    new-instance v0, Lu/s;

    .line 35
    .line 36
    const/4 v7, 0x0

    .line 37
    move-object v1, p0

    .line 38
    invoke-direct/range {v0 .. v7}, Lu/s;-><init>(Lu/y;Ljava/lang/String;Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;I)V

    .line 39
    .line 40
    .line 41
    iget-object p0, v1, Lu/y;->f:Lj0/h;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final s()V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lu/y;->d:Lb81/c;

    .line 4
    .line 5
    invoke-virtual {v1}, Lb81/c;->n()Lh0/y1;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iget-object v3, v1, Lb81/c;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-virtual {v2}, Lh0/y1;->b()Lh0/z1;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    iget-object v4, v2, Lh0/z1;->g:Lh0/o0;

    .line 18
    .line 19
    iget-object v4, v4, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-static {v4}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    invoke-virtual {v2}, Lh0/z1;->b()Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    iget-object v5, v0, Lu/y;->D:Lu/x0;

    .line 38
    .line 39
    const/4 v6, 0x0

    .line 40
    if-nez v5, :cond_0

    .line 41
    .line 42
    move v5, v6

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-static {v5}, Lu/y;->z(Lu/x0;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    invoke-virtual {v1, v5}, Lb81/c;->s(Ljava/lang/String;)Z

    .line 49
    .line 50
    .line 51
    move-result v5

    .line 52
    :goto_0
    const/4 v7, 0x0

    .line 53
    const/4 v8, 0x1

    .line 54
    if-eqz v5, :cond_b

    .line 55
    .line 56
    if-ne v4, v8, :cond_2

    .line 57
    .line 58
    if-ne v2, v8, :cond_1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    move v1, v6

    .line 62
    goto :goto_2

    .line 63
    :cond_2
    :goto_1
    move v1, v8

    .line 64
    :goto_2
    if-nez v1, :cond_3

    .line 65
    .line 66
    iget-object v2, v0, Lu/y;->D:Lu/x0;

    .line 67
    .line 68
    invoke-virtual {v0, v2}, Lu/y;->B(Lu/x0;)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_a

    .line 73
    .line 74
    :cond_3
    iget-object v2, v0, Lu/y;->D:Lu/x0;

    .line 75
    .line 76
    if-eqz v2, :cond_9

    .line 77
    .line 78
    new-instance v2, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    const-string v4, "MeteringRepeating"

    .line 81
    .line 82
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    iget-object v5, v0, Lu/y;->D:Lu/x0;

    .line 86
    .line 87
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    iget-object v5, v0, Lu/y;->D:Lu/x0;

    .line 91
    .line 92
    invoke-virtual {v5}, Ljava/lang/Object;->hashCode()I

    .line 93
    .line 94
    .line 95
    move-result v5

    .line 96
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    invoke-interface {v3, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v5

    .line 107
    if-nez v5, :cond_4

    .line 108
    .line 109
    goto :goto_3

    .line 110
    :cond_4
    invoke-virtual {v3, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    check-cast v5, Lh0/l2;

    .line 115
    .line 116
    iput-boolean v6, v5, Lh0/l2;->e:Z

    .line 117
    .line 118
    iget-boolean v5, v5, Lh0/l2;->f:Z

    .line 119
    .line 120
    if-nez v5, :cond_5

    .line 121
    .line 122
    invoke-interface {v3, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    :cond_5
    :goto_3
    new-instance v2, Ljava/lang/StringBuilder;

    .line 126
    .line 127
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    iget-object v5, v0, Lu/y;->D:Lu/x0;

    .line 131
    .line 132
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    iget-object v5, v0, Lu/y;->D:Lu/x0;

    .line 136
    .line 137
    invoke-virtual {v5}, Ljava/lang/Object;->hashCode()I

    .line 138
    .line 139
    .line 140
    move-result v5

    .line 141
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    invoke-interface {v3, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v5

    .line 152
    if-nez v5, :cond_6

    .line 153
    .line 154
    goto :goto_4

    .line 155
    :cond_6
    invoke-virtual {v3, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v5

    .line 159
    check-cast v5, Lh0/l2;

    .line 160
    .line 161
    iput-boolean v6, v5, Lh0/l2;->f:Z

    .line 162
    .line 163
    iget-boolean v5, v5, Lh0/l2;->e:Z

    .line 164
    .line 165
    if-nez v5, :cond_7

    .line 166
    .line 167
    invoke-interface {v3, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    :cond_7
    :goto_4
    iget-object v2, v0, Lu/y;->D:Lu/x0;

    .line 171
    .line 172
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    const-string v3, "MeteringRepeating clear!"

    .line 176
    .line 177
    invoke-static {v4, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    iget-object v3, v2, Lu/x0;->a:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v3, Lb0/u1;

    .line 183
    .line 184
    if-eqz v3, :cond_8

    .line 185
    .line 186
    invoke-virtual {v3}, Lh0/t0;->a()V

    .line 187
    .line 188
    .line 189
    :cond_8
    iput-object v7, v2, Lu/x0;->a:Ljava/lang/Object;

    .line 190
    .line 191
    iput-object v7, v0, Lu/y;->D:Lu/x0;

    .line 192
    .line 193
    :cond_9
    if-nez v1, :cond_a

    .line 194
    .line 195
    goto/16 :goto_a

    .line 196
    .line 197
    :cond_a
    move v6, v8

    .line 198
    goto/16 :goto_a

    .line 199
    .line 200
    :cond_b
    if-nez v4, :cond_19

    .line 201
    .line 202
    if-lez v2, :cond_19

    .line 203
    .line 204
    iget-object v2, v0, Lu/y;->D:Lu/x0;

    .line 205
    .line 206
    if-nez v2, :cond_14

    .line 207
    .line 208
    new-instance v2, Lu/x0;

    .line 209
    .line 210
    iget-object v3, v0, Lu/y;->l:Lu/z;

    .line 211
    .line 212
    iget-object v3, v3, Lu/z;->b:Lv/b;

    .line 213
    .line 214
    new-instance v4, Lu/p;

    .line 215
    .line 216
    const/4 v5, 0x1

    .line 217
    invoke-direct {v4, v0, v5}, Lu/p;-><init>(Lu/y;I)V

    .line 218
    .line 219
    .line 220
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 221
    .line 222
    .line 223
    new-instance v5, Ly/c;

    .line 224
    .line 225
    invoke-direct {v5}, Ly/c;-><init>()V

    .line 226
    .line 227
    .line 228
    const/4 v9, 0x0

    .line 229
    iput-object v9, v2, Lu/x0;->f:Ljava/lang/Object;

    .line 230
    .line 231
    new-instance v10, Lu/w0;

    .line 232
    .line 233
    invoke-direct {v10}, Lu/w0;-><init>()V

    .line 234
    .line 235
    .line 236
    iput-object v10, v2, Lu/x0;->c:Ljava/lang/Object;

    .line 237
    .line 238
    iput-object v4, v2, Lu/x0;->e:Ljava/lang/Object;

    .line 239
    .line 240
    invoke-virtual {v3}, Lv/b;->c()Lrn/i;

    .line 241
    .line 242
    .line 243
    move-result-object v3

    .line 244
    const/16 v4, 0x22

    .line 245
    .line 246
    invoke-virtual {v3, v4}, Lrn/i;->t(I)[Landroid/util/Size;

    .line 247
    .line 248
    .line 249
    move-result-object v3

    .line 250
    const-string v4, "MeteringRepeating"

    .line 251
    .line 252
    const/4 v10, 0x0

    .line 253
    if-nez v3, :cond_c

    .line 254
    .line 255
    const-string v3, "Can not get output size list."

    .line 256
    .line 257
    invoke-static {v4, v3}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    new-instance v3, Landroid/util/Size;

    .line 261
    .line 262
    invoke-direct {v3, v10, v10}, Landroid/util/Size;-><init>(II)V

    .line 263
    .line 264
    .line 265
    goto/16 :goto_8

    .line 266
    .line 267
    :cond_c
    iget-object v5, v5, Ly/c;->a:Landroidx/camera/camera2/internal/compat/quirk/RepeatingStreamConstraintForVideoRecordingQuirk;

    .line 268
    .line 269
    if-eqz v5, :cond_f

    .line 270
    .line 271
    const-string v5, "Huawei"

    .line 272
    .line 273
    sget-object v11, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 274
    .line 275
    invoke-virtual {v5, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 276
    .line 277
    .line 278
    move-result v5

    .line 279
    if-eqz v5, :cond_f

    .line 280
    .line 281
    const-string v5, "mha-l29"

    .line 282
    .line 283
    sget-object v11, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 284
    .line 285
    invoke-virtual {v5, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 286
    .line 287
    .line 288
    move-result v5

    .line 289
    if-eqz v5, :cond_f

    .line 290
    .line 291
    new-instance v5, Ljava/util/ArrayList;

    .line 292
    .line 293
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 294
    .line 295
    .line 296
    array-length v11, v3

    .line 297
    move v12, v10

    .line 298
    :goto_5
    if-ge v12, v11, :cond_e

    .line 299
    .line 300
    aget-object v13, v3, v12

    .line 301
    .line 302
    sget-object v14, Ly/c;->c:Li0/c;

    .line 303
    .line 304
    sget-object v15, Ly/c;->b:Landroid/util/Size;

    .line 305
    .line 306
    invoke-virtual {v14, v13, v15}, Li0/c;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 307
    .line 308
    .line 309
    move-result v14

    .line 310
    if-ltz v14, :cond_d

    .line 311
    .line 312
    invoke-virtual {v5, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    :cond_d
    add-int/lit8 v12, v12, 0x1

    .line 316
    .line 317
    goto :goto_5

    .line 318
    :cond_e
    new-array v3, v10, [Landroid/util/Size;

    .line 319
    .line 320
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v3

    .line 324
    check-cast v3, [Landroid/util/Size;

    .line 325
    .line 326
    :cond_f
    invoke-static {v3}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 327
    .line 328
    .line 329
    move-result-object v5

    .line 330
    new-instance v11, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 331
    .line 332
    const/16 v12, 0x17

    .line 333
    .line 334
    invoke-direct {v11, v12}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 335
    .line 336
    .line 337
    invoke-static {v5, v11}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 338
    .line 339
    .line 340
    iget-object v11, v0, Lu/y;->K:Lu/q0;

    .line 341
    .line 342
    invoke-virtual {v11}, Lu/q0;->e()Landroid/util/Size;

    .line 343
    .line 344
    .line 345
    move-result-object v11

    .line 346
    invoke-virtual {v11}, Landroid/util/Size;->getWidth()I

    .line 347
    .line 348
    .line 349
    move-result v12

    .line 350
    int-to-long v12, v12

    .line 351
    invoke-virtual {v11}, Landroid/util/Size;->getHeight()I

    .line 352
    .line 353
    .line 354
    move-result v11

    .line 355
    int-to-long v14, v11

    .line 356
    mul-long/2addr v12, v14

    .line 357
    const-wide/32 v14, 0x4b000

    .line 358
    .line 359
    .line 360
    invoke-static {v12, v13, v14, v15}, Ljava/lang/Math;->min(JJ)J

    .line 361
    .line 362
    .line 363
    move-result-wide v11

    .line 364
    array-length v13, v3

    .line 365
    move v14, v10

    .line 366
    :goto_6
    if-ge v14, v13, :cond_13

    .line 367
    .line 368
    aget-object v15, v3, v14

    .line 369
    .line 370
    invoke-virtual {v15}, Landroid/util/Size;->getWidth()I

    .line 371
    .line 372
    .line 373
    move-result v6

    .line 374
    int-to-long v7, v6

    .line 375
    invoke-virtual {v15}, Landroid/util/Size;->getHeight()I

    .line 376
    .line 377
    .line 378
    move-result v6

    .line 379
    move-wide/from16 v16, v11

    .line 380
    .line 381
    int-to-long v10, v6

    .line 382
    mul-long/2addr v7, v10

    .line 383
    cmp-long v6, v7, v16

    .line 384
    .line 385
    if-nez v6, :cond_10

    .line 386
    .line 387
    move-object v3, v15

    .line 388
    goto :goto_8

    .line 389
    :cond_10
    if-lez v6, :cond_12

    .line 390
    .line 391
    if-eqz v9, :cond_11

    .line 392
    .line 393
    move-object v3, v9

    .line 394
    goto :goto_8

    .line 395
    :cond_11
    const/4 v3, 0x0

    .line 396
    goto :goto_7

    .line 397
    :cond_12
    add-int/lit8 v14, v14, 0x1

    .line 398
    .line 399
    move-object v9, v15

    .line 400
    move-wide/from16 v11, v16

    .line 401
    .line 402
    const/4 v6, 0x0

    .line 403
    const/4 v7, 0x0

    .line 404
    const/4 v8, 0x1

    .line 405
    const/4 v10, 0x0

    .line 406
    goto :goto_6

    .line 407
    :cond_13
    move v3, v10

    .line 408
    :goto_7
    invoke-interface {v5, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v3

    .line 412
    check-cast v3, Landroid/util/Size;

    .line 413
    .line 414
    :goto_8
    iput-object v3, v2, Lu/x0;->d:Ljava/lang/Object;

    .line 415
    .line 416
    new-instance v5, Ljava/lang/StringBuilder;

    .line 417
    .line 418
    const-string v6, "MeteringSession SurfaceTexture size: "

    .line 419
    .line 420
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 424
    .line 425
    .line 426
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v3

    .line 430
    invoke-static {v4, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 431
    .line 432
    .line 433
    invoke-virtual {v2}, Lu/x0;->e()Lh0/z1;

    .line 434
    .line 435
    .line 436
    move-result-object v3

    .line 437
    iput-object v3, v2, Lu/x0;->b:Ljava/lang/Object;

    .line 438
    .line 439
    iput-object v2, v0, Lu/y;->D:Lu/x0;

    .line 440
    .line 441
    :cond_14
    iget-object v2, v0, Lu/y;->D:Lu/x0;

    .line 442
    .line 443
    invoke-virtual {v0, v2}, Lu/y;->B(Lu/x0;)Z

    .line 444
    .line 445
    .line 446
    move-result v2

    .line 447
    if-eqz v2, :cond_15

    .line 448
    .line 449
    const/4 v6, 0x0

    .line 450
    goto :goto_a

    .line 451
    :cond_15
    iget-object v2, v0, Lu/y;->D:Lu/x0;

    .line 452
    .line 453
    if-eqz v2, :cond_18

    .line 454
    .line 455
    invoke-static {v2}, Lu/y;->z(Lu/x0;)Ljava/lang/String;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    iget-object v3, v0, Lu/y;->D:Lu/x0;

    .line 460
    .line 461
    iget-object v4, v3, Lu/x0;->b:Ljava/lang/Object;

    .line 462
    .line 463
    check-cast v4, Lh0/z1;

    .line 464
    .line 465
    iget-object v3, v3, Lu/x0;->c:Ljava/lang/Object;

    .line 466
    .line 467
    check-cast v3, Lu/w0;

    .line 468
    .line 469
    sget-object v7, Lh0/q2;->i:Lh0/q2;

    .line 470
    .line 471
    invoke-static {v7}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 472
    .line 473
    .line 474
    move-result-object v6

    .line 475
    iget-object v5, v1, Lb81/c;->f:Ljava/lang/Object;

    .line 476
    .line 477
    check-cast v5, Ljava/util/LinkedHashMap;

    .line 478
    .line 479
    invoke-virtual {v5, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v8

    .line 483
    check-cast v8, Lh0/l2;

    .line 484
    .line 485
    const/4 v9, 0x0

    .line 486
    if-nez v8, :cond_16

    .line 487
    .line 488
    new-instance v8, Lh0/l2;

    .line 489
    .line 490
    invoke-direct {v8, v4, v3, v9, v6}, Lh0/l2;-><init>(Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;)V

    .line 491
    .line 492
    .line 493
    invoke-interface {v5, v2, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 494
    .line 495
    .line 496
    :cond_16
    const/4 v5, 0x1

    .line 497
    iput-boolean v5, v8, Lh0/l2;->e:Z

    .line 498
    .line 499
    move-object v5, v4

    .line 500
    move-object v4, v3

    .line 501
    move-object v3, v5

    .line 502
    move-object v5, v9

    .line 503
    invoke-virtual/range {v1 .. v6}, Lb81/c;->y(Ljava/lang/String;Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;)V

    .line 504
    .line 505
    .line 506
    iget-object v3, v0, Lu/y;->D:Lu/x0;

    .line 507
    .line 508
    iget-object v4, v3, Lu/x0;->b:Ljava/lang/Object;

    .line 509
    .line 510
    check-cast v4, Lh0/z1;

    .line 511
    .line 512
    iget-object v3, v3, Lu/x0;->c:Ljava/lang/Object;

    .line 513
    .line 514
    check-cast v3, Lu/w0;

    .line 515
    .line 516
    invoke-static {v7}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 517
    .line 518
    .line 519
    move-result-object v5

    .line 520
    iget-object v1, v1, Lb81/c;->f:Ljava/lang/Object;

    .line 521
    .line 522
    check-cast v1, Ljava/util/LinkedHashMap;

    .line 523
    .line 524
    invoke-virtual {v1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 525
    .line 526
    .line 527
    move-result-object v6

    .line 528
    check-cast v6, Lh0/l2;

    .line 529
    .line 530
    if-nez v6, :cond_17

    .line 531
    .line 532
    new-instance v6, Lh0/l2;

    .line 533
    .line 534
    const/4 v7, 0x0

    .line 535
    invoke-direct {v6, v4, v3, v7, v5}, Lh0/l2;-><init>(Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;)V

    .line 536
    .line 537
    .line 538
    invoke-interface {v1, v2, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 539
    .line 540
    .line 541
    :cond_17
    const/4 v5, 0x1

    .line 542
    iput-boolean v5, v6, Lh0/l2;->f:Z

    .line 543
    .line 544
    goto :goto_9

    .line 545
    :cond_18
    const/4 v5, 0x1

    .line 546
    goto :goto_9

    .line 547
    :cond_19
    move v5, v8

    .line 548
    :goto_9
    move v6, v5

    .line 549
    :goto_a
    iget-object v0, v0, Lu/y;->j:Lu/m;

    .line 550
    .line 551
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 552
    .line 553
    .line 554
    if-nez v6, :cond_1a

    .line 555
    .line 556
    const-string v0, "Camera2CameraImpl"

    .line 557
    .line 558
    const-string v1, "The repeating surface is missing, CameraControl and ImageCapture may encounter issues due to the absence of repeating surface. Please add a UseCase (Preview or ImageAnalysis) that can provide a repeating surface for CameraControl and ImageCapture to function properly."

    .line 559
    .line 560
    invoke-static {v0, v1}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 561
    .line 562
    .line 563
    :cond_1a
    return-void
.end method

.method public final t()V
    .locals 5

    .line 1
    iget v0, p0, Lu/y;->O:I

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    if-eq v0, v1, :cond_1

    .line 5
    .line 6
    iget v0, p0, Lu/y;->O:I

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    iget v0, p0, Lu/y;->O:I

    .line 12
    .line 13
    const/16 v1, 0x8

    .line 14
    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    iget v0, p0, Lu/y;->n:I

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    :goto_0
    const/4 v0, 0x1

    .line 25
    :goto_1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v2, "closeCamera should only be called in a CLOSING, RELEASING or REOPENING (with error) state. Current state: "

    .line 28
    .line 29
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget v2, p0, Lu/y;->O:I

    .line 33
    .line 34
    invoke-static {v2}, Lu/w;->p(I)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v2, " (error: "

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget v2, p0, Lu/y;->n:I

    .line 47
    .line 48
    invoke-static {v2}, Lu/y;->y(I)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v2, ")"

    .line 56
    .line 57
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Lu/y;->F()V

    .line 68
    .line 69
    .line 70
    iget-object p0, p0, Lu/y;->o:Lu/p0;

    .line 71
    .line 72
    iget-object v0, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 73
    .line 74
    monitor-enter v0

    .line 75
    :try_start_0
    iget-object v1, p0, Lu/p0;->b:Ljava/util/ArrayList;

    .line 76
    .line 77
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-nez v1, :cond_2

    .line 82
    .line 83
    new-instance v1, Ljava/util/ArrayList;

    .line 84
    .line 85
    iget-object v2, p0, Lu/p0;->b:Ljava/util/ArrayList;

    .line 86
    .line 87
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 88
    .line 89
    .line 90
    iget-object p0, p0, Lu/p0;->b:Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 93
    .line 94
    .line 95
    goto :goto_2

    .line 96
    :catchall_0
    move-exception p0

    .line 97
    goto :goto_5

    .line 98
    :cond_2
    const/4 v1, 0x0

    .line 99
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 100
    if-eqz v1, :cond_5

    .line 101
    .line 102
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    :cond_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    if-eqz v0, :cond_5

    .line 111
    .line 112
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    check-cast v0, Lh0/o0;

    .line 117
    .line 118
    iget-object v1, v0, Lh0/o0;->d:Ljava/util/List;

    .line 119
    .line 120
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    if-eqz v2, :cond_3

    .line 129
    .line 130
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    check-cast v2, Lh0/m;

    .line 135
    .line 136
    iget-object v3, v0, Lh0/o0;->f:Lh0/j2;

    .line 137
    .line 138
    const-string v4, "CAPTURE_CONFIG_ID_KEY"

    .line 139
    .line 140
    iget-object v3, v3, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 141
    .line 142
    invoke-virtual {v3, v4}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    if-nez v3, :cond_4

    .line 147
    .line 148
    const/4 v3, -0x1

    .line 149
    goto :goto_4

    .line 150
    :cond_4
    check-cast v3, Ljava/lang/Integer;

    .line 151
    .line 152
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 153
    .line 154
    .line 155
    move-result v3

    .line 156
    :goto_4
    invoke-virtual {v2, v3}, Lh0/m;->a(I)V

    .line 157
    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_5
    return-void

    .line 161
    :goto_5
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 162
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object p0, p0, Lu/y;->l:Lu/z;

    .line 12
    .line 13
    iget-object p0, p0, Lu/z;->a:Ljava/lang/String;

    .line 14
    .line 15
    filled-new-array {v1, p0}, [Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const-string v1, "Camera@%x[id=%s]"

    .line 20
    .line 21
    invoke-static {v0, v1, p0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public final u()V
    .locals 4

    .line 1
    iget v0, p0, Lu/y;->O:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x0

    .line 6
    if-eq v0, v1, :cond_1

    .line 7
    .line 8
    iget v0, p0, Lu/y;->O:I

    .line 9
    .line 10
    const/4 v1, 0x6

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v0, v3

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    :goto_0
    move v0, v2

    .line 17
    :goto_1
    const/4 v1, 0x0

    .line 18
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 22
    .line 23
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 28
    .line 29
    .line 30
    iget-boolean v0, p0, Lu/y;->A:Z

    .line 31
    .line 32
    if-nez v0, :cond_2

    .line 33
    .line 34
    invoke-virtual {p0}, Lu/y;->x()V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_2
    iget-boolean v0, p0, Lu/y;->B:Z

    .line 39
    .line 40
    if-eqz v0, :cond_3

    .line 41
    .line 42
    const-string v0, "Ignored since configAndClose is processing"

    .line 43
    .line 44
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_3
    iget-object v0, p0, Lu/y;->u:Lu/u;

    .line 49
    .line 50
    iget-boolean v0, v0, Lu/u;->b:Z

    .line 51
    .line 52
    if-nez v0, :cond_4

    .line 53
    .line 54
    iput-boolean v3, p0, Lu/y;->A:Z

    .line 55
    .line 56
    invoke-virtual {p0}, Lu/y;->x()V

    .line 57
    .line 58
    .line 59
    const-string v0, "Ignore configAndClose and finish the close flow directly since camera is unavailable."

    .line 60
    .line 61
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_4
    const-string v0, "Open camera to configAndClose"

    .line 66
    .line 67
    invoke-virtual {p0, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 68
    .line 69
    .line 70
    new-instance v0, Lu/p;

    .line 71
    .line 72
    const/4 v1, 0x0

    .line 73
    invoke-direct {v0, p0, v1}, Lu/p;-><init>(Lu/y;I)V

    .line 74
    .line 75
    .line 76
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    iput-boolean v2, p0, Lu/y;->B:Z

    .line 81
    .line 82
    new-instance v1, Lu/o;

    .line 83
    .line 84
    const/4 v2, 0x1

    .line 85
    invoke-direct {v1, p0, v2}, Lu/o;-><init>(Lu/y;I)V

    .line 86
    .line 87
    .line 88
    iget-object p0, p0, Lu/y;->f:Lj0/h;

    .line 89
    .line 90
    iget-object v0, v0, Ly4/k;->e:Ly4/j;

    .line 91
    .line 92
    invoke-virtual {v0, p0, v1}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 93
    .line 94
    .line 95
    return-void
.end method

.method public final v()Landroid/hardware/camera2/CameraDevice$StateCallback;
    .locals 2

    .line 1
    iget-object v0, p0, Lu/y;->d:Lb81/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb81/c;->n()Lh0/y1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Lh0/y1;->b()Lh0/z1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v0, v0, Lh0/z1;->c:Ljava/util/List;

    .line 12
    .line 13
    new-instance v1, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lu/y;->E:Lu/x0;

    .line 19
    .line 20
    iget-object v0, v0, Lu/x0;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lu/j0;

    .line 23
    .line 24
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lu/y;->k:Lu/x;

    .line 28
    .line 29
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Llp/x0;->b(Ljava/util/ArrayList;)Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public final w(Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lu/y;->toString()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "{"

    .line 6
    .line 7
    const-string v1, "} "

    .line 8
    .line 9
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string p1, "Camera2CameraImpl"

    .line 14
    .line 15
    invoke-static {p1, p0, p2}, Ljp/v1;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final x()V
    .locals 4

    .line 1
    iget v0, p0, Lu/y;->O:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x6

    .line 6
    if-eq v0, v1, :cond_1

    .line 7
    .line 8
    iget v0, p0, Lu/y;->O:I

    .line 9
    .line 10
    if-ne v0, v3, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    goto :goto_1

    .line 15
    :cond_1
    :goto_0
    move v0, v2

    .line 16
    :goto_1
    const/4 v1, 0x0

    .line 17
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 27
    .line 28
    .line 29
    iput-object v1, p0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 30
    .line 31
    iget v0, p0, Lu/y;->O:I

    .line 32
    .line 33
    if-ne v0, v3, :cond_2

    .line 34
    .line 35
    const/4 v0, 0x3

    .line 36
    invoke-virtual {p0, v0}, Lu/y;->G(I)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_2
    iget-object v0, p0, Lu/y;->e:Lv/d;

    .line 41
    .line 42
    iget-object v3, p0, Lu/y;->u:Lu/u;

    .line 43
    .line 44
    iget-object v0, v0, Lv/d;->a:Lv/e;

    .line 45
    .line 46
    iget-object v0, v0, Lh/w;->b:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v0, Landroid/hardware/camera2/CameraManager;

    .line 49
    .line 50
    invoke-virtual {v0, v3}, Landroid/hardware/camera2/CameraManager;->unregisterAvailabilityCallback(Landroid/hardware/camera2/CameraManager$AvailabilityCallback;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v2}, Lu/y;->G(I)V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lu/y;->r:Ly4/h;

    .line 57
    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    iput-object v1, p0, Lu/y;->r:Ly4/h;

    .line 64
    .line 65
    :cond_3
    return-void
.end method
