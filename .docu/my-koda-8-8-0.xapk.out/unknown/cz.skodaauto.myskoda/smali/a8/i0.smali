.class public final La8/i0;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/media3/exoplayer/ExoPlayer;


# instance fields
.field public final A:J

.field public A1:J

.field public final B:J

.field public final C:Lw7/r;

.field public final D:La8/f0;

.field public final E:La8/g0;

.field public final F:La8/b;

.field public final G:La8/t1;

.field public final H:La8/t1;

.field public final I:J

.field public final J:Lca/j;

.field public K:I

.field public L:Z

.field public M:I

.field public N:I

.field public O:Z

.field public P:Z

.field public Q:Lhr/k0;

.field public final R:La8/q1;

.field public final S:La8/r1;

.field public T:Lh8/a1;

.field public final U:La8/r;

.field public V:Lt7/h0;

.field public W:Lt7/a0;

.field public X:Lt7/o;

.field public Y:Ljava/lang/Object;

.field public Z:Landroid/view/Surface;

.field public a0:Landroid/view/SurfaceHolder;

.field public b0:Ln8/k;

.field public c0:Z

.field public d0:Landroid/view/TextureView;

.field public final e0:I

.field public final f:Lj8/s;

.field public f0:Lw7/q;

.field public final g:Lt7/h0;

.field public final g0:Lt7/c;

.field public final h:Lw7/e;

.field public final i:Landroid/content/Context;

.field public final j:La8/i0;

.field public final k:[La8/f;

.field public final l:[La8/f;

.field public final m:Lh/w;

.field public final n:Lw7/t;

.field public final o:La8/y;

.field public final p:La8/q0;

.field public final q:Le30/v;

.field public q1:F

.field public final r:Ljava/util/concurrent/CopyOnWriteArraySet;

.field public r1:Z

.field public final s:Lt7/n0;

.field public s1:Lv7/c;

.field public final t:Ljava/util/ArrayList;

.field public final t1:Z

.field public final u:Z

.field public u1:Z

.field public final v:Lh8/a0;

.field public final v1:I

.field public final w:Lb8/e;

.field public w1:Lt7/a1;

.field public final x:Landroid/os/Looper;

.field public x1:Lt7/a0;

.field public final y:Lk8/d;

.field public y1:La8/i1;

.field public final z:J

.field public z1:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "media3.exoplayer"

    .line 2
    .line 3
    invoke-static {v0}, Lt7/y;->a(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public constructor <init>(La8/q;)V
    .locals 33

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 7
    .line 8
    .line 9
    move-result-object v3

    .line 10
    const-string v4, " [AndroidXMedia3/1.8.0] ["

    .line 11
    .line 12
    const-string v5, "Init "

    .line 13
    .line 14
    const/4 v6, 0x7

    .line 15
    invoke-direct {v1, v6}, Lap0/o;-><init>(I)V

    .line 16
    .line 17
    .line 18
    new-instance v6, Lw7/e;

    .line 19
    .line 20
    invoke-direct {v6}, Lw7/e;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v6, v1, La8/i0;->h:Lw7/e;

    .line 24
    .line 25
    :try_start_0
    const-string v6, "ExoPlayerImpl"

    .line 26
    .line 27
    new-instance v7, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    invoke-direct {v7, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    invoke-static {v5}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    sget-object v4, Lw7/w;->a:Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v4, "]"

    .line 52
    .line 53
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    invoke-static {v6, v4}, Lw7/a;->s(Ljava/lang/String;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    iget-object v4, v0, La8/q;->a:Landroid/content/Context;

    .line 64
    .line 65
    iget-object v5, v0, La8/q;->g:Landroid/os/Looper;

    .line 66
    .line 67
    iget-object v6, v0, La8/q;->b:Lw7/r;

    .line 68
    .line 69
    invoke-virtual {v4}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    iput-object v7, v1, La8/i0;->i:Landroid/content/Context;

    .line 74
    .line 75
    new-instance v7, Lb8/e;

    .line 76
    .line 77
    invoke-direct {v7, v6}, Lb8/e;-><init>(Lw7/r;)V

    .line 78
    .line 79
    .line 80
    iput-object v7, v1, La8/i0;->w:Lb8/e;

    .line 81
    .line 82
    iget v7, v0, La8/q;->h:I

    .line 83
    .line 84
    iput v7, v1, La8/i0;->v1:I

    .line 85
    .line 86
    iget-object v7, v0, La8/q;->i:Lt7/c;

    .line 87
    .line 88
    iput-object v7, v1, La8/i0;->g0:Lt7/c;

    .line 89
    .line 90
    iget v7, v0, La8/q;->j:I

    .line 91
    .line 92
    iput v7, v1, La8/i0;->e0:I

    .line 93
    .line 94
    iput-boolean v2, v1, La8/i0;->r1:Z

    .line 95
    .line 96
    iget-wide v7, v0, La8/q;->s:J

    .line 97
    .line 98
    iput-wide v7, v1, La8/i0;->I:J

    .line 99
    .line 100
    new-instance v11, La8/f0;

    .line 101
    .line 102
    invoke-direct {v11, v1}, La8/f0;-><init>(La8/i0;)V

    .line 103
    .line 104
    .line 105
    iput-object v11, v1, La8/i0;->D:La8/f0;

    .line 106
    .line 107
    new-instance v7, La8/g0;

    .line 108
    .line 109
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 110
    .line 111
    .line 112
    iput-object v7, v1, La8/i0;->E:La8/g0;

    .line 113
    .line 114
    new-instance v10, Landroid/os/Handler;

    .line 115
    .line 116
    invoke-direct {v10, v5}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 117
    .line 118
    .line 119
    iget-object v7, v0, La8/q;->c:La8/d;

    .line 120
    .line 121
    invoke-virtual {v7}, La8/d;->get()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    move-object v9, v7

    .line 126
    check-cast v9, Lb81/c;

    .line 127
    .line 128
    move-object v12, v11

    .line 129
    move-object v13, v11

    .line 130
    move-object v14, v11

    .line 131
    invoke-virtual/range {v9 .. v14}, Lb81/c;->k(Landroid/os/Handler;La8/f0;La8/f0;La8/f0;La8/f0;)[La8/f;

    .line 132
    .line 133
    .line 134
    move-result-object v7

    .line 135
    iput-object v7, v1, La8/i0;->k:[La8/f;

    .line 136
    .line 137
    array-length v8, v7

    .line 138
    const/4 v9, 0x1

    .line 139
    if-lez v8, :cond_0

    .line 140
    .line 141
    move v8, v9

    .line 142
    goto :goto_0

    .line 143
    :cond_0
    move v8, v2

    .line 144
    :goto_0
    invoke-static {v8}, Lw7/a;->j(Z)V

    .line 145
    .line 146
    .line 147
    array-length v7, v7

    .line 148
    new-array v7, v7, [La8/f;

    .line 149
    .line 150
    iput-object v7, v1, La8/i0;->l:[La8/f;

    .line 151
    .line 152
    move v7, v2

    .line 153
    :goto_1
    iget-object v8, v1, La8/i0;->l:[La8/f;

    .line 154
    .line 155
    array-length v10, v8

    .line 156
    const/4 v11, 0x0

    .line 157
    if-ge v7, v10, :cond_1

    .line 158
    .line 159
    iget-object v10, v1, La8/i0;->k:[La8/f;

    .line 160
    .line 161
    aget-object v10, v10, v7

    .line 162
    .line 163
    iget v10, v10, La8/f;->e:I

    .line 164
    .line 165
    aput-object v11, v8, v7

    .line 166
    .line 167
    add-int/lit8 v7, v7, 0x1

    .line 168
    .line 169
    goto :goto_1

    .line 170
    :catchall_0
    move-exception v0

    .line 171
    goto/16 :goto_5

    .line 172
    .line 173
    :cond_1
    iget-object v7, v0, La8/q;->e:La8/d;

    .line 174
    .line 175
    invoke-virtual {v7}, La8/d;->get()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v7

    .line 179
    check-cast v7, Lh/w;

    .line 180
    .line 181
    iput-object v7, v1, La8/i0;->m:Lh/w;

    .line 182
    .line 183
    iget-object v7, v0, La8/q;->d:La8/d;

    .line 184
    .line 185
    invoke-virtual {v7}, La8/d;->get()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v7

    .line 189
    check-cast v7, Lh8/a0;

    .line 190
    .line 191
    iput-object v7, v1, La8/i0;->v:Lh8/a0;

    .line 192
    .line 193
    iget-object v7, v0, La8/q;->f:La8/d;

    .line 194
    .line 195
    invoke-virtual {v7}, La8/d;->get()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v7

    .line 199
    check-cast v7, Lk8/d;

    .line 200
    .line 201
    iput-object v7, v1, La8/i0;->y:Lk8/d;

    .line 202
    .line 203
    iget-boolean v7, v0, La8/q;->k:Z

    .line 204
    .line 205
    iput-boolean v7, v1, La8/i0;->u:Z

    .line 206
    .line 207
    iget-object v7, v0, La8/q;->l:La8/r1;

    .line 208
    .line 209
    iput-object v7, v1, La8/i0;->S:La8/r1;

    .line 210
    .line 211
    iget-wide v7, v0, La8/q;->n:J

    .line 212
    .line 213
    iput-wide v7, v1, La8/i0;->z:J

    .line 214
    .line 215
    iget-wide v7, v0, La8/q;->o:J

    .line 216
    .line 217
    iput-wide v7, v1, La8/i0;->A:J

    .line 218
    .line 219
    iget-wide v7, v0, La8/q;->p:J

    .line 220
    .line 221
    iput-wide v7, v1, La8/i0;->B:J

    .line 222
    .line 223
    iget-object v7, v0, La8/q;->m:La8/q1;

    .line 224
    .line 225
    iput-object v7, v1, La8/i0;->R:La8/q1;

    .line 226
    .line 227
    iput-object v5, v1, La8/i0;->x:Landroid/os/Looper;

    .line 228
    .line 229
    iput-object v6, v1, La8/i0;->C:Lw7/r;

    .line 230
    .line 231
    iput-object v1, v1, La8/i0;->j:La8/i0;

    .line 232
    .line 233
    new-instance v7, Le30/v;

    .line 234
    .line 235
    new-instance v8, La6/a;

    .line 236
    .line 237
    invoke-direct {v8, v1}, La6/a;-><init>(La8/i0;)V

    .line 238
    .line 239
    .line 240
    invoke-direct {v7, v5, v6, v8}, Le30/v;-><init>(Landroid/os/Looper;Lw7/r;Lw7/k;)V

    .line 241
    .line 242
    .line 243
    iput-object v7, v1, La8/i0;->q:Le30/v;

    .line 244
    .line 245
    new-instance v5, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 246
    .line 247
    invoke-direct {v5}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 248
    .line 249
    .line 250
    iput-object v5, v1, La8/i0;->r:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 251
    .line 252
    new-instance v5, Ljava/util/ArrayList;

    .line 253
    .line 254
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 255
    .line 256
    .line 257
    iput-object v5, v1, La8/i0;->t:Ljava/util/ArrayList;

    .line 258
    .line 259
    new-instance v5, Lh8/a1;

    .line 260
    .line 261
    invoke-direct {v5}, Lh8/a1;-><init>()V

    .line 262
    .line 263
    .line 264
    iput-object v5, v1, La8/i0;->T:Lh8/a1;

    .line 265
    .line 266
    sget-object v5, La8/r;->a:La8/r;

    .line 267
    .line 268
    iput-object v5, v1, La8/i0;->U:La8/r;

    .line 269
    .line 270
    new-instance v5, Lj8/s;

    .line 271
    .line 272
    iget-object v6, v1, La8/i0;->k:[La8/f;

    .line 273
    .line 274
    array-length v7, v6

    .line 275
    new-array v7, v7, [La8/o1;

    .line 276
    .line 277
    array-length v6, v6

    .line 278
    new-array v6, v6, [Lj8/q;

    .line 279
    .line 280
    sget-object v8, Lt7/w0;->b:Lt7/w0;

    .line 281
    .line 282
    invoke-direct {v5, v7, v6, v8, v11}, Lj8/s;-><init>([La8/o1;[Lj8/q;Lt7/w0;Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    iput-object v5, v1, La8/i0;->f:Lj8/s;

    .line 286
    .line 287
    new-instance v5, Lt7/n0;

    .line 288
    .line 289
    invoke-direct {v5}, Lt7/n0;-><init>()V

    .line 290
    .line 291
    .line 292
    iput-object v5, v1, La8/i0;->s:Lt7/n0;

    .line 293
    .line 294
    new-instance v5, Landroid/util/SparseBooleanArray;

    .line 295
    .line 296
    invoke-direct {v5}, Landroid/util/SparseBooleanArray;-><init>()V

    .line 297
    .line 298
    .line 299
    const/16 v6, 0x14

    .line 300
    .line 301
    new-array v7, v6, [I

    .line 302
    .line 303
    fill-array-data v7, :array_0

    .line 304
    .line 305
    .line 306
    move v8, v2

    .line 307
    :goto_2
    if-ge v8, v6, :cond_2

    .line 308
    .line 309
    aget v10, v7, v8

    .line 310
    .line 311
    const/4 v12, 0x0

    .line 312
    xor-int/2addr v12, v9

    .line 313
    invoke-static {v12}, Lw7/a;->j(Z)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {v5, v10, v9}, Landroid/util/SparseBooleanArray;->append(IZ)V

    .line 317
    .line 318
    .line 319
    add-int/lit8 v8, v8, 0x1

    .line 320
    .line 321
    goto :goto_2

    .line 322
    :cond_2
    iget-object v6, v1, La8/i0;->m:Lh/w;

    .line 323
    .line 324
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 325
    .line 326
    .line 327
    const/4 v6, 0x0

    .line 328
    xor-int/2addr v6, v9

    .line 329
    invoke-static {v6}, Lw7/a;->j(Z)V

    .line 330
    .line 331
    .line 332
    const/16 v6, 0x1d

    .line 333
    .line 334
    invoke-virtual {v5, v6, v9}, Landroid/util/SparseBooleanArray;->append(IZ)V

    .line 335
    .line 336
    .line 337
    new-instance v6, Lt7/h0;

    .line 338
    .line 339
    const/4 v7, 0x0

    .line 340
    xor-int/2addr v7, v9

    .line 341
    invoke-static {v7}, Lw7/a;->j(Z)V

    .line 342
    .line 343
    .line 344
    new-instance v7, Lt7/m;

    .line 345
    .line 346
    invoke-direct {v7, v5}, Lt7/m;-><init>(Landroid/util/SparseBooleanArray;)V

    .line 347
    .line 348
    .line 349
    invoke-direct {v6, v7}, Lt7/h0;-><init>(Lt7/m;)V

    .line 350
    .line 351
    .line 352
    iput-object v6, v1, La8/i0;->g:Lt7/h0;

    .line 353
    .line 354
    new-instance v5, Landroid/util/SparseBooleanArray;

    .line 355
    .line 356
    invoke-direct {v5}, Landroid/util/SparseBooleanArray;-><init>()V

    .line 357
    .line 358
    .line 359
    move v6, v2

    .line 360
    :goto_3
    iget-object v8, v7, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 361
    .line 362
    invoke-virtual {v8}, Landroid/util/SparseBooleanArray;->size()I

    .line 363
    .line 364
    .line 365
    move-result v8

    .line 366
    if-ge v6, v8, :cond_3

    .line 367
    .line 368
    invoke-virtual {v7, v6}, Lt7/m;->a(I)I

    .line 369
    .line 370
    .line 371
    move-result v8

    .line 372
    const/4 v10, 0x0

    .line 373
    xor-int/2addr v10, v9

    .line 374
    invoke-static {v10}, Lw7/a;->j(Z)V

    .line 375
    .line 376
    .line 377
    invoke-virtual {v5, v8, v9}, Landroid/util/SparseBooleanArray;->append(IZ)V

    .line 378
    .line 379
    .line 380
    add-int/lit8 v6, v6, 0x1

    .line 381
    .line 382
    goto :goto_3

    .line 383
    :cond_3
    const/4 v6, 0x0

    .line 384
    xor-int/2addr v6, v9

    .line 385
    invoke-static {v6}, Lw7/a;->j(Z)V

    .line 386
    .line 387
    .line 388
    const/4 v6, 0x4

    .line 389
    invoke-virtual {v5, v6, v9}, Landroid/util/SparseBooleanArray;->append(IZ)V

    .line 390
    .line 391
    .line 392
    const/4 v7, 0x0

    .line 393
    xor-int/2addr v7, v9

    .line 394
    invoke-static {v7}, Lw7/a;->j(Z)V

    .line 395
    .line 396
    .line 397
    const/16 v7, 0xa

    .line 398
    .line 399
    invoke-virtual {v5, v7, v9}, Landroid/util/SparseBooleanArray;->append(IZ)V

    .line 400
    .line 401
    .line 402
    new-instance v7, Lt7/h0;

    .line 403
    .line 404
    const/4 v8, 0x0

    .line 405
    xor-int/2addr v8, v9

    .line 406
    invoke-static {v8}, Lw7/a;->j(Z)V

    .line 407
    .line 408
    .line 409
    new-instance v8, Lt7/m;

    .line 410
    .line 411
    invoke-direct {v8, v5}, Lt7/m;-><init>(Landroid/util/SparseBooleanArray;)V

    .line 412
    .line 413
    .line 414
    invoke-direct {v7, v8}, Lt7/h0;-><init>(Lt7/m;)V

    .line 415
    .line 416
    .line 417
    iput-object v7, v1, La8/i0;->V:Lt7/h0;

    .line 418
    .line 419
    iget-object v5, v1, La8/i0;->C:Lw7/r;

    .line 420
    .line 421
    iget-object v7, v1, La8/i0;->x:Landroid/os/Looper;

    .line 422
    .line 423
    invoke-virtual {v5, v7, v11}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 424
    .line 425
    .line 426
    move-result-object v5

    .line 427
    iput-object v5, v1, La8/i0;->n:Lw7/t;

    .line 428
    .line 429
    new-instance v5, La8/y;

    .line 430
    .line 431
    invoke-direct {v5, v1}, La8/y;-><init>(La8/i0;)V

    .line 432
    .line 433
    .line 434
    iput-object v5, v1, La8/i0;->o:La8/y;

    .line 435
    .line 436
    iget-object v7, v1, La8/i0;->f:Lj8/s;

    .line 437
    .line 438
    invoke-static {v7}, La8/i1;->k(Lj8/s;)La8/i1;

    .line 439
    .line 440
    .line 441
    move-result-object v7

    .line 442
    iput-object v7, v1, La8/i0;->y1:La8/i1;

    .line 443
    .line 444
    iget-object v7, v1, La8/i0;->w:Lb8/e;

    .line 445
    .line 446
    iget-object v8, v1, La8/i0;->j:La8/i0;

    .line 447
    .line 448
    iget-object v10, v1, La8/i0;->x:Landroid/os/Looper;

    .line 449
    .line 450
    invoke-virtual {v7, v8, v10}, Lb8/e;->N(La8/i0;Landroid/os/Looper;)V

    .line 451
    .line 452
    .line 453
    new-instance v7, Lb8/k;

    .line 454
    .line 455
    iget-object v8, v0, La8/q;->v:Ljava/lang/String;

    .line 456
    .line 457
    invoke-direct {v7, v8}, Lb8/k;-><init>(Ljava/lang/String;)V

    .line 458
    .line 459
    .line 460
    new-instance v12, La8/q0;

    .line 461
    .line 462
    iget-object v13, v1, La8/i0;->i:Landroid/content/Context;

    .line 463
    .line 464
    iget-object v14, v1, La8/i0;->k:[La8/f;

    .line 465
    .line 466
    iget-object v15, v1, La8/i0;->l:[La8/f;

    .line 467
    .line 468
    iget-object v8, v1, La8/i0;->m:Lh/w;

    .line 469
    .line 470
    iget-object v10, v1, La8/i0;->f:Lj8/s;

    .line 471
    .line 472
    new-instance v18, La8/k;

    .line 473
    .line 474
    invoke-direct/range {v18 .. v18}, La8/k;-><init>()V

    .line 475
    .line 476
    .line 477
    iget-object v6, v1, La8/i0;->y:Lk8/d;

    .line 478
    .line 479
    iget v11, v1, La8/i0;->K:I

    .line 480
    .line 481
    iget-boolean v9, v1, La8/i0;->L:Z

    .line 482
    .line 483
    iget-object v2, v1, La8/i0;->w:Lb8/e;

    .line 484
    .line 485
    move-object/from16 v22, v2

    .line 486
    .line 487
    iget-object v2, v1, La8/i0;->S:La8/r1;

    .line 488
    .line 489
    move-object/from16 v23, v2

    .line 490
    .line 491
    iget-object v2, v0, La8/q;->q:La8/i;

    .line 492
    .line 493
    move-object/from16 v29, v5

    .line 494
    .line 495
    move-object/from16 v19, v6

    .line 496
    .line 497
    iget-wide v5, v0, La8/q;->r:J

    .line 498
    .line 499
    move-object/from16 v24, v2

    .line 500
    .line 501
    iget-object v2, v1, La8/i0;->x:Landroid/os/Looper;

    .line 502
    .line 503
    move-object/from16 v27, v2

    .line 504
    .line 505
    iget-object v2, v1, La8/i0;->C:Lw7/r;

    .line 506
    .line 507
    move-object/from16 v28, v2

    .line 508
    .line 509
    iget-object v2, v1, La8/i0;->U:La8/r;

    .line 510
    .line 511
    move-object/from16 v31, v2

    .line 512
    .line 513
    iget-object v2, v1, La8/i0;->E:La8/g0;

    .line 514
    .line 515
    move-object/from16 v32, v2

    .line 516
    .line 517
    move-wide/from16 v25, v5

    .line 518
    .line 519
    move-object/from16 v30, v7

    .line 520
    .line 521
    move-object/from16 v16, v8

    .line 522
    .line 523
    move/from16 v21, v9

    .line 524
    .line 525
    move-object/from16 v17, v10

    .line 526
    .line 527
    move/from16 v20, v11

    .line 528
    .line 529
    invoke-direct/range {v12 .. v32}, La8/q0;-><init>(Landroid/content/Context;[La8/f;[La8/f;Lh/w;Lj8/s;La8/k;Lk8/d;IZLb8/e;La8/r1;La8/i;JLandroid/os/Looper;Lw7/r;La8/y;Lb8/k;La8/r;Lm8/x;)V

    .line 530
    .line 531
    .line 532
    move-object/from16 v2, v30

    .line 533
    .line 534
    iget-object v5, v12, La8/q0;->k:Lw7/t;

    .line 535
    .line 536
    iput-object v12, v1, La8/i0;->p:La8/q0;

    .line 537
    .line 538
    iget-object v8, v12, La8/q0;->m:Landroid/os/Looper;

    .line 539
    .line 540
    const/high16 v6, 0x3f800000    # 1.0f

    .line 541
    .line 542
    iput v6, v1, La8/i0;->q1:F

    .line 543
    .line 544
    const/4 v6, 0x0

    .line 545
    iput v6, v1, La8/i0;->K:I

    .line 546
    .line 547
    sget-object v6, Lt7/a0;->B:Lt7/a0;

    .line 548
    .line 549
    iput-object v6, v1, La8/i0;->W:Lt7/a0;

    .line 550
    .line 551
    iput-object v6, v1, La8/i0;->x1:Lt7/a0;

    .line 552
    .line 553
    const/4 v13, -0x1

    .line 554
    iput v13, v1, La8/i0;->z1:I

    .line 555
    .line 556
    sget-object v6, Lv7/c;->c:Lv7/c;

    .line 557
    .line 558
    iput-object v6, v1, La8/i0;->s1:Lv7/c;

    .line 559
    .line 560
    const/4 v6, 0x1

    .line 561
    iput-boolean v6, v1, La8/i0;->t1:Z

    .line 562
    .line 563
    iget-object v6, v1, La8/i0;->w:Lb8/e;

    .line 564
    .line 565
    iget-object v7, v1, La8/i0;->q:Le30/v;

    .line 566
    .line 567
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 568
    .line 569
    .line 570
    invoke-virtual {v7, v6}, Le30/v;->a(Ljava/lang/Object;)V

    .line 571
    .line 572
    .line 573
    iget-object v6, v1, La8/i0;->y:Lk8/d;

    .line 574
    .line 575
    new-instance v7, Landroid/os/Handler;

    .line 576
    .line 577
    iget-object v9, v1, La8/i0;->x:Landroid/os/Looper;

    .line 578
    .line 579
    invoke-direct {v7, v9}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 580
    .line 581
    .line 582
    iget-object v9, v1, La8/i0;->w:Lb8/e;

    .line 583
    .line 584
    check-cast v6, Lk8/g;

    .line 585
    .line 586
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 587
    .line 588
    .line 589
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 590
    .line 591
    .line 592
    iget-object v6, v6, Lk8/g;->c:Lh6/e;

    .line 593
    .line 594
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 595
    .line 596
    .line 597
    iget-object v6, v6, Lh6/e;->e:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast v6, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 600
    .line 601
    invoke-virtual {v6}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 602
    .line 603
    .line 604
    move-result-object v10

    .line 605
    :cond_4
    :goto_4
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 606
    .line 607
    .line 608
    move-result v11

    .line 609
    if-eqz v11, :cond_5

    .line 610
    .line 611
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object v11

    .line 615
    check-cast v11, Lk8/c;

    .line 616
    .line 617
    iget-object v14, v11, Lk8/c;->b:Lb8/e;

    .line 618
    .line 619
    if-ne v14, v9, :cond_4

    .line 620
    .line 621
    const/4 v14, 0x1

    .line 622
    iput-boolean v14, v11, Lk8/c;->c:Z

    .line 623
    .line 624
    invoke-virtual {v6, v11}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 625
    .line 626
    .line 627
    goto :goto_4

    .line 628
    :cond_5
    new-instance v10, Lk8/c;

    .line 629
    .line 630
    invoke-direct {v10, v7, v9}, Lk8/c;-><init>(Landroid/os/Handler;Lb8/e;)V

    .line 631
    .line 632
    .line 633
    invoke-virtual {v6, v10}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 634
    .line 635
    .line 636
    iget-object v6, v1, La8/i0;->D:La8/f0;

    .line 637
    .line 638
    iget-object v7, v1, La8/i0;->r:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 639
    .line 640
    invoke-virtual {v7, v6}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 641
    .line 642
    .line 643
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 644
    .line 645
    const/16 v14, 0x1f

    .line 646
    .line 647
    if-lt v6, v14, :cond_6

    .line 648
    .line 649
    iget-object v6, v1, La8/i0;->i:Landroid/content/Context;

    .line 650
    .line 651
    iget-boolean v7, v0, La8/q;->t:Z

    .line 652
    .line 653
    iget-object v9, v1, La8/i0;->C:Lw7/r;

    .line 654
    .line 655
    iget-object v10, v12, La8/q0;->m:Landroid/os/Looper;

    .line 656
    .line 657
    const/4 v11, 0x0

    .line 658
    invoke-virtual {v9, v10, v11}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 659
    .line 660
    .line 661
    move-result-object v9

    .line 662
    new-instance v10, La8/c0;

    .line 663
    .line 664
    invoke-direct {v10, v6, v7, v1, v2}, La8/c0;-><init>(Landroid/content/Context;ZLa8/i0;Lb8/k;)V

    .line 665
    .line 666
    .line 667
    invoke-virtual {v9, v10}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 668
    .line 669
    .line 670
    :cond_6
    new-instance v2, Lca/j;

    .line 671
    .line 672
    iget-object v6, v1, La8/i0;->x:Landroid/os/Looper;

    .line 673
    .line 674
    iget-object v7, v1, La8/i0;->C:Lw7/r;

    .line 675
    .line 676
    new-instance v9, La8/y;

    .line 677
    .line 678
    invoke-direct {v9, v1}, La8/y;-><init>(La8/i0;)V

    .line 679
    .line 680
    .line 681
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 682
    .line 683
    .line 684
    const/4 v11, 0x0

    .line 685
    invoke-virtual {v7, v8, v11}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 686
    .line 687
    .line 688
    move-result-object v10

    .line 689
    iput-object v10, v2, Lca/j;->b:Ljava/lang/Object;

    .line 690
    .line 691
    invoke-virtual {v7, v6, v11}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    .line 692
    .line 693
    .line 694
    move-result-object v6

    .line 695
    iput-object v6, v2, Lca/j;->c:Ljava/lang/Object;

    .line 696
    .line 697
    iput-object v3, v2, Lca/j;->e:Ljava/lang/Object;

    .line 698
    .line 699
    iput-object v3, v2, Lca/j;->f:Ljava/lang/Object;

    .line 700
    .line 701
    iput-object v9, v2, Lca/j;->d:Ljava/lang/Object;

    .line 702
    .line 703
    iput-object v2, v1, La8/i0;->J:Lca/j;

    .line 704
    .line 705
    new-instance v6, La0/d;

    .line 706
    .line 707
    const/4 v12, 0x3

    .line 708
    invoke-direct {v6, v1, v12}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 709
    .line 710
    .line 711
    invoke-virtual {v2, v6}, Lca/j;->k(Ljava/lang/Runnable;)V

    .line 712
    .line 713
    .line 714
    new-instance v6, La8/b;

    .line 715
    .line 716
    iget-object v7, v0, La8/q;->a:Landroid/content/Context;

    .line 717
    .line 718
    iget-object v9, v0, La8/q;->g:Landroid/os/Looper;

    .line 719
    .line 720
    iget-object v10, v1, La8/i0;->D:La8/f0;

    .line 721
    .line 722
    iget-object v11, v1, La8/i0;->C:Lw7/r;

    .line 723
    .line 724
    invoke-direct/range {v6 .. v11}, La8/b;-><init>(Landroid/content/Context;Landroid/os/Looper;Landroid/os/Looper;La8/f0;Lw7/r;)V

    .line 725
    .line 726
    .line 727
    iput-object v6, v1, La8/i0;->F:La8/b;

    .line 728
    .line 729
    invoke-virtual {v6}, La8/b;->p()V

    .line 730
    .line 731
    .line 732
    new-instance v0, La8/t1;

    .line 733
    .line 734
    iget-object v2, v1, La8/i0;->C:Lw7/r;

    .line 735
    .line 736
    const/4 v6, 0x0

    .line 737
    invoke-direct {v0, v4, v8, v2, v6}, La8/t1;-><init>(Landroid/content/Context;Landroid/os/Looper;Lw7/r;I)V

    .line 738
    .line 739
    .line 740
    iput-object v0, v1, La8/i0;->G:La8/t1;

    .line 741
    .line 742
    new-instance v0, La8/t1;

    .line 743
    .line 744
    iget-object v2, v1, La8/i0;->C:Lw7/r;

    .line 745
    .line 746
    const/4 v6, 0x1

    .line 747
    invoke-direct {v0, v4, v8, v2, v6}, La8/t1;-><init>(Landroid/content/Context;Landroid/os/Looper;Lw7/r;I)V

    .line 748
    .line 749
    .line 750
    iput-object v0, v1, La8/i0;->H:La8/t1;

    .line 751
    .line 752
    sget v0, Lt7/h;->c:I

    .line 753
    .line 754
    sget-object v0, Lt7/a1;->d:Lt7/a1;

    .line 755
    .line 756
    iput-object v0, v1, La8/i0;->w1:Lt7/a1;

    .line 757
    .line 758
    sget-object v0, Lw7/q;->c:Lw7/q;

    .line 759
    .line 760
    iput-object v0, v1, La8/i0;->f0:Lw7/q;

    .line 761
    .line 762
    iget-object v0, v1, La8/i0;->R:La8/q1;

    .line 763
    .line 764
    const/16 v2, 0x26

    .line 765
    .line 766
    invoke-virtual {v5, v2, v0}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 767
    .line 768
    .line 769
    move-result-object v0

    .line 770
    invoke-virtual {v0}, Lw7/s;->b()V

    .line 771
    .line 772
    .line 773
    iget-object v0, v1, La8/i0;->g0:Lt7/c;

    .line 774
    .line 775
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 776
    .line 777
    .line 778
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 779
    .line 780
    .line 781
    move-result-object v2

    .line 782
    iget-object v4, v5, Lw7/t;->a:Landroid/os/Handler;

    .line 783
    .line 784
    const/4 v6, 0x0

    .line 785
    invoke-virtual {v4, v14, v6, v6, v0}, Landroid/os/Handler;->obtainMessage(IIILjava/lang/Object;)Landroid/os/Message;

    .line 786
    .line 787
    .line 788
    move-result-object v0

    .line 789
    iput-object v0, v2, Lw7/s;->a:Landroid/os/Message;

    .line 790
    .line 791
    invoke-virtual {v2}, Lw7/s;->b()V

    .line 792
    .line 793
    .line 794
    iget-object v0, v1, La8/i0;->g0:Lt7/c;

    .line 795
    .line 796
    const/4 v6, 0x1

    .line 797
    invoke-virtual {v1, v6, v0, v12}, La8/i0;->A0(ILjava/lang/Object;I)V

    .line 798
    .line 799
    .line 800
    iget v0, v1, La8/i0;->e0:I

    .line 801
    .line 802
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 803
    .line 804
    .line 805
    move-result-object v0

    .line 806
    const/4 v2, 0x2

    .line 807
    const/4 v4, 0x4

    .line 808
    invoke-virtual {v1, v2, v0, v4}, La8/i0;->A0(ILjava/lang/Object;I)V

    .line 809
    .line 810
    .line 811
    const/4 v0, 0x5

    .line 812
    invoke-virtual {v1, v2, v3, v0}, La8/i0;->A0(ILjava/lang/Object;I)V

    .line 813
    .line 814
    .line 815
    iget-boolean v0, v1, La8/i0;->r1:Z

    .line 816
    .line 817
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 818
    .line 819
    .line 820
    move-result-object v0

    .line 821
    const/16 v2, 0x9

    .line 822
    .line 823
    const/4 v6, 0x1

    .line 824
    invoke-virtual {v1, v6, v0, v2}, La8/i0;->A0(ILjava/lang/Object;I)V

    .line 825
    .line 826
    .line 827
    iget-object v0, v1, La8/i0;->E:La8/g0;

    .line 828
    .line 829
    const/4 v2, 0x6

    .line 830
    const/16 v3, 0x8

    .line 831
    .line 832
    invoke-virtual {v1, v2, v0, v3}, La8/i0;->A0(ILjava/lang/Object;I)V

    .line 833
    .line 834
    .line 835
    iget v0, v1, La8/i0;->v1:I

    .line 836
    .line 837
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 838
    .line 839
    .line 840
    move-result-object v0

    .line 841
    const/16 v2, 0x10

    .line 842
    .line 843
    invoke-virtual {v1, v13, v0, v2}, La8/i0;->A0(ILjava/lang/Object;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 844
    .line 845
    .line 846
    iget-object v0, v1, La8/i0;->h:Lw7/e;

    .line 847
    .line 848
    invoke-virtual {v0}, Lw7/e;->c()Z

    .line 849
    .line 850
    .line 851
    return-void

    .line 852
    :goto_5
    iget-object v1, v1, La8/i0;->h:Lw7/e;

    .line 853
    .line 854
    invoke-virtual {v1}, Lw7/e;->c()Z

    .line 855
    .line 856
    .line 857
    throw v0

    .line 858
    nop

    .line 859
    :array_0
    .array-data 4
        0x1
        0x2
        0x3
        0xd
        0xe
        0xf
        0x10
        0x11
        0x12
        0x13
        0x1f
        0x14
        0x1e
        0x15
        0x23
        0x16
        0x18
        0x1b
        0x1c
        0x20
    .end array-data
.end method

.method public static p0(La8/i1;)J
    .locals 6

    .line 1
    new-instance v0, Lt7/o0;

    .line 2
    .line 3
    invoke-direct {v0}, Lt7/o0;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lt7/n0;

    .line 7
    .line 8
    invoke-direct {v1}, Lt7/n0;-><init>()V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, La8/i1;->a:Lt7/p0;

    .line 12
    .line 13
    iget-object v3, p0, La8/i1;->b:Lh8/b0;

    .line 14
    .line 15
    iget-object v3, v3, Lh8/b0;->a:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-virtual {v2, v3, v1}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 18
    .line 19
    .line 20
    iget-wide v2, p0, La8/i1;->c:J

    .line 21
    .line 22
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    cmp-long v4, v2, v4

    .line 28
    .line 29
    if-nez v4, :cond_0

    .line 30
    .line 31
    iget-object p0, p0, La8/i1;->a:Lt7/p0;

    .line 32
    .line 33
    iget v1, v1, Lt7/n0;->c:I

    .line 34
    .line 35
    const-wide/16 v2, 0x0

    .line 36
    .line 37
    invoke-virtual {p0, v1, v0, v2, v3}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    iget-wide v0, p0, Lt7/o0;->k:J

    .line 42
    .line 43
    return-wide v0

    .line 44
    :cond_0
    iget-wide v0, v1, Lt7/n0;->e:J

    .line 45
    .line 46
    add-long/2addr v0, v2

    .line 47
    return-wide v0
.end method

.method public static s0(La8/i1;I)La8/i1;
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, La8/i1;->h(I)La8/i1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x1

    .line 6
    if-eq p1, v0, :cond_1

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    if-ne p1, v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object p0

    .line 13
    :cond_1
    :goto_0
    const/4 p1, 0x0

    .line 14
    invoke-virtual {p0, p1}, La8/i1;->b(Z)La8/i1;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method


# virtual methods
.method public final A0(ILjava/lang/Object;I)V
    .locals 6

    .line 1
    iget-object v0, p0, La8/i0;->k:[La8/f;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    :goto_0
    const/4 v4, -0x1

    .line 7
    if-ge v3, v1, :cond_2

    .line 8
    .line 9
    aget-object v5, v0, v3

    .line 10
    .line 11
    if-eq p1, v4, :cond_0

    .line 12
    .line 13
    iget v4, v5, La8/f;->e:I

    .line 14
    .line 15
    if-ne v4, p1, :cond_1

    .line 16
    .line 17
    :cond_0
    invoke-virtual {p0, v5}, La8/i0;->d0(La8/k1;)La8/l1;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-boolean v5, v4, La8/l1;->f:Z

    .line 22
    .line 23
    xor-int/lit8 v5, v5, 0x1

    .line 24
    .line 25
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 26
    .line 27
    .line 28
    iput p3, v4, La8/l1;->c:I

    .line 29
    .line 30
    iget-boolean v5, v4, La8/l1;->f:Z

    .line 31
    .line 32
    xor-int/lit8 v5, v5, 0x1

    .line 33
    .line 34
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 35
    .line 36
    .line 37
    iput-object p2, v4, La8/l1;->d:Ljava/lang/Object;

    .line 38
    .line 39
    invoke-virtual {v4}, La8/l1;->b()V

    .line 40
    .line 41
    .line 42
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    iget-object v0, p0, La8/i0;->l:[La8/f;

    .line 46
    .line 47
    array-length v1, v0

    .line 48
    :goto_1
    if-ge v2, v1, :cond_5

    .line 49
    .line 50
    aget-object v3, v0, v2

    .line 51
    .line 52
    if-eqz v3, :cond_4

    .line 53
    .line 54
    if-eq p1, v4, :cond_3

    .line 55
    .line 56
    iget v5, v3, La8/f;->e:I

    .line 57
    .line 58
    if-ne v5, p1, :cond_4

    .line 59
    .line 60
    :cond_3
    invoke-virtual {p0, v3}, La8/i0;->d0(La8/k1;)La8/l1;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    iget-boolean v5, v3, La8/l1;->f:Z

    .line 65
    .line 66
    xor-int/lit8 v5, v5, 0x1

    .line 67
    .line 68
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 69
    .line 70
    .line 71
    iput p3, v3, La8/l1;->c:I

    .line 72
    .line 73
    iget-boolean v5, v3, La8/l1;->f:Z

    .line 74
    .line 75
    xor-int/lit8 v5, v5, 0x1

    .line 76
    .line 77
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 78
    .line 79
    .line 80
    iput-object p2, v3, La8/l1;->d:Ljava/lang/Object;

    .line 81
    .line 82
    invoke-virtual {v3}, La8/l1;->b()V

    .line 83
    .line 84
    .line 85
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_5
    return-void
.end method

.method public final B0(Landroid/view/SurfaceHolder;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, La8/i0;->c0:Z

    .line 3
    .line 4
    iput-object p1, p0, La8/i0;->a0:Landroid/view/SurfaceHolder;

    .line 5
    .line 6
    iget-object v1, p0, La8/i0;->D:La8/f0;

    .line 7
    .line 8
    invoke-interface {p1, v1}, Landroid/view/SurfaceHolder;->addCallback(Landroid/view/SurfaceHolder$Callback;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, La8/i0;->a0:Landroid/view/SurfaceHolder;

    .line 12
    .line 13
    invoke-interface {p1}, Landroid/view/SurfaceHolder;->getSurface()Landroid/view/Surface;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/view/Surface;->isValid()Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    iget-object p1, p0, La8/i0;->a0:Landroid/view/SurfaceHolder;

    .line 26
    .line 27
    invoke-interface {p1}, Landroid/view/SurfaceHolder;->getSurfaceFrame()Landroid/graphics/Rect;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p1}, Landroid/graphics/Rect;->width()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-virtual {p1}, Landroid/graphics/Rect;->height()I

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    invoke-virtual {p0, v0, p1}, La8/i0;->v0(II)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_0
    invoke-virtual {p0, v0, v0}, La8/i0;->v0(II)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final C0(I)V
    .locals 4

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget v0, p0, La8/i0;->K:I

    .line 5
    .line 6
    if-eq v0, p1, :cond_0

    .line 7
    .line 8
    iput p1, p0, La8/i0;->K:I

    .line 9
    .line 10
    iget-object v0, p0, La8/i0;->p:La8/q0;

    .line 11
    .line 12
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 22
    .line 23
    const/16 v2, 0xb

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-virtual {v0, v2, p1, v3}, Landroid/os/Handler;->obtainMessage(III)Landroid/os/Message;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iput-object v0, v1, Lw7/s;->a:Landroid/os/Message;

    .line 31
    .line 32
    invoke-virtual {v1}, Lw7/s;->b()V

    .line 33
    .line 34
    .line 35
    new-instance v0, La8/w;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    invoke-direct {v0, p1, v1}, La8/w;-><init>(II)V

    .line 39
    .line 40
    .line 41
    iget-object p1, p0, La8/i0;->q:Le30/v;

    .line 42
    .line 43
    const/16 v1, 0x8

    .line 44
    .line 45
    invoke-virtual {p1, v1, v0}, Le30/v;->c(ILw7/j;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, La8/i0;->H0()V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1}, Le30/v;->b()V

    .line 52
    .line 53
    .line 54
    :cond_0
    return-void
.end method

.method public final D0(Lt7/u0;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, La8/i0;->m:Lh/w;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, La8/i0;->q0()Lt7/u0;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-boolean v2, p0, La8/i0;->P:Z

    .line 14
    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    iget-object v2, p1, Lt7/u0;->t:Lhr/k0;

    .line 18
    .line 19
    iput-object v2, p0, La8/i0;->Q:Lhr/k0;

    .line 20
    .line 21
    iget-object v2, p0, La8/i0;->R:La8/q1;

    .line 22
    .line 23
    iget-object v2, v2, La8/q1;->a:Lhr/k0;

    .line 24
    .line 25
    invoke-virtual {p1}, Lt7/u0;->a()Lt7/t0;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    invoke-virtual {v2}, Lhr/k0;->s()Lhr/l1;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    if-eqz v4, :cond_0

    .line 38
    .line 39
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    const/4 v5, 0x1

    .line 50
    invoke-virtual {v3, v4, v5}, Lt7/t0;->i(IZ)Lt7/t0;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    invoke-virtual {v3}, Lt7/t0;->a()Lt7/u0;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    goto :goto_1

    .line 59
    :cond_1
    move-object v2, p1

    .line 60
    :goto_1
    move-object v3, v0

    .line 61
    check-cast v3, Lj8/o;

    .line 62
    .line 63
    invoke-virtual {v3}, Lj8/o;->s()Lj8/i;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-virtual {v2, v3}, Lt7/u0;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-nez v3, :cond_2

    .line 72
    .line 73
    invoke-virtual {v0, v2}, Lh/w;->o(Lt7/u0;)V

    .line 74
    .line 75
    .line 76
    :cond_2
    invoke-virtual {v1, p1}, Lt7/u0;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-nez v0, :cond_3

    .line 81
    .line 82
    new-instance v0, La8/t;

    .line 83
    .line 84
    const/4 v1, 0x1

    .line 85
    invoke-direct {v0, p1, v1}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    iget-object p0, p0, La8/i0;->q:Le30/v;

    .line 89
    .line 90
    const/16 p1, 0x13

    .line 91
    .line 92
    invoke-virtual {p0, p1, v0}, Le30/v;->e(ILw7/j;)V

    .line 93
    .line 94
    .line 95
    :cond_3
    return-void
.end method

.method public final E0(Ljava/lang/Object;)V
    .locals 10

    .line 1
    iget-object v0, p0, La8/i0;->Y:Ljava/lang/Object;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    if-eq v0, p1, :cond_0

    .line 7
    .line 8
    move v0, v1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    iget-wide v4, p0, La8/i0;->I:J

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-wide v4, v2

    .line 22
    :goto_1
    iget-object v6, p0, La8/i0;->p:La8/q0;

    .line 23
    .line 24
    iget-boolean v7, v6, La8/q0;->K:Z

    .line 25
    .line 26
    if-nez v7, :cond_3

    .line 27
    .line 28
    iget-object v7, v6, La8/q0;->m:Landroid/os/Looper;

    .line 29
    .line 30
    invoke-virtual {v7}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 31
    .line 32
    .line 33
    move-result-object v7

    .line 34
    invoke-virtual {v7}, Ljava/lang/Thread;->isAlive()Z

    .line 35
    .line 36
    .line 37
    move-result v7

    .line 38
    if-nez v7, :cond_2

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    new-instance v7, Lw7/e;

    .line 42
    .line 43
    iget-object v8, v6, La8/q0;->s:Lw7/r;

    .line 44
    .line 45
    invoke-direct {v7, v8}, Lw7/e;-><init>(Lw7/r;)V

    .line 46
    .line 47
    .line 48
    iget-object v6, v6, La8/q0;->k:Lw7/t;

    .line 49
    .line 50
    new-instance v8, Landroid/util/Pair;

    .line 51
    .line 52
    invoke-direct {v8, p1, v7}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    const/16 v9, 0x1e

    .line 56
    .line 57
    invoke-virtual {v6, v9, v8}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    invoke-virtual {v6}, Lw7/s;->b()V

    .line 62
    .line 63
    .line 64
    cmp-long v2, v4, v2

    .line 65
    .line 66
    if-eqz v2, :cond_3

    .line 67
    .line 68
    invoke-virtual {v7, v4, v5}, Lw7/e;->b(J)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    :cond_3
    :goto_2
    if-eqz v0, :cond_4

    .line 73
    .line 74
    iget-object v0, p0, La8/i0;->Y:Ljava/lang/Object;

    .line 75
    .line 76
    iget-object v2, p0, La8/i0;->Z:Landroid/view/Surface;

    .line 77
    .line 78
    if-ne v0, v2, :cond_4

    .line 79
    .line 80
    invoke-virtual {v2}, Landroid/view/Surface;->release()V

    .line 81
    .line 82
    .line 83
    const/4 v0, 0x0

    .line 84
    iput-object v0, p0, La8/i0;->Z:Landroid/view/Surface;

    .line 85
    .line 86
    :cond_4
    iput-object p1, p0, La8/i0;->Y:Ljava/lang/Object;

    .line 87
    .line 88
    if-nez v1, :cond_5

    .line 89
    .line 90
    new-instance p1, La8/r0;

    .line 91
    .line 92
    const-string v0, "Detaching surface timed out."

    .line 93
    .line 94
    invoke-direct {p1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    new-instance v0, La8/o;

    .line 98
    .line 99
    const/4 v1, 0x2

    .line 100
    const/16 v2, 0x3eb

    .line 101
    .line 102
    invoke-direct {v0, v1, p1, v2}, La8/o;-><init>(ILjava/lang/Exception;I)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {p0, v0}, La8/i0;->G0(La8/o;)V

    .line 106
    .line 107
    .line 108
    :cond_5
    return-void
.end method

.method public final F0(F)V
    .locals 3

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    const/high16 v1, 0x3f800000    # 1.0f

    .line 6
    .line 7
    invoke-static {p1, v0, v1}, Lw7/w;->f(FFF)F

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    iget v0, p0, La8/i0;->q1:F

    .line 12
    .line 13
    cmpl-float v0, v0, p1

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iput p1, p0, La8/i0;->q1:F

    .line 19
    .line 20
    iget-object v0, p0, La8/i0;->p:La8/q0;

    .line 21
    .line 22
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 23
    .line 24
    const/16 v1, 0x20

    .line 25
    .line 26
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v0, v1, v2}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v0}, Lw7/s;->b()V

    .line 35
    .line 36
    .line 37
    new-instance v0, La8/a0;

    .line 38
    .line 39
    invoke-direct {v0, p1}, La8/a0;-><init>(F)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, La8/i0;->q:Le30/v;

    .line 43
    .line 44
    const/16 p1, 0x16

    .line 45
    .line 46
    invoke-virtual {p0, p1, v0}, Le30/v;->e(ILw7/j;)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final G0(La8/o;)V
    .locals 11

    .line 1
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 2
    .line 3
    iget-object v1, v0, La8/i1;->b:Lh8/b0;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, La8/i1;->c(Lh8/b0;)La8/i1;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-wide v1, v0, La8/i1;->s:J

    .line 10
    .line 11
    iput-wide v1, v0, La8/i1;->q:J

    .line 12
    .line 13
    const-wide/16 v1, 0x0

    .line 14
    .line 15
    iput-wide v1, v0, La8/i1;->r:J

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-static {v0, v1}, La8/i0;->s0(La8/i1;I)La8/i1;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    invoke-virtual {v0, p1}, La8/i1;->f(La8/o;)La8/i1;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    :cond_0
    move-object v3, v0

    .line 29
    iget p1, p0, La8/i0;->M:I

    .line 30
    .line 31
    add-int/2addr p1, v1

    .line 32
    iput p1, p0, La8/i0;->M:I

    .line 33
    .line 34
    iget-object p1, p0, La8/i0;->p:La8/q0;

    .line 35
    .line 36
    iget-object p1, p1, La8/q0;->k:Lw7/t;

    .line 37
    .line 38
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iget-object p1, p1, Lw7/t;->a:Landroid/os/Handler;

    .line 46
    .line 47
    const/4 v1, 0x6

    .line 48
    invoke-virtual {p1, v1}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    iput-object p1, v0, Lw7/s;->a:Landroid/os/Message;

    .line 53
    .line 54
    invoke-virtual {v0}, Lw7/s;->b()V

    .line 55
    .line 56
    .line 57
    const/4 v9, -0x1

    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v4, 0x0

    .line 60
    const/4 v5, 0x0

    .line 61
    const/4 v6, 0x5

    .line 62
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 63
    .line 64
    .line 65
    .line 66
    .line 67
    move-object v2, p0

    .line 68
    invoke-virtual/range {v2 .. v10}, La8/i0;->J0(La8/i1;IZIJIZ)V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public final H0()V
    .locals 15

    .line 1
    iget-object v0, p0, La8/i0;->V:Lt7/h0;

    .line 2
    .line 3
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v1, p0, La8/i0;->j:La8/i0;

    .line 6
    .line 7
    invoke-virtual {v1}, La8/i0;->r0()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {v1}, Lap0/o;->L()Z

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-virtual {v1}, La8/i0;->k0()Lt7/p0;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual {v4}, Lt7/p0;->p()Z

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x1

    .line 25
    const/4 v8, -0x1

    .line 26
    if-eqz v5, :cond_0

    .line 27
    .line 28
    move v4, v8

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {v1}, La8/i0;->h0()I

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 35
    .line 36
    .line 37
    iget v9, v1, La8/i0;->K:I

    .line 38
    .line 39
    if-ne v9, v7, :cond_1

    .line 40
    .line 41
    move v9, v6

    .line 42
    :cond_1
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 43
    .line 44
    .line 45
    iget-boolean v10, v1, La8/i0;->L:Z

    .line 46
    .line 47
    invoke-virtual {v4, v5, v9, v10}, Lt7/p0;->k(IIZ)I

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    :goto_0
    if-eq v4, v8, :cond_2

    .line 52
    .line 53
    move v4, v7

    .line 54
    goto :goto_1

    .line 55
    :cond_2
    move v4, v6

    .line 56
    :goto_1
    invoke-virtual {v1}, La8/i0;->k0()Lt7/p0;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    invoke-virtual {v5}, Lt7/p0;->p()Z

    .line 61
    .line 62
    .line 63
    move-result v9

    .line 64
    if-eqz v9, :cond_3

    .line 65
    .line 66
    move v5, v8

    .line 67
    goto :goto_2

    .line 68
    :cond_3
    invoke-virtual {v1}, La8/i0;->h0()I

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 73
    .line 74
    .line 75
    iget v10, v1, La8/i0;->K:I

    .line 76
    .line 77
    if-ne v10, v7, :cond_4

    .line 78
    .line 79
    move v10, v6

    .line 80
    :cond_4
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 81
    .line 82
    .line 83
    iget-boolean v11, v1, La8/i0;->L:Z

    .line 84
    .line 85
    invoke-virtual {v5, v9, v10, v11}, Lt7/p0;->e(IIZ)I

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    :goto_2
    if-eq v5, v8, :cond_5

    .line 90
    .line 91
    move v5, v7

    .line 92
    goto :goto_3

    .line 93
    :cond_5
    move v5, v6

    .line 94
    :goto_3
    invoke-virtual {v1}, Lap0/o;->K()Z

    .line 95
    .line 96
    .line 97
    move-result v8

    .line 98
    invoke-virtual {v1}, Lap0/o;->J()Z

    .line 99
    .line 100
    .line 101
    move-result v9

    .line 102
    invoke-virtual {v1}, La8/i0;->k0()Lt7/p0;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    new-instance v10, Lt1/j0;

    .line 111
    .line 112
    invoke-direct {v10, v7}, Lt1/j0;-><init>(I)V

    .line 113
    .line 114
    .line 115
    iget-object v11, v10, Lt1/j0;->e:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v11, Lb6/f;

    .line 118
    .line 119
    iget-object v12, p0, La8/i0;->g:Lt7/h0;

    .line 120
    .line 121
    iget-object v12, v12, Lt7/h0;->a:Lt7/m;

    .line 122
    .line 123
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    move v13, v6

    .line 127
    :goto_4
    iget-object v14, v12, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 128
    .line 129
    invoke-virtual {v14}, Landroid/util/SparseBooleanArray;->size()I

    .line 130
    .line 131
    .line 132
    move-result v14

    .line 133
    if-ge v13, v14, :cond_6

    .line 134
    .line 135
    invoke-virtual {v12, v13}, Lt7/m;->a(I)I

    .line 136
    .line 137
    .line 138
    move-result v14

    .line 139
    invoke-virtual {v11, v14}, Lb6/f;->h(I)V

    .line 140
    .line 141
    .line 142
    add-int/lit8 v13, v13, 0x1

    .line 143
    .line 144
    goto :goto_4

    .line 145
    :cond_6
    xor-int/lit8 v12, v2, 0x1

    .line 146
    .line 147
    const/4 v13, 0x4

    .line 148
    invoke-virtual {v10, v13, v12}, Lt1/j0;->l(IZ)V

    .line 149
    .line 150
    .line 151
    if-eqz v3, :cond_7

    .line 152
    .line 153
    if-nez v2, :cond_7

    .line 154
    .line 155
    move v13, v7

    .line 156
    goto :goto_5

    .line 157
    :cond_7
    move v13, v6

    .line 158
    :goto_5
    const/4 v14, 0x5

    .line 159
    invoke-virtual {v10, v14, v13}, Lt1/j0;->l(IZ)V

    .line 160
    .line 161
    .line 162
    if-eqz v4, :cond_8

    .line 163
    .line 164
    if-nez v2, :cond_8

    .line 165
    .line 166
    move v13, v7

    .line 167
    goto :goto_6

    .line 168
    :cond_8
    move v13, v6

    .line 169
    :goto_6
    const/4 v14, 0x6

    .line 170
    invoke-virtual {v10, v14, v13}, Lt1/j0;->l(IZ)V

    .line 171
    .line 172
    .line 173
    if-nez v1, :cond_a

    .line 174
    .line 175
    if-nez v4, :cond_9

    .line 176
    .line 177
    if-eqz v8, :cond_9

    .line 178
    .line 179
    if-eqz v3, :cond_a

    .line 180
    .line 181
    :cond_9
    if-nez v2, :cond_a

    .line 182
    .line 183
    move v4, v7

    .line 184
    goto :goto_7

    .line 185
    :cond_a
    move v4, v6

    .line 186
    :goto_7
    const/4 v13, 0x7

    .line 187
    invoke-virtual {v10, v13, v4}, Lt1/j0;->l(IZ)V

    .line 188
    .line 189
    .line 190
    if-eqz v5, :cond_b

    .line 191
    .line 192
    if-nez v2, :cond_b

    .line 193
    .line 194
    move v4, v7

    .line 195
    goto :goto_8

    .line 196
    :cond_b
    move v4, v6

    .line 197
    :goto_8
    const/16 v13, 0x8

    .line 198
    .line 199
    invoke-virtual {v10, v13, v4}, Lt1/j0;->l(IZ)V

    .line 200
    .line 201
    .line 202
    if-nez v1, :cond_d

    .line 203
    .line 204
    if-nez v5, :cond_c

    .line 205
    .line 206
    if-eqz v8, :cond_d

    .line 207
    .line 208
    if-eqz v9, :cond_d

    .line 209
    .line 210
    :cond_c
    if-nez v2, :cond_d

    .line 211
    .line 212
    move v1, v7

    .line 213
    goto :goto_9

    .line 214
    :cond_d
    move v1, v6

    .line 215
    :goto_9
    const/16 v4, 0x9

    .line 216
    .line 217
    invoke-virtual {v10, v4, v1}, Lt1/j0;->l(IZ)V

    .line 218
    .line 219
    .line 220
    const/16 v1, 0xa

    .line 221
    .line 222
    invoke-virtual {v10, v1, v12}, Lt1/j0;->l(IZ)V

    .line 223
    .line 224
    .line 225
    if-eqz v3, :cond_e

    .line 226
    .line 227
    if-nez v2, :cond_e

    .line 228
    .line 229
    move v1, v7

    .line 230
    goto :goto_a

    .line 231
    :cond_e
    move v1, v6

    .line 232
    :goto_a
    const/16 v4, 0xb

    .line 233
    .line 234
    invoke-virtual {v10, v4, v1}, Lt1/j0;->l(IZ)V

    .line 235
    .line 236
    .line 237
    if-eqz v3, :cond_f

    .line 238
    .line 239
    if-nez v2, :cond_f

    .line 240
    .line 241
    move v6, v7

    .line 242
    :cond_f
    const/16 v1, 0xc

    .line 243
    .line 244
    invoke-virtual {v10, v1, v6}, Lt1/j0;->l(IZ)V

    .line 245
    .line 246
    .line 247
    new-instance v1, Lt7/h0;

    .line 248
    .line 249
    invoke-virtual {v11}, Lb6/f;->i()Lt7/m;

    .line 250
    .line 251
    .line 252
    move-result-object v2

    .line 253
    invoke-direct {v1, v2}, Lt7/h0;-><init>(Lt7/m;)V

    .line 254
    .line 255
    .line 256
    iput-object v1, p0, La8/i0;->V:Lt7/h0;

    .line 257
    .line 258
    invoke-virtual {v1, v0}, Lt7/h0;->equals(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v0

    .line 262
    if-nez v0, :cond_10

    .line 263
    .line 264
    new-instance v0, La8/y;

    .line 265
    .line 266
    invoke-direct {v0, p0}, La8/y;-><init>(La8/i0;)V

    .line 267
    .line 268
    .line 269
    iget-object p0, p0, La8/i0;->q:Le30/v;

    .line 270
    .line 271
    const/16 v1, 0xd

    .line 272
    .line 273
    invoke-virtual {p0, v1, v0}, Le30/v;->c(ILw7/j;)V

    .line 274
    .line 275
    .line 276
    :cond_10
    return-void
.end method

.method public final I0(IZ)V
    .locals 13

    .line 1
    iget-boolean v0, p0, La8/i0;->P:Z

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move v0, v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 10
    .line 11
    iget v0, v0, La8/i1;->n:I

    .line 12
    .line 13
    if-ne v0, v2, :cond_1

    .line 14
    .line 15
    if-nez p2, :cond_1

    .line 16
    .line 17
    move v0, v2

    .line 18
    goto :goto_0

    .line 19
    :cond_1
    const/4 v0, 0x0

    .line 20
    :goto_0
    iget-object v3, p0, La8/i0;->y1:La8/i1;

    .line 21
    .line 22
    iget-boolean v4, v3, La8/i1;->l:Z

    .line 23
    .line 24
    if-ne v4, p2, :cond_2

    .line 25
    .line 26
    iget v4, v3, La8/i1;->n:I

    .line 27
    .line 28
    if-ne v4, v0, :cond_2

    .line 29
    .line 30
    iget v4, v3, La8/i1;->m:I

    .line 31
    .line 32
    if-ne v4, p1, :cond_2

    .line 33
    .line 34
    return-void

    .line 35
    :cond_2
    iget v4, p0, La8/i0;->M:I

    .line 36
    .line 37
    add-int/2addr v4, v2

    .line 38
    iput v4, p0, La8/i0;->M:I

    .line 39
    .line 40
    iget-boolean v4, v3, La8/i1;->p:Z

    .line 41
    .line 42
    if-eqz v4, :cond_3

    .line 43
    .line 44
    invoke-virtual {v3}, La8/i1;->a()La8/i1;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    :cond_3
    invoke-virtual {v3, p1, v0, p2}, La8/i1;->e(IIZ)La8/i1;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    shl-int/2addr v0, v1

    .line 53
    or-int/2addr p1, v0

    .line 54
    iget-object v0, p0, La8/i0;->p:La8/q0;

    .line 55
    .line 56
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 66
    .line 67
    invoke-virtual {v0, v2, p2, p1}, Landroid/os/Handler;->obtainMessage(III)Landroid/os/Message;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, v1, Lw7/s;->a:Landroid/os/Message;

    .line 72
    .line 73
    invoke-virtual {v1}, Lw7/s;->b()V

    .line 74
    .line 75
    .line 76
    const/4 v11, -0x1

    .line 77
    const/4 v12, 0x0

    .line 78
    const/4 v6, 0x0

    .line 79
    const/4 v7, 0x0

    .line 80
    const/4 v8, 0x5

    .line 81
    const-wide v9, -0x7fffffffffffffffL    # -4.9E-324

    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    move-object v4, p0

    .line 87
    invoke-virtual/range {v4 .. v12}, La8/i0;->J0(La8/i1;IZIJIZ)V

    .line 88
    .line 89
    .line 90
    return-void
.end method

.method public final J0(La8/i1;IZIJIZ)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p4

    .line 6
    .line 7
    iget-object v3, v0, La8/i0;->y1:La8/i1;

    .line 8
    .line 9
    iput-object v1, v0, La8/i0;->y1:La8/i1;

    .line 10
    .line 11
    iget-object v4, v3, La8/i1;->a:Lt7/p0;

    .line 12
    .line 13
    iget-object v5, v1, La8/i1;->a:Lt7/p0;

    .line 14
    .line 15
    invoke-virtual {v4, v5}, Lt7/p0;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    iget-object v5, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v5, Lt7/o0;

    .line 22
    .line 23
    iget-object v6, v0, La8/i0;->s:Lt7/n0;

    .line 24
    .line 25
    const/4 v7, -0x1

    .line 26
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object v8

    .line 30
    iget-object v9, v3, La8/i1;->a:Lt7/p0;

    .line 31
    .line 32
    iget-object v10, v3, La8/i1;->b:Lh8/b0;

    .line 33
    .line 34
    iget-object v11, v1, La8/i1;->a:Lt7/p0;

    .line 35
    .line 36
    iget-object v12, v1, La8/i1;->b:Lh8/b0;

    .line 37
    .line 38
    invoke-virtual {v11}, Lt7/p0;->p()Z

    .line 39
    .line 40
    .line 41
    move-result v13

    .line 42
    const/16 v16, 0x0

    .line 43
    .line 44
    const/16 v17, 0x2

    .line 45
    .line 46
    const-wide/16 v14, 0x0

    .line 47
    .line 48
    const/16 v18, 0x3

    .line 49
    .line 50
    if-eqz v13, :cond_0

    .line 51
    .line 52
    invoke-virtual {v9}, Lt7/p0;->p()Z

    .line 53
    .line 54
    .line 55
    move-result v13

    .line 56
    if-eqz v13, :cond_0

    .line 57
    .line 58
    new-instance v5, Landroid/util/Pair;

    .line 59
    .line 60
    sget-object v6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 61
    .line 62
    invoke-direct {v5, v6, v8}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto/16 :goto_1

    .line 66
    .line 67
    :cond_0
    invoke-virtual {v11}, Lt7/p0;->p()Z

    .line 68
    .line 69
    .line 70
    move-result v13

    .line 71
    invoke-virtual {v9}, Lt7/p0;->p()Z

    .line 72
    .line 73
    .line 74
    move-result v7

    .line 75
    if-eq v13, v7, :cond_1

    .line 76
    .line 77
    new-instance v5, Landroid/util/Pair;

    .line 78
    .line 79
    sget-object v6, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 80
    .line 81
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    invoke-direct {v5, v6, v7}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    goto/16 :goto_1

    .line 89
    .line 90
    :cond_1
    iget-object v7, v10, Lh8/b0;->a:Ljava/lang/Object;

    .line 91
    .line 92
    invoke-virtual {v9, v7, v6}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    iget v7, v7, Lt7/n0;->c:I

    .line 97
    .line 98
    invoke-virtual {v9, v7, v5, v14, v15}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 99
    .line 100
    .line 101
    move-result-object v7

    .line 102
    iget-object v7, v7, Lt7/o0;->a:Ljava/lang/Object;

    .line 103
    .line 104
    iget-object v9, v12, Lh8/b0;->a:Ljava/lang/Object;

    .line 105
    .line 106
    invoke-virtual {v11, v9, v6}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    iget v6, v6, Lt7/n0;->c:I

    .line 111
    .line 112
    invoke-virtual {v11, v6, v5, v14, v15}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    iget-object v5, v5, Lt7/o0;->a:Ljava/lang/Object;

    .line 117
    .line 118
    invoke-virtual {v7, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v5

    .line 122
    if-nez v5, :cond_5

    .line 123
    .line 124
    if-eqz p3, :cond_2

    .line 125
    .line 126
    if-nez v2, :cond_2

    .line 127
    .line 128
    const/4 v5, 0x1

    .line 129
    goto :goto_0

    .line 130
    :cond_2
    if-eqz p3, :cond_3

    .line 131
    .line 132
    const/4 v5, 0x1

    .line 133
    if-ne v2, v5, :cond_3

    .line 134
    .line 135
    move/from16 v5, v17

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_3
    if-nez v4, :cond_4

    .line 139
    .line 140
    move/from16 v5, v18

    .line 141
    .line 142
    :goto_0
    new-instance v6, Landroid/util/Pair;

    .line 143
    .line 144
    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 145
    .line 146
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object v5

    .line 150
    invoke-direct {v6, v7, v5}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    move-object v5, v6

    .line 154
    goto :goto_1

    .line 155
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 156
    .line 157
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 158
    .line 159
    .line 160
    throw v0

    .line 161
    :cond_5
    if-eqz p3, :cond_6

    .line 162
    .line 163
    if-nez v2, :cond_6

    .line 164
    .line 165
    iget-wide v5, v10, Lh8/b0;->d:J

    .line 166
    .line 167
    iget-wide v9, v12, Lh8/b0;->d:J

    .line 168
    .line 169
    cmp-long v5, v5, v9

    .line 170
    .line 171
    if-gez v5, :cond_6

    .line 172
    .line 173
    new-instance v5, Landroid/util/Pair;

    .line 174
    .line 175
    sget-object v6, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 176
    .line 177
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v7

    .line 181
    invoke-direct {v5, v6, v7}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    goto :goto_1

    .line 185
    :cond_6
    if-eqz p3, :cond_7

    .line 186
    .line 187
    const/4 v5, 0x1

    .line 188
    if-ne v2, v5, :cond_7

    .line 189
    .line 190
    if-eqz p8, :cond_7

    .line 191
    .line 192
    new-instance v5, Landroid/util/Pair;

    .line 193
    .line 194
    sget-object v6, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 195
    .line 196
    invoke-static/range {v17 .. v17}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 197
    .line 198
    .line 199
    move-result-object v7

    .line 200
    invoke-direct {v5, v6, v7}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    goto :goto_1

    .line 204
    :cond_7
    new-instance v5, Landroid/util/Pair;

    .line 205
    .line 206
    sget-object v6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 207
    .line 208
    invoke-direct {v5, v6, v8}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    :goto_1
    iget-object v6, v5, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast v6, Ljava/lang/Boolean;

    .line 214
    .line 215
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 216
    .line 217
    .line 218
    move-result v6

    .line 219
    iget-object v5, v5, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v5, Ljava/lang/Integer;

    .line 222
    .line 223
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 224
    .line 225
    .line 226
    move-result v5

    .line 227
    if-eqz v6, :cond_9

    .line 228
    .line 229
    iget-object v8, v1, La8/i1;->a:Lt7/p0;

    .line 230
    .line 231
    invoke-virtual {v8}, Lt7/p0;->p()Z

    .line 232
    .line 233
    .line 234
    move-result v8

    .line 235
    if-nez v8, :cond_8

    .line 236
    .line 237
    iget-object v8, v1, La8/i1;->a:Lt7/p0;

    .line 238
    .line 239
    iget-object v9, v1, La8/i1;->b:Lh8/b0;

    .line 240
    .line 241
    iget-object v9, v9, Lh8/b0;->a:Ljava/lang/Object;

    .line 242
    .line 243
    iget-object v10, v0, La8/i0;->s:Lt7/n0;

    .line 244
    .line 245
    invoke-virtual {v8, v9, v10}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 246
    .line 247
    .line 248
    move-result-object v8

    .line 249
    iget v8, v8, Lt7/n0;->c:I

    .line 250
    .line 251
    iget-object v9, v1, La8/i1;->a:Lt7/p0;

    .line 252
    .line 253
    iget-object v10, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 254
    .line 255
    check-cast v10, Lt7/o0;

    .line 256
    .line 257
    invoke-virtual {v9, v8, v10, v14, v15}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 258
    .line 259
    .line 260
    move-result-object v8

    .line 261
    iget-object v8, v8, Lt7/o0;->c:Lt7/x;

    .line 262
    .line 263
    goto :goto_2

    .line 264
    :cond_8
    const/4 v8, 0x0

    .line 265
    :goto_2
    sget-object v9, Lt7/a0;->B:Lt7/a0;

    .line 266
    .line 267
    iput-object v9, v0, La8/i0;->x1:Lt7/a0;

    .line 268
    .line 269
    goto :goto_3

    .line 270
    :cond_9
    const/4 v8, 0x0

    .line 271
    :goto_3
    if-nez v6, :cond_a

    .line 272
    .line 273
    iget-object v9, v3, La8/i1;->j:Ljava/util/List;

    .line 274
    .line 275
    iget-object v10, v1, La8/i1;->j:Ljava/util/List;

    .line 276
    .line 277
    invoke-interface {v9, v10}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 278
    .line 279
    .line 280
    move-result v9

    .line 281
    if-nez v9, :cond_d

    .line 282
    .line 283
    :cond_a
    iget-object v9, v0, La8/i0;->x1:Lt7/a0;

    .line 284
    .line 285
    invoke-virtual {v9}, Lt7/a0;->a()Lt7/z;

    .line 286
    .line 287
    .line 288
    move-result-object v9

    .line 289
    iget-object v10, v1, La8/i1;->j:Ljava/util/List;

    .line 290
    .line 291
    move/from16 v11, v16

    .line 292
    .line 293
    :goto_4
    invoke-interface {v10}, Ljava/util/List;->size()I

    .line 294
    .line 295
    .line 296
    move-result v12

    .line 297
    if-ge v11, v12, :cond_c

    .line 298
    .line 299
    invoke-interface {v10, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v12

    .line 303
    check-cast v12, Lt7/c0;

    .line 304
    .line 305
    move/from16 v13, v16

    .line 306
    .line 307
    :goto_5
    iget-object v7, v12, Lt7/c0;->a:[Lt7/b0;

    .line 308
    .line 309
    array-length v14, v7

    .line 310
    if-ge v13, v14, :cond_b

    .line 311
    .line 312
    aget-object v7, v7, v13

    .line 313
    .line 314
    invoke-interface {v7, v9}, Lt7/b0;->c(Lt7/z;)V

    .line 315
    .line 316
    .line 317
    add-int/lit8 v13, v13, 0x1

    .line 318
    .line 319
    const-wide/16 v14, 0x0

    .line 320
    .line 321
    goto :goto_5

    .line 322
    :cond_b
    add-int/lit8 v11, v11, 0x1

    .line 323
    .line 324
    const-wide/16 v14, 0x0

    .line 325
    .line 326
    goto :goto_4

    .line 327
    :cond_c
    new-instance v7, Lt7/a0;

    .line 328
    .line 329
    invoke-direct {v7, v9}, Lt7/a0;-><init>(Lt7/z;)V

    .line 330
    .line 331
    .line 332
    iput-object v7, v0, La8/i0;->x1:Lt7/a0;

    .line 333
    .line 334
    :cond_d
    invoke-virtual {v0}, La8/i0;->b0()Lt7/a0;

    .line 335
    .line 336
    .line 337
    move-result-object v7

    .line 338
    iget-object v9, v0, La8/i0;->W:Lt7/a0;

    .line 339
    .line 340
    invoke-virtual {v7, v9}, Lt7/a0;->equals(Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v9

    .line 344
    iput-object v7, v0, La8/i0;->W:Lt7/a0;

    .line 345
    .line 346
    iget-boolean v7, v3, La8/i1;->l:Z

    .line 347
    .line 348
    iget-boolean v10, v1, La8/i1;->l:Z

    .line 349
    .line 350
    if-eq v7, v10, :cond_e

    .line 351
    .line 352
    const/4 v7, 0x1

    .line 353
    goto :goto_6

    .line 354
    :cond_e
    move/from16 v7, v16

    .line 355
    .line 356
    :goto_6
    iget v10, v3, La8/i1;->e:I

    .line 357
    .line 358
    iget v11, v1, La8/i1;->e:I

    .line 359
    .line 360
    if-eq v10, v11, :cond_f

    .line 361
    .line 362
    const/4 v10, 0x1

    .line 363
    goto :goto_7

    .line 364
    :cond_f
    move/from16 v10, v16

    .line 365
    .line 366
    :goto_7
    if-nez v10, :cond_10

    .line 367
    .line 368
    if-eqz v7, :cond_11

    .line 369
    .line 370
    :cond_10
    invoke-virtual {v0}, La8/i0;->K0()V

    .line 371
    .line 372
    .line 373
    :cond_11
    iget-boolean v11, v3, La8/i1;->g:Z

    .line 374
    .line 375
    iget-boolean v12, v1, La8/i1;->g:Z

    .line 376
    .line 377
    if-eq v11, v12, :cond_12

    .line 378
    .line 379
    const/4 v11, 0x1

    .line 380
    goto :goto_8

    .line 381
    :cond_12
    move/from16 v11, v16

    .line 382
    .line 383
    :goto_8
    if-nez v4, :cond_13

    .line 384
    .line 385
    iget-object v4, v0, La8/i0;->q:Le30/v;

    .line 386
    .line 387
    new-instance v12, La8/s;

    .line 388
    .line 389
    const/4 v13, 0x0

    .line 390
    move/from16 v14, p2

    .line 391
    .line 392
    invoke-direct {v12, v1, v14, v13}, La8/s;-><init>(Ljava/lang/Object;II)V

    .line 393
    .line 394
    .line 395
    move/from16 v13, v16

    .line 396
    .line 397
    invoke-virtual {v4, v13, v12}, Le30/v;->c(ILw7/j;)V

    .line 398
    .line 399
    .line 400
    :cond_13
    if-eqz p3, :cond_1b

    .line 401
    .line 402
    new-instance v4, Lt7/n0;

    .line 403
    .line 404
    invoke-direct {v4}, Lt7/n0;-><init>()V

    .line 405
    .line 406
    .line 407
    iget-object v12, v3, La8/i1;->a:Lt7/p0;

    .line 408
    .line 409
    invoke-virtual {v12}, Lt7/p0;->p()Z

    .line 410
    .line 411
    .line 412
    move-result v12

    .line 413
    if-nez v12, :cond_14

    .line 414
    .line 415
    iget-object v12, v3, La8/i1;->b:Lh8/b0;

    .line 416
    .line 417
    iget-object v12, v12, Lh8/b0;->a:Ljava/lang/Object;

    .line 418
    .line 419
    iget-object v13, v3, La8/i1;->a:Lt7/p0;

    .line 420
    .line 421
    invoke-virtual {v13, v12, v4}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 422
    .line 423
    .line 424
    iget v13, v4, Lt7/n0;->c:I

    .line 425
    .line 426
    iget-object v14, v3, La8/i1;->a:Lt7/p0;

    .line 427
    .line 428
    invoke-virtual {v14, v12}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 429
    .line 430
    .line 431
    move-result v14

    .line 432
    iget-object v15, v3, La8/i1;->a:Lt7/p0;

    .line 433
    .line 434
    move/from16 v16, v6

    .line 435
    .line 436
    iget-object v6, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 437
    .line 438
    check-cast v6, Lt7/o0;

    .line 439
    .line 440
    move/from16 v19, v9

    .line 441
    .line 442
    move/from16 v20, v10

    .line 443
    .line 444
    const-wide/16 v9, 0x0

    .line 445
    .line 446
    invoke-virtual {v15, v13, v6, v9, v10}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 447
    .line 448
    .line 449
    move-result-object v6

    .line 450
    iget-object v6, v6, Lt7/o0;->a:Ljava/lang/Object;

    .line 451
    .line 452
    iget-object v9, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 453
    .line 454
    check-cast v9, Lt7/o0;

    .line 455
    .line 456
    iget-object v9, v9, Lt7/o0;->c:Lt7/x;

    .line 457
    .line 458
    move-object/from16 v22, v6

    .line 459
    .line 460
    move-object/from16 v24, v9

    .line 461
    .line 462
    move-object/from16 v25, v12

    .line 463
    .line 464
    move/from16 v23, v13

    .line 465
    .line 466
    move/from16 v26, v14

    .line 467
    .line 468
    goto :goto_9

    .line 469
    :cond_14
    move/from16 v16, v6

    .line 470
    .line 471
    move/from16 v19, v9

    .line 472
    .line 473
    move/from16 v20, v10

    .line 474
    .line 475
    move/from16 v23, p7

    .line 476
    .line 477
    const/16 v22, 0x0

    .line 478
    .line 479
    const/16 v24, 0x0

    .line 480
    .line 481
    const/16 v25, 0x0

    .line 482
    .line 483
    const/16 v26, -0x1

    .line 484
    .line 485
    :goto_9
    if-nez v2, :cond_17

    .line 486
    .line 487
    iget-object v6, v3, La8/i1;->b:Lh8/b0;

    .line 488
    .line 489
    invoke-virtual {v6}, Lh8/b0;->b()Z

    .line 490
    .line 491
    .line 492
    move-result v6

    .line 493
    if-eqz v6, :cond_15

    .line 494
    .line 495
    iget-object v6, v3, La8/i1;->b:Lh8/b0;

    .line 496
    .line 497
    iget v9, v6, Lh8/b0;->b:I

    .line 498
    .line 499
    iget v6, v6, Lh8/b0;->c:I

    .line 500
    .line 501
    invoke-virtual {v4, v9, v6}, Lt7/n0;->a(II)J

    .line 502
    .line 503
    .line 504
    move-result-wide v9

    .line 505
    invoke-static {v3}, La8/i0;->p0(La8/i1;)J

    .line 506
    .line 507
    .line 508
    move-result-wide v12

    .line 509
    goto :goto_c

    .line 510
    :cond_15
    iget-object v6, v3, La8/i1;->b:Lh8/b0;

    .line 511
    .line 512
    iget v6, v6, Lh8/b0;->e:I

    .line 513
    .line 514
    const/4 v9, -0x1

    .line 515
    if-eq v6, v9, :cond_16

    .line 516
    .line 517
    iget-object v4, v0, La8/i0;->y1:La8/i1;

    .line 518
    .line 519
    invoke-static {v4}, La8/i0;->p0(La8/i1;)J

    .line 520
    .line 521
    .line 522
    move-result-wide v9

    .line 523
    :goto_a
    move-wide v12, v9

    .line 524
    goto :goto_c

    .line 525
    :cond_16
    iget-wide v9, v4, Lt7/n0;->e:J

    .line 526
    .line 527
    iget-wide v12, v4, Lt7/n0;->d:J

    .line 528
    .line 529
    :goto_b
    add-long/2addr v9, v12

    .line 530
    goto :goto_a

    .line 531
    :cond_17
    iget-object v6, v3, La8/i1;->b:Lh8/b0;

    .line 532
    .line 533
    invoke-virtual {v6}, Lh8/b0;->b()Z

    .line 534
    .line 535
    .line 536
    move-result v6

    .line 537
    if-eqz v6, :cond_18

    .line 538
    .line 539
    iget-wide v9, v3, La8/i1;->s:J

    .line 540
    .line 541
    invoke-static {v3}, La8/i0;->p0(La8/i1;)J

    .line 542
    .line 543
    .line 544
    move-result-wide v12

    .line 545
    goto :goto_c

    .line 546
    :cond_18
    iget-wide v9, v4, Lt7/n0;->e:J

    .line 547
    .line 548
    iget-wide v12, v3, La8/i1;->s:J

    .line 549
    .line 550
    goto :goto_b

    .line 551
    :goto_c
    new-instance v21, Lt7/k0;

    .line 552
    .line 553
    invoke-static {v9, v10}, Lw7/w;->N(J)J

    .line 554
    .line 555
    .line 556
    move-result-wide v27

    .line 557
    invoke-static {v12, v13}, Lw7/w;->N(J)J

    .line 558
    .line 559
    .line 560
    move-result-wide v29

    .line 561
    iget-object v4, v3, La8/i1;->b:Lh8/b0;

    .line 562
    .line 563
    iget v6, v4, Lh8/b0;->b:I

    .line 564
    .line 565
    iget v4, v4, Lh8/b0;->c:I

    .line 566
    .line 567
    move/from16 v32, v4

    .line 568
    .line 569
    move/from16 v31, v6

    .line 570
    .line 571
    invoke-direct/range {v21 .. v32}, Lt7/k0;-><init>(Ljava/lang/Object;ILt7/x;Ljava/lang/Object;IJJII)V

    .line 572
    .line 573
    .line 574
    move-object/from16 v4, v21

    .line 575
    .line 576
    iget-object v6, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 577
    .line 578
    check-cast v6, Lt7/o0;

    .line 579
    .line 580
    invoke-virtual {v0}, La8/i0;->h0()I

    .line 581
    .line 582
    .line 583
    move-result v9

    .line 584
    iget-object v10, v0, La8/i0;->y1:La8/i1;

    .line 585
    .line 586
    iget-object v10, v10, La8/i1;->a:Lt7/p0;

    .line 587
    .line 588
    invoke-virtual {v10}, Lt7/p0;->p()Z

    .line 589
    .line 590
    .line 591
    move-result v10

    .line 592
    if-nez v10, :cond_19

    .line 593
    .line 594
    iget-object v10, v0, La8/i0;->y1:La8/i1;

    .line 595
    .line 596
    iget-object v12, v10, La8/i1;->b:Lh8/b0;

    .line 597
    .line 598
    iget-object v12, v12, Lh8/b0;->a:Ljava/lang/Object;

    .line 599
    .line 600
    iget-object v10, v10, La8/i1;->a:Lt7/p0;

    .line 601
    .line 602
    iget-object v13, v0, La8/i0;->s:Lt7/n0;

    .line 603
    .line 604
    invoke-virtual {v10, v12, v13}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 605
    .line 606
    .line 607
    iget-object v10, v0, La8/i0;->y1:La8/i1;

    .line 608
    .line 609
    iget-object v10, v10, La8/i1;->a:Lt7/p0;

    .line 610
    .line 611
    invoke-virtual {v10, v12}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 612
    .line 613
    .line 614
    move-result v10

    .line 615
    iget-object v13, v0, La8/i0;->y1:La8/i1;

    .line 616
    .line 617
    iget-object v13, v13, La8/i1;->a:Lt7/p0;

    .line 618
    .line 619
    const-wide/16 v14, 0x0

    .line 620
    .line 621
    invoke-virtual {v13, v9, v6, v14, v15}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 622
    .line 623
    .line 624
    move-result-object v13

    .line 625
    iget-object v13, v13, Lt7/o0;->a:Ljava/lang/Object;

    .line 626
    .line 627
    iget-object v6, v6, Lt7/o0;->c:Lt7/x;

    .line 628
    .line 629
    move-object/from16 v24, v6

    .line 630
    .line 631
    move/from16 v26, v10

    .line 632
    .line 633
    move-object/from16 v25, v12

    .line 634
    .line 635
    move-object/from16 v22, v13

    .line 636
    .line 637
    goto :goto_d

    .line 638
    :cond_19
    const/16 v22, 0x0

    .line 639
    .line 640
    const/16 v24, 0x0

    .line 641
    .line 642
    const/16 v25, 0x0

    .line 643
    .line 644
    const/16 v26, -0x1

    .line 645
    .line 646
    :goto_d
    invoke-static/range {p5 .. p6}, Lw7/w;->N(J)J

    .line 647
    .line 648
    .line 649
    move-result-wide v27

    .line 650
    new-instance v21, Lt7/k0;

    .line 651
    .line 652
    iget-object v6, v0, La8/i0;->y1:La8/i1;

    .line 653
    .line 654
    iget-object v6, v6, La8/i1;->b:Lh8/b0;

    .line 655
    .line 656
    invoke-virtual {v6}, Lh8/b0;->b()Z

    .line 657
    .line 658
    .line 659
    move-result v6

    .line 660
    if-eqz v6, :cond_1a

    .line 661
    .line 662
    iget-object v6, v0, La8/i0;->y1:La8/i1;

    .line 663
    .line 664
    invoke-static {v6}, La8/i0;->p0(La8/i1;)J

    .line 665
    .line 666
    .line 667
    move-result-wide v12

    .line 668
    invoke-static {v12, v13}, Lw7/w;->N(J)J

    .line 669
    .line 670
    .line 671
    move-result-wide v12

    .line 672
    move-wide/from16 v29, v12

    .line 673
    .line 674
    goto :goto_e

    .line 675
    :cond_1a
    move-wide/from16 v29, v27

    .line 676
    .line 677
    :goto_e
    iget-object v6, v0, La8/i0;->y1:La8/i1;

    .line 678
    .line 679
    iget-object v6, v6, La8/i1;->b:Lh8/b0;

    .line 680
    .line 681
    iget v10, v6, Lh8/b0;->b:I

    .line 682
    .line 683
    iget v6, v6, Lh8/b0;->c:I

    .line 684
    .line 685
    move/from16 v32, v6

    .line 686
    .line 687
    move/from16 v23, v9

    .line 688
    .line 689
    move/from16 v31, v10

    .line 690
    .line 691
    invoke-direct/range {v21 .. v32}, Lt7/k0;-><init>(Ljava/lang/Object;ILt7/x;Ljava/lang/Object;IJJII)V

    .line 692
    .line 693
    .line 694
    move-object/from16 v6, v21

    .line 695
    .line 696
    iget-object v9, v0, La8/i0;->q:Le30/v;

    .line 697
    .line 698
    new-instance v10, La8/b0;

    .line 699
    .line 700
    invoke-direct {v10, v2, v4, v6}, La8/b0;-><init>(ILt7/k0;Lt7/k0;)V

    .line 701
    .line 702
    .line 703
    const/16 v2, 0xb

    .line 704
    .line 705
    invoke-virtual {v9, v2, v10}, Le30/v;->c(ILw7/j;)V

    .line 706
    .line 707
    .line 708
    goto :goto_f

    .line 709
    :cond_1b
    move/from16 v16, v6

    .line 710
    .line 711
    move/from16 v19, v9

    .line 712
    .line 713
    move/from16 v20, v10

    .line 714
    .line 715
    :goto_f
    if-eqz v16, :cond_1c

    .line 716
    .line 717
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 718
    .line 719
    new-instance v4, La8/s;

    .line 720
    .line 721
    const/4 v6, 0x1

    .line 722
    invoke-direct {v4, v8, v5, v6}, La8/s;-><init>(Ljava/lang/Object;II)V

    .line 723
    .line 724
    .line 725
    const/4 v5, 0x1

    .line 726
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 727
    .line 728
    .line 729
    :cond_1c
    iget-object v2, v3, La8/i1;->f:La8/o;

    .line 730
    .line 731
    iget-object v4, v1, La8/i1;->f:La8/o;

    .line 732
    .line 733
    if-eq v2, v4, :cond_1d

    .line 734
    .line 735
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 736
    .line 737
    new-instance v4, La8/u;

    .line 738
    .line 739
    const/4 v5, 0x7

    .line 740
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 741
    .line 742
    .line 743
    const/16 v5, 0xa

    .line 744
    .line 745
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 746
    .line 747
    .line 748
    iget-object v2, v1, La8/i1;->f:La8/o;

    .line 749
    .line 750
    if-eqz v2, :cond_1d

    .line 751
    .line 752
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 753
    .line 754
    new-instance v4, La8/u;

    .line 755
    .line 756
    const/16 v6, 0x8

    .line 757
    .line 758
    invoke-direct {v4, v1, v6}, La8/u;-><init>(La8/i1;I)V

    .line 759
    .line 760
    .line 761
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 762
    .line 763
    .line 764
    :cond_1d
    iget-object v2, v3, La8/i1;->i:Lj8/s;

    .line 765
    .line 766
    iget-object v4, v1, La8/i1;->i:Lj8/s;

    .line 767
    .line 768
    if-eq v2, v4, :cond_1e

    .line 769
    .line 770
    iget-object v2, v0, La8/i0;->m:Lh/w;

    .line 771
    .line 772
    iget-object v4, v4, Lj8/s;->e:Ljava/lang/Object;

    .line 773
    .line 774
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 775
    .line 776
    .line 777
    check-cast v4, Lj8/r;

    .line 778
    .line 779
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 780
    .line 781
    new-instance v4, La8/u;

    .line 782
    .line 783
    const/16 v5, 0x9

    .line 784
    .line 785
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 786
    .line 787
    .line 788
    move/from16 v5, v17

    .line 789
    .line 790
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 791
    .line 792
    .line 793
    :cond_1e
    if-nez v19, :cond_1f

    .line 794
    .line 795
    iget-object v2, v0, La8/i0;->W:Lt7/a0;

    .line 796
    .line 797
    iget-object v4, v0, La8/i0;->q:Le30/v;

    .line 798
    .line 799
    new-instance v5, La8/t;

    .line 800
    .line 801
    const/4 v6, 0x0

    .line 802
    invoke-direct {v5, v2, v6}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 803
    .line 804
    .line 805
    const/16 v2, 0xe

    .line 806
    .line 807
    invoke-virtual {v4, v2, v5}, Le30/v;->c(ILw7/j;)V

    .line 808
    .line 809
    .line 810
    :cond_1f
    if-eqz v11, :cond_20

    .line 811
    .line 812
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 813
    .line 814
    new-instance v4, La8/u;

    .line 815
    .line 816
    const/4 v5, 0x0

    .line 817
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 818
    .line 819
    .line 820
    move/from16 v5, v18

    .line 821
    .line 822
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 823
    .line 824
    .line 825
    :cond_20
    if-nez v20, :cond_21

    .line 826
    .line 827
    if-eqz v7, :cond_22

    .line 828
    .line 829
    :cond_21
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 830
    .line 831
    new-instance v4, La8/u;

    .line 832
    .line 833
    const/4 v5, 0x1

    .line 834
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 835
    .line 836
    .line 837
    const/4 v9, -0x1

    .line 838
    invoke-virtual {v2, v9, v4}, Le30/v;->c(ILw7/j;)V

    .line 839
    .line 840
    .line 841
    :cond_22
    if-eqz v20, :cond_23

    .line 842
    .line 843
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 844
    .line 845
    new-instance v4, La8/u;

    .line 846
    .line 847
    const/4 v5, 0x2

    .line 848
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 849
    .line 850
    .line 851
    const/4 v5, 0x4

    .line 852
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 853
    .line 854
    .line 855
    :cond_23
    if-nez v7, :cond_24

    .line 856
    .line 857
    iget v2, v3, La8/i1;->m:I

    .line 858
    .line 859
    iget v4, v1, La8/i1;->m:I

    .line 860
    .line 861
    if-eq v2, v4, :cond_25

    .line 862
    .line 863
    :cond_24
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 864
    .line 865
    new-instance v4, La8/u;

    .line 866
    .line 867
    const/4 v5, 0x3

    .line 868
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 869
    .line 870
    .line 871
    const/4 v5, 0x5

    .line 872
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 873
    .line 874
    .line 875
    :cond_25
    iget v2, v3, La8/i1;->n:I

    .line 876
    .line 877
    iget v4, v1, La8/i1;->n:I

    .line 878
    .line 879
    if-eq v2, v4, :cond_26

    .line 880
    .line 881
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 882
    .line 883
    new-instance v4, La8/u;

    .line 884
    .line 885
    const/4 v5, 0x4

    .line 886
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 887
    .line 888
    .line 889
    const/4 v5, 0x6

    .line 890
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 891
    .line 892
    .line 893
    :cond_26
    invoke-virtual {v3}, La8/i1;->m()Z

    .line 894
    .line 895
    .line 896
    move-result v2

    .line 897
    invoke-virtual {v1}, La8/i1;->m()Z

    .line 898
    .line 899
    .line 900
    move-result v4

    .line 901
    if-eq v2, v4, :cond_27

    .line 902
    .line 903
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 904
    .line 905
    new-instance v4, La8/u;

    .line 906
    .line 907
    const/4 v5, 0x5

    .line 908
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 909
    .line 910
    .line 911
    const/4 v5, 0x7

    .line 912
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 913
    .line 914
    .line 915
    :cond_27
    iget-object v2, v3, La8/i1;->o:Lt7/g0;

    .line 916
    .line 917
    iget-object v4, v1, La8/i1;->o:Lt7/g0;

    .line 918
    .line 919
    invoke-virtual {v2, v4}, Lt7/g0;->equals(Ljava/lang/Object;)Z

    .line 920
    .line 921
    .line 922
    move-result v2

    .line 923
    if-nez v2, :cond_28

    .line 924
    .line 925
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 926
    .line 927
    new-instance v4, La8/u;

    .line 928
    .line 929
    const/4 v5, 0x6

    .line 930
    invoke-direct {v4, v1, v5}, La8/u;-><init>(La8/i1;I)V

    .line 931
    .line 932
    .line 933
    const/16 v5, 0xc

    .line 934
    .line 935
    invoke-virtual {v2, v5, v4}, Le30/v;->c(ILw7/j;)V

    .line 936
    .line 937
    .line 938
    :cond_28
    invoke-virtual {v0}, La8/i0;->H0()V

    .line 939
    .line 940
    .line 941
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 942
    .line 943
    invoke-virtual {v2}, Le30/v;->b()V

    .line 944
    .line 945
    .line 946
    iget-boolean v2, v3, La8/i1;->p:Z

    .line 947
    .line 948
    iget-boolean v1, v1, La8/i1;->p:Z

    .line 949
    .line 950
    if-eq v2, v1, :cond_29

    .line 951
    .line 952
    iget-object v0, v0, La8/i0;->r:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 953
    .line 954
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 955
    .line 956
    .line 957
    move-result-object v0

    .line 958
    :goto_10
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 959
    .line 960
    .line 961
    move-result v1

    .line 962
    if-eqz v1, :cond_29

    .line 963
    .line 964
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 965
    .line 966
    .line 967
    move-result-object v1

    .line 968
    check-cast v1, La8/f0;

    .line 969
    .line 970
    iget-object v1, v1, La8/f0;->d:La8/i0;

    .line 971
    .line 972
    invoke-virtual {v1}, La8/i0;->K0()V

    .line 973
    .line 974
    .line 975
    goto :goto_10

    .line 976
    :cond_29
    return-void
.end method

.method public final K0()V
    .locals 6

    .line 1
    invoke-virtual {p0}, La8/i0;->o0()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, La8/i0;->H:La8/t1;

    .line 6
    .line 7
    iget-object v2, p0, La8/i0;->G:La8/t1;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x1

    .line 11
    if-eq v0, v4, :cond_3

    .line 12
    .line 13
    const/4 v5, 0x2

    .line 14
    if-eq v0, v5, :cond_1

    .line 15
    .line 16
    const/4 v5, 0x3

    .line 17
    if-eq v0, v5, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x4

    .line 20
    if-ne v0, p0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 33
    .line 34
    iget-boolean v0, v0, La8/i1;->p:Z

    .line 35
    .line 36
    invoke-virtual {p0}, La8/i0;->n0()Z

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-eqz v5, :cond_2

    .line 41
    .line 42
    if-nez v0, :cond_2

    .line 43
    .line 44
    move v3, v4

    .line 45
    :cond_2
    invoke-virtual {v2, v3}, La8/t1;->c(Z)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, La8/i0;->n0()Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    invoke-virtual {v1, p0}, La8/t1;->c(Z)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :cond_3
    :goto_0
    invoke-virtual {v2, v3}, La8/t1;->c(Z)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1, v3}, La8/t1;->c(Z)V

    .line 60
    .line 61
    .line 62
    return-void
.end method

.method public final L0()V
    .locals 5

    .line 1
    iget-object v0, p0, La8/i0;->h:Lw7/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Lw7/e;->a()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v1, p0, La8/i0;->x:Landroid/os/Looper;

    .line 11
    .line 12
    invoke-virtual {v1}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    if-eq v0, v2, :cond_2

    .line 17
    .line 18
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {v1}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {v1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 35
    .line 36
    sget-object v2, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 37
    .line 38
    const-string v2, "\'\nExpected thread: \'"

    .line 39
    .line 40
    const-string v3, "\'\nSee https://developer.android.com/guide/topics/media/issues/player-accessed-on-wrong-thread"

    .line 41
    .line 42
    const-string v4, "Player is accessed on the wrong thread.\nCurrent thread: \'"

    .line 43
    .line 44
    invoke-static {v4, v0, v2, v1, v3}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iget-boolean v1, p0, La8/i0;->t1:Z

    .line 49
    .line 50
    if-nez v1, :cond_1

    .line 51
    .line 52
    iget-boolean v1, p0, La8/i0;->u1:Z

    .line 53
    .line 54
    if-eqz v1, :cond_0

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    goto :goto_0

    .line 58
    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    invoke-direct {v1}, Ljava/lang/IllegalStateException;-><init>()V

    .line 61
    .line 62
    .line 63
    :goto_0
    const-string v2, "ExoPlayerImpl"

    .line 64
    .line 65
    invoke-static {v2, v0, v1}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 66
    .line 67
    .line 68
    const/4 v0, 0x1

    .line 69
    iput-boolean v0, p0, La8/i0;->u1:Z

    .line 70
    .line 71
    return-void

    .line 72
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :cond_2
    return-void
.end method

.method public final P(JIZ)V
    .locals 10

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    const/4 v2, -0x1

    .line 5
    if-ne p3, v2, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    const/4 v3, 0x1

    .line 9
    if-ltz p3, :cond_1

    .line 10
    .line 11
    move v4, v3

    .line 12
    goto :goto_0

    .line 13
    :cond_1
    const/4 v4, 0x0

    .line 14
    :goto_0
    invoke-static {v4}, Lw7/a;->c(Z)V

    .line 15
    .line 16
    .line 17
    iget-object v4, p0, La8/i0;->y1:La8/i1;

    .line 18
    .line 19
    iget-object v4, v4, La8/i1;->a:Lt7/p0;

    .line 20
    .line 21
    invoke-virtual {v4}, Lt7/p0;->p()Z

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    if-nez v5, :cond_2

    .line 26
    .line 27
    invoke-virtual {v4}, Lt7/p0;->o()I

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-lt p3, v5, :cond_2

    .line 32
    .line 33
    :goto_1
    return-void

    .line 34
    :cond_2
    iget-object v5, p0, La8/i0;->w:Lb8/e;

    .line 35
    .line 36
    iget-boolean v6, v5, Lb8/e;->l:Z

    .line 37
    .line 38
    if-nez v6, :cond_3

    .line 39
    .line 40
    invoke-virtual {v5}, Lb8/e;->H()Lb8/a;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    iput-boolean v3, v5, Lb8/e;->l:Z

    .line 45
    .line 46
    new-instance v7, La6/a;

    .line 47
    .line 48
    const/16 v8, 0x13

    .line 49
    .line 50
    invoke-direct {v7, v8}, La6/a;-><init>(I)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v5, v6, v2, v7}, Lb8/e;->M(Lb8/a;ILw7/j;)V

    .line 54
    .line 55
    .line 56
    :cond_3
    iget v2, p0, La8/i0;->M:I

    .line 57
    .line 58
    add-int/2addr v2, v3

    .line 59
    iput v2, p0, La8/i0;->M:I

    .line 60
    .line 61
    invoke-virtual {p0}, La8/i0;->r0()Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_4

    .line 66
    .line 67
    const-string v1, "ExoPlayerImpl"

    .line 68
    .line 69
    const-string v2, "seekTo ignored because an ad is playing"

    .line 70
    .line 71
    invoke-static {v1, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    new-instance v1, La8/n0;

    .line 75
    .line 76
    iget-object v2, p0, La8/i0;->y1:La8/i1;

    .line 77
    .line 78
    invoke-direct {v1, v2}, La8/n0;-><init>(La8/i1;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1, v3}, La8/n0;->f(I)V

    .line 82
    .line 83
    .line 84
    iget-object v0, p0, La8/i0;->o:La8/y;

    .line 85
    .line 86
    iget-object v0, v0, La8/y;->d:La8/i0;

    .line 87
    .line 88
    iget-object v2, v0, La8/i0;->n:Lw7/t;

    .line 89
    .line 90
    new-instance v3, La8/z;

    .line 91
    .line 92
    const/4 v4, 0x0

    .line 93
    invoke-direct {v3, v4, v0, v1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v2, v3}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :cond_4
    iget-object v2, p0, La8/i0;->y1:La8/i1;

    .line 101
    .line 102
    iget v3, v2, La8/i1;->e:I

    .line 103
    .line 104
    const/4 v5, 0x3

    .line 105
    if-eq v3, v5, :cond_5

    .line 106
    .line 107
    const/4 v6, 0x4

    .line 108
    if-ne v3, v6, :cond_6

    .line 109
    .line 110
    invoke-virtual {v4}, Lt7/p0;->p()Z

    .line 111
    .line 112
    .line 113
    move-result v3

    .line 114
    if-nez v3, :cond_6

    .line 115
    .line 116
    :cond_5
    iget-object v2, p0, La8/i0;->y1:La8/i1;

    .line 117
    .line 118
    const/4 v3, 0x2

    .line 119
    invoke-virtual {v2, v3}, La8/i1;->h(I)La8/i1;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    :cond_6
    invoke-virtual {p0}, La8/i0;->h0()I

    .line 124
    .line 125
    .line 126
    move-result v7

    .line 127
    invoke-virtual {p0, v4, p3, p1, p2}, La8/i0;->u0(Lt7/p0;IJ)Landroid/util/Pair;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    invoke-virtual {p0, v2, v4, v3}, La8/i0;->t0(La8/i1;Lt7/p0;Landroid/util/Pair;)La8/i1;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    invoke-static {p1, p2}, Lw7/w;->D(J)J

    .line 136
    .line 137
    .line 138
    move-result-wide v8

    .line 139
    iget-object v3, p0, La8/i0;->p:La8/q0;

    .line 140
    .line 141
    iget-object v3, v3, La8/q0;->k:Lw7/t;

    .line 142
    .line 143
    new-instance v6, La8/p0;

    .line 144
    .line 145
    invoke-direct {v6, v4, p3, v8, v9}, La8/p0;-><init>(Lt7/p0;IJ)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v3, v5, v6}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    invoke-virtual {v1}, Lw7/s;->b()V

    .line 153
    .line 154
    .line 155
    const/4 v4, 0x1

    .line 156
    invoke-virtual {p0, v2}, La8/i0;->j0(La8/i1;)J

    .line 157
    .line 158
    .line 159
    move-result-wide v5

    .line 160
    move-object v1, v2

    .line 161
    const/4 v2, 0x0

    .line 162
    const/4 v3, 0x1

    .line 163
    move-object v0, p0

    .line 164
    move v8, p4

    .line 165
    invoke-virtual/range {v0 .. v8}, La8/i0;->J0(La8/i1;IZIJIZ)V

    .line 166
    .line 167
    .line 168
    return-void
.end method

.method public final b0()Lt7/a0;
    .locals 5

    .line 1
    invoke-virtual {p0}, La8/i0;->k0()Lt7/p0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, La8/i0;->x1:Lt7/a0;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-virtual {p0}, La8/i0;->h0()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    iget-object v2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Lt7/o0;

    .line 21
    .line 22
    const-wide/16 v3, 0x0

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2, v3, v4}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iget-object v0, v0, Lt7/o0;->c:Lt7/x;

    .line 29
    .line 30
    iget-object p0, p0, La8/i0;->x1:Lt7/a0;

    .line 31
    .line 32
    invoke-virtual {p0}, Lt7/a0;->a()Lt7/z;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    iget-object v0, v0, Lt7/x;->d:Lt7/a0;

    .line 37
    .line 38
    if-nez v0, :cond_1

    .line 39
    .line 40
    goto/16 :goto_1

    .line 41
    .line 42
    :cond_1
    iget-object v1, v0, Lt7/a0;->A:Lhr/h0;

    .line 43
    .line 44
    iget-object v2, v0, Lt7/a0;->f:[B

    .line 45
    .line 46
    iget-object v3, v0, Lt7/a0;->a:Ljava/lang/CharSequence;

    .line 47
    .line 48
    if-eqz v3, :cond_2

    .line 49
    .line 50
    iput-object v3, p0, Lt7/z;->a:Ljava/lang/CharSequence;

    .line 51
    .line 52
    :cond_2
    iget-object v3, v0, Lt7/a0;->b:Ljava/lang/CharSequence;

    .line 53
    .line 54
    if-eqz v3, :cond_3

    .line 55
    .line 56
    iput-object v3, p0, Lt7/z;->b:Ljava/lang/CharSequence;

    .line 57
    .line 58
    :cond_3
    iget-object v3, v0, Lt7/a0;->c:Ljava/lang/CharSequence;

    .line 59
    .line 60
    if-eqz v3, :cond_4

    .line 61
    .line 62
    iput-object v3, p0, Lt7/z;->c:Ljava/lang/CharSequence;

    .line 63
    .line 64
    :cond_4
    iget-object v3, v0, Lt7/a0;->d:Ljava/lang/CharSequence;

    .line 65
    .line 66
    if-eqz v3, :cond_5

    .line 67
    .line 68
    iput-object v3, p0, Lt7/z;->d:Ljava/lang/CharSequence;

    .line 69
    .line 70
    :cond_5
    iget-object v3, v0, Lt7/a0;->e:Ljava/lang/CharSequence;

    .line 71
    .line 72
    if-eqz v3, :cond_6

    .line 73
    .line 74
    iput-object v3, p0, Lt7/z;->e:Ljava/lang/CharSequence;

    .line 75
    .line 76
    :cond_6
    if-eqz v2, :cond_8

    .line 77
    .line 78
    iget-object v3, v0, Lt7/a0;->g:Ljava/lang/Integer;

    .line 79
    .line 80
    if-nez v2, :cond_7

    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    goto :goto_0

    .line 84
    :cond_7
    invoke-virtual {v2}, [B->clone()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    check-cast v2, [B

    .line 89
    .line 90
    :goto_0
    iput-object v2, p0, Lt7/z;->f:[B

    .line 91
    .line 92
    iput-object v3, p0, Lt7/z;->g:Ljava/lang/Integer;

    .line 93
    .line 94
    :cond_8
    iget-object v2, v0, Lt7/a0;->h:Ljava/lang/Integer;

    .line 95
    .line 96
    if-eqz v2, :cond_9

    .line 97
    .line 98
    iput-object v2, p0, Lt7/z;->h:Ljava/lang/Integer;

    .line 99
    .line 100
    :cond_9
    iget-object v2, v0, Lt7/a0;->i:Ljava/lang/Integer;

    .line 101
    .line 102
    if-eqz v2, :cond_a

    .line 103
    .line 104
    iput-object v2, p0, Lt7/z;->i:Ljava/lang/Integer;

    .line 105
    .line 106
    :cond_a
    iget-object v2, v0, Lt7/a0;->j:Ljava/lang/Integer;

    .line 107
    .line 108
    if-eqz v2, :cond_b

    .line 109
    .line 110
    iput-object v2, p0, Lt7/z;->j:Ljava/lang/Integer;

    .line 111
    .line 112
    :cond_b
    iget-object v2, v0, Lt7/a0;->k:Ljava/lang/Boolean;

    .line 113
    .line 114
    if-eqz v2, :cond_c

    .line 115
    .line 116
    iput-object v2, p0, Lt7/z;->k:Ljava/lang/Boolean;

    .line 117
    .line 118
    :cond_c
    iget-object v2, v0, Lt7/a0;->l:Ljava/lang/Integer;

    .line 119
    .line 120
    if-eqz v2, :cond_d

    .line 121
    .line 122
    iput-object v2, p0, Lt7/z;->l:Ljava/lang/Integer;

    .line 123
    .line 124
    :cond_d
    iget-object v2, v0, Lt7/a0;->m:Ljava/lang/Integer;

    .line 125
    .line 126
    if-eqz v2, :cond_e

    .line 127
    .line 128
    iput-object v2, p0, Lt7/z;->l:Ljava/lang/Integer;

    .line 129
    .line 130
    :cond_e
    iget-object v2, v0, Lt7/a0;->n:Ljava/lang/Integer;

    .line 131
    .line 132
    if-eqz v2, :cond_f

    .line 133
    .line 134
    iput-object v2, p0, Lt7/z;->m:Ljava/lang/Integer;

    .line 135
    .line 136
    :cond_f
    iget-object v2, v0, Lt7/a0;->o:Ljava/lang/Integer;

    .line 137
    .line 138
    if-eqz v2, :cond_10

    .line 139
    .line 140
    iput-object v2, p0, Lt7/z;->n:Ljava/lang/Integer;

    .line 141
    .line 142
    :cond_10
    iget-object v2, v0, Lt7/a0;->p:Ljava/lang/Integer;

    .line 143
    .line 144
    if-eqz v2, :cond_11

    .line 145
    .line 146
    iput-object v2, p0, Lt7/z;->o:Ljava/lang/Integer;

    .line 147
    .line 148
    :cond_11
    iget-object v2, v0, Lt7/a0;->q:Ljava/lang/Integer;

    .line 149
    .line 150
    if-eqz v2, :cond_12

    .line 151
    .line 152
    iput-object v2, p0, Lt7/z;->p:Ljava/lang/Integer;

    .line 153
    .line 154
    :cond_12
    iget-object v2, v0, Lt7/a0;->r:Ljava/lang/Integer;

    .line 155
    .line 156
    if-eqz v2, :cond_13

    .line 157
    .line 158
    iput-object v2, p0, Lt7/z;->q:Ljava/lang/Integer;

    .line 159
    .line 160
    :cond_13
    iget-object v2, v0, Lt7/a0;->s:Ljava/lang/CharSequence;

    .line 161
    .line 162
    if-eqz v2, :cond_14

    .line 163
    .line 164
    iput-object v2, p0, Lt7/z;->r:Ljava/lang/CharSequence;

    .line 165
    .line 166
    :cond_14
    iget-object v2, v0, Lt7/a0;->t:Ljava/lang/CharSequence;

    .line 167
    .line 168
    if-eqz v2, :cond_15

    .line 169
    .line 170
    iput-object v2, p0, Lt7/z;->s:Ljava/lang/CharSequence;

    .line 171
    .line 172
    :cond_15
    iget-object v2, v0, Lt7/a0;->u:Ljava/lang/CharSequence;

    .line 173
    .line 174
    if-eqz v2, :cond_16

    .line 175
    .line 176
    iput-object v2, p0, Lt7/z;->t:Ljava/lang/CharSequence;

    .line 177
    .line 178
    :cond_16
    iget-object v2, v0, Lt7/a0;->v:Ljava/lang/Integer;

    .line 179
    .line 180
    if-eqz v2, :cond_17

    .line 181
    .line 182
    iput-object v2, p0, Lt7/z;->u:Ljava/lang/Integer;

    .line 183
    .line 184
    :cond_17
    iget-object v2, v0, Lt7/a0;->w:Ljava/lang/Integer;

    .line 185
    .line 186
    if-eqz v2, :cond_18

    .line 187
    .line 188
    iput-object v2, p0, Lt7/z;->v:Ljava/lang/Integer;

    .line 189
    .line 190
    :cond_18
    iget-object v2, v0, Lt7/a0;->x:Ljava/lang/CharSequence;

    .line 191
    .line 192
    if-eqz v2, :cond_19

    .line 193
    .line 194
    iput-object v2, p0, Lt7/z;->w:Ljava/lang/CharSequence;

    .line 195
    .line 196
    :cond_19
    iget-object v2, v0, Lt7/a0;->y:Ljava/lang/CharSequence;

    .line 197
    .line 198
    if-eqz v2, :cond_1a

    .line 199
    .line 200
    iput-object v2, p0, Lt7/z;->x:Ljava/lang/CharSequence;

    .line 201
    .line 202
    :cond_1a
    iget-object v0, v0, Lt7/a0;->z:Ljava/lang/Integer;

    .line 203
    .line 204
    if-eqz v0, :cond_1b

    .line 205
    .line 206
    iput-object v0, p0, Lt7/z;->y:Ljava/lang/Integer;

    .line 207
    .line 208
    :cond_1b
    invoke-virtual {v1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 209
    .line 210
    .line 211
    move-result v0

    .line 212
    if-nez v0, :cond_1c

    .line 213
    .line 214
    invoke-static {v1}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    iput-object v0, p0, Lt7/z;->z:Lhr/h0;

    .line 219
    .line 220
    :cond_1c
    :goto_1
    new-instance v0, Lt7/a0;

    .line 221
    .line 222
    invoke-direct {v0, p0}, Lt7/a0;-><init>(Lt7/z;)V

    .line 223
    .line 224
    .line 225
    return-object v0
.end method

.method public final c0()V
    .locals 1

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, La8/i0;->z0()V

    .line 5
    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, v0}, La8/i0;->E0(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p0, v0, v0}, La8/i0;->v0(II)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final d0(La8/k1;)La8/l1;
    .locals 7

    .line 1
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, La8/i0;->m0(La8/i1;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, La8/l1;

    .line 8
    .line 9
    iget-object v2, p0, La8/i0;->y1:La8/i1;

    .line 10
    .line 11
    iget-object v4, v2, La8/i1;->a:Lt7/p0;

    .line 12
    .line 13
    const/4 v2, -0x1

    .line 14
    if-ne v0, v2, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    :cond_0
    move v5, v0

    .line 18
    iget-object v2, p0, La8/i0;->p:La8/q0;

    .line 19
    .line 20
    iget-object v6, v2, La8/q0;->m:Landroid/os/Looper;

    .line 21
    .line 22
    move-object v3, p1

    .line 23
    invoke-direct/range {v1 .. v6}, La8/l1;-><init>(La8/j1;La8/k1;Lt7/p0;ILandroid/os/Looper;)V

    .line 24
    .line 25
    .line 26
    return-object v1
.end method

.method public final e0(La8/i1;)J
    .locals 7

    .line 1
    iget-object v0, p1, La8/i1;->b:Lh8/b0;

    .line 2
    .line 3
    iget-wide v1, p1, La8/i1;->c:J

    .line 4
    .line 5
    iget-object v3, p1, La8/i1;->a:Lt7/p0;

    .line 6
    .line 7
    invoke-virtual {v0}, Lh8/b0;->b()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p1, La8/i1;->b:Lh8/b0;

    .line 14
    .line 15
    iget-object v0, v0, Lh8/b0;->a:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v4, p0, La8/i0;->s:Lt7/n0;

    .line 18
    .line 19
    invoke-virtual {v3, v0, v4}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 20
    .line 21
    .line 22
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    cmp-long v0, v1, v5

    .line 28
    .line 29
    if-nez v0, :cond_0

    .line 30
    .line 31
    invoke-virtual {p0, p1}, La8/i0;->m0(La8/i1;)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lt7/o0;

    .line 38
    .line 39
    const-wide/16 v0, 0x0

    .line 40
    .line 41
    invoke-virtual {v3, p1, p0, v0, v1}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    iget-wide p0, p0, Lt7/o0;->k:J

    .line 46
    .line 47
    invoke-static {p0, p1}, Lw7/w;->N(J)J

    .line 48
    .line 49
    .line 50
    move-result-wide p0

    .line 51
    return-wide p0

    .line 52
    :cond_0
    iget-wide p0, v4, Lt7/n0;->e:J

    .line 53
    .line 54
    invoke-static {p0, p1}, Lw7/w;->N(J)J

    .line 55
    .line 56
    .line 57
    move-result-wide p0

    .line 58
    invoke-static {v1, v2}, Lw7/w;->N(J)J

    .line 59
    .line 60
    .line 61
    move-result-wide v0

    .line 62
    add-long/2addr v0, p0

    .line 63
    return-wide v0

    .line 64
    :cond_1
    invoke-virtual {p0, p1}, La8/i0;->j0(La8/i1;)J

    .line 65
    .line 66
    .line 67
    move-result-wide p0

    .line 68
    invoke-static {p0, p1}, Lw7/w;->N(J)J

    .line 69
    .line 70
    .line 71
    move-result-wide p0

    .line 72
    return-wide p0
.end method

.method public final f0()I
    .locals 1

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, La8/i0;->r0()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, La8/i0;->y1:La8/i1;

    .line 11
    .line 12
    iget-object p0, p0, La8/i1;->b:Lh8/b0;

    .line 13
    .line 14
    iget p0, p0, Lh8/b0;->b:I

    .line 15
    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, -0x1

    .line 18
    return p0
.end method

.method public final g0()I
    .locals 1

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, La8/i0;->r0()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, La8/i0;->y1:La8/i1;

    .line 11
    .line 12
    iget-object p0, p0, La8/i1;->b:Lh8/b0;

    .line 13
    .line 14
    iget p0, p0, Lh8/b0;->c:I

    .line 15
    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, -0x1

    .line 18
    return p0
.end method

.method public final h0()I
    .locals 1

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    invoke-virtual {p0, v0}, La8/i0;->m0(La8/i1;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, -0x1

    .line 11
    if-ne p0, v0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    :cond_0
    return p0
.end method

.method public final i0()J
    .locals 2

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    invoke-virtual {p0, v0}, La8/i0;->j0(La8/i1;)J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    invoke-static {v0, v1}, Lw7/w;->N(J)J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    return-wide v0
.end method

.method public final isScrubbingModeEnabled()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-boolean p0, p0, La8/i0;->P:Z

    .line 5
    .line 6
    return p0
.end method

.method public final j0(La8/i1;)J
    .locals 3

    .line 1
    iget-object v0, p1, La8/i1;->a:Lt7/p0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-wide p0, p0, La8/i0;->A1:J

    .line 10
    .line 11
    invoke-static {p0, p1}, Lw7/w;->D(J)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0

    .line 16
    :cond_0
    iget-boolean v0, p1, La8/i1;->p:Z

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {p1}, La8/i1;->l()J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    iget-wide v0, p1, La8/i1;->s:J

    .line 26
    .line 27
    :goto_0
    iget-object v2, p1, La8/i1;->b:Lh8/b0;

    .line 28
    .line 29
    invoke-virtual {v2}, Lh8/b0;->b()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    return-wide v0

    .line 36
    :cond_2
    iget-object v2, p1, La8/i1;->a:Lt7/p0;

    .line 37
    .line 38
    iget-object p1, p1, La8/i1;->b:Lh8/b0;

    .line 39
    .line 40
    iget-object p1, p1, Lh8/b0;->a:Ljava/lang/Object;

    .line 41
    .line 42
    iget-object p0, p0, La8/i0;->s:Lt7/n0;

    .line 43
    .line 44
    invoke-virtual {v2, p1, p0}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 45
    .line 46
    .line 47
    iget-wide p0, p0, Lt7/n0;->e:J

    .line 48
    .line 49
    add-long/2addr v0, p0

    .line 50
    return-wide v0
.end method

.method public final k0()Lt7/p0;
    .locals 0

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    iget-object p0, p0, La8/i1;->a:Lt7/p0;

    .line 7
    .line 8
    return-object p0
.end method

.method public final l0()Lt7/w0;
    .locals 0

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    iget-object p0, p0, La8/i1;->i:Lj8/s;

    .line 7
    .line 8
    iget-object p0, p0, Lj8/s;->d:Lt7/w0;

    .line 9
    .line 10
    return-object p0
.end method

.method public final m0(La8/i1;)I
    .locals 1

    .line 1
    iget-object v0, p1, La8/i1;->a:Lt7/p0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget p0, p0, La8/i0;->z1:I

    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    iget-object v0, p1, La8/i1;->a:Lt7/p0;

    .line 13
    .line 14
    iget-object p1, p1, La8/i1;->b:Lh8/b0;

    .line 15
    .line 16
    iget-object p1, p1, Lh8/b0;->a:Ljava/lang/Object;

    .line 17
    .line 18
    iget-object p0, p0, La8/i0;->s:Lt7/n0;

    .line 19
    .line 20
    invoke-virtual {v0, p1, p0}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    iget p0, p0, Lt7/n0;->c:I

    .line 25
    .line 26
    return p0
.end method

.method public final n0()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    iget-boolean p0, p0, La8/i1;->l:Z

    .line 7
    .line 8
    return p0
.end method

.method public final o0()I
    .locals 0

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    iget p0, p0, La8/i1;->e:I

    .line 7
    .line 8
    return p0
.end method

.method public final q0()Lt7/u0;
    .locals 2

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, La8/i0;->m:Lh/w;

    .line 5
    .line 6
    check-cast v0, Lj8/o;

    .line 7
    .line 8
    invoke-virtual {v0}, Lj8/o;->s()Lj8/i;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-boolean v1, p0, La8/i0;->P:Z

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    new-instance v1, Lj8/h;

    .line 20
    .line 21
    invoke-direct {v1, v0}, Lj8/h;-><init>(Lj8/i;)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, La8/i0;->Q:Lhr/k0;

    .line 25
    .line 26
    invoke-virtual {v1, p0}, Lj8/h;->j(Ljava/util/Set;)V

    .line 27
    .line 28
    .line 29
    new-instance p0, Lj8/i;

    .line 30
    .line 31
    invoke-direct {p0, v1}, Lj8/i;-><init>(Lj8/h;)V

    .line 32
    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_0
    return-object v0
.end method

.method public final r0()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    iget-object p0, p0, La8/i1;->b:Lh8/b0;

    .line 7
    .line 8
    invoke-virtual {p0}, Lh8/b0;->b()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final setImageOutput(Landroidx/media3/exoplayer/image/ImageOutput;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x4

    .line 5
    const/16 v1, 0xf

    .line 6
    .line 7
    invoke-virtual {p0, v0, p1, v1}, La8/i0;->A0(ILjava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final setScrubbingModeEnabled(Z)V
    .locals 6

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, La8/i0;->P:Z

    .line 5
    .line 6
    if-ne p1, v0, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iput-boolean p1, p0, La8/i0;->P:Z

    .line 10
    .line 11
    iget-object v0, p0, La8/i0;->R:La8/q1;

    .line 12
    .line 13
    iget-object v1, v0, La8/q1;->a:Lhr/k0;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_3

    .line 20
    .line 21
    iget-object v1, p0, La8/i0;->m:Lh/w;

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    move-object v2, v1

    .line 27
    check-cast v2, Lj8/o;

    .line 28
    .line 29
    invoke-virtual {v2}, Lj8/o;->s()Lj8/i;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    if-eqz p1, :cond_2

    .line 34
    .line 35
    iget-object v3, v2, Lt7/u0;->t:Lhr/k0;

    .line 36
    .line 37
    iput-object v3, p0, La8/i0;->Q:Lhr/k0;

    .line 38
    .line 39
    iget-object v0, v0, La8/q1;->a:Lhr/k0;

    .line 40
    .line 41
    invoke-virtual {v2}, Lj8/i;->a()Lt7/t0;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-virtual {v0}, Lhr/k0;->s()Lhr/l1;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-eqz v4, :cond_1

    .line 54
    .line 55
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    check-cast v4, Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    const/4 v5, 0x1

    .line 66
    invoke-virtual {v3, v4, v5}, Lt7/t0;->i(IZ)Lt7/t0;

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    invoke-virtual {v3}, Lt7/t0;->a()Lt7/u0;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    goto :goto_1

    .line 75
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    new-instance v0, Lj8/h;

    .line 79
    .line 80
    invoke-direct {v0, v2}, Lj8/h;-><init>(Lj8/i;)V

    .line 81
    .line 82
    .line 83
    iget-object v3, p0, La8/i0;->Q:Lhr/k0;

    .line 84
    .line 85
    invoke-virtual {v0, v3}, Lj8/h;->j(Ljava/util/Set;)V

    .line 86
    .line 87
    .line 88
    new-instance v3, Lj8/i;

    .line 89
    .line 90
    invoke-direct {v3, v0}, Lj8/i;-><init>(Lj8/h;)V

    .line 91
    .line 92
    .line 93
    const/4 v0, 0x0

    .line 94
    iput-object v0, p0, La8/i0;->Q:Lhr/k0;

    .line 95
    .line 96
    move-object v0, v3

    .line 97
    :goto_1
    invoke-virtual {v0, v2}, Lt7/u0;->equals(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    if-nez v2, :cond_3

    .line 102
    .line 103
    invoke-virtual {v1, v0}, Lh/w;->o(Lt7/u0;)V

    .line 104
    .line 105
    .line 106
    :cond_3
    iget-object v0, p0, La8/i0;->p:La8/q0;

    .line 107
    .line 108
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 109
    .line 110
    const/16 v1, 0x24

    .line 111
    .line 112
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    invoke-virtual {v0, v1, p1}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-virtual {p1}, Lw7/s;->b()V

    .line 121
    .line 122
    .line 123
    iget-object p1, p0, La8/i0;->y1:La8/i1;

    .line 124
    .line 125
    iget-boolean v0, p1, La8/i1;->l:Z

    .line 126
    .line 127
    iget p1, p1, La8/i1;->m:I

    .line 128
    .line 129
    invoke-virtual {p0, p1, v0}, La8/i0;->I0(IZ)V

    .line 130
    .line 131
    .line 132
    return-void
.end method

.method public final t0(La8/i1;Lt7/p0;Landroid/util/Pair;)La8/i1;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    const/4 v4, 0x0

    .line 12
    const/4 v5, 0x1

    .line 13
    if-nez v3, :cond_1

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v3, v4

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    :goto_0
    move v3, v5

    .line 21
    :goto_1
    invoke-static {v3}, Lw7/a;->c(Z)V

    .line 22
    .line 23
    .line 24
    move-object/from16 v3, p1

    .line 25
    .line 26
    iget-object v6, v3, La8/i1;->a:Lt7/p0;

    .line 27
    .line 28
    invoke-virtual/range {p0 .. p1}, La8/i0;->e0(La8/i1;)J

    .line 29
    .line 30
    .line 31
    move-result-wide v7

    .line 32
    invoke-virtual/range {p1 .. p2}, La8/i1;->j(Lt7/p0;)La8/i1;

    .line 33
    .line 34
    .line 35
    move-result-object v9

    .line 36
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_2

    .line 41
    .line 42
    sget-object v10, La8/i1;->u:Lh8/b0;

    .line 43
    .line 44
    iget-wide v1, v0, La8/i0;->A1:J

    .line 45
    .line 46
    invoke-static {v1, v2}, Lw7/w;->D(J)J

    .line 47
    .line 48
    .line 49
    move-result-wide v11

    .line 50
    sget-object v19, Lh8/e1;->d:Lh8/e1;

    .line 51
    .line 52
    iget-object v0, v0, La8/i0;->f:Lj8/s;

    .line 53
    .line 54
    sget-object v21, Lhr/x0;->h:Lhr/x0;

    .line 55
    .line 56
    const-wide/16 v17, 0x0

    .line 57
    .line 58
    move-wide v13, v11

    .line 59
    move-wide v15, v11

    .line 60
    move-object/from16 v20, v0

    .line 61
    .line 62
    invoke-virtual/range {v9 .. v21}, La8/i1;->d(Lh8/b0;JJJJLh8/e1;Lj8/s;Ljava/util/List;)La8/i1;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {v0, v10}, La8/i1;->c(Lh8/b0;)La8/i1;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iget-wide v1, v0, La8/i1;->s:J

    .line 71
    .line 72
    iput-wide v1, v0, La8/i1;->q:J

    .line 73
    .line 74
    return-object v0

    .line 75
    :cond_2
    iget-object v3, v9, La8/i1;->b:Lh8/b0;

    .line 76
    .line 77
    iget-object v3, v3, Lh8/b0;->a:Ljava/lang/Object;

    .line 78
    .line 79
    iget-object v10, v2, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 80
    .line 81
    invoke-virtual {v3, v10}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v10

    .line 85
    if-nez v10, :cond_3

    .line 86
    .line 87
    new-instance v11, Lh8/b0;

    .line 88
    .line 89
    iget-object v12, v2, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 90
    .line 91
    invoke-direct {v11, v12}, Lh8/b0;-><init>(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_3
    iget-object v11, v9, La8/i1;->b:Lh8/b0;

    .line 96
    .line 97
    :goto_2
    iget-object v2, v2, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v2, Ljava/lang/Long;

    .line 100
    .line 101
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 102
    .line 103
    .line 104
    move-result-wide v12

    .line 105
    invoke-static {v7, v8}, Lw7/w;->D(J)J

    .line 106
    .line 107
    .line 108
    move-result-wide v7

    .line 109
    invoke-virtual {v6}, Lt7/p0;->p()Z

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    if-nez v2, :cond_4

    .line 114
    .line 115
    iget-object v2, v0, La8/i0;->s:Lt7/n0;

    .line 116
    .line 117
    invoke-virtual {v6, v3, v2}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    iget-wide v2, v2, Lt7/n0;->e:J

    .line 122
    .line 123
    sub-long/2addr v7, v2

    .line 124
    :cond_4
    if-eqz v10, :cond_5

    .line 125
    .line 126
    cmp-long v2, v12, v7

    .line 127
    .line 128
    if-gez v2, :cond_6

    .line 129
    .line 130
    :cond_5
    move v1, v10

    .line 131
    move-object v10, v11

    .line 132
    move-wide v11, v12

    .line 133
    goto/16 :goto_6

    .line 134
    .line 135
    :cond_6
    if-nez v2, :cond_a

    .line 136
    .line 137
    iget-object v2, v9, La8/i1;->k:Lh8/b0;

    .line 138
    .line 139
    iget-object v2, v2, Lh8/b0;->a:Ljava/lang/Object;

    .line 140
    .line 141
    invoke-virtual {v1, v2}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    const/4 v3, -0x1

    .line 146
    if-eq v2, v3, :cond_8

    .line 147
    .line 148
    iget-object v3, v0, La8/i0;->s:Lt7/n0;

    .line 149
    .line 150
    invoke-virtual {v1, v2, v3, v4}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    iget v2, v2, Lt7/n0;->c:I

    .line 155
    .line 156
    iget-object v3, v11, Lh8/b0;->a:Ljava/lang/Object;

    .line 157
    .line 158
    iget-object v4, v0, La8/i0;->s:Lt7/n0;

    .line 159
    .line 160
    invoke-virtual {v1, v3, v4}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    iget v3, v3, Lt7/n0;->c:I

    .line 165
    .line 166
    if-eq v2, v3, :cond_7

    .line 167
    .line 168
    goto :goto_3

    .line 169
    :cond_7
    return-object v9

    .line 170
    :cond_8
    :goto_3
    iget-object v2, v11, Lh8/b0;->a:Ljava/lang/Object;

    .line 171
    .line 172
    iget-object v3, v0, La8/i0;->s:Lt7/n0;

    .line 173
    .line 174
    invoke-virtual {v1, v2, v3}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v11}, Lh8/b0;->b()Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-eqz v1, :cond_9

    .line 182
    .line 183
    iget-object v0, v0, La8/i0;->s:Lt7/n0;

    .line 184
    .line 185
    iget v1, v11, Lh8/b0;->b:I

    .line 186
    .line 187
    iget v2, v11, Lh8/b0;->c:I

    .line 188
    .line 189
    invoke-virtual {v0, v1, v2}, Lt7/n0;->a(II)J

    .line 190
    .line 191
    .line 192
    move-result-wide v0

    .line 193
    :goto_4
    move-object v10, v11

    .line 194
    goto :goto_5

    .line 195
    :cond_9
    iget-object v0, v0, La8/i0;->s:Lt7/n0;

    .line 196
    .line 197
    iget-wide v0, v0, Lt7/n0;->d:J

    .line 198
    .line 199
    goto :goto_4

    .line 200
    :goto_5
    iget-wide v11, v9, La8/i1;->s:J

    .line 201
    .line 202
    iget-wide v13, v9, La8/i1;->s:J

    .line 203
    .line 204
    iget-wide v2, v9, La8/i1;->d:J

    .line 205
    .line 206
    iget-wide v4, v9, La8/i1;->s:J

    .line 207
    .line 208
    sub-long v17, v0, v4

    .line 209
    .line 210
    iget-object v4, v9, La8/i1;->h:Lh8/e1;

    .line 211
    .line 212
    iget-object v5, v9, La8/i1;->i:Lj8/s;

    .line 213
    .line 214
    iget-object v6, v9, La8/i1;->j:Ljava/util/List;

    .line 215
    .line 216
    move-wide v15, v2

    .line 217
    move-object/from16 v19, v4

    .line 218
    .line 219
    move-object/from16 v20, v5

    .line 220
    .line 221
    move-object/from16 v21, v6

    .line 222
    .line 223
    invoke-virtual/range {v9 .. v21}, La8/i1;->d(Lh8/b0;JJJJLh8/e1;Lj8/s;Ljava/util/List;)La8/i1;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    invoke-virtual {v2, v10}, La8/i1;->c(Lh8/b0;)La8/i1;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    iput-wide v0, v2, La8/i1;->q:J

    .line 232
    .line 233
    return-object v2

    .line 234
    :cond_a
    move-object v10, v11

    .line 235
    invoke-virtual {v10}, Lh8/b0;->b()Z

    .line 236
    .line 237
    .line 238
    move-result v0

    .line 239
    xor-int/2addr v0, v5

    .line 240
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 241
    .line 242
    .line 243
    iget-wide v0, v9, La8/i1;->r:J

    .line 244
    .line 245
    sub-long v2, v12, v7

    .line 246
    .line 247
    sub-long/2addr v0, v2

    .line 248
    const-wide/16 v2, 0x0

    .line 249
    .line 250
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 251
    .line 252
    .line 253
    move-result-wide v17

    .line 254
    iget-wide v0, v9, La8/i1;->q:J

    .line 255
    .line 256
    iget-object v2, v9, La8/i1;->k:Lh8/b0;

    .line 257
    .line 258
    iget-object v3, v9, La8/i1;->b:Lh8/b0;

    .line 259
    .line 260
    invoke-virtual {v2, v3}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v2

    .line 264
    if-eqz v2, :cond_b

    .line 265
    .line 266
    add-long v0, v12, v17

    .line 267
    .line 268
    :cond_b
    iget-object v2, v9, La8/i1;->h:Lh8/e1;

    .line 269
    .line 270
    iget-object v3, v9, La8/i1;->i:Lj8/s;

    .line 271
    .line 272
    iget-object v4, v9, La8/i1;->j:Ljava/util/List;

    .line 273
    .line 274
    move-wide v11, v12

    .line 275
    move-wide v13, v11

    .line 276
    move-wide v15, v11

    .line 277
    move-object/from16 v19, v2

    .line 278
    .line 279
    move-object/from16 v20, v3

    .line 280
    .line 281
    move-object/from16 v21, v4

    .line 282
    .line 283
    invoke-virtual/range {v9 .. v21}, La8/i1;->d(Lh8/b0;JJJJLh8/e1;Lj8/s;Ljava/util/List;)La8/i1;

    .line 284
    .line 285
    .line 286
    move-result-object v2

    .line 287
    iput-wide v0, v2, La8/i1;->q:J

    .line 288
    .line 289
    return-object v2

    .line 290
    :goto_6
    invoke-virtual {v10}, Lh8/b0;->b()Z

    .line 291
    .line 292
    .line 293
    move-result v2

    .line 294
    xor-int/2addr v2, v5

    .line 295
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 296
    .line 297
    .line 298
    if-nez v1, :cond_c

    .line 299
    .line 300
    sget-object v2, Lh8/e1;->d:Lh8/e1;

    .line 301
    .line 302
    :goto_7
    move-object/from16 v19, v2

    .line 303
    .line 304
    goto :goto_8

    .line 305
    :cond_c
    iget-object v2, v9, La8/i1;->h:Lh8/e1;

    .line 306
    .line 307
    goto :goto_7

    .line 308
    :goto_8
    if-nez v1, :cond_d

    .line 309
    .line 310
    iget-object v0, v0, La8/i0;->f:Lj8/s;

    .line 311
    .line 312
    :goto_9
    move-object/from16 v20, v0

    .line 313
    .line 314
    goto :goto_a

    .line 315
    :cond_d
    iget-object v0, v9, La8/i1;->i:Lj8/s;

    .line 316
    .line 317
    goto :goto_9

    .line 318
    :goto_a
    if-nez v1, :cond_e

    .line 319
    .line 320
    sget-object v0, Lhr/h0;->e:Lhr/f0;

    .line 321
    .line 322
    sget-object v0, Lhr/x0;->h:Lhr/x0;

    .line 323
    .line 324
    :goto_b
    move-object/from16 v21, v0

    .line 325
    .line 326
    goto :goto_c

    .line 327
    :cond_e
    iget-object v0, v9, La8/i1;->j:Ljava/util/List;

    .line 328
    .line 329
    goto :goto_b

    .line 330
    :goto_c
    const-wide/16 v17, 0x0

    .line 331
    .line 332
    move-wide v13, v11

    .line 333
    move-wide v15, v11

    .line 334
    invoke-virtual/range {v9 .. v21}, La8/i1;->d(Lh8/b0;JJJJLh8/e1;Lj8/s;Ljava/util/List;)La8/i1;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    invoke-virtual {v0, v10}, La8/i1;->c(Lh8/b0;)La8/i1;

    .line 339
    .line 340
    .line 341
    move-result-object v0

    .line 342
    iput-wide v11, v0, La8/i1;->q:J

    .line 343
    .line 344
    return-object v0
.end method

.method public final u0(Lt7/p0;IJ)Landroid/util/Pair;
    .locals 6

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
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iput p2, p0, La8/i0;->z1:I

    .line 10
    .line 11
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    cmp-long p1, p3, p1

    .line 17
    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    move-wide p3, v1

    .line 21
    :cond_0
    iput-wide p3, p0, La8/i0;->A1:J

    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    return-object p0

    .line 25
    :cond_1
    const/4 v0, -0x1

    .line 26
    if-eq p2, v0, :cond_3

    .line 27
    .line 28
    invoke-virtual {p1}, Lt7/p0;->o()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-lt p2, v0, :cond_2

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_2
    :goto_0
    move v3, p2

    .line 36
    goto :goto_2

    .line 37
    :cond_3
    :goto_1
    iget-boolean p2, p0, La8/i0;->L:Z

    .line 38
    .line 39
    invoke-virtual {p1, p2}, Lt7/p0;->a(Z)I

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    iget-object p3, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p3, Lt7/o0;

    .line 46
    .line 47
    invoke-virtual {p1, p2, p3, v1, v2}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 48
    .line 49
    .line 50
    move-result-object p3

    .line 51
    iget-wide p3, p3, Lt7/o0;->k:J

    .line 52
    .line 53
    invoke-static {p3, p4}, Lw7/w;->N(J)J

    .line 54
    .line 55
    .line 56
    move-result-wide p3

    .line 57
    goto :goto_0

    .line 58
    :goto_2
    iget-object p2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 59
    .line 60
    move-object v1, p2

    .line 61
    check-cast v1, Lt7/o0;

    .line 62
    .line 63
    iget-object v2, p0, La8/i0;->s:Lt7/n0;

    .line 64
    .line 65
    invoke-static {p3, p4}, Lw7/w;->D(J)J

    .line 66
    .line 67
    .line 68
    move-result-wide v4

    .line 69
    move-object v0, p1

    .line 70
    invoke-virtual/range {v0 .. v5}, Lt7/p0;->i(Lt7/o0;Lt7/n0;IJ)Landroid/util/Pair;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0
.end method

.method public final v0(II)V
    .locals 3

    .line 1
    iget-object v0, p0, La8/i0;->f0:Lw7/q;

    .line 2
    .line 3
    iget v1, v0, Lw7/q;->a:I

    .line 4
    .line 5
    if-ne p1, v1, :cond_1

    .line 6
    .line 7
    iget v0, v0, Lw7/q;->b:I

    .line 8
    .line 9
    if-eq p2, v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-void

    .line 13
    :cond_1
    :goto_0
    new-instance v0, Lw7/q;

    .line 14
    .line 15
    invoke-direct {v0, p1, p2}, Lw7/q;-><init>(II)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, La8/i0;->f0:Lw7/q;

    .line 19
    .line 20
    new-instance v0, La8/v;

    .line 21
    .line 22
    invoke-direct {v0, p1, p2}, La8/v;-><init>(II)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, La8/i0;->q:Le30/v;

    .line 26
    .line 27
    const/16 v2, 0x18

    .line 28
    .line 29
    invoke-virtual {v1, v2, v0}, Le30/v;->e(ILw7/j;)V

    .line 30
    .line 31
    .line 32
    new-instance v0, Lw7/q;

    .line 33
    .line 34
    invoke-direct {v0, p1, p2}, Lw7/q;-><init>(II)V

    .line 35
    .line 36
    .line 37
    const/4 p1, 0x2

    .line 38
    const/16 p2, 0xe

    .line 39
    .line 40
    invoke-virtual {p0, p1, v0, p2}, La8/i0;->A0(ILjava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final w0()V
    .locals 12

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 5
    .line 6
    iget v1, v0, La8/i1;->e:I

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    if-eq v1, v2, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    const/4 v1, 0x0

    .line 13
    invoke-virtual {v0, v1}, La8/i1;->f(La8/o;)La8/i1;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-object v1, v0, La8/i1;->a:Lt7/p0;

    .line 18
    .line 19
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/4 v1, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 v1, 0x2

    .line 28
    :goto_0
    invoke-static {v0, v1}, La8/i0;->s0(La8/i1;I)La8/i1;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    iget v0, p0, La8/i0;->M:I

    .line 33
    .line 34
    add-int/2addr v0, v2

    .line 35
    iput v0, p0, La8/i0;->M:I

    .line 36
    .line 37
    iget-object v0, p0, La8/i0;->p:La8/q0;

    .line 38
    .line 39
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 49
    .line 50
    const/16 v2, 0x1d

    .line 51
    .line 52
    invoke-virtual {v0, v2}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    iput-object v0, v1, Lw7/s;->a:Landroid/os/Message;

    .line 57
    .line 58
    invoke-virtual {v1}, Lw7/s;->b()V

    .line 59
    .line 60
    .line 61
    const/4 v10, -0x1

    .line 62
    const/4 v11, 0x0

    .line 63
    const/4 v5, 0x1

    .line 64
    const/4 v6, 0x0

    .line 65
    const/4 v7, 0x5

    .line 66
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    move-object v3, p0

    .line 72
    invoke-virtual/range {v3 .. v11}, La8/i0;->J0(La8/i1;IZIJIZ)V

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method public final x0()V
    .locals 7

    .line 1
    const-string v0, "ExoPlayerImpl"

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "Release "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-static {v2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v2, " [AndroidXMedia3/1.8.0] ["

    .line 22
    .line 23
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v2, "] ["

    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    sget-object v2, Lt7/y;->a:Ljava/util/HashSet;

    .line 37
    .line 38
    const-class v2, Lt7/y;

    .line 39
    .line 40
    monitor-enter v2

    .line 41
    :try_start_0
    sget-object v3, Lt7/y;->b:Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    monitor-exit v2

    .line 44
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v2, "]"

    .line 48
    .line 49
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-static {v0, v1}, Lw7/a;->s(Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 60
    .line 61
    .line 62
    iget-object v0, p0, La8/i0;->F:La8/b;

    .line 63
    .line 64
    invoke-virtual {v0}, La8/b;->p()V

    .line 65
    .line 66
    .line 67
    iget-object v0, p0, La8/i0;->G:La8/t1;

    .line 68
    .line 69
    const/4 v1, 0x0

    .line 70
    invoke-virtual {v0, v1}, La8/t1;->c(Z)V

    .line 71
    .line 72
    .line 73
    iget-object v0, p0, La8/i0;->H:La8/t1;

    .line 74
    .line 75
    invoke-virtual {v0, v1}, La8/t1;->c(Z)V

    .line 76
    .line 77
    .line 78
    iget-object v0, p0, La8/i0;->p:La8/q0;

    .line 79
    .line 80
    iget-boolean v1, v0, La8/q0;->K:Z

    .line 81
    .line 82
    const/4 v2, 0x1

    .line 83
    if-nez v1, :cond_1

    .line 84
    .line 85
    iget-object v1, v0, La8/q0;->m:Landroid/os/Looper;

    .line 86
    .line 87
    invoke-virtual {v1}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-virtual {v1}, Ljava/lang/Thread;->isAlive()Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-nez v1, :cond_0

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_0
    iput-boolean v2, v0, La8/q0;->K:Z

    .line 99
    .line 100
    new-instance v1, Lw7/e;

    .line 101
    .line 102
    iget-object v3, v0, La8/q0;->s:Lw7/r;

    .line 103
    .line 104
    invoke-direct {v1, v3}, Lw7/e;-><init>(Lw7/r;)V

    .line 105
    .line 106
    .line 107
    iget-object v3, v0, La8/q0;->k:Lw7/t;

    .line 108
    .line 109
    const/4 v4, 0x7

    .line 110
    invoke-virtual {v3, v4, v1}, Lw7/t;->a(ILjava/lang/Object;)Lw7/s;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    invoke-virtual {v3}, Lw7/s;->b()V

    .line 115
    .line 116
    .line 117
    iget-wide v3, v0, La8/q0;->x:J

    .line 118
    .line 119
    invoke-virtual {v1, v3, v4}, Lw7/e;->b(J)Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    goto :goto_1

    .line 124
    :cond_1
    :goto_0
    move v0, v2

    .line 125
    :goto_1
    if-nez v0, :cond_2

    .line 126
    .line 127
    iget-object v0, p0, La8/i0;->q:Le30/v;

    .line 128
    .line 129
    new-instance v1, La6/a;

    .line 130
    .line 131
    const/4 v3, 0x2

    .line 132
    invoke-direct {v1, v3}, La6/a;-><init>(I)V

    .line 133
    .line 134
    .line 135
    const/16 v3, 0xa

    .line 136
    .line 137
    invoke-virtual {v0, v3, v1}, Le30/v;->e(ILw7/j;)V

    .line 138
    .line 139
    .line 140
    :cond_2
    iget-object v0, p0, La8/i0;->q:Le30/v;

    .line 141
    .line 142
    invoke-virtual {v0}, Le30/v;->d()V

    .line 143
    .line 144
    .line 145
    iget-object v0, p0, La8/i0;->n:Lw7/t;

    .line 146
    .line 147
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 148
    .line 149
    const/4 v1, 0x0

    .line 150
    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    iget-object v0, p0, La8/i0;->y:Lk8/d;

    .line 154
    .line 155
    iget-object v3, p0, La8/i0;->w:Lb8/e;

    .line 156
    .line 157
    check-cast v0, Lk8/g;

    .line 158
    .line 159
    iget-object v0, v0, Lk8/g;->c:Lh6/e;

    .line 160
    .line 161
    iget-object v0, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    :cond_3
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 170
    .line 171
    .line 172
    move-result v5

    .line 173
    if-eqz v5, :cond_4

    .line 174
    .line 175
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v5

    .line 179
    check-cast v5, Lk8/c;

    .line 180
    .line 181
    iget-object v6, v5, Lk8/c;->b:Lb8/e;

    .line 182
    .line 183
    if-ne v6, v3, :cond_3

    .line 184
    .line 185
    iput-boolean v2, v5, Lk8/c;->c:Z

    .line 186
    .line 187
    invoke-virtual {v0, v5}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    goto :goto_2

    .line 191
    :cond_4
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 192
    .line 193
    iget-boolean v3, v0, La8/i1;->p:Z

    .line 194
    .line 195
    if-eqz v3, :cond_5

    .line 196
    .line 197
    invoke-virtual {v0}, La8/i1;->a()La8/i1;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    iput-object v0, p0, La8/i0;->y1:La8/i1;

    .line 202
    .line 203
    :cond_5
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 204
    .line 205
    invoke-static {v0, v2}, La8/i0;->s0(La8/i1;I)La8/i1;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    iput-object v0, p0, La8/i0;->y1:La8/i1;

    .line 210
    .line 211
    iget-object v2, v0, La8/i1;->b:Lh8/b0;

    .line 212
    .line 213
    invoke-virtual {v0, v2}, La8/i1;->c(Lh8/b0;)La8/i1;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    iput-object v0, p0, La8/i0;->y1:La8/i1;

    .line 218
    .line 219
    iget-wide v2, v0, La8/i1;->s:J

    .line 220
    .line 221
    iput-wide v2, v0, La8/i1;->q:J

    .line 222
    .line 223
    iget-object v0, p0, La8/i0;->y1:La8/i1;

    .line 224
    .line 225
    const-wide/16 v2, 0x0

    .line 226
    .line 227
    iput-wide v2, v0, La8/i1;->r:J

    .line 228
    .line 229
    iget-object v0, p0, La8/i0;->w:Lb8/e;

    .line 230
    .line 231
    iget-object v2, v0, Lb8/e;->k:Lw7/t;

    .line 232
    .line 233
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    new-instance v3, La0/d;

    .line 237
    .line 238
    const/16 v4, 0xb

    .line 239
    .line 240
    invoke-direct {v3, v0, v4}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v2, v3}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 244
    .line 245
    .line 246
    invoke-virtual {p0}, La8/i0;->z0()V

    .line 247
    .line 248
    .line 249
    iget-object v0, p0, La8/i0;->Z:Landroid/view/Surface;

    .line 250
    .line 251
    if-eqz v0, :cond_6

    .line 252
    .line 253
    invoke-virtual {v0}, Landroid/view/Surface;->release()V

    .line 254
    .line 255
    .line 256
    iput-object v1, p0, La8/i0;->Z:Landroid/view/Surface;

    .line 257
    .line 258
    :cond_6
    sget-object v0, Lv7/c;->c:Lv7/c;

    .line 259
    .line 260
    iput-object v0, p0, La8/i0;->s1:Lv7/c;

    .line 261
    .line 262
    return-void

    .line 263
    :catchall_0
    move-exception p0

    .line 264
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 265
    throw p0
.end method

.method public final y0(Lt7/j0;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, La8/i0;->q:Le30/v;

    .line 8
    .line 9
    invoke-virtual {p0}, Le30/v;->f()V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 13
    .line 14
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_2

    .line 25
    .line 26
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Lw7/l;

    .line 31
    .line 32
    iget-object v3, v2, Lw7/l;->a:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-virtual {v3, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-eqz v3, :cond_0

    .line 39
    .line 40
    iget-object v3, p0, Le30/v;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v3, Lw7/k;

    .line 43
    .line 44
    const/4 v4, 0x1

    .line 45
    iput-boolean v4, v2, Lw7/l;->d:Z

    .line 46
    .line 47
    iget-boolean v4, v2, Lw7/l;->c:Z

    .line 48
    .line 49
    if-eqz v4, :cond_1

    .line 50
    .line 51
    const/4 v4, 0x0

    .line 52
    iput-boolean v4, v2, Lw7/l;->c:Z

    .line 53
    .line 54
    iget-object v4, v2, Lw7/l;->a:Ljava/lang/Object;

    .line 55
    .line 56
    iget-object v5, v2, Lw7/l;->b:Lb6/f;

    .line 57
    .line 58
    invoke-virtual {v5}, Lb6/f;->i()Lt7/m;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    invoke-interface {v3, v4, v5}, Lw7/k;->a(Ljava/lang/Object;Lt7/m;)V

    .line 63
    .line 64
    .line 65
    :cond_1
    invoke-virtual {v0, v2}, Ljava/util/concurrent/CopyOnWriteArraySet;->remove(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    return-void
.end method

.method public final z0()V
    .locals 4

    .line 1
    iget-object v0, p0, La8/i0;->b0:Ln8/k;

    .line 2
    .line 3
    iget-object v1, p0, La8/i0;->D:La8/f0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, La8/i0;->E:La8/g0;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, La8/i0;->d0(La8/k1;)La8/l1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-boolean v3, v0, La8/l1;->f:Z

    .line 15
    .line 16
    xor-int/lit8 v3, v3, 0x1

    .line 17
    .line 18
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 19
    .line 20
    .line 21
    const/16 v3, 0x2710

    .line 22
    .line 23
    iput v3, v0, La8/l1;->c:I

    .line 24
    .line 25
    iget-boolean v3, v0, La8/l1;->f:Z

    .line 26
    .line 27
    xor-int/lit8 v3, v3, 0x1

    .line 28
    .line 29
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 30
    .line 31
    .line 32
    iput-object v2, v0, La8/l1;->d:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-virtual {v0}, La8/l1;->b()V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, La8/i0;->b0:Ln8/k;

    .line 38
    .line 39
    iget-object v0, v0, Ln8/k;->d:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    iput-object v2, p0, La8/i0;->b0:Ln8/k;

    .line 45
    .line 46
    :cond_0
    iget-object v0, p0, La8/i0;->d0:Landroid/view/TextureView;

    .line 47
    .line 48
    if-eqz v0, :cond_2

    .line 49
    .line 50
    invoke-virtual {v0}, Landroid/view/TextureView;->getSurfaceTextureListener()Landroid/view/TextureView$SurfaceTextureListener;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    if-eq v0, v1, :cond_1

    .line 55
    .line 56
    const-string v0, "ExoPlayerImpl"

    .line 57
    .line 58
    const-string v3, "SurfaceTextureListener already unset or replaced."

    .line 59
    .line 60
    invoke-static {v0, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    iget-object v0, p0, La8/i0;->d0:Landroid/view/TextureView;

    .line 65
    .line 66
    invoke-virtual {v0, v2}, Landroid/view/TextureView;->setSurfaceTextureListener(Landroid/view/TextureView$SurfaceTextureListener;)V

    .line 67
    .line 68
    .line 69
    :goto_0
    iput-object v2, p0, La8/i0;->d0:Landroid/view/TextureView;

    .line 70
    .line 71
    :cond_2
    iget-object v0, p0, La8/i0;->a0:Landroid/view/SurfaceHolder;

    .line 72
    .line 73
    if-eqz v0, :cond_3

    .line 74
    .line 75
    invoke-interface {v0, v1}, Landroid/view/SurfaceHolder;->removeCallback(Landroid/view/SurfaceHolder$Callback;)V

    .line 76
    .line 77
    .line 78
    iput-object v2, p0, La8/i0;->a0:Landroid/view/SurfaceHolder;

    .line 79
    .line 80
    :cond_3
    return-void
.end method
