.class public final synthetic Lb0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lb0/u;

.field public final synthetic f:Ljava/util/concurrent/Executor;

.field public final synthetic g:J

.field public final synthetic h:I

.field public final synthetic i:Landroid/content/Context;

.field public final synthetic j:Ly4/h;


# direct methods
.method public synthetic constructor <init>(Lb0/u;Landroid/content/Context;Ljava/util/concurrent/Executor;ILy4/h;J)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lb0/t;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb0/t;->e:Lb0/u;

    iput-object p2, p0, Lb0/t;->i:Landroid/content/Context;

    iput-object p3, p0, Lb0/t;->f:Ljava/util/concurrent/Executor;

    iput p4, p0, Lb0/t;->h:I

    iput-object p5, p0, Lb0/t;->j:Ly4/h;

    iput-wide p6, p0, Lb0/t;->g:J

    return-void
.end method

.method public synthetic constructor <init>(Lb0/u;Ljava/util/concurrent/Executor;JILandroid/content/Context;Ly4/h;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lb0/t;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb0/t;->e:Lb0/u;

    iput-object p2, p0, Lb0/t;->f:Ljava/util/concurrent/Executor;

    iput-wide p3, p0, Lb0/t;->g:J

    iput p5, p0, Lb0/t;->h:I

    iput-object p6, p0, Lb0/t;->i:Landroid/content/Context;

    iput-object p7, p0, Lb0/t;->j:Ly4/h;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb0/t;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v3, v0, Lb0/t;->e:Lb0/u;

    .line 9
    .line 10
    iget-object v5, v0, Lb0/t;->f:Ljava/util/concurrent/Executor;

    .line 11
    .line 12
    iget-wide v8, v0, Lb0/t;->g:J

    .line 13
    .line 14
    iget v1, v0, Lb0/t;->h:I

    .line 15
    .line 16
    iget-object v4, v0, Lb0/t;->i:Landroid/content/Context;

    .line 17
    .line 18
    iget-object v7, v0, Lb0/t;->j:Ly4/h;

    .line 19
    .line 20
    add-int/lit8 v6, v1, 0x1

    .line 21
    .line 22
    new-instance v2, Lb0/t;

    .line 23
    .line 24
    invoke-direct/range {v2 .. v9}, Lb0/t;-><init>(Lb0/u;Landroid/content/Context;Ljava/util/concurrent/Executor;ILy4/h;J)V

    .line 25
    .line 26
    .line 27
    invoke-interface {v5, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :pswitch_0
    iget-object v7, v0, Lb0/t;->e:Lb0/u;

    .line 32
    .line 33
    iget-object v1, v0, Lb0/t;->i:Landroid/content/Context;

    .line 34
    .line 35
    iget-object v8, v0, Lb0/t;->f:Ljava/util/concurrent/Executor;

    .line 36
    .line 37
    iget v11, v0, Lb0/t;->h:I

    .line 38
    .line 39
    iget-object v13, v0, Lb0/t;->j:Ly4/h;

    .line 40
    .line 41
    iget-wide v9, v0, Lb0/t;->g:J

    .line 42
    .line 43
    const-string v0, "CX:initAndRetryRecursively"

    .line 44
    .line 45
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-static {v1}, Llp/i1;->a(Landroid/content/Context;)Landroid/content/Context;

    .line 53
    .line 54
    .line 55
    move-result-object v15

    .line 56
    const/4 v1, 0x4

    .line 57
    const/4 v2, 0x0

    .line 58
    :try_start_0
    iget-object v0, v7, Lb0/u;->c:Lb0/w;

    .line 59
    .line 60
    invoke-virtual {v0}, Lb0/w;->c()Ls/a;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    if-eqz v0, :cond_5

    .line 65
    .line 66
    iget-object v0, v7, Lb0/u;->d:Ljava/util/concurrent/Executor;

    .line 67
    .line 68
    iget-object v3, v7, Lb0/u;->e:Landroid/os/Handler;

    .line 69
    .line 70
    new-instance v4, Lh0/f;

    .line 71
    .line 72
    invoke-direct {v4, v0, v3}, Lh0/f;-><init>(Ljava/util/concurrent/Executor;Landroid/os/Handler;)V

    .line 73
    .line 74
    .line 75
    iget-object v0, v7, Lb0/u;->c:Lb0/w;

    .line 76
    .line 77
    invoke-virtual {v0}, Lb0/w;->a()Lb0/r;

    .line 78
    .line 79
    .line 80
    move-result-object v17

    .line 81
    iget-object v0, v7, Lb0/u;->c:Lb0/w;

    .line 82
    .line 83
    invoke-virtual {v0}, Lb0/w;->h()J

    .line 84
    .line 85
    .line 86
    move-result-wide v18

    .line 87
    iget-object v0, v7, Lb0/u;->c:Lb0/w;

    .line 88
    .line 89
    invoke-virtual {v0}, Lb0/w;->n()Ls/c;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    if-eqz v0, :cond_4

    .line 94
    .line 95
    new-instance v0, Lu/g0;

    .line 96
    .line 97
    invoke-direct {v0, v15}, Lu/g0;-><init>(Landroid/content/Context;)V

    .line 98
    .line 99
    .line 100
    iput-object v0, v7, Lb0/u;->i:Lu/g0;

    .line 101
    .line 102
    new-instance v3, Lc2/k;

    .line 103
    .line 104
    invoke-direct {v3, v0}, Lc2/k;-><init>(Lu/g0;)V

    .line 105
    .line 106
    .line 107
    iput-object v3, v7, Lb0/u;->j:Lc2/k;

    .line 108
    .line 109
    iget-object v0, v7, Lb0/u;->c:Lb0/w;

    .line 110
    .line 111
    new-instance v14, Lu/n;

    .line 112
    .line 113
    move-object/from16 v20, v0

    .line 114
    .line 115
    move-object/from16 v21, v3

    .line 116
    .line 117
    move-object/from16 v16, v4

    .line 118
    .line 119
    invoke-direct/range {v14 .. v21}, Lu/n;-><init>(Landroid/content/Context;Lh0/f;Lb0/r;JLb0/w;Lc2/k;)V

    .line 120
    .line 121
    .line 122
    move-object/from16 v0, v17

    .line 123
    .line 124
    iput-object v14, v7, Lb0/u;->g:Lu/n;

    .line 125
    .line 126
    iget-object v3, v7, Lb0/u;->c:Lb0/w;

    .line 127
    .line 128
    invoke-virtual {v3}, Lb0/w;->m()Ls/b;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    if-eqz v3, :cond_3

    .line 133
    .line 134
    iget-object v3, v7, Lb0/u;->g:Lu/n;

    .line 135
    .line 136
    iget-object v4, v3, Lu/n;->e:Lv/d;

    .line 137
    .line 138
    invoke-virtual {v3}, Lu/n;->a()Ljava/util/LinkedHashSet;

    .line 139
    .line 140
    .line 141
    move-result-object v3

    .line 142
    invoke-static {v15, v4, v3}, Ls/b;->a(Landroid/content/Context;Ljava/lang/Object;Ljava/util/LinkedHashSet;)Lu/d0;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    iput-object v3, v7, Lb0/u;->h:Lu/d0;

    .line 147
    .line 148
    iget-object v4, v7, Lb0/u;->j:Lc2/k;

    .line 149
    .line 150
    iput-object v3, v4, Lc2/k;->f:Ljava/lang/Object;

    .line 151
    .line 152
    instance-of v3, v8, Lb0/o;

    .line 153
    .line 154
    if-eqz v3, :cond_0

    .line 155
    .line 156
    move-object v3, v8

    .line 157
    check-cast v3, Lb0/o;

    .line 158
    .line 159
    iget-object v4, v7, Lb0/u;->g:Lu/n;

    .line 160
    .line 161
    invoke-virtual {v3, v4}, Lb0/o;->a(Lu/n;)V

    .line 162
    .line 163
    .line 164
    goto :goto_0

    .line 165
    :catch_0
    move-exception v0

    .line 166
    goto/16 :goto_3

    .line 167
    .line 168
    :cond_0
    :goto_0
    iget-object v3, v7, Lb0/u;->a:Lh0/i0;

    .line 169
    .line 170
    iget-object v4, v7, Lb0/u;->g:Lu/n;

    .line 171
    .line 172
    invoke-virtual {v3, v4}, Lh0/i0;->d(Lu/n;)V

    .line 173
    .line 174
    .line 175
    iget-object v3, v7, Lb0/u;->g:Lu/n;

    .line 176
    .line 177
    iget-object v3, v3, Lu/n;->b:Lz/a;

    .line 178
    .line 179
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    new-instance v4, Lcom/google/firebase/messaging/w;

    .line 183
    .line 184
    iget-object v5, v7, Lb0/u;->a:Lh0/i0;

    .line 185
    .line 186
    iget-object v6, v7, Lb0/u;->i:Lu/g0;

    .line 187
    .line 188
    iget-object v12, v7, Lb0/u;->j:Lc2/k;

    .line 189
    .line 190
    invoke-direct {v4, v5, v3, v6, v12}, Lcom/google/firebase/messaging/w;-><init>(Lh0/i0;Lz/a;Lu/g0;Lc2/k;)V

    .line 191
    .line 192
    .line 193
    iput-object v4, v7, Lb0/u;->k:Lcom/google/firebase/messaging/w;

    .line 194
    .line 195
    iget-object v3, v7, Lb0/u;->a:Lh0/i0;

    .line 196
    .line 197
    invoke-virtual {v3}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 198
    .line 199
    .line 200
    move-result-object v3

    .line 201
    invoke-virtual {v3}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 206
    .line 207
    .line 208
    move-result v4

    .line 209
    if-eqz v4, :cond_1

    .line 210
    .line 211
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    check-cast v4, Lh0/b0;

    .line 216
    .line 217
    invoke-interface {v4}, Lh0/b0;->l()Lh0/z;

    .line 218
    .line 219
    .line 220
    move-result-object v4

    .line 221
    iget-object v5, v7, Lb0/u;->k:Lcom/google/firebase/messaging/w;

    .line 222
    .line 223
    invoke-interface {v4, v5}, Lh0/z;->n(Lcom/google/firebase/messaging/w;)V

    .line 224
    .line 225
    .line 226
    goto :goto_1

    .line 227
    :cond_1
    iget-object v3, v7, Lb0/u;->n:Lh0/e0;

    .line 228
    .line 229
    iget-object v4, v7, Lb0/u;->g:Lu/n;

    .line 230
    .line 231
    iget-object v5, v7, Lb0/u;->a:Lh0/i0;

    .line 232
    .line 233
    invoke-virtual {v3, v4, v5}, Lh0/e0;->f(Lu/n;Lh0/i0;)V

    .line 234
    .line 235
    .line 236
    iget-object v3, v7, Lb0/u;->n:Lh0/e0;

    .line 237
    .line 238
    iget-object v4, v7, Lb0/u;->h:Lu/d0;

    .line 239
    .line 240
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 241
    .line 242
    .line 243
    const-string v5, "listener"

    .line 244
    .line 245
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    iget-object v3, v3, Lh0/e0;->i:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 249
    .line 250
    invoke-virtual {v3, v4}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    iget-object v3, v7, Lb0/u;->n:Lh0/e0;

    .line 254
    .line 255
    iget-object v4, v7, Lb0/u;->g:Lu/n;

    .line 256
    .line 257
    iget-object v4, v4, Lu/n;->b:Lz/a;

    .line 258
    .line 259
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 260
    .line 261
    .line 262
    const-string v5, "listener"

    .line 263
    .line 264
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    iget-object v3, v3, Lh0/e0;->i:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 268
    .line 269
    invoke-virtual {v3, v4}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    iget-object v3, v7, Lb0/u;->a:Lh0/i0;

    .line 273
    .line 274
    invoke-static {v15, v3, v0}, Lh0/n0;->a(Landroid/content/Context;Lh0/i0;Lb0/r;)V

    .line 275
    .line 276
    .line 277
    const/4 v0, 0x1

    .line 278
    if-le v11, v0, :cond_2

    .line 279
    .line 280
    invoke-static {}, Lab/a;->a()Z

    .line 281
    .line 282
    .line 283
    move-result v0

    .line 284
    if-eqz v0, :cond_2

    .line 285
    .line 286
    const-string v0, "CX:CameraProvider-RetryStatus"

    .line 287
    .line 288
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    const/4 v3, -0x1

    .line 293
    int-to-long v3, v3

    .line 294
    invoke-static {v0, v3, v4}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 295
    .line 296
    .line 297
    :cond_2
    iget-object v3, v7, Lb0/u;->b:Ljava/lang/Object;

    .line 298
    .line 299
    monitor-enter v3
    :try_end_0
    .catch Lh0/m0; {:try_start_0 .. :try_end_0} :catch_0
    .catch Lb0/c1; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 300
    :try_start_1
    iput v1, v7, Lb0/u;->o:I

    .line 301
    .line 302
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 303
    :try_start_2
    invoke-virtual {v13, v2}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_2
    .catch Lh0/m0; {:try_start_2 .. :try_end_2} :catch_0
    .catch Lb0/c1; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 304
    .line 305
    .line 306
    :goto_2
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 307
    .line 308
    .line 309
    goto/16 :goto_4

    .line 310
    .line 311
    :catchall_0
    move-exception v0

    .line 312
    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 313
    :try_start_4
    throw v0

    .line 314
    :cond_3
    new-instance v0, Lb0/c1;

    .line 315
    .line 316
    new-instance v3, Ljava/lang/IllegalArgumentException;

    .line 317
    .line 318
    const-string v4, "Invalid app configuration provided. Missing CameraDeviceSurfaceManager."

    .line 319
    .line 320
    invoke-direct {v3, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    invoke-direct {v0, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 324
    .line 325
    .line 326
    throw v0

    .line 327
    :cond_4
    new-instance v0, Lb0/c1;

    .line 328
    .line 329
    new-instance v3, Ljava/lang/IllegalArgumentException;

    .line 330
    .line 331
    const-string v4, "Invalid app configuration provided. Missing UseCaseConfigFactory."

    .line 332
    .line 333
    invoke-direct {v3, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 334
    .line 335
    .line 336
    invoke-direct {v0, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 337
    .line 338
    .line 339
    throw v0

    .line 340
    :cond_5
    new-instance v0, Lb0/c1;

    .line 341
    .line 342
    new-instance v3, Ljava/lang/IllegalArgumentException;

    .line 343
    .line 344
    const-string v4, "Invalid app configuration provided. Missing CameraFactory."

    .line 345
    .line 346
    invoke-direct {v3, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    invoke-direct {v0, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 350
    .line 351
    .line 352
    throw v0
    :try_end_4
    .catch Lh0/m0; {:try_start_4 .. :try_end_4} :catch_0
    .catch Lb0/c1; {:try_start_4 .. :try_end_4} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 353
    :goto_3
    :try_start_5
    new-instance v3, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 354
    .line 355
    invoke-direct {v3, v9, v10, v0}, Lcom/google/crypto/tink/shaded/protobuf/d;-><init>(JLjava/lang/Exception;)V

    .line 356
    .line 357
    .line 358
    iget-object v4, v7, Lb0/u;->l:Lb0/m1;

    .line 359
    .line 360
    invoke-interface {v4, v3}, Lb0/m1;->b(Lcom/google/crypto/tink/shaded/protobuf/d;)Lb0/l1;

    .line 361
    .line 362
    .line 363
    move-result-object v4

    .line 364
    invoke-static {}, Lab/a;->a()Z

    .line 365
    .line 366
    .line 367
    move-result v5

    .line 368
    if-eqz v5, :cond_6

    .line 369
    .line 370
    iget v3, v3, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 371
    .line 372
    const-string v5, "CX:CameraProvider-RetryStatus"

    .line 373
    .line 374
    invoke-static {v5}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 375
    .line 376
    .line 377
    move-result-object v5

    .line 378
    int-to-long v2, v3

    .line 379
    invoke-static {v5, v2, v3}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 380
    .line 381
    .line 382
    :cond_6
    iget-object v2, v7, Lb0/u;->n:Lh0/e0;

    .line 383
    .line 384
    invoke-virtual {v2}, Lh0/e0;->e()V

    .line 385
    .line 386
    .line 387
    iget-boolean v2, v4, Lb0/l1;->b:Z

    .line 388
    .line 389
    if-eqz v2, :cond_7

    .line 390
    .line 391
    const v2, 0x7fffffff

    .line 392
    .line 393
    .line 394
    if-ge v11, v2, :cond_7

    .line 395
    .line 396
    const-string v1, "CameraX"

    .line 397
    .line 398
    new-instance v2, Ljava/lang/StringBuilder;

    .line 399
    .line 400
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 401
    .line 402
    .line 403
    const-string v3, "Retry init. Start time "

    .line 404
    .line 405
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 406
    .line 407
    .line 408
    invoke-virtual {v2, v9, v10}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 409
    .line 410
    .line 411
    const-string v3, " current time "

    .line 412
    .line 413
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 414
    .line 415
    .line 416
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 417
    .line 418
    .line 419
    move-result-wide v5

    .line 420
    invoke-virtual {v2, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 421
    .line 422
    .line 423
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 424
    .line 425
    .line 426
    move-result-object v2

    .line 427
    invoke-static {v1, v2, v0}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 428
    .line 429
    .line 430
    iget-object v0, v7, Lb0/u;->e:Landroid/os/Handler;

    .line 431
    .line 432
    new-instance v6, Lb0/t;

    .line 433
    .line 434
    move-object v12, v15

    .line 435
    invoke-direct/range {v6 .. v13}, Lb0/t;-><init>(Lb0/u;Ljava/util/concurrent/Executor;JILandroid/content/Context;Ly4/h;)V

    .line 436
    .line 437
    .line 438
    const-string v1, "retry_token"

    .line 439
    .line 440
    iget-wide v2, v4, Lb0/l1;->a:J

    .line 441
    .line 442
    invoke-virtual {v0, v6, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;Ljava/lang/Object;J)Z

    .line 443
    .line 444
    .line 445
    goto/16 :goto_2

    .line 446
    .line 447
    :cond_7
    iget-object v2, v7, Lb0/u;->b:Ljava/lang/Object;

    .line 448
    .line 449
    monitor-enter v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 450
    const/4 v3, 0x3

    .line 451
    :try_start_6
    iput v3, v7, Lb0/u;->o:I

    .line 452
    .line 453
    monitor-exit v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 454
    :try_start_7
    iget-boolean v2, v4, Lb0/l1;->c:Z

    .line 455
    .line 456
    if-eqz v2, :cond_8

    .line 457
    .line 458
    iget-object v2, v7, Lb0/u;->b:Ljava/lang/Object;

    .line 459
    .line 460
    monitor-enter v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 461
    :try_start_8
    iput v1, v7, Lb0/u;->o:I

    .line 462
    .line 463
    monitor-exit v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 464
    const/4 v1, 0x0

    .line 465
    :try_start_9
    invoke-virtual {v13, v1}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 466
    .line 467
    .line 468
    goto/16 :goto_2

    .line 469
    .line 470
    :catchall_1
    move-exception v0

    .line 471
    :try_start_a
    monitor-exit v2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    .line 472
    :try_start_b
    throw v0

    .line 473
    :cond_8
    instance-of v1, v0, Lh0/m0;

    .line 474
    .line 475
    if-eqz v1, :cond_9

    .line 476
    .line 477
    new-instance v1, Ljava/lang/StringBuilder;

    .line 478
    .line 479
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 480
    .line 481
    .line 482
    const-string v2, "Device reporting less cameras than anticipated. On real devices: Retrying initialization might resolve temporary camera errors. On emulators: Ensure virtual camera configuration matches supported camera features as reported by PackageManager#hasSystemFeature. Available cameras: "

    .line 483
    .line 484
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 485
    .line 486
    .line 487
    move-object v2, v0

    .line 488
    check-cast v2, Lh0/m0;

    .line 489
    .line 490
    iget v2, v2, Lh0/m0;->d:I

    .line 491
    .line 492
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 493
    .line 494
    .line 495
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 496
    .line 497
    .line 498
    move-result-object v1

    .line 499
    const-string v2, "CameraX"

    .line 500
    .line 501
    invoke-static {v2, v1, v0}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 502
    .line 503
    .line 504
    new-instance v0, Lb0/c1;

    .line 505
    .line 506
    new-instance v2, Lb0/s;

    .line 507
    .line 508
    invoke-direct {v2, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 509
    .line 510
    .line 511
    invoke-direct {v0, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 512
    .line 513
    .line 514
    invoke-virtual {v13, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 515
    .line 516
    .line 517
    goto/16 :goto_2

    .line 518
    .line 519
    :cond_9
    instance-of v1, v0, Lb0/c1;

    .line 520
    .line 521
    if-eqz v1, :cond_a

    .line 522
    .line 523
    invoke-virtual {v13, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 524
    .line 525
    .line 526
    goto/16 :goto_2

    .line 527
    .line 528
    :cond_a
    new-instance v1, Lb0/c1;

    .line 529
    .line 530
    invoke-direct {v1, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 531
    .line 532
    .line 533
    invoke-virtual {v13, v1}, Ly4/h;->d(Ljava/lang/Throwable;)Z
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_3

    .line 534
    .line 535
    .line 536
    goto/16 :goto_2

    .line 537
    .line 538
    :goto_4
    return-void

    .line 539
    :catchall_2
    move-exception v0

    .line 540
    :try_start_c
    monitor-exit v2
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_2

    .line 541
    :try_start_d
    throw v0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_3

    .line 542
    :catchall_3
    move-exception v0

    .line 543
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 544
    .line 545
    .line 546
    throw v0

    .line 547
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
