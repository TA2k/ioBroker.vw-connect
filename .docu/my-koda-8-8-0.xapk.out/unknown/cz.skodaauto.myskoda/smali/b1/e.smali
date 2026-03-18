.class public final Lb1/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lb1/e;->f:I

    iput-object p2, p0, Lb1/e;->g:Ljava/lang/Object;

    iput-object p3, p0, Lb1/e;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Ll2/b1;Lay0/k;)V
    .locals 1

    const/16 v0, 0xb

    iput v0, p0, Lb1/e;->f:I

    .line 2
    iput-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    check-cast p2, Lkotlin/jvm/internal/n;

    iput-object p2, p0, Lb1/e;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lb1/e;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 7
    .line 8
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Lx4/t;

    .line 11
    .line 12
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lx4/v;

    .line 15
    .line 16
    invoke-virtual {p1, p0}, Lx4/t;->setPositionProvider(Lx4/v;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Lx4/t;->n()V

    .line 20
    .line 21
    .line 22
    new-instance p0, Lx4/g;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    check-cast p1, Lx21/x;

    .line 29
    .line 30
    iget-object v0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lx21/x;

    .line 33
    .line 34
    const-string v1, "item"

    .line 35
    .line 36
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Lx21/y;

    .line 42
    .line 43
    iget-object v1, p0, Lx21/y;->r:Ljava/util/HashSet;

    .line 44
    .line 45
    iget-object v2, p1, Lx21/x;->a:Lm1/m;

    .line 46
    .line 47
    iget-object v2, v2, Lm1/m;->k:Ljava/lang/Object;

    .line 48
    .line 49
    invoke-virtual {v1, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_4

    .line 54
    .line 55
    iget-object v1, p0, Lx21/y;->g:Lx21/a0;

    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    const/4 v2, 0x1

    .line 62
    if-eqz v1, :cond_1

    .line 63
    .line 64
    if-ne v1, v2, :cond_0

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_0
    new-instance p0, La8/r0;

    .line 68
    .line 69
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_1
    invoke-virtual {p0}, Lx21/y;->f()Lg1/w1;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-eqz p0, :cond_3

    .line 82
    .line 83
    if-ne p0, v2, :cond_2

    .line 84
    .line 85
    invoke-virtual {p1}, Lx21/x;->b()J

    .line 86
    .line 87
    .line 88
    move-result-wide p0

    .line 89
    const-wide v3, 0xffffffffL

    .line 90
    .line 91
    .line 92
    .line 93
    .line 94
    and-long/2addr p0, v3

    .line 95
    long-to-int p0, p0

    .line 96
    invoke-virtual {v0}, Lx21/x;->b()J

    .line 97
    .line 98
    .line 99
    move-result-wide v0

    .line 100
    and-long/2addr v0, v3

    .line 101
    long-to-int p1, v0

    .line 102
    if-ne p0, p1, :cond_4

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_2
    new-instance p0, La8/r0;

    .line 106
    .line 107
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_3
    invoke-virtual {p1}, Lx21/x;->b()J

    .line 112
    .line 113
    .line 114
    move-result-wide p0

    .line 115
    const/16 v1, 0x20

    .line 116
    .line 117
    shr-long/2addr p0, v1

    .line 118
    long-to-int p0, p0

    .line 119
    invoke-virtual {v0}, Lx21/x;->b()J

    .line 120
    .line 121
    .line 122
    move-result-wide v3

    .line 123
    shr-long v0, v3, v1

    .line 124
    .line 125
    long-to-int p1, v0

    .line 126
    if-ne p0, p1, :cond_4

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_4
    const/4 v2, 0x0

    .line 130
    :goto_0
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :pswitch_1
    check-cast p1, Lt3/y;

    .line 136
    .line 137
    const-string v0, "it"

    .line 138
    .line 139
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v0, Ll2/b1;

    .line 145
    .line 146
    const-wide/16 v1, 0x0

    .line 147
    .line 148
    invoke-interface {p1, v1, v2}, Lt3/y;->R(J)J

    .line 149
    .line 150
    .line 151
    move-result-wide v1

    .line 152
    new-instance v3, Ld3/b;

    .line 153
    .line 154
    invoke-direct {v3, v1, v2}, Ld3/b;-><init>(J)V

    .line 155
    .line 156
    .line 157
    invoke-interface {v0, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast p0, Ll2/b1;

    .line 163
    .line 164
    invoke-interface {p1}, Lt3/y;->h()J

    .line 165
    .line 166
    .line 167
    move-result-wide v0

    .line 168
    new-instance p1, Lt4/l;

    .line 169
    .line 170
    invoke-direct {p1, v0, v1}, Lt4/l;-><init>(J)V

    .line 171
    .line 172
    .line 173
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 177
    .line 178
    return-object p0

    .line 179
    :pswitch_2
    check-cast p1, Lt3/d1;

    .line 180
    .line 181
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v0, Lt3/e1;

    .line 184
    .line 185
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p0, Lx2/v;

    .line 188
    .line 189
    iget p0, p0, Lx2/v;->r:F

    .line 190
    .line 191
    const/4 v1, 0x0

    .line 192
    invoke-virtual {p1, v0, v1, v1, p0}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 193
    .line 194
    .line 195
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 196
    .line 197
    return-object p0

    .line 198
    :pswitch_3
    check-cast p1, Lx2/s;

    .line 199
    .line 200
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v0, Lv3/h0;

    .line 203
    .line 204
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast p0, Lx2/s;

    .line 207
    .line 208
    invoke-interface {p1, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    invoke-virtual {v0, p0}, Lv3/h0;->i0(Lx2/s;)V

    .line 213
    .line 214
    .line 215
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 216
    .line 217
    return-object p0

    .line 218
    :pswitch_4
    check-cast p1, Lw3/l;

    .line 219
    .line 220
    iget-object v0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast v0, Lay0/n;

    .line 223
    .line 224
    iget-object p0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast p0, Lw3/s2;

    .line 227
    .line 228
    iget-boolean v1, p0, Lw3/s2;->f:Z

    .line 229
    .line 230
    if-nez v1, :cond_6

    .line 231
    .line 232
    iget-object p1, p1, Lw3/l;->a:Landroidx/lifecycle/x;

    .line 233
    .line 234
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    iput-object v0, p0, Lw3/s2;->h:Lay0/n;

    .line 239
    .line 240
    iget-object v1, p0, Lw3/s2;->g:Landroidx/lifecycle/r;

    .line 241
    .line 242
    if-nez v1, :cond_5

    .line 243
    .line 244
    iput-object p1, p0, Lw3/s2;->g:Landroidx/lifecycle/r;

    .line 245
    .line 246
    invoke-virtual {p1, p0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 247
    .line 248
    .line 249
    goto :goto_1

    .line 250
    :cond_5
    invoke-virtual {p1}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 251
    .line 252
    .line 253
    move-result-object p1

    .line 254
    sget-object v1, Landroidx/lifecycle/q;->f:Landroidx/lifecycle/q;

    .line 255
    .line 256
    invoke-virtual {p1, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 257
    .line 258
    .line 259
    move-result p1

    .line 260
    if-ltz p1, :cond_6

    .line 261
    .line 262
    iget-object p1, p0, Lw3/s2;->e:Ll2/a0;

    .line 263
    .line 264
    new-instance v1, Lw3/r2;

    .line 265
    .line 266
    const/4 v2, 0x1

    .line 267
    invoke-direct {v1, p0, v0, v2}, Lw3/r2;-><init>(Lw3/s2;Lay0/n;I)V

    .line 268
    .line 269
    .line 270
    new-instance p0, Lt2/b;

    .line 271
    .line 272
    const/4 v0, 0x1

    .line 273
    const v2, 0x4f523a4f

    .line 274
    .line 275
    .line 276
    invoke-direct {p0, v1, v0, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {p1, p0}, Ll2/a0;->A(Lay0/n;)V

    .line 280
    .line 281
    .line 282
    :cond_6
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 283
    .line 284
    return-object p0

    .line 285
    :pswitch_5
    check-cast p1, Landroid/view/View;

    .line 286
    .line 287
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 288
    .line 289
    check-cast v0, Landroid/view/View;

    .line 290
    .line 291
    invoke-virtual {p1}, Landroid/view/View;->getNextFocusForwardId()I

    .line 292
    .line 293
    .line 294
    move-result v1

    .line 295
    new-instance v2, Lc3/k;

    .line 296
    .line 297
    const/4 v3, 0x2

    .line 298
    invoke-direct {v2, v1, v3}, Lc3/k;-><init>(II)V

    .line 299
    .line 300
    .line 301
    const/4 v1, 0x0

    .line 302
    move-object v3, v1

    .line 303
    :goto_2
    invoke-static {p1, v2, v3}, Lw3/h0;->q(Landroid/view/View;Lay0/k;Landroid/view/View;)Landroid/view/View;

    .line 304
    .line 305
    .line 306
    move-result-object v3

    .line 307
    if-nez v3, :cond_9

    .line 308
    .line 309
    if-ne p1, v0, :cond_7

    .line 310
    .line 311
    goto :goto_3

    .line 312
    :cond_7
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 313
    .line 314
    .line 315
    move-result-object v3

    .line 316
    if-eqz v3, :cond_a

    .line 317
    .line 318
    instance-of v4, v3, Landroid/view/View;

    .line 319
    .line 320
    if-nez v4, :cond_8

    .line 321
    .line 322
    goto :goto_4

    .line 323
    :cond_8
    check-cast v3, Landroid/view/View;

    .line 324
    .line 325
    move-object v12, v3

    .line 326
    move-object v3, p1

    .line 327
    move-object p1, v12

    .line 328
    goto :goto_2

    .line 329
    :cond_9
    :goto_3
    move-object v1, v3

    .line 330
    :cond_a
    :goto_4
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 331
    .line 332
    check-cast p0, Landroid/view/View;

    .line 333
    .line 334
    if-ne v1, p0, :cond_b

    .line 335
    .line 336
    const/4 p0, 0x1

    .line 337
    goto :goto_5

    .line 338
    :cond_b
    const/4 p0, 0x0

    .line 339
    :goto_5
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 340
    .line 341
    .line 342
    move-result-object p0

    .line 343
    return-object p0

    .line 344
    :pswitch_6
    check-cast p1, Ljava/lang/Throwable;

    .line 345
    .line 346
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 347
    .line 348
    check-cast p1, Ll2/l1;

    .line 349
    .line 350
    iget-object p1, p1, Ll2/l1;->e:Ljava/lang/Object;

    .line 351
    .line 352
    check-cast p1, Landroid/view/Choreographer;

    .line 353
    .line 354
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 355
    .line 356
    check-cast p0, Lw3/q0;

    .line 357
    .line 358
    invoke-virtual {p1, p0}, Landroid/view/Choreographer;->removeFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 359
    .line 360
    .line 361
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 362
    .line 363
    return-object p0

    .line 364
    :pswitch_7
    check-cast p1, Ljava/lang/Throwable;

    .line 365
    .line 366
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 367
    .line 368
    check-cast p1, Lw3/p0;

    .line 369
    .line 370
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast p0, Lw3/q0;

    .line 373
    .line 374
    iget-object v1, p1, Lw3/p0;->g:Ljava/lang/Object;

    .line 375
    .line 376
    monitor-enter v1

    .line 377
    :try_start_0
    iget-object p1, p1, Lw3/p0;->i:Ljava/util/ArrayList;

    .line 378
    .line 379
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 380
    .line 381
    .line 382
    monitor-exit v1

    .line 383
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 384
    .line 385
    return-object p0

    .line 386
    :catchall_0
    move-exception v0

    .line 387
    move-object p0, v0

    .line 388
    monitor-exit v1

    .line 389
    throw p0

    .line 390
    :pswitch_8
    check-cast p1, Ljava/lang/Throwable;

    .line 391
    .line 392
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast p1, Lw3/p1;

    .line 395
    .line 396
    iget-object v1, p1, Lw3/p1;->c:Ljava/lang/Object;

    .line 397
    .line 398
    monitor-enter v1

    .line 399
    const/4 v0, 0x1

    .line 400
    :try_start_1
    iput-boolean v0, p1, Lw3/p1;->e:Z

    .line 401
    .line 402
    iget-object v0, p1, Lw3/p1;->d:Ln2/b;

    .line 403
    .line 404
    iget-object v2, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 405
    .line 406
    iget v0, v0, Ln2/b;->f:I

    .line 407
    .line 408
    const/4 v3, 0x0

    .line 409
    :goto_6
    const/4 v4, 0x0

    .line 410
    if-ge v3, v0, :cond_d

    .line 411
    .line 412
    aget-object v5, v2, v3

    .line 413
    .line 414
    check-cast v5, Lv3/e2;

    .line 415
    .line 416
    invoke-virtual {v5}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 417
    .line 418
    .line 419
    move-result-object v5

    .line 420
    check-cast v5, Ll4/m;

    .line 421
    .line 422
    if-eqz v5, :cond_c

    .line 423
    .line 424
    iget-object v6, v5, Ll4/m;->b:Lc2/q;

    .line 425
    .line 426
    if-eqz v6, :cond_c

    .line 427
    .line 428
    invoke-virtual {v5, v6}, Ll4/m;->a(Lc2/q;)V

    .line 429
    .line 430
    .line 431
    iput-object v4, v5, Ll4/m;->b:Lc2/q;

    .line 432
    .line 433
    :cond_c
    add-int/lit8 v3, v3, 0x1

    .line 434
    .line 435
    goto :goto_6

    .line 436
    :catchall_1
    move-exception v0

    .line 437
    move-object p0, v0

    .line 438
    goto :goto_7

    .line 439
    :cond_d
    iget-object p1, p1, Lw3/p1;->d:Ln2/b;

    .line 440
    .line 441
    invoke-virtual {p1}, Ln2/b;->i()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 442
    .line 443
    .line 444
    monitor-exit v1

    .line 445
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 446
    .line 447
    check-cast p0, Lw3/m0;

    .line 448
    .line 449
    iget-object p0, p0, Lw3/m0;->e:Ll4/w;

    .line 450
    .line 451
    iget-object p1, p0, Ll4/w;->b:Ljava/util/concurrent/atomic/AtomicReference;

    .line 452
    .line 453
    invoke-virtual {p1, v4}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 454
    .line 455
    .line 456
    iget-object p0, p0, Ll4/w;->a:Ll4/q;

    .line 457
    .line 458
    invoke-interface {p0}, Ll4/q;->b()V

    .line 459
    .line 460
    .line 461
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 462
    .line 463
    return-object p0

    .line 464
    :goto_7
    monitor-exit v1

    .line 465
    throw p0

    .line 466
    :pswitch_9
    check-cast p1, Lvy0/b0;

    .line 467
    .line 468
    new-instance p1, Lw3/p1;

    .line 469
    .line 470
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 471
    .line 472
    check-cast v0, Lc2/p;

    .line 473
    .line 474
    new-instance v1, La7/j;

    .line 475
    .line 476
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 477
    .line 478
    check-cast p0, Lw3/m0;

    .line 479
    .line 480
    const/16 v2, 0x1a

    .line 481
    .line 482
    invoke-direct {v1, p0, v2}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 483
    .line 484
    .line 485
    invoke-direct {p1, v0, v1}, Lw3/p1;-><init>(Lc2/p;La7/j;)V

    .line 486
    .line 487
    .line 488
    return-object p1

    .line 489
    :pswitch_a
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 490
    .line 491
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 492
    .line 493
    check-cast p1, Landroid/content/Context;

    .line 494
    .line 495
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 500
    .line 501
    check-cast p0, Lw3/k0;

    .line 502
    .line 503
    invoke-virtual {v0, p0}, Landroid/content/Context;->registerComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 504
    .line 505
    .line 506
    new-instance v0, Laa/t;

    .line 507
    .line 508
    const/16 v1, 0x12

    .line 509
    .line 510
    invoke-direct {v0, v1, p1, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 511
    .line 512
    .line 513
    return-object v0

    .line 514
    :pswitch_b
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 515
    .line 516
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast p1, Landroid/content/Context;

    .line 519
    .line 520
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 521
    .line 522
    .line 523
    move-result-object v0

    .line 524
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 525
    .line 526
    check-cast p0, Lw3/j0;

    .line 527
    .line 528
    invoke-virtual {v0, p0}, Landroid/content/Context;->registerComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 529
    .line 530
    .line 531
    new-instance v0, Laa/t;

    .line 532
    .line 533
    const/16 v1, 0x11

    .line 534
    .line 535
    invoke-direct {v0, v1, p1, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 536
    .line 537
    .line 538
    return-object v0

    .line 539
    :pswitch_c
    check-cast p1, Ld3/b;

    .line 540
    .line 541
    iget-wide v0, p1, Ld3/b;->a:J

    .line 542
    .line 543
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 544
    .line 545
    check-cast p1, Ll2/b1;

    .line 546
    .line 547
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 548
    .line 549
    .line 550
    move-result-object p1

    .line 551
    check-cast p1, Lg4/l0;

    .line 552
    .line 553
    if-eqz p1, :cond_e

    .line 554
    .line 555
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 556
    .line 557
    check-cast p0, Lkotlin/jvm/internal/n;

    .line 558
    .line 559
    iget-object p1, p1, Lg4/l0;->b:Lg4/o;

    .line 560
    .line 561
    invoke-virtual {p1, v0, v1}, Lg4/o;->g(J)I

    .line 562
    .line 563
    .line 564
    move-result p1

    .line 565
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 566
    .line 567
    .line 568
    move-result-object p1

    .line 569
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 570
    .line 571
    .line 572
    :cond_e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 573
    .line 574
    return-object p0

    .line 575
    :pswitch_d
    move-object v0, p1

    .line 576
    check-cast v0, Lv3/m0;

    .line 577
    .line 578
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 579
    .line 580
    check-cast p1, Lt3/i1;

    .line 581
    .line 582
    iget-object v1, p1, Lt3/i1;->r:Lt3/s;

    .line 583
    .line 584
    iget-object v1, v1, Lt3/s;->j:Ll2/g1;

    .line 585
    .line 586
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 587
    .line 588
    .line 589
    move-result v1

    .line 590
    if-lez v1, :cond_11

    .line 591
    .line 592
    invoke-virtual {v0}, Lv3/m0;->b()Lt3/y;

    .line 593
    .line 594
    .line 595
    move-result-object v1

    .line 596
    invoke-interface {v1}, Lt3/y;->h()J

    .line 597
    .line 598
    .line 599
    move-result-wide v1

    .line 600
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 601
    .line 602
    check-cast p0, Lt3/s;

    .line 603
    .line 604
    iget-object p0, p0, Lt3/s;->i:Landroidx/collection/q0;

    .line 605
    .line 606
    const/16 v3, 0x20

    .line 607
    .line 608
    shr-long v3, v1, v3

    .line 609
    .line 610
    long-to-int v4, v3

    .line 611
    const-wide v5, 0xffffffffL

    .line 612
    .line 613
    .line 614
    .line 615
    .line 616
    and-long/2addr v1, v5

    .line 617
    long-to-int v5, v1

    .line 618
    sget-object v6, Landroidx/compose/ui/layout/b;->b:[Lt3/u1;

    .line 619
    .line 620
    array-length v7, v6

    .line 621
    const/4 v8, 0x0

    .line 622
    move v9, v8

    .line 623
    :goto_8
    if-ge v9, v7, :cond_10

    .line 624
    .line 625
    aget-object v1, v6, v9

    .line 626
    .line 627
    invoke-virtual {p0, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 628
    .line 629
    .line 630
    move-result-object v2

    .line 631
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 632
    .line 633
    .line 634
    move-object v10, v2

    .line 635
    check-cast v10, Lt3/w1;

    .line 636
    .line 637
    move-object v11, v1

    .line 638
    check-cast v11, Lt3/v1;

    .line 639
    .line 640
    iget-object v1, v11, Lt3/v1;->c:Lt3/r;

    .line 641
    .line 642
    iget-wide v2, v10, Lt3/w1;->h:J

    .line 643
    .line 644
    invoke-static/range {v0 .. v5}, Landroidx/compose/ui/layout/b;->a(Lv3/m0;Lt3/r;JII)V

    .line 645
    .line 646
    .line 647
    iget-object v1, v10, Lt3/w1;->b:Ll2/j1;

    .line 648
    .line 649
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 650
    .line 651
    .line 652
    move-result-object v1

    .line 653
    check-cast v1, Ljava/lang/Boolean;

    .line 654
    .line 655
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 656
    .line 657
    .line 658
    move-result v1

    .line 659
    if-eqz v1, :cond_f

    .line 660
    .line 661
    iget-object v1, v10, Lt3/w1;->f:Lt3/r;

    .line 662
    .line 663
    iget-wide v2, v10, Lt3/w1;->j:J

    .line 664
    .line 665
    invoke-static/range {v0 .. v5}, Landroidx/compose/ui/layout/b;->a(Lv3/m0;Lt3/r;JII)V

    .line 666
    .line 667
    .line 668
    iget-object v1, v10, Lt3/w1;->g:Lt3/r;

    .line 669
    .line 670
    iget-wide v2, v10, Lt3/w1;->k:J

    .line 671
    .line 672
    invoke-static/range {v0 .. v5}, Landroidx/compose/ui/layout/b;->a(Lv3/m0;Lt3/r;JII)V

    .line 673
    .line 674
    .line 675
    :cond_f
    iget-object v1, v11, Lt3/v1;->d:Lt3/r;

    .line 676
    .line 677
    iget-wide v2, v10, Lt3/w1;->i:J

    .line 678
    .line 679
    invoke-static/range {v0 .. v5}, Landroidx/compose/ui/layout/b;->a(Lv3/m0;Lt3/r;JII)V

    .line 680
    .line 681
    .line 682
    add-int/lit8 v9, v9, 0x1

    .line 683
    .line 684
    goto :goto_8

    .line 685
    :cond_10
    iget-object p0, p1, Lt3/i1;->r:Lt3/s;

    .line 686
    .line 687
    iget-object p0, p0, Lt3/s;->k:Landroidx/collection/l0;

    .line 688
    .line 689
    invoke-virtual {p0}, Landroidx/collection/l0;->h()Z

    .line 690
    .line 691
    .line 692
    move-result p0

    .line 693
    if-eqz p0, :cond_11

    .line 694
    .line 695
    iget-object p0, p1, Lt3/i1;->r:Lt3/s;

    .line 696
    .line 697
    iget-object p0, p0, Lt3/s;->k:Landroidx/collection/l0;

    .line 698
    .line 699
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 700
    .line 701
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 702
    .line 703
    :goto_9
    if-ge v8, p0, :cond_11

    .line 704
    .line 705
    aget-object v2, v1, v8

    .line 706
    .line 707
    check-cast v2, Ll2/b1;

    .line 708
    .line 709
    iget-object v3, p1, Lt3/i1;->r:Lt3/s;

    .line 710
    .line 711
    iget-object v3, v3, Lt3/s;->l:Lv2/o;

    .line 712
    .line 713
    invoke-virtual {v3, v8}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 714
    .line 715
    .line 716
    move-result-object v3

    .line 717
    check-cast v3, Lt3/r;

    .line 718
    .line 719
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 720
    .line 721
    .line 722
    move-result-object v2

    .line 723
    check-cast v2, Landroid/graphics/Rect;

    .line 724
    .line 725
    invoke-virtual {v3}, Lt3/r;->b()Lt3/q;

    .line 726
    .line 727
    .line 728
    move-result-object v4

    .line 729
    iget v5, v2, Landroid/graphics/Rect;->left:I

    .line 730
    .line 731
    int-to-float v5, v5

    .line 732
    invoke-virtual {v0, v4, v5}, Lv3/m0;->c(Lt3/q;F)V

    .line 733
    .line 734
    .line 735
    invoke-virtual {v3}, Lt3/r;->d()Lt3/q;

    .line 736
    .line 737
    .line 738
    move-result-object v4

    .line 739
    iget v5, v2, Landroid/graphics/Rect;->top:I

    .line 740
    .line 741
    int-to-float v5, v5

    .line 742
    invoke-virtual {v0, v4, v5}, Lv3/m0;->c(Lt3/q;F)V

    .line 743
    .line 744
    .line 745
    invoke-virtual {v3}, Lt3/r;->c()Lt3/q;

    .line 746
    .line 747
    .line 748
    move-result-object v4

    .line 749
    iget v5, v2, Landroid/graphics/Rect;->right:I

    .line 750
    .line 751
    int-to-float v5, v5

    .line 752
    invoke-virtual {v0, v4, v5}, Lv3/m0;->c(Lt3/q;F)V

    .line 753
    .line 754
    .line 755
    invoke-virtual {v3}, Lt3/r;->a()Lt3/q;

    .line 756
    .line 757
    .line 758
    move-result-object v3

    .line 759
    iget v2, v2, Landroid/graphics/Rect;->bottom:I

    .line 760
    .line 761
    int-to-float v2, v2

    .line 762
    invoke-virtual {v0, v3, v2}, Lv3/m0;->c(Lt3/q;F)V

    .line 763
    .line 764
    .line 765
    add-int/lit8 v8, v8, 0x1

    .line 766
    .line 767
    goto :goto_9

    .line 768
    :cond_11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 769
    .line 770
    return-object p0

    .line 771
    :pswitch_e
    const-string v0, "onTouchEvent"

    .line 772
    .line 773
    check-cast p1, Landroid/view/MotionEvent;

    .line 774
    .line 775
    iget-object v1, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 776
    .line 777
    check-cast v1, Lp3/a0;

    .line 778
    .line 779
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 780
    .line 781
    .line 782
    move-result v2

    .line 783
    const/4 v3, 0x0

    .line 784
    if-nez v2, :cond_14

    .line 785
    .line 786
    iget-object p0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 787
    .line 788
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 789
    .line 790
    iget-object v1, v1, Lp3/a0;->b:Lay0/k;

    .line 791
    .line 792
    if-eqz v1, :cond_13

    .line 793
    .line 794
    invoke-interface {v1, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 795
    .line 796
    .line 797
    move-result-object p1

    .line 798
    check-cast p1, Ljava/lang/Boolean;

    .line 799
    .line 800
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 801
    .line 802
    .line 803
    move-result p1

    .line 804
    if-eqz p1, :cond_12

    .line 805
    .line 806
    sget-object p1, Lp3/y;->e:Lp3/y;

    .line 807
    .line 808
    goto :goto_a

    .line 809
    :cond_12
    sget-object p1, Lp3/y;->f:Lp3/y;

    .line 810
    .line 811
    :goto_a
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 812
    .line 813
    goto :goto_b

    .line 814
    :cond_13
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 815
    .line 816
    .line 817
    throw v3

    .line 818
    :cond_14
    iget-object p0, v1, Lp3/a0;->b:Lay0/k;

    .line 819
    .line 820
    if-eqz p0, :cond_15

    .line 821
    .line 822
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 823
    .line 824
    .line 825
    :goto_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 826
    .line 827
    return-object p0

    .line 828
    :cond_15
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 829
    .line 830
    .line 831
    throw v3

    .line 832
    :pswitch_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 833
    .line 834
    move-object v1, p1

    .line 835
    check-cast v1, Ljava/lang/Throwable;

    .line 836
    .line 837
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 838
    .line 839
    check-cast p1, La3/f;

    .line 840
    .line 841
    invoke-virtual {p1, v1}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 842
    .line 843
    .line 844
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 845
    .line 846
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 847
    .line 848
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 849
    .line 850
    move-object v2, p0

    .line 851
    check-cast v2, Lxy0/j;

    .line 852
    .line 853
    const/4 p0, 0x0

    .line 854
    invoke-virtual {v2, v1, p0}, Lxy0/j;->j(Ljava/lang/Throwable;Z)Z

    .line 855
    .line 856
    .line 857
    :cond_16
    invoke-virtual {v2}, Lxy0/j;->n()Ljava/lang/Object;

    .line 858
    .line 859
    .line 860
    move-result-object p0

    .line 861
    invoke-static {p0}, Lxy0/q;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 862
    .line 863
    .line 864
    move-result-object p0

    .line 865
    if-eqz p0, :cond_18

    .line 866
    .line 867
    check-cast p0, Lm6/j0;

    .line 868
    .line 869
    iget-object p0, p0, Lm6/j0;->b:Lvy0/r;

    .line 870
    .line 871
    if-nez v1, :cond_17

    .line 872
    .line 873
    new-instance p1, Ljava/util/concurrent/CancellationException;

    .line 874
    .line 875
    const-string v3, "DataStore scope was cancelled before updateData could complete"

    .line 876
    .line 877
    invoke-direct {p1, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 878
    .line 879
    .line 880
    goto :goto_c

    .line 881
    :cond_17
    move-object p1, v1

    .line 882
    :goto_c
    invoke-virtual {p0, p1}, Lvy0/r;->l0(Ljava/lang/Throwable;)Z

    .line 883
    .line 884
    .line 885
    move-object p0, v0

    .line 886
    goto :goto_d

    .line 887
    :cond_18
    const/4 p0, 0x0

    .line 888
    :goto_d
    if-nez p0, :cond_16

    .line 889
    .line 890
    return-object v0

    .line 891
    :pswitch_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 892
    .line 893
    check-cast p1, Ljava/lang/String;

    .line 894
    .line 895
    iget-object v1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 896
    .line 897
    check-cast v1, Ljava/io/File;

    .line 898
    .line 899
    invoke-virtual {v1}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 900
    .line 901
    .line 902
    move-result-object v1

    .line 903
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 904
    .line 905
    .line 906
    move-result p1

    .line 907
    if-eqz p1, :cond_1a

    .line 908
    .line 909
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 910
    .line 911
    check-cast p0, Lxy0/x;

    .line 912
    .line 913
    invoke-interface {p0, v0}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 914
    .line 915
    .line 916
    move-result-object p1

    .line 917
    instance-of v1, p1, Lxy0/p;

    .line 918
    .line 919
    if-nez v1, :cond_19

    .line 920
    .line 921
    check-cast p1, Llx0/b0;

    .line 922
    .line 923
    goto :goto_e

    .line 924
    :cond_19
    new-instance p1, Lws/b;

    .line 925
    .line 926
    const/4 v1, 0x7

    .line 927
    const/4 v2, 0x0

    .line 928
    invoke-direct {p1, v1, p0, v0, v2}, Lws/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 929
    .line 930
    .line 931
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 932
    .line 933
    invoke-static {p0, p1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 934
    .line 935
    .line 936
    move-result-object p0

    .line 937
    check-cast p0, Lxy0/q;

    .line 938
    .line 939
    iget-object p0, p0, Lxy0/q;->a:Ljava/lang/Object;

    .line 940
    .line 941
    :cond_1a
    :goto_e
    return-object v0

    .line 942
    :pswitch_11
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 943
    .line 944
    const-string v0, "$this$DisposableEffect"

    .line 945
    .line 946
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 947
    .line 948
    .line 949
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 950
    .line 951
    check-cast p1, Lkn/c0;

    .line 952
    .line 953
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 954
    .line 955
    check-cast p0, Lkn/k0;

    .line 956
    .line 957
    new-instance v0, Laa/t;

    .line 958
    .line 959
    const/16 v1, 0x8

    .line 960
    .line 961
    invoke-direct {v0, v1, p1, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 962
    .line 963
    .line 964
    return-object v0

    .line 965
    :pswitch_12
    check-cast p1, Ljava/lang/Number;

    .line 966
    .line 967
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 968
    .line 969
    .line 970
    move-result p1

    .line 971
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 972
    .line 973
    check-cast v0, Lvy0/b0;

    .line 974
    .line 975
    new-instance v1, Li2/f;

    .line 976
    .line 977
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 978
    .line 979
    check-cast p0, Lc1/c;

    .line 980
    .line 981
    const/4 v2, 0x1

    .line 982
    const/4 v3, 0x0

    .line 983
    invoke-direct {v1, p0, p1, v3, v2}, Li2/f;-><init>(Ljava/lang/Object;FLkotlin/coroutines/Continuation;I)V

    .line 984
    .line 985
    .line 986
    const/4 p0, 0x3

    .line 987
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 988
    .line 989
    .line 990
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 991
    .line 992
    return-object p0

    .line 993
    :pswitch_13
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 994
    .line 995
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 996
    .line 997
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 998
    .line 999
    const/4 v1, 0x0

    .line 1000
    const/4 v2, 0x1

    .line 1001
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 1002
    .line 1003
    .line 1004
    move-result v0

    .line 1005
    if-eqz v0, :cond_1b

    .line 1006
    .line 1007
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 1008
    .line 1009
    check-cast p0, Lxy0/j;

    .line 1010
    .line 1011
    invoke-interface {p0, p1}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1012
    .line 1013
    .line 1014
    :cond_1b
    return-object p1

    .line 1015
    :pswitch_14
    check-cast p1, Ljava/lang/Throwable;

    .line 1016
    .line 1017
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 1018
    .line 1019
    check-cast v0, Ly4/h;

    .line 1020
    .line 1021
    if-eqz p1, :cond_1d

    .line 1022
    .line 1023
    instance-of p0, p1, Ljava/util/concurrent/CancellationException;

    .line 1024
    .line 1025
    if-eqz p0, :cond_1c

    .line 1026
    .line 1027
    invoke-virtual {v0}, Ly4/h;->c()V

    .line 1028
    .line 1029
    .line 1030
    goto :goto_f

    .line 1031
    :cond_1c
    invoke-virtual {v0, p1}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 1032
    .line 1033
    .line 1034
    goto :goto_f

    .line 1035
    :cond_1d
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 1036
    .line 1037
    check-cast p0, Lvy0/i0;

    .line 1038
    .line 1039
    invoke-virtual {p0}, Lvy0/p1;->K()Ljava/lang/Object;

    .line 1040
    .line 1041
    .line 1042
    move-result-object p0

    .line 1043
    invoke-virtual {v0, p0}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 1044
    .line 1045
    .line 1046
    :goto_f
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1047
    .line 1048
    return-object p0

    .line 1049
    :pswitch_15
    move-object v0, p1

    .line 1050
    check-cast v0, Lt3/d1;

    .line 1051
    .line 1052
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 1053
    .line 1054
    move-object v1, p1

    .line 1055
    check-cast v1, Lt3/e1;

    .line 1056
    .line 1057
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 1058
    .line 1059
    check-cast p0, Le3/o0;

    .line 1060
    .line 1061
    iget-object v4, p0, Le3/o0;->F:La3/f;

    .line 1062
    .line 1063
    const/4 v5, 0x4

    .line 1064
    const/4 v2, 0x0

    .line 1065
    const/4 v3, 0x0

    .line 1066
    invoke-static/range {v0 .. v5}, Lt3/d1;->z(Lt3/d1;Lt3/e1;IILay0/k;I)V

    .line 1067
    .line 1068
    .line 1069
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1070
    .line 1071
    return-object p0

    .line 1072
    :pswitch_16
    move-object v0, p1

    .line 1073
    check-cast v0, Lt3/d1;

    .line 1074
    .line 1075
    iget-object p1, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 1076
    .line 1077
    move-object v1, p1

    .line 1078
    check-cast v1, Lt3/e1;

    .line 1079
    .line 1080
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 1081
    .line 1082
    check-cast p0, Le3/n;

    .line 1083
    .line 1084
    iget-object v4, p0, Le3/n;->r:Lay0/k;

    .line 1085
    .line 1086
    const/4 v5, 0x4

    .line 1087
    const/4 v2, 0x0

    .line 1088
    const/4 v3, 0x0

    .line 1089
    invoke-static/range {v0 .. v5}, Lt3/d1;->z(Lt3/d1;Lt3/e1;IILay0/k;I)V

    .line 1090
    .line 1091
    .line 1092
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1093
    .line 1094
    return-object p0

    .line 1095
    :pswitch_17
    check-cast p1, Lt3/d1;

    .line 1096
    .line 1097
    iget-object v0, p0, Lb1/e;->g:Ljava/lang/Object;

    .line 1098
    .line 1099
    check-cast v0, Lt3/e1;

    .line 1100
    .line 1101
    iget-object p0, p0, Lb1/e;->h:Ljava/lang/Object;

    .line 1102
    .line 1103
    check-cast p0, Lb1/d0;

    .line 1104
    .line 1105
    iget-object p0, p0, Lb1/d0;->c:Ll2/f1;

    .line 1106
    .line 1107
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 1108
    .line 1109
    .line 1110
    move-result p0

    .line 1111
    const/4 v1, 0x0

    .line 1112
    invoke-virtual {p1, v0, v1, v1, p0}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 1113
    .line 1114
    .line 1115
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1116
    .line 1117
    return-object p0

    .line 1118
    nop

    .line 1119
    :pswitch_data_0
    .packed-switch 0x0
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
