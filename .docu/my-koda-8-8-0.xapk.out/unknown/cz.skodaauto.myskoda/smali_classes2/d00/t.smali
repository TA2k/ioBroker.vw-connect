.class public final synthetic Ld00/t;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Ld00/t;->d:I

    .line 2
    .line 3
    move-object v0, p4

    .line 4
    move-object p4, p2

    .line 5
    move p2, p6

    .line 6
    move-object p6, p5

    .line 7
    move-object p5, v0

    .line 8
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld00/t;->d:I

    .line 4
    .line 5
    const/16 v2, 0x12

    .line 6
    .line 7
    const-string v3, "Reset Spin Sign In warning canceled by user"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x1

    .line 11
    const/4 v6, 0x2

    .line 12
    const/4 v7, 0x3

    .line 13
    const/4 v8, 0x0

    .line 14
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lc80/d0;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    new-instance v2, Lc80/a0;

    .line 31
    .line 32
    invoke-direct {v2, v0, v8, v6}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    return-object v9

    .line 39
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lc80/z;

    .line 42
    .line 43
    iget-object v0, v0, Lc80/z;->h:Lzd0/a;

    .line 44
    .line 45
    new-instance v1, Lne0/c;

    .line 46
    .line 47
    new-instance v2, Ljava/util/concurrent/CancellationException;

    .line 48
    .line 49
    const-string v3, "The spin reset warning screen was cancelled"

    .line 50
    .line 51
    invoke-direct {v2, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const/4 v5, 0x0

    .line 55
    const/16 v6, 0x1e

    .line 56
    .line 57
    const/4 v3, 0x0

    .line 58
    const/4 v4, 0x0

    .line 59
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 63
    .line 64
    .line 65
    return-object v9

    .line 66
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Lc80/z;

    .line 69
    .line 70
    iget-object v0, v0, Lc80/z;->h:Lzd0/a;

    .line 71
    .line 72
    new-instance v1, Lne0/e;

    .line 73
    .line 74
    invoke-direct {v1, v9}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 78
    .line 79
    .line 80
    return-object v9

    .line 81
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v0, Lc80/y;

    .line 84
    .line 85
    iget-object v1, v0, Lc80/y;->m:Lzd0/a;

    .line 86
    .line 87
    iget-object v0, v0, Lc80/y;->n:Lne0/c;

    .line 88
    .line 89
    if-nez v0, :cond_0

    .line 90
    .line 91
    new-instance v2, Lne0/c;

    .line 92
    .line 93
    new-instance v3, Ljava/lang/IllegalStateException;

    .line 94
    .line 95
    const-string v0, "Unexpected state in reset spin request component"

    .line 96
    .line 97
    invoke-direct {v3, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    const/4 v6, 0x0

    .line 101
    const/16 v7, 0x1e

    .line 102
    .line 103
    const/4 v4, 0x0

    .line 104
    const/4 v5, 0x0

    .line 105
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 106
    .line 107
    .line 108
    move-object v0, v2

    .line 109
    :cond_0
    invoke-virtual {v1, v0}, Lzd0/a;->a(Lne0/t;)V

    .line 110
    .line 111
    .line 112
    return-object v9

    .line 113
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v0, Lc80/y;

    .line 116
    .line 117
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    check-cast v1, Lc80/w;

    .line 122
    .line 123
    iget-boolean v1, v1, Lc80/w;->e:Z

    .line 124
    .line 125
    if-eqz v1, :cond_1

    .line 126
    .line 127
    invoke-virtual {v0}, Lc80/y;->j()V

    .line 128
    .line 129
    .line 130
    goto :goto_0

    .line 131
    :cond_1
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    check-cast v1, Lc80/w;

    .line 136
    .line 137
    iget-boolean v1, v1, Lc80/w;->c:Z

    .line 138
    .line 139
    if-eqz v1, :cond_2

    .line 140
    .line 141
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    new-instance v2, Lc80/v;

    .line 146
    .line 147
    invoke-direct {v2, v0, v8, v6}, Lc80/v;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V

    .line 148
    .line 149
    .line 150
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 151
    .line 152
    .line 153
    goto :goto_0

    .line 154
    :cond_2
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    move-object v2, v1

    .line 159
    check-cast v2, Lc80/w;

    .line 160
    .line 161
    const/4 v7, 0x0

    .line 162
    const/16 v8, 0x2f

    .line 163
    .line 164
    const/4 v3, 0x0

    .line 165
    const/4 v4, 0x0

    .line 166
    const/4 v5, 0x0

    .line 167
    const/4 v6, 0x0

    .line 168
    invoke-static/range {v2 .. v8}, Lc80/w;->a(Lc80/w;Lql0/g;ZZLjava/lang/String;ZI)Lc80/w;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 173
    .line 174
    .line 175
    :goto_0
    return-object v9

    .line 176
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v0, Lc80/y;

    .line 179
    .line 180
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 181
    .line 182
    .line 183
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    new-instance v2, Lc80/v;

    .line 188
    .line 189
    invoke-direct {v2, v0, v8, v5}, Lc80/v;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V

    .line 190
    .line 191
    .line 192
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 193
    .line 194
    .line 195
    return-object v9

    .line 196
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v0, Lc80/y;

    .line 199
    .line 200
    invoke-virtual {v0}, Lc80/y;->j()V

    .line 201
    .line 202
    .line 203
    return-object v9

    .line 204
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v0, Lc80/y;

    .line 207
    .line 208
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    move-object v2, v1

    .line 213
    check-cast v2, Lc80/w;

    .line 214
    .line 215
    const/4 v7, 0x0

    .line 216
    const/16 v8, 0x2f

    .line 217
    .line 218
    const/4 v3, 0x0

    .line 219
    const/4 v4, 0x0

    .line 220
    const/4 v5, 0x0

    .line 221
    const/4 v6, 0x0

    .line 222
    invoke-static/range {v2 .. v8}, Lc80/w;->a(Lc80/w;Lql0/g;ZZLjava/lang/String;ZI)Lc80/w;

    .line 223
    .line 224
    .line 225
    move-result-object v1

    .line 226
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 227
    .line 228
    .line 229
    return-object v9

    .line 230
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v0, Lc80/y;

    .line 233
    .line 234
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    new-instance v2, Lc80/v;

    .line 242
    .line 243
    invoke-direct {v2, v0, v8, v6}, Lc80/v;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V

    .line 244
    .line 245
    .line 246
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 247
    .line 248
    .line 249
    return-object v9

    .line 250
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v0, Lc80/y;

    .line 253
    .line 254
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    move-object v2, v1

    .line 259
    check-cast v2, Lc80/w;

    .line 260
    .line 261
    const/4 v7, 0x1

    .line 262
    const/16 v8, 0x1f

    .line 263
    .line 264
    const/4 v3, 0x0

    .line 265
    const/4 v4, 0x0

    .line 266
    const/4 v5, 0x0

    .line 267
    const/4 v6, 0x0

    .line 268
    invoke-static/range {v2 .. v8}, Lc80/w;->a(Lc80/w;Lql0/g;ZZLjava/lang/String;ZI)Lc80/w;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 273
    .line 274
    .line 275
    return-object v9

    .line 276
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 277
    .line 278
    check-cast v0, Lc80/t;

    .line 279
    .line 280
    iget-object v0, v0, Lc80/t;->i:Lzd0/a;

    .line 281
    .line 282
    new-instance v1, Lne0/c;

    .line 283
    .line 284
    new-instance v2, Lyq0/j;

    .line 285
    .line 286
    const-string v3, "Spin reset is requested"

    .line 287
    .line 288
    invoke-direct {v2, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    const/4 v5, 0x0

    .line 292
    const/16 v6, 0x1e

    .line 293
    .line 294
    const/4 v3, 0x0

    .line 295
    const/4 v4, 0x0

    .line 296
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 300
    .line 301
    .line 302
    return-object v9

    .line 303
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v0, Lc80/t;

    .line 306
    .line 307
    invoke-virtual {v0}, Lc80/t;->j()V

    .line 308
    .line 309
    .line 310
    return-object v9

    .line 311
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast v0, Lc80/t;

    .line 314
    .line 315
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 316
    .line 317
    .line 318
    move-result-object v1

    .line 319
    check-cast v1, Lc80/r;

    .line 320
    .line 321
    iget-object v1, v1, Lc80/r;->a:Ljava/util/List;

    .line 322
    .line 323
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 324
    .line 325
    .line 326
    move-result v1

    .line 327
    sub-int/2addr v1, v5

    .line 328
    if-ltz v1, :cond_3

    .line 329
    .line 330
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    move-object v10, v1

    .line 335
    check-cast v10, Lc80/r;

    .line 336
    .line 337
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 338
    .line 339
    .line 340
    move-result-object v1

    .line 341
    check-cast v1, Lc80/r;

    .line 342
    .line 343
    iget-object v1, v1, Lc80/r;->a:Ljava/util/List;

    .line 344
    .line 345
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 346
    .line 347
    .line 348
    move-result-object v2

    .line 349
    check-cast v2, Lc80/r;

    .line 350
    .line 351
    iget-object v2, v2, Lc80/r;->a:Ljava/util/List;

    .line 352
    .line 353
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 354
    .line 355
    .line 356
    move-result v2

    .line 357
    sub-int/2addr v2, v5

    .line 358
    invoke-interface {v1, v4, v2}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 359
    .line 360
    .line 361
    move-result-object v11

    .line 362
    const/16 v16, 0x0

    .line 363
    .line 364
    const/16 v17, 0x3fe

    .line 365
    .line 366
    const/4 v12, 0x0

    .line 367
    const/4 v13, 0x0

    .line 368
    const/4 v14, 0x0

    .line 369
    const/4 v15, 0x0

    .line 370
    invoke-static/range {v10 .. v17}, Lc80/r;->a(Lc80/r;Ljava/util/List;ZLjava/lang/String;ZLql0/g;Ljava/lang/String;I)Lc80/r;

    .line 371
    .line 372
    .line 373
    move-result-object v1

    .line 374
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 375
    .line 376
    .line 377
    :cond_3
    return-object v9

    .line 378
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 379
    .line 380
    check-cast v0, Lc80/t;

    .line 381
    .line 382
    iget-object v1, v0, Lc80/t;->n:Lvy0/x1;

    .line 383
    .line 384
    if-eqz v1, :cond_4

    .line 385
    .line 386
    invoke-virtual {v1, v8}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 387
    .line 388
    .line 389
    :cond_4
    iget-object v0, v0, Lc80/t;->i:Lzd0/a;

    .line 390
    .line 391
    new-instance v1, Lne0/c;

    .line 392
    .line 393
    new-instance v2, Ljava/util/concurrent/CancellationException;

    .line 394
    .line 395
    const-string v3, "The getting of SPIN was cancelled"

    .line 396
    .line 397
    invoke-direct {v2, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 398
    .line 399
    .line 400
    const/4 v5, 0x0

    .line 401
    const/16 v6, 0x1e

    .line 402
    .line 403
    const/4 v3, 0x0

    .line 404
    const/4 v4, 0x0

    .line 405
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 409
    .line 410
    .line 411
    return-object v9

    .line 412
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 413
    .line 414
    check-cast v0, Lc80/o;

    .line 415
    .line 416
    iget-object v0, v0, Lc80/o;->h:Lzd0/a;

    .line 417
    .line 418
    new-instance v10, Lne0/c;

    .line 419
    .line 420
    new-instance v11, Ljava/util/concurrent/CancellationException;

    .line 421
    .line 422
    invoke-direct {v11, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 423
    .line 424
    .line 425
    const/4 v14, 0x0

    .line 426
    const/16 v15, 0x1e

    .line 427
    .line 428
    const/4 v12, 0x0

    .line 429
    const/4 v13, 0x0

    .line 430
    invoke-direct/range {v10 .. v15}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 431
    .line 432
    .line 433
    invoke-virtual {v0, v10}, Lzd0/a;->a(Lne0/t;)V

    .line 434
    .line 435
    .line 436
    return-object v9

    .line 437
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 438
    .line 439
    check-cast v0, Lc80/o;

    .line 440
    .line 441
    iget-object v0, v0, Lc80/o;->h:Lzd0/a;

    .line 442
    .line 443
    new-instance v10, Lne0/c;

    .line 444
    .line 445
    new-instance v11, Ljava/util/concurrent/CancellationException;

    .line 446
    .line 447
    invoke-direct {v11, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    const/4 v14, 0x0

    .line 451
    const/16 v15, 0x1e

    .line 452
    .line 453
    const/4 v12, 0x0

    .line 454
    const/4 v13, 0x0

    .line 455
    invoke-direct/range {v10 .. v15}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v0, v10}, Lzd0/a;->a(Lne0/t;)V

    .line 459
    .line 460
    .line 461
    return-object v9

    .line 462
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast v0, Lc80/o;

    .line 465
    .line 466
    iget-object v0, v0, Lc80/o;->h:Lzd0/a;

    .line 467
    .line 468
    new-instance v1, Lne0/e;

    .line 469
    .line 470
    invoke-direct {v1, v9}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 471
    .line 472
    .line 473
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 474
    .line 475
    .line 476
    return-object v9

    .line 477
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 478
    .line 479
    check-cast v0, Lc80/m;

    .line 480
    .line 481
    iget-object v0, v0, Lc80/m;->i:Lzd0/a;

    .line 482
    .line 483
    new-instance v1, Lne0/e;

    .line 484
    .line 485
    invoke-direct {v1, v9}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 489
    .line 490
    .line 491
    return-object v9

    .line 492
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 493
    .line 494
    check-cast v0, Lc80/m;

    .line 495
    .line 496
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 497
    .line 498
    .line 499
    move-result-object v1

    .line 500
    check-cast v1, Lc80/k;

    .line 501
    .line 502
    iget-object v1, v1, Lc80/k;->a:Ljava/util/List;

    .line 503
    .line 504
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 505
    .line 506
    .line 507
    move-result v1

    .line 508
    sub-int/2addr v1, v5

    .line 509
    if-ltz v1, :cond_5

    .line 510
    .line 511
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 512
    .line 513
    .line 514
    move-result-object v1

    .line 515
    move-object v10, v1

    .line 516
    check-cast v10, Lc80/k;

    .line 517
    .line 518
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 519
    .line 520
    .line 521
    move-result-object v1

    .line 522
    check-cast v1, Lc80/k;

    .line 523
    .line 524
    iget-object v1, v1, Lc80/k;->a:Ljava/util/List;

    .line 525
    .line 526
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 527
    .line 528
    .line 529
    move-result-object v2

    .line 530
    check-cast v2, Lc80/k;

    .line 531
    .line 532
    iget-object v2, v2, Lc80/k;->a:Ljava/util/List;

    .line 533
    .line 534
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 535
    .line 536
    .line 537
    move-result v2

    .line 538
    sub-int/2addr v2, v5

    .line 539
    invoke-interface {v1, v4, v2}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 540
    .line 541
    .line 542
    move-result-object v11

    .line 543
    const/16 v17, 0x0

    .line 544
    .line 545
    const/16 v18, 0x7e

    .line 546
    .line 547
    const/4 v12, 0x0

    .line 548
    const/4 v13, 0x0

    .line 549
    const/4 v14, 0x0

    .line 550
    const/4 v15, 0x0

    .line 551
    const/16 v16, 0x0

    .line 552
    .line 553
    invoke-static/range {v10 .. v18}, Lc80/k;->a(Lc80/k;Ljava/util/List;Ljava/lang/String;Lql0/g;Ljava/lang/String;Ljava/lang/String;ZZI)Lc80/k;

    .line 554
    .line 555
    .line 556
    move-result-object v1

    .line 557
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 558
    .line 559
    .line 560
    :cond_5
    return-object v9

    .line 561
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 562
    .line 563
    check-cast v0, Lc80/m;

    .line 564
    .line 565
    iget-object v0, v0, Lc80/m;->i:Lzd0/a;

    .line 566
    .line 567
    new-instance v1, Lne0/c;

    .line 568
    .line 569
    new-instance v2, Ljava/util/concurrent/CancellationException;

    .line 570
    .line 571
    const-string v3, "The getting of new SPIN was cancelled"

    .line 572
    .line 573
    invoke-direct {v2, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 574
    .line 575
    .line 576
    const/4 v5, 0x0

    .line 577
    const/16 v6, 0x1e

    .line 578
    .line 579
    const/4 v3, 0x0

    .line 580
    const/4 v4, 0x0

    .line 581
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 582
    .line 583
    .line 584
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 585
    .line 586
    .line 587
    return-object v9

    .line 588
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 589
    .line 590
    check-cast v0, Lc80/g;

    .line 591
    .line 592
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 593
    .line 594
    .line 595
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 596
    .line 597
    .line 598
    move-result-object v1

    .line 599
    new-instance v3, La50/a;

    .line 600
    .line 601
    invoke-direct {v3, v0, v8, v2}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 602
    .line 603
    .line 604
    invoke-static {v1, v8, v8, v3, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 605
    .line 606
    .line 607
    return-object v9

    .line 608
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 609
    .line 610
    check-cast v0, Lc80/g;

    .line 611
    .line 612
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 613
    .line 614
    .line 615
    move-result-object v1

    .line 616
    check-cast v1, Lc80/c;

    .line 617
    .line 618
    const/4 v2, 0x6

    .line 619
    invoke-static {v1, v8, v8, v2}, Lc80/c;->a(Lc80/c;Lc80/b;Lc80/a;I)Lc80/c;

    .line 620
    .line 621
    .line 622
    move-result-object v1

    .line 623
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 624
    .line 625
    .line 626
    return-object v9

    .line 627
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 628
    .line 629
    check-cast v0, Lc80/g;

    .line 630
    .line 631
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 632
    .line 633
    .line 634
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 635
    .line 636
    .line 637
    move-result-object v1

    .line 638
    new-instance v3, La50/a;

    .line 639
    .line 640
    invoke-direct {v3, v0, v8, v2}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 641
    .line 642
    .line 643
    invoke-static {v1, v8, v8, v3, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 644
    .line 645
    .line 646
    return-object v9

    .line 647
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 648
    .line 649
    check-cast v0, Lc70/i;

    .line 650
    .line 651
    iget-object v0, v0, Lc70/i;->m:La70/a;

    .line 652
    .line 653
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    return-object v9

    .line 657
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 658
    .line 659
    check-cast v0, Lc70/i;

    .line 660
    .line 661
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 662
    .line 663
    .line 664
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 665
    .line 666
    .line 667
    move-result-object v1

    .line 668
    new-instance v2, Lc70/f;

    .line 669
    .line 670
    invoke-direct {v2, v0, v8, v7}, Lc70/f;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 671
    .line 672
    .line 673
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 674
    .line 675
    .line 676
    return-object v9

    .line 677
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 678
    .line 679
    check-cast v0, Lc70/i;

    .line 680
    .line 681
    iget-object v1, v0, Lc70/i;->i:Lep0/a;

    .line 682
    .line 683
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 684
    .line 685
    .line 686
    move-result-object v1

    .line 687
    check-cast v1, Lyy0/i;

    .line 688
    .line 689
    new-instance v2, La10/a;

    .line 690
    .line 691
    const/4 v3, 0x5

    .line 692
    invoke-direct {v2, v0, v8, v3}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 693
    .line 694
    .line 695
    new-instance v3, Lne0/n;

    .line 696
    .line 697
    invoke-direct {v3, v2, v1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 698
    .line 699
    .line 700
    invoke-static {v3}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 701
    .line 702
    .line 703
    move-result-object v1

    .line 704
    new-instance v2, Lbv0/d;

    .line 705
    .line 706
    invoke-direct {v2, v0, v8, v6}, Lbv0/d;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 707
    .line 708
    .line 709
    new-instance v3, Lyy0/x;

    .line 710
    .line 711
    invoke-direct {v3, v1, v2}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 712
    .line 713
    .line 714
    new-instance v1, Lc70/g;

    .line 715
    .line 716
    invoke-direct {v1, v0, v8, v7}, Lc70/g;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 717
    .line 718
    .line 719
    invoke-static {v1, v3}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 720
    .line 721
    .line 722
    move-result-object v1

    .line 723
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 724
    .line 725
    .line 726
    move-result-object v0

    .line 727
    invoke-static {v1, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 728
    .line 729
    .line 730
    return-object v9

    .line 731
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 732
    .line 733
    check-cast v0, Lc70/i;

    .line 734
    .line 735
    iget-object v0, v0, Lc70/i;->j:Ltr0/b;

    .line 736
    .line 737
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 738
    .line 739
    .line 740
    return-object v9

    .line 741
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 742
    .line 743
    check-cast v0, Lc70/e;

    .line 744
    .line 745
    iget-object v0, v0, Lc70/e;->l:La70/d;

    .line 746
    .line 747
    iget-object v0, v0, La70/d;->a:La70/e;

    .line 748
    .line 749
    check-cast v0, Liy/b;

    .line 750
    .line 751
    sget-object v1, Lly/b;->Q3:Lly/b;

    .line 752
    .line 753
    invoke-interface {v0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 754
    .line 755
    .line 756
    return-object v9

    .line 757
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 758
    .line 759
    check-cast v0, Lc00/y1;

    .line 760
    .line 761
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 762
    .line 763
    .line 764
    new-instance v1, La71/u;

    .line 765
    .line 766
    const/16 v2, 0x13

    .line 767
    .line 768
    invoke-direct {v1, v0, v2}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 769
    .line 770
    .line 771
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 772
    .line 773
    .line 774
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 775
    .line 776
    .line 777
    move-result-object v1

    .line 778
    new-instance v2, La50/c;

    .line 779
    .line 780
    const/16 v3, 0x15

    .line 781
    .line 782
    invoke-direct {v2, v0, v8, v3}, La50/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 783
    .line 784
    .line 785
    invoke-static {v1, v8, v8, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 786
    .line 787
    .line 788
    return-object v9

    .line 789
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 790
    .line 791
    check-cast v0, Lc00/y1;

    .line 792
    .line 793
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 794
    .line 795
    .line 796
    move-result-object v1

    .line 797
    move-object v10, v1

    .line 798
    check-cast v10, Lc00/x1;

    .line 799
    .line 800
    iget-object v1, v0, Lc00/y1;->o:Lmb0/l;

    .line 801
    .line 802
    sget v2, Lc00/z1;->b:I

    .line 803
    .line 804
    const-string v2, "<this>"

    .line 805
    .line 806
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 807
    .line 808
    .line 809
    const-string v2, "originalSettings"

    .line 810
    .line 811
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 812
    .line 813
    .line 814
    iget-object v2, v10, Lc00/x1;->d:Lc00/v1;

    .line 815
    .line 816
    if-eqz v2, :cond_6

    .line 817
    .line 818
    invoke-static {v2}, Ljp/gc;->d(Lc00/v1;)Lc00/v1;

    .line 819
    .line 820
    .line 821
    move-result-object v8

    .line 822
    :cond_6
    move-object v14, v8

    .line 823
    sget-wide v18, Lc00/z1;->a:J

    .line 824
    .line 825
    const/16 v20, 0x0

    .line 826
    .line 827
    const/16 v21, 0x177

    .line 828
    .line 829
    const/4 v11, 0x0

    .line 830
    const/4 v12, 0x0

    .line 831
    const/4 v13, 0x0

    .line 832
    const/4 v15, 0x0

    .line 833
    const/16 v16, 0x0

    .line 834
    .line 835
    const/16 v17, 0x0

    .line 836
    .line 837
    invoke-static/range {v10 .. v21}, Lc00/x1;->a(Lc00/x1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/w1;ZZJZI)Lc00/x1;

    .line 838
    .line 839
    .line 840
    move-result-object v2

    .line 841
    invoke-static {v2, v1}, Lc00/z1;->d(Lc00/x1;Lmb0/l;)Lc00/x1;

    .line 842
    .line 843
    .line 844
    move-result-object v1

    .line 845
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 846
    .line 847
    .line 848
    return-object v9

    .line 849
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
