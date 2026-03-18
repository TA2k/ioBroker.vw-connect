.class public final Ln90/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ln90/k;


# direct methods
.method public synthetic constructor <init>(Ln90/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Ln90/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln90/c;->e:Ln90/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Ln90/c;->d:I

    .line 6
    .line 7
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    iget-object v0, v0, Ln90/c;->e:Ln90/k;

    .line 12
    .line 13
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    packed-switch v2, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    move-object/from16 v2, p1

    .line 19
    .line 20
    check-cast v2, Lne0/s;

    .line 21
    .line 22
    instance-of v7, v2, Lne0/e;

    .line 23
    .line 24
    if-eqz v7, :cond_0

    .line 25
    .line 26
    check-cast v2, Lne0/e;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    new-instance v3, Lm70/i0;

    .line 36
    .line 37
    const/16 v4, 0x1b

    .line 38
    .line 39
    invoke-direct {v3, v4, v0, v2, v5}, Lm70/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 40
    .line 41
    .line 42
    const/4 v0, 0x3

    .line 43
    invoke-static {v1, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 44
    .line 45
    .line 46
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_1

    .line 54
    .line 55
    iget-object v2, v0, Ln90/k;->o:Lrq0/f;

    .line 56
    .line 57
    new-instance v3, Lsq0/c;

    .line 58
    .line 59
    iget-object v0, v0, Ln90/k;->q:Lij0/a;

    .line 60
    .line 61
    new-array v7, v4, [Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Ljj0/f;

    .line 64
    .line 65
    const v8, 0x7f1214a0

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, v8, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    const/4 v7, 0x6

    .line 73
    invoke-direct {v3, v7, v0, v5, v5}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v2, v3, v4, v1}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 81
    .line 82
    if-ne v0, v1, :cond_2

    .line 83
    .line 84
    move-object v6, v0

    .line 85
    goto :goto_0

    .line 86
    :cond_1
    instance-of v1, v2, Lne0/c;

    .line 87
    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    move-object v7, v1

    .line 95
    check-cast v7, Ln90/h;

    .line 96
    .line 97
    check-cast v2, Lne0/c;

    .line 98
    .line 99
    iget-object v1, v0, Ln90/k;->q:Lij0/a;

    .line 100
    .line 101
    invoke-static {v2, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 102
    .line 103
    .line 104
    move-result-object v28

    .line 105
    const/16 v35, 0x0

    .line 106
    .line 107
    const v36, 0xfefffff

    .line 108
    .line 109
    .line 110
    const/4 v8, 0x0

    .line 111
    const/4 v9, 0x0

    .line 112
    const/4 v10, 0x0

    .line 113
    const/4 v11, 0x0

    .line 114
    const/4 v12, 0x0

    .line 115
    const/4 v13, 0x0

    .line 116
    const/4 v14, 0x0

    .line 117
    const/4 v15, 0x0

    .line 118
    const/16 v16, 0x0

    .line 119
    .line 120
    const/16 v17, 0x0

    .line 121
    .line 122
    const/16 v18, 0x0

    .line 123
    .line 124
    const/16 v19, 0x0

    .line 125
    .line 126
    const/16 v20, 0x0

    .line 127
    .line 128
    const/16 v21, 0x0

    .line 129
    .line 130
    const/16 v22, 0x0

    .line 131
    .line 132
    const/16 v23, 0x0

    .line 133
    .line 134
    const/16 v24, 0x0

    .line 135
    .line 136
    const/16 v25, 0x0

    .line 137
    .line 138
    const/16 v26, 0x0

    .line 139
    .line 140
    const/16 v27, 0x0

    .line 141
    .line 142
    const/16 v29, 0x0

    .line 143
    .line 144
    const/16 v30, 0x0

    .line 145
    .line 146
    const/16 v31, 0x0

    .line 147
    .line 148
    const/16 v32, 0x0

    .line 149
    .line 150
    const/16 v33, 0x0

    .line 151
    .line 152
    const/16 v34, 0x0

    .line 153
    .line 154
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 159
    .line 160
    .line 161
    :cond_2
    :goto_0
    return-object v6

    .line 162
    :cond_3
    new-instance v0, La8/r0;

    .line 163
    .line 164
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 165
    .line 166
    .line 167
    throw v0

    .line 168
    :pswitch_0
    move-object/from16 v2, p1

    .line 169
    .line 170
    check-cast v2, Lne0/s;

    .line 171
    .line 172
    instance-of v7, v2, Lne0/e;

    .line 173
    .line 174
    if-eqz v7, :cond_5

    .line 175
    .line 176
    check-cast v2, Lne0/e;

    .line 177
    .line 178
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast v2, Lm90/a;

    .line 181
    .line 182
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    move-object v7, v3

    .line 187
    check-cast v7, Ln90/h;

    .line 188
    .line 189
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 190
    .line 191
    .line 192
    move-result-object v3

    .line 193
    check-cast v3, Ln90/h;

    .line 194
    .line 195
    iget-object v8, v3, Ln90/h;->v:Ln90/f;

    .line 196
    .line 197
    const/4 v12, 0x0

    .line 198
    const/16 v13, 0xd

    .line 199
    .line 200
    const/4 v9, 0x0

    .line 201
    const/4 v10, 0x0

    .line 202
    const/4 v11, 0x0

    .line 203
    invoke-static/range {v8 .. v13}, Ln90/f;->a(Ln90/f;ZZZLer0/g;I)Ln90/f;

    .line 204
    .line 205
    .line 206
    move-result-object v29

    .line 207
    const/16 v35, 0x0

    .line 208
    .line 209
    const v36, 0xfdfffff

    .line 210
    .line 211
    .line 212
    const/4 v8, 0x0

    .line 213
    const/4 v9, 0x0

    .line 214
    const/4 v10, 0x0

    .line 215
    const/4 v11, 0x0

    .line 216
    const/4 v13, 0x0

    .line 217
    const/4 v14, 0x0

    .line 218
    const/4 v15, 0x0

    .line 219
    const/16 v16, 0x0

    .line 220
    .line 221
    const/16 v17, 0x0

    .line 222
    .line 223
    const/16 v18, 0x0

    .line 224
    .line 225
    const/16 v19, 0x0

    .line 226
    .line 227
    const/16 v20, 0x0

    .line 228
    .line 229
    const/16 v21, 0x0

    .line 230
    .line 231
    const/16 v22, 0x0

    .line 232
    .line 233
    const/16 v23, 0x0

    .line 234
    .line 235
    const/16 v24, 0x0

    .line 236
    .line 237
    const/16 v25, 0x0

    .line 238
    .line 239
    const/16 v26, 0x0

    .line 240
    .line 241
    const/16 v27, 0x0

    .line 242
    .line 243
    const/16 v28, 0x0

    .line 244
    .line 245
    const/16 v30, 0x0

    .line 246
    .line 247
    const/16 v31, 0x0

    .line 248
    .line 249
    const/16 v32, 0x0

    .line 250
    .line 251
    const/16 v33, 0x0

    .line 252
    .line 253
    const/16 v34, 0x0

    .line 254
    .line 255
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 256
    .line 257
    .line 258
    move-result-object v3

    .line 259
    invoke-virtual {v0, v3}, Lql0/j;->g(Lql0/h;)V

    .line 260
    .line 261
    .line 262
    iget-object v3, v0, Ln90/k;->u:Lk90/c;

    .line 263
    .line 264
    new-instance v7, Lk90/a;

    .line 265
    .line 266
    iget-object v8, v2, Lm90/a;->b:Ljava/lang/String;

    .line 267
    .line 268
    iget-object v9, v0, Ln90/k;->q:Lij0/a;

    .line 269
    .line 270
    new-array v10, v4, [Ljava/lang/Object;

    .line 271
    .line 272
    check-cast v9, Ljj0/f;

    .line 273
    .line 274
    const v11, 0x7f1214a2

    .line 275
    .line 276
    .line 277
    invoke-virtual {v9, v11, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v9

    .line 281
    const-string v10, "fileTitle"

    .line 282
    .line 283
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 287
    .line 288
    .line 289
    iput-object v2, v7, Lk90/a;->a:Lm90/a;

    .line 290
    .line 291
    iput-object v8, v7, Lk90/a;->b:Ljava/lang/String;

    .line 292
    .line 293
    iput-object v9, v7, Lk90/a;->c:Ljava/lang/String;

    .line 294
    .line 295
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 296
    .line 297
    .line 298
    new-instance v2, Lk90/b;

    .line 299
    .line 300
    invoke-direct {v2, v4, v3, v7, v5}, Lk90/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 301
    .line 302
    .line 303
    new-instance v3, Lyy0/m1;

    .line 304
    .line 305
    invoke-direct {v3, v2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 306
    .line 307
    .line 308
    new-instance v2, Ln90/c;

    .line 309
    .line 310
    const/4 v4, 0x4

    .line 311
    invoke-direct {v2, v0, v4}, Ln90/c;-><init>(Ln90/k;I)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v3, v2, v1}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 319
    .line 320
    if-ne v0, v1, :cond_4

    .line 321
    .line 322
    goto :goto_1

    .line 323
    :cond_4
    move-object v0, v6

    .line 324
    :goto_1
    if-ne v0, v1, :cond_7

    .line 325
    .line 326
    move-object v6, v0

    .line 327
    goto/16 :goto_2

    .line 328
    .line 329
    :cond_5
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v1

    .line 333
    if-eqz v1, :cond_6

    .line 334
    .line 335
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 336
    .line 337
    .line 338
    move-result-object v1

    .line 339
    move-object v7, v1

    .line 340
    check-cast v7, Ln90/h;

    .line 341
    .line 342
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 343
    .line 344
    .line 345
    move-result-object v1

    .line 346
    check-cast v1, Ln90/h;

    .line 347
    .line 348
    iget-object v8, v1, Ln90/h;->v:Ln90/f;

    .line 349
    .line 350
    const/4 v12, 0x0

    .line 351
    const/16 v13, 0xd

    .line 352
    .line 353
    const/4 v9, 0x0

    .line 354
    const/4 v10, 0x1

    .line 355
    const/4 v11, 0x0

    .line 356
    invoke-static/range {v8 .. v13}, Ln90/f;->a(Ln90/f;ZZZLer0/g;I)Ln90/f;

    .line 357
    .line 358
    .line 359
    move-result-object v29

    .line 360
    const/16 v35, 0x0

    .line 361
    .line 362
    const v36, 0xfdfffff

    .line 363
    .line 364
    .line 365
    const/4 v8, 0x0

    .line 366
    const/4 v9, 0x0

    .line 367
    const/4 v10, 0x0

    .line 368
    const/4 v11, 0x0

    .line 369
    const/4 v13, 0x0

    .line 370
    const/4 v14, 0x0

    .line 371
    const/4 v15, 0x0

    .line 372
    const/16 v16, 0x0

    .line 373
    .line 374
    const/16 v17, 0x0

    .line 375
    .line 376
    const/16 v18, 0x0

    .line 377
    .line 378
    const/16 v19, 0x0

    .line 379
    .line 380
    const/16 v20, 0x0

    .line 381
    .line 382
    const/16 v21, 0x0

    .line 383
    .line 384
    const/16 v22, 0x0

    .line 385
    .line 386
    const/16 v23, 0x0

    .line 387
    .line 388
    const/16 v24, 0x0

    .line 389
    .line 390
    const/16 v25, 0x0

    .line 391
    .line 392
    const/16 v26, 0x0

    .line 393
    .line 394
    const/16 v27, 0x0

    .line 395
    .line 396
    const/16 v28, 0x0

    .line 397
    .line 398
    const/16 v30, 0x0

    .line 399
    .line 400
    const/16 v31, 0x0

    .line 401
    .line 402
    const/16 v32, 0x0

    .line 403
    .line 404
    const/16 v33, 0x0

    .line 405
    .line 406
    const/16 v34, 0x0

    .line 407
    .line 408
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 409
    .line 410
    .line 411
    move-result-object v1

    .line 412
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 413
    .line 414
    .line 415
    goto :goto_2

    .line 416
    :cond_6
    instance-of v1, v2, Lne0/c;

    .line 417
    .line 418
    if-eqz v1, :cond_8

    .line 419
    .line 420
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 421
    .line 422
    .line 423
    move-result-object v1

    .line 424
    move-object v7, v1

    .line 425
    check-cast v7, Ln90/h;

    .line 426
    .line 427
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    check-cast v1, Ln90/h;

    .line 432
    .line 433
    iget-object v8, v1, Ln90/h;->v:Ln90/f;

    .line 434
    .line 435
    const/4 v12, 0x0

    .line 436
    const/16 v13, 0xd

    .line 437
    .line 438
    const/4 v9, 0x0

    .line 439
    const/4 v10, 0x0

    .line 440
    const/4 v11, 0x0

    .line 441
    invoke-static/range {v8 .. v13}, Ln90/f;->a(Ln90/f;ZZZLer0/g;I)Ln90/f;

    .line 442
    .line 443
    .line 444
    move-result-object v29

    .line 445
    check-cast v2, Lne0/c;

    .line 446
    .line 447
    iget-object v1, v0, Ln90/k;->q:Lij0/a;

    .line 448
    .line 449
    invoke-static {v2, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 450
    .line 451
    .line 452
    move-result-object v28

    .line 453
    const/16 v35, 0x0

    .line 454
    .line 455
    const v36, 0xfcfffff

    .line 456
    .line 457
    .line 458
    const/4 v8, 0x0

    .line 459
    const/4 v9, 0x0

    .line 460
    const/4 v10, 0x0

    .line 461
    const/4 v11, 0x0

    .line 462
    const/4 v13, 0x0

    .line 463
    const/4 v14, 0x0

    .line 464
    const/4 v15, 0x0

    .line 465
    const/16 v16, 0x0

    .line 466
    .line 467
    const/16 v17, 0x0

    .line 468
    .line 469
    const/16 v18, 0x0

    .line 470
    .line 471
    const/16 v19, 0x0

    .line 472
    .line 473
    const/16 v20, 0x0

    .line 474
    .line 475
    const/16 v21, 0x0

    .line 476
    .line 477
    const/16 v22, 0x0

    .line 478
    .line 479
    const/16 v23, 0x0

    .line 480
    .line 481
    const/16 v24, 0x0

    .line 482
    .line 483
    const/16 v25, 0x0

    .line 484
    .line 485
    const/16 v26, 0x0

    .line 486
    .line 487
    const/16 v27, 0x0

    .line 488
    .line 489
    const/16 v30, 0x0

    .line 490
    .line 491
    const/16 v31, 0x0

    .line 492
    .line 493
    const/16 v32, 0x0

    .line 494
    .line 495
    const/16 v33, 0x0

    .line 496
    .line 497
    const/16 v34, 0x0

    .line 498
    .line 499
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 500
    .line 501
    .line 502
    move-result-object v1

    .line 503
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 504
    .line 505
    .line 506
    :cond_7
    :goto_2
    return-object v6

    .line 507
    :cond_8
    new-instance v0, La8/r0;

    .line 508
    .line 509
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 510
    .line 511
    .line 512
    throw v0

    .line 513
    :pswitch_1
    move-object/from16 v1, p1

    .line 514
    .line 515
    check-cast v1, Lne0/s;

    .line 516
    .line 517
    instance-of v2, v1, Lne0/e;

    .line 518
    .line 519
    if-eqz v2, :cond_9

    .line 520
    .line 521
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 522
    .line 523
    .line 524
    move-result-object v2

    .line 525
    move-object v7, v2

    .line 526
    check-cast v7, Ln90/h;

    .line 527
    .line 528
    check-cast v1, Lne0/e;

    .line 529
    .line 530
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 531
    .line 532
    check-cast v1, Ljava/util/Collection;

    .line 533
    .line 534
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 535
    .line 536
    .line 537
    move-result v1

    .line 538
    xor-int/lit8 v31, v1, 0x1

    .line 539
    .line 540
    const/16 v35, 0x0

    .line 541
    .line 542
    const v36, 0xf7fffff

    .line 543
    .line 544
    .line 545
    const/4 v8, 0x0

    .line 546
    const/4 v9, 0x0

    .line 547
    const/4 v10, 0x0

    .line 548
    const/4 v11, 0x0

    .line 549
    const/4 v12, 0x0

    .line 550
    const/4 v13, 0x0

    .line 551
    const/4 v14, 0x0

    .line 552
    const/4 v15, 0x0

    .line 553
    const/16 v16, 0x0

    .line 554
    .line 555
    const/16 v17, 0x0

    .line 556
    .line 557
    const/16 v18, 0x0

    .line 558
    .line 559
    const/16 v19, 0x0

    .line 560
    .line 561
    const/16 v20, 0x0

    .line 562
    .line 563
    const/16 v21, 0x0

    .line 564
    .line 565
    const/16 v22, 0x0

    .line 566
    .line 567
    const/16 v23, 0x0

    .line 568
    .line 569
    const/16 v24, 0x0

    .line 570
    .line 571
    const/16 v25, 0x0

    .line 572
    .line 573
    const/16 v26, 0x0

    .line 574
    .line 575
    const/16 v27, 0x0

    .line 576
    .line 577
    const/16 v28, 0x0

    .line 578
    .line 579
    const/16 v29, 0x0

    .line 580
    .line 581
    const/16 v30, 0x0

    .line 582
    .line 583
    const/16 v32, 0x0

    .line 584
    .line 585
    const/16 v33, 0x0

    .line 586
    .line 587
    const/16 v34, 0x0

    .line 588
    .line 589
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 590
    .line 591
    .line 592
    move-result-object v1

    .line 593
    goto :goto_3

    .line 594
    :cond_9
    instance-of v1, v1, Lne0/c;

    .line 595
    .line 596
    if-eqz v1, :cond_a

    .line 597
    .line 598
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 599
    .line 600
    .line 601
    move-result-object v1

    .line 602
    move-object v7, v1

    .line 603
    check-cast v7, Ln90/h;

    .line 604
    .line 605
    const/16 v35, 0x0

    .line 606
    .line 607
    const v36, 0xf7fffff

    .line 608
    .line 609
    .line 610
    const/4 v8, 0x0

    .line 611
    const/4 v9, 0x0

    .line 612
    const/4 v10, 0x0

    .line 613
    const/4 v11, 0x0

    .line 614
    const/4 v12, 0x0

    .line 615
    const/4 v13, 0x0

    .line 616
    const/4 v14, 0x0

    .line 617
    const/4 v15, 0x0

    .line 618
    const/16 v16, 0x0

    .line 619
    .line 620
    const/16 v17, 0x0

    .line 621
    .line 622
    const/16 v18, 0x0

    .line 623
    .line 624
    const/16 v19, 0x0

    .line 625
    .line 626
    const/16 v20, 0x0

    .line 627
    .line 628
    const/16 v21, 0x0

    .line 629
    .line 630
    const/16 v22, 0x0

    .line 631
    .line 632
    const/16 v23, 0x0

    .line 633
    .line 634
    const/16 v24, 0x0

    .line 635
    .line 636
    const/16 v25, 0x0

    .line 637
    .line 638
    const/16 v26, 0x0

    .line 639
    .line 640
    const/16 v27, 0x0

    .line 641
    .line 642
    const/16 v28, 0x0

    .line 643
    .line 644
    const/16 v29, 0x0

    .line 645
    .line 646
    const/16 v30, 0x0

    .line 647
    .line 648
    const/16 v31, 0x0

    .line 649
    .line 650
    const/16 v32, 0x0

    .line 651
    .line 652
    const/16 v33, 0x0

    .line 653
    .line 654
    const/16 v34, 0x0

    .line 655
    .line 656
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 657
    .line 658
    .line 659
    move-result-object v1

    .line 660
    goto :goto_3

    .line 661
    :cond_a
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 662
    .line 663
    .line 664
    move-result-object v1

    .line 665
    check-cast v1, Ln90/h;

    .line 666
    .line 667
    :goto_3
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 668
    .line 669
    .line 670
    return-object v6

    .line 671
    :pswitch_2
    move-object/from16 v1, p1

    .line 672
    .line 673
    check-cast v1, Lhf0/c;

    .line 674
    .line 675
    const-string v2, "how_to_videos_tab"

    .line 676
    .line 677
    if-eqz v1, :cond_b

    .line 678
    .line 679
    move-object v1, v2

    .line 680
    goto :goto_4

    .line 681
    :cond_b
    move-object v1, v5

    .line 682
    :goto_4
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 683
    .line 684
    .line 685
    move-result v1

    .line 686
    if-eqz v1, :cond_c

    .line 687
    .line 688
    sget-object v1, Ln90/g;->e:Ln90/g;

    .line 689
    .line 690
    invoke-virtual {v0, v1}, Ln90/k;->l(Ln90/g;)V

    .line 691
    .line 692
    .line 693
    iget-object v0, v0, Ln90/k;->A:Lgf0/f;

    .line 694
    .line 695
    iget-object v0, v0, Lgf0/f;->a:Lgf0/b;

    .line 696
    .line 697
    check-cast v0, Ldf0/a;

    .line 698
    .line 699
    iget-object v0, v0, Ldf0/a;->a:Lyy0/c2;

    .line 700
    .line 701
    invoke-virtual {v0, v5}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 702
    .line 703
    .line 704
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 705
    .line 706
    :cond_c
    return-object v6

    .line 707
    :pswitch_3
    move-object/from16 v1, p1

    .line 708
    .line 709
    check-cast v1, Lne0/s;

    .line 710
    .line 711
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 712
    .line 713
    .line 714
    move-result-object v2

    .line 715
    move-object v7, v2

    .line 716
    check-cast v7, Ln90/h;

    .line 717
    .line 718
    instance-of v2, v1, Lne0/d;

    .line 719
    .line 720
    instance-of v3, v1, Lne0/c;

    .line 721
    .line 722
    if-eqz v3, :cond_d

    .line 723
    .line 724
    move-object v3, v1

    .line 725
    check-cast v3, Lne0/c;

    .line 726
    .line 727
    goto :goto_5

    .line 728
    :cond_d
    move-object v3, v5

    .line 729
    :goto_5
    if-eqz v3, :cond_e

    .line 730
    .line 731
    iget-object v4, v0, Ln90/k;->q:Lij0/a;

    .line 732
    .line 733
    invoke-static {v3, v4}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 734
    .line 735
    .line 736
    move-result-object v5

    .line 737
    :cond_e
    move-object/from16 v25, v5

    .line 738
    .line 739
    const/16 v35, 0x0

    .line 740
    .line 741
    const v36, 0xff9ffff

    .line 742
    .line 743
    .line 744
    const/4 v8, 0x0

    .line 745
    const/4 v9, 0x0

    .line 746
    const/4 v10, 0x0

    .line 747
    const/4 v11, 0x0

    .line 748
    const/4 v12, 0x0

    .line 749
    const/4 v13, 0x0

    .line 750
    const/4 v14, 0x0

    .line 751
    const/4 v15, 0x0

    .line 752
    const/16 v16, 0x0

    .line 753
    .line 754
    const/16 v17, 0x0

    .line 755
    .line 756
    const/16 v18, 0x0

    .line 757
    .line 758
    const/16 v19, 0x0

    .line 759
    .line 760
    const/16 v20, 0x0

    .line 761
    .line 762
    const/16 v21, 0x0

    .line 763
    .line 764
    const/16 v22, 0x0

    .line 765
    .line 766
    const/16 v23, 0x0

    .line 767
    .line 768
    const/16 v24, 0x0

    .line 769
    .line 770
    const/16 v27, 0x0

    .line 771
    .line 772
    const/16 v28, 0x0

    .line 773
    .line 774
    const/16 v29, 0x0

    .line 775
    .line 776
    const/16 v30, 0x0

    .line 777
    .line 778
    const/16 v31, 0x0

    .line 779
    .line 780
    const/16 v32, 0x0

    .line 781
    .line 782
    const/16 v33, 0x0

    .line 783
    .line 784
    const/16 v34, 0x0

    .line 785
    .line 786
    move/from16 v26, v2

    .line 787
    .line 788
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 789
    .line 790
    .line 791
    move-result-object v2

    .line 792
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 793
    .line 794
    .line 795
    instance-of v2, v1, Lne0/e;

    .line 796
    .line 797
    if-eqz v2, :cond_f

    .line 798
    .line 799
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 800
    .line 801
    .line 802
    move-result-object v2

    .line 803
    move-object v7, v2

    .line 804
    check-cast v7, Ln90/h;

    .line 805
    .line 806
    check-cast v1, Lne0/e;

    .line 807
    .line 808
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 809
    .line 810
    check-cast v1, Ljava/util/List;

    .line 811
    .line 812
    sget-object v2, Lhp0/d;->d:Lwq/f;

    .line 813
    .line 814
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 815
    .line 816
    .line 817
    invoke-static {}, Lwq/f;->k()Ljava/util/List;

    .line 818
    .line 819
    .line 820
    move-result-object v2

    .line 821
    invoke-static {v1, v2}, Llp/b1;->c(Ljava/util/List;Ljava/util/List;)Ljava/util/ArrayList;

    .line 822
    .line 823
    .line 824
    move-result-object v27

    .line 825
    const/16 v35, 0x0

    .line 826
    .line 827
    const v36, 0xff7ffff

    .line 828
    .line 829
    .line 830
    const/4 v8, 0x0

    .line 831
    const/4 v9, 0x0

    .line 832
    const/4 v10, 0x0

    .line 833
    const/4 v11, 0x0

    .line 834
    const/4 v12, 0x0

    .line 835
    const/4 v13, 0x0

    .line 836
    const/4 v14, 0x0

    .line 837
    const/4 v15, 0x0

    .line 838
    const/16 v16, 0x0

    .line 839
    .line 840
    const/16 v17, 0x0

    .line 841
    .line 842
    const/16 v18, 0x0

    .line 843
    .line 844
    const/16 v19, 0x0

    .line 845
    .line 846
    const/16 v20, 0x0

    .line 847
    .line 848
    const/16 v21, 0x0

    .line 849
    .line 850
    const/16 v22, 0x0

    .line 851
    .line 852
    const/16 v23, 0x0

    .line 853
    .line 854
    const/16 v24, 0x0

    .line 855
    .line 856
    const/16 v25, 0x0

    .line 857
    .line 858
    const/16 v26, 0x0

    .line 859
    .line 860
    const/16 v28, 0x0

    .line 861
    .line 862
    const/16 v29, 0x0

    .line 863
    .line 864
    const/16 v30, 0x0

    .line 865
    .line 866
    const/16 v31, 0x0

    .line 867
    .line 868
    const/16 v32, 0x0

    .line 869
    .line 870
    const/16 v33, 0x0

    .line 871
    .line 872
    const/16 v34, 0x0

    .line 873
    .line 874
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 875
    .line 876
    .line 877
    move-result-object v1

    .line 878
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 879
    .line 880
    .line 881
    :cond_f
    return-object v6

    .line 882
    nop

    .line 883
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
