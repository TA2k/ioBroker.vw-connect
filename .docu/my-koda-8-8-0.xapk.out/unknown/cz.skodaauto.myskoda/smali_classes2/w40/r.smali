.class public final Lw40/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw40/s;


# direct methods
.method public synthetic constructor <init>(Lw40/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw40/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw40/r;->e:Lw40/s;

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
    .locals 41

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lw40/r;->d:I

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    const/4 v4, 0x1

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v6, 0x3

    .line 11
    const/4 v7, 0x6

    .line 12
    const/4 v8, 0x0

    .line 13
    iget-object v0, v0, Lw40/r;->e:Lw40/s;

    .line 14
    .line 15
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    packed-switch v2, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    move-object/from16 v2, p1

    .line 21
    .line 22
    check-cast v2, Lne0/s;

    .line 23
    .line 24
    instance-of v3, v2, Lne0/c;

    .line 25
    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    sget-object v3, Lw40/s;->I:Lon0/a0;

    .line 29
    .line 30
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    move-object v10, v3

    .line 35
    check-cast v10, Lw40/n;

    .line 36
    .line 37
    const/16 v39, 0x0

    .line 38
    .line 39
    const v40, 0x3ff7ffff

    .line 40
    .line 41
    .line 42
    const/4 v11, 0x0

    .line 43
    const/4 v12, 0x0

    .line 44
    const/4 v13, 0x0

    .line 45
    const/4 v14, 0x0

    .line 46
    const/4 v15, 0x0

    .line 47
    const/16 v16, 0x0

    .line 48
    .line 49
    const/16 v17, 0x0

    .line 50
    .line 51
    const/16 v18, 0x0

    .line 52
    .line 53
    const/16 v19, 0x0

    .line 54
    .line 55
    const/16 v20, 0x0

    .line 56
    .line 57
    const/16 v21, 0x0

    .line 58
    .line 59
    const/16 v22, 0x0

    .line 60
    .line 61
    const/16 v23, 0x0

    .line 62
    .line 63
    const/16 v24, 0x0

    .line 64
    .line 65
    const/16 v25, 0x0

    .line 66
    .line 67
    const/16 v26, 0x0

    .line 68
    .line 69
    const/16 v27, 0x0

    .line 70
    .line 71
    const/16 v28, 0x0

    .line 72
    .line 73
    const/16 v29, 0x0

    .line 74
    .line 75
    const/16 v30, 0x0

    .line 76
    .line 77
    const/16 v31, 0x0

    .line 78
    .line 79
    const/16 v32, 0x0

    .line 80
    .line 81
    const/16 v33, 0x0

    .line 82
    .line 83
    const/16 v34, 0x0

    .line 84
    .line 85
    const/16 v35, 0x0

    .line 86
    .line 87
    const/16 v36, 0x0

    .line 88
    .line 89
    const/16 v37, 0x0

    .line 90
    .line 91
    const/16 v38, 0x0

    .line 92
    .line 93
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    invoke-virtual {v0, v3}, Lql0/j;->g(Lql0/h;)V

    .line 98
    .line 99
    .line 100
    check-cast v2, Lne0/c;

    .line 101
    .line 102
    invoke-virtual {v0, v2, v1}, Lw40/s;->q(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    if-ne v0, v1, :cond_2

    .line 109
    .line 110
    move-object v9, v0

    .line 111
    goto/16 :goto_0

    .line 112
    .line 113
    :cond_0
    instance-of v1, v2, Lne0/d;

    .line 114
    .line 115
    if-eqz v1, :cond_1

    .line 116
    .line 117
    sget-object v1, Lw40/s;->I:Lon0/a0;

    .line 118
    .line 119
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    move-object v10, v1

    .line 124
    check-cast v10, Lw40/n;

    .line 125
    .line 126
    const/16 v39, 0x0

    .line 127
    .line 128
    const v40, 0x3f77ffff

    .line 129
    .line 130
    .line 131
    const/4 v11, 0x0

    .line 132
    const/4 v12, 0x0

    .line 133
    const/4 v13, 0x0

    .line 134
    const/4 v14, 0x0

    .line 135
    const/4 v15, 0x0

    .line 136
    const/16 v16, 0x0

    .line 137
    .line 138
    const/16 v17, 0x0

    .line 139
    .line 140
    const/16 v18, 0x0

    .line 141
    .line 142
    const/16 v19, 0x0

    .line 143
    .line 144
    const/16 v20, 0x0

    .line 145
    .line 146
    const/16 v21, 0x0

    .line 147
    .line 148
    const/16 v22, 0x0

    .line 149
    .line 150
    const/16 v23, 0x0

    .line 151
    .line 152
    const/16 v24, 0x0

    .line 153
    .line 154
    const/16 v25, 0x0

    .line 155
    .line 156
    const/16 v26, 0x0

    .line 157
    .line 158
    const/16 v27, 0x0

    .line 159
    .line 160
    const/16 v28, 0x0

    .line 161
    .line 162
    const/16 v29, 0x0

    .line 163
    .line 164
    const/16 v30, 0x1

    .line 165
    .line 166
    const/16 v31, 0x0

    .line 167
    .line 168
    const/16 v32, 0x0

    .line 169
    .line 170
    const/16 v33, 0x0

    .line 171
    .line 172
    const/16 v34, 0x0

    .line 173
    .line 174
    const/16 v35, 0x0

    .line 175
    .line 176
    const/16 v36, 0x0

    .line 177
    .line 178
    const/16 v37, 0x0

    .line 179
    .line 180
    const/16 v38, 0x0

    .line 181
    .line 182
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 187
    .line 188
    .line 189
    goto :goto_0

    .line 190
    :cond_1
    instance-of v1, v2, Lne0/e;

    .line 191
    .line 192
    if-eqz v1, :cond_3

    .line 193
    .line 194
    sget-object v1, Lw40/s;->I:Lon0/a0;

    .line 195
    .line 196
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    move-object v10, v1

    .line 201
    check-cast v10, Lw40/n;

    .line 202
    .line 203
    const/16 v39, 0x0

    .line 204
    .line 205
    const v40, 0x3ff7ffff

    .line 206
    .line 207
    .line 208
    const/4 v11, 0x0

    .line 209
    const/4 v12, 0x0

    .line 210
    const/4 v13, 0x0

    .line 211
    const/4 v14, 0x0

    .line 212
    const/4 v15, 0x0

    .line 213
    const/16 v16, 0x0

    .line 214
    .line 215
    const/16 v17, 0x0

    .line 216
    .line 217
    const/16 v18, 0x0

    .line 218
    .line 219
    const/16 v19, 0x0

    .line 220
    .line 221
    const/16 v20, 0x0

    .line 222
    .line 223
    const/16 v21, 0x0

    .line 224
    .line 225
    const/16 v22, 0x0

    .line 226
    .line 227
    const/16 v23, 0x0

    .line 228
    .line 229
    const/16 v24, 0x0

    .line 230
    .line 231
    const/16 v25, 0x0

    .line 232
    .line 233
    const/16 v26, 0x0

    .line 234
    .line 235
    const/16 v27, 0x0

    .line 236
    .line 237
    const/16 v28, 0x0

    .line 238
    .line 239
    const/16 v29, 0x0

    .line 240
    .line 241
    const/16 v30, 0x0

    .line 242
    .line 243
    const/16 v31, 0x0

    .line 244
    .line 245
    const/16 v32, 0x0

    .line 246
    .line 247
    const/16 v33, 0x0

    .line 248
    .line 249
    const/16 v34, 0x0

    .line 250
    .line 251
    const/16 v35, 0x0

    .line 252
    .line 253
    const/16 v36, 0x0

    .line 254
    .line 255
    const/16 v37, 0x0

    .line 256
    .line 257
    const/16 v38, 0x0

    .line 258
    .line 259
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 264
    .line 265
    .line 266
    iget-object v1, v0, Lw40/s;->w:Lu40/m;

    .line 267
    .line 268
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    new-instance v2, Lw40/q;

    .line 276
    .line 277
    invoke-direct {v2, v0, v8, v7}, Lw40/q;-><init>(Lw40/s;Lkotlin/coroutines/Continuation;I)V

    .line 278
    .line 279
    .line 280
    invoke-static {v1, v8, v8, v2, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 281
    .line 282
    .line 283
    :cond_2
    :goto_0
    return-object v9

    .line 284
    :cond_3
    new-instance v0, La8/r0;

    .line 285
    .line 286
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 287
    .line 288
    .line 289
    throw v0

    .line 290
    :pswitch_0
    move-object/from16 v1, p1

    .line 291
    .line 292
    check-cast v1, Lne0/s;

    .line 293
    .line 294
    instance-of v2, v1, Lne0/c;

    .line 295
    .line 296
    if-eqz v2, :cond_4

    .line 297
    .line 298
    sget-object v2, Lw40/s;->I:Lon0/a0;

    .line 299
    .line 300
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    move-object v10, v2

    .line 305
    check-cast v10, Lw40/n;

    .line 306
    .line 307
    check-cast v1, Lne0/c;

    .line 308
    .line 309
    iget-object v2, v0, Lw40/s;->n:Lij0/a;

    .line 310
    .line 311
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 312
    .line 313
    .line 314
    move-result-object v37

    .line 315
    const/16 v39, 0x0

    .line 316
    .line 317
    const v40, 0x3bfeffff

    .line 318
    .line 319
    .line 320
    const/4 v11, 0x0

    .line 321
    const/4 v12, 0x0

    .line 322
    const/4 v13, 0x0

    .line 323
    const/4 v14, 0x0

    .line 324
    const/4 v15, 0x0

    .line 325
    const/16 v16, 0x0

    .line 326
    .line 327
    const/16 v17, 0x0

    .line 328
    .line 329
    const/16 v18, 0x0

    .line 330
    .line 331
    const/16 v19, 0x0

    .line 332
    .line 333
    const/16 v20, 0x0

    .line 334
    .line 335
    const/16 v21, 0x0

    .line 336
    .line 337
    const/16 v22, 0x0

    .line 338
    .line 339
    const/16 v23, 0x0

    .line 340
    .line 341
    const/16 v24, 0x0

    .line 342
    .line 343
    const/16 v25, 0x0

    .line 344
    .line 345
    const/16 v26, 0x0

    .line 346
    .line 347
    const/16 v27, 0x0

    .line 348
    .line 349
    const/16 v28, 0x0

    .line 350
    .line 351
    const/16 v29, 0x0

    .line 352
    .line 353
    const/16 v30, 0x0

    .line 354
    .line 355
    const/16 v31, 0x0

    .line 356
    .line 357
    const/16 v32, 0x0

    .line 358
    .line 359
    const/16 v33, 0x0

    .line 360
    .line 361
    const/16 v34, 0x0

    .line 362
    .line 363
    const/16 v35, 0x0

    .line 364
    .line 365
    const/16 v36, 0x0

    .line 366
    .line 367
    const/16 v38, 0x0

    .line 368
    .line 369
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 370
    .line 371
    .line 372
    move-result-object v1

    .line 373
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 374
    .line 375
    .line 376
    goto :goto_1

    .line 377
    :cond_4
    instance-of v2, v1, Lne0/d;

    .line 378
    .line 379
    if-eqz v2, :cond_5

    .line 380
    .line 381
    sget-object v1, Lw40/s;->I:Lon0/a0;

    .line 382
    .line 383
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 384
    .line 385
    .line 386
    move-result-object v1

    .line 387
    move-object v10, v1

    .line 388
    check-cast v10, Lw40/n;

    .line 389
    .line 390
    const/16 v39, 0x0

    .line 391
    .line 392
    const v40, 0x3ffeffff

    .line 393
    .line 394
    .line 395
    const/4 v11, 0x0

    .line 396
    const/4 v12, 0x0

    .line 397
    const/4 v13, 0x0

    .line 398
    const/4 v14, 0x0

    .line 399
    const/4 v15, 0x0

    .line 400
    const/16 v16, 0x0

    .line 401
    .line 402
    const/16 v17, 0x0

    .line 403
    .line 404
    const/16 v18, 0x0

    .line 405
    .line 406
    const/16 v19, 0x0

    .line 407
    .line 408
    const/16 v20, 0x0

    .line 409
    .line 410
    const/16 v21, 0x0

    .line 411
    .line 412
    const/16 v22, 0x0

    .line 413
    .line 414
    const/16 v23, 0x0

    .line 415
    .line 416
    const/16 v24, 0x0

    .line 417
    .line 418
    const/16 v25, 0x0

    .line 419
    .line 420
    const/16 v26, 0x0

    .line 421
    .line 422
    const/16 v27, 0x1

    .line 423
    .line 424
    const/16 v28, 0x0

    .line 425
    .line 426
    const/16 v29, 0x0

    .line 427
    .line 428
    const/16 v30, 0x0

    .line 429
    .line 430
    const/16 v31, 0x0

    .line 431
    .line 432
    const/16 v32, 0x0

    .line 433
    .line 434
    const/16 v33, 0x0

    .line 435
    .line 436
    const/16 v34, 0x0

    .line 437
    .line 438
    const/16 v35, 0x0

    .line 439
    .line 440
    const/16 v36, 0x0

    .line 441
    .line 442
    const/16 v37, 0x0

    .line 443
    .line 444
    const/16 v38, 0x0

    .line 445
    .line 446
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 451
    .line 452
    .line 453
    goto :goto_1

    .line 454
    :cond_5
    instance-of v2, v1, Lne0/e;

    .line 455
    .line 456
    if-eqz v2, :cond_6

    .line 457
    .line 458
    check-cast v1, Lne0/e;

    .line 459
    .line 460
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 461
    .line 462
    check-cast v1, Lv40/a;

    .line 463
    .line 464
    sget-object v2, Lw40/s;->I:Lon0/a0;

    .line 465
    .line 466
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 467
    .line 468
    .line 469
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 470
    .line 471
    .line 472
    move-result-object v2

    .line 473
    new-instance v3, Lvu/j;

    .line 474
    .line 475
    const/16 v4, 0x15

    .line 476
    .line 477
    invoke-direct {v3, v4, v0, v1, v8}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 478
    .line 479
    .line 480
    invoke-static {v2, v8, v8, v3, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 481
    .line 482
    .line 483
    :goto_1
    return-object v9

    .line 484
    :cond_6
    new-instance v0, La8/r0;

    .line 485
    .line 486
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 487
    .line 488
    .line 489
    throw v0

    .line 490
    :pswitch_1
    move-object/from16 v2, p1

    .line 491
    .line 492
    check-cast v2, Lne0/s;

    .line 493
    .line 494
    instance-of v6, v2, Lne0/c;

    .line 495
    .line 496
    if-eqz v6, :cond_8

    .line 497
    .line 498
    check-cast v2, Lne0/c;

    .line 499
    .line 500
    sget-object v3, Lw40/s;->I:Lon0/a0;

    .line 501
    .line 502
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 503
    .line 504
    .line 505
    move-result-object v3

    .line 506
    move-object v10, v3

    .line 507
    check-cast v10, Lw40/n;

    .line 508
    .line 509
    const/16 v39, 0x0

    .line 510
    .line 511
    const v40, 0x3ffdff17

    .line 512
    .line 513
    .line 514
    const/4 v11, 0x0

    .line 515
    const/4 v12, 0x0

    .line 516
    const/4 v13, 0x0

    .line 517
    const-string v14, ""

    .line 518
    .line 519
    const/4 v15, 0x0

    .line 520
    const/16 v16, 0x0

    .line 521
    .line 522
    const-string v17, ""

    .line 523
    .line 524
    const-string v18, ""

    .line 525
    .line 526
    const/16 v19, 0x0

    .line 527
    .line 528
    const/16 v20, 0x0

    .line 529
    .line 530
    const/16 v21, 0x0

    .line 531
    .line 532
    const/16 v22, 0x0

    .line 533
    .line 534
    const/16 v23, 0x0

    .line 535
    .line 536
    const/16 v24, 0x0

    .line 537
    .line 538
    const/16 v25, 0x0

    .line 539
    .line 540
    const/16 v26, 0x0

    .line 541
    .line 542
    const/16 v27, 0x0

    .line 543
    .line 544
    const/16 v28, 0x0

    .line 545
    .line 546
    const/16 v29, 0x0

    .line 547
    .line 548
    const/16 v30, 0x0

    .line 549
    .line 550
    const/16 v31, 0x0

    .line 551
    .line 552
    const/16 v32, 0x0

    .line 553
    .line 554
    const/16 v33, 0x0

    .line 555
    .line 556
    const/16 v34, 0x0

    .line 557
    .line 558
    const/16 v35, 0x0

    .line 559
    .line 560
    const/16 v36, 0x0

    .line 561
    .line 562
    const/16 v37, 0x0

    .line 563
    .line 564
    const/16 v38, 0x0

    .line 565
    .line 566
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 567
    .line 568
    .line 569
    move-result-object v3

    .line 570
    invoke-virtual {v0, v3}, Lql0/j;->g(Lql0/h;)V

    .line 571
    .line 572
    .line 573
    invoke-virtual {v0, v2, v1}, Lw40/s;->q(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 574
    .line 575
    .line 576
    move-result-object v0

    .line 577
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 578
    .line 579
    if-ne v0, v1, :cond_7

    .line 580
    .line 581
    goto :goto_2

    .line 582
    :cond_7
    move-object v0, v9

    .line 583
    :goto_2
    if-ne v0, v1, :cond_c

    .line 584
    .line 585
    move-object v9, v0

    .line 586
    goto/16 :goto_4

    .line 587
    .line 588
    :cond_8
    instance-of v1, v2, Lne0/d;

    .line 589
    .line 590
    if-eqz v1, :cond_9

    .line 591
    .line 592
    sget-object v1, Lw40/s;->I:Lon0/a0;

    .line 593
    .line 594
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 595
    .line 596
    .line 597
    move-result-object v1

    .line 598
    move-object v10, v1

    .line 599
    check-cast v10, Lw40/n;

    .line 600
    .line 601
    const/16 v39, 0x0

    .line 602
    .line 603
    const v40, 0x3ffdffff

    .line 604
    .line 605
    .line 606
    const/4 v11, 0x0

    .line 607
    const/4 v12, 0x0

    .line 608
    const/4 v13, 0x0

    .line 609
    const/4 v14, 0x0

    .line 610
    const/4 v15, 0x0

    .line 611
    const/16 v16, 0x0

    .line 612
    .line 613
    const/16 v17, 0x0

    .line 614
    .line 615
    const/16 v18, 0x0

    .line 616
    .line 617
    const/16 v19, 0x0

    .line 618
    .line 619
    const/16 v20, 0x0

    .line 620
    .line 621
    const/16 v21, 0x0

    .line 622
    .line 623
    const/16 v22, 0x0

    .line 624
    .line 625
    const/16 v23, 0x0

    .line 626
    .line 627
    const/16 v24, 0x0

    .line 628
    .line 629
    const/16 v25, 0x0

    .line 630
    .line 631
    const/16 v26, 0x0

    .line 632
    .line 633
    const/16 v27, 0x0

    .line 634
    .line 635
    const/16 v28, 0x1

    .line 636
    .line 637
    const/16 v29, 0x0

    .line 638
    .line 639
    const/16 v30, 0x0

    .line 640
    .line 641
    const/16 v31, 0x0

    .line 642
    .line 643
    const/16 v32, 0x0

    .line 644
    .line 645
    const/16 v33, 0x0

    .line 646
    .line 647
    const/16 v34, 0x0

    .line 648
    .line 649
    const/16 v35, 0x0

    .line 650
    .line 651
    const/16 v36, 0x0

    .line 652
    .line 653
    const/16 v37, 0x0

    .line 654
    .line 655
    const/16 v38, 0x0

    .line 656
    .line 657
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 658
    .line 659
    .line 660
    move-result-object v1

    .line 661
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 662
    .line 663
    .line 664
    goto/16 :goto_4

    .line 665
    .line 666
    :cond_9
    instance-of v1, v2, Lne0/e;

    .line 667
    .line 668
    if-eqz v1, :cond_d

    .line 669
    .line 670
    check-cast v2, Lne0/e;

    .line 671
    .line 672
    sget-object v1, Lw40/s;->I:Lon0/a0;

    .line 673
    .line 674
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 675
    .line 676
    .line 677
    iget-object v1, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 678
    .line 679
    check-cast v1, Lv40/d;

    .line 680
    .line 681
    iget-object v2, v1, Lv40/d;->b:Ljava/time/OffsetDateTime;

    .line 682
    .line 683
    iput-object v2, v0, Lw40/s;->H:Ljava/time/OffsetDateTime;

    .line 684
    .line 685
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 686
    .line 687
    .line 688
    move-result-object v2

    .line 689
    move-object v10, v2

    .line 690
    check-cast v10, Lw40/n;

    .line 691
    .line 692
    iget-object v2, v1, Lv40/d;->a:Lol0/a;

    .line 693
    .line 694
    invoke-static {v2, v3}, Ljp/qd;->a(Lol0/a;I)Ljava/lang/String;

    .line 695
    .line 696
    .line 697
    move-result-object v14

    .line 698
    iget-object v15, v1, Lv40/d;->d:Lv40/e;

    .line 699
    .line 700
    iget-object v2, v1, Lv40/d;->b:Ljava/time/OffsetDateTime;

    .line 701
    .line 702
    invoke-static {v2}, Lvo/a;->k(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 703
    .line 704
    .line 705
    move-result-object v18

    .line 706
    iget-wide v2, v1, Lv40/d;->c:J

    .line 707
    .line 708
    iget-object v6, v0, Lw40/s;->n:Lij0/a;

    .line 709
    .line 710
    invoke-static {v2, v3, v6, v5, v7}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 711
    .line 712
    .line 713
    move-result-object v17

    .line 714
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 715
    .line 716
    .line 717
    move-result-object v6

    .line 718
    check-cast v6, Lw40/n;

    .line 719
    .line 720
    iget-object v6, v6, Lw40/n;->k:Lon0/a0;

    .line 721
    .line 722
    if-eqz v6, :cond_a

    .line 723
    .line 724
    iget-boolean v6, v6, Lon0/a0;->e:Z

    .line 725
    .line 726
    if-nez v6, :cond_a

    .line 727
    .line 728
    move/from16 v29, v4

    .line 729
    .line 730
    goto :goto_3

    .line 731
    :cond_a
    move/from16 v29, v5

    .line 732
    .line 733
    :goto_3
    iget-object v4, v1, Lv40/d;->e:Ljava/lang/Boolean;

    .line 734
    .line 735
    if-eqz v4, :cond_b

    .line 736
    .line 737
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 738
    .line 739
    .line 740
    move-result v5

    .line 741
    :cond_b
    move/from16 v33, v5

    .line 742
    .line 743
    iget-boolean v1, v1, Lv40/d;->f:Z

    .line 744
    .line 745
    new-instance v4, Lmy0/c;

    .line 746
    .line 747
    invoke-direct {v4, v2, v3}, Lmy0/c;-><init>(J)V

    .line 748
    .line 749
    .line 750
    const/16 v39, 0x0

    .line 751
    .line 752
    const v40, 0x2fb9ff07

    .line 753
    .line 754
    .line 755
    const/4 v11, 0x0

    .line 756
    const/4 v12, 0x0

    .line 757
    const/4 v13, 0x0

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
    const/16 v25, 0x0

    .line 771
    .line 772
    const/16 v26, 0x0

    .line 773
    .line 774
    const/16 v27, 0x0

    .line 775
    .line 776
    const/16 v28, 0x0

    .line 777
    .line 778
    const/16 v30, 0x0

    .line 779
    .line 780
    const/16 v31, 0x0

    .line 781
    .line 782
    const/16 v32, 0x0

    .line 783
    .line 784
    const/16 v34, 0x0

    .line 785
    .line 786
    const/16 v35, 0x0

    .line 787
    .line 788
    const/16 v36, 0x0

    .line 789
    .line 790
    const/16 v37, 0x0

    .line 791
    .line 792
    move/from16 v38, v1

    .line 793
    .line 794
    move-object/from16 v16, v4

    .line 795
    .line 796
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 797
    .line 798
    .line 799
    move-result-object v1

    .line 800
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 801
    .line 802
    .line 803
    :cond_c
    :goto_4
    return-object v9

    .line 804
    :cond_d
    new-instance v0, La8/r0;

    .line 805
    .line 806
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 807
    .line 808
    .line 809
    throw v0

    .line 810
    :pswitch_2
    move-object/from16 v1, p1

    .line 811
    .line 812
    check-cast v1, Lne0/t;

    .line 813
    .line 814
    instance-of v2, v1, Lne0/e;

    .line 815
    .line 816
    if-eqz v2, :cond_12

    .line 817
    .line 818
    iget-object v2, v0, Lw40/s;->k:Lbd0/c;

    .line 819
    .line 820
    iget-object v0, v0, Lw40/s;->B:Lu40/a;

    .line 821
    .line 822
    check-cast v1, Lne0/e;

    .line 823
    .line 824
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 825
    .line 826
    check-cast v1, Ljava/lang/String;

    .line 827
    .line 828
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 829
    .line 830
    .line 831
    const-string v0, "input"

    .line 832
    .line 833
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 834
    .line 835
    .line 836
    sget-object v0, Lv40/b;->d:[Lv40/b;

    .line 837
    .line 838
    const-string v0, "&redirect=myskoda://redirect/parkfuel/new-card-success&cancel=myskoda://redirect/parkfuel/new-card-cancel"

    .line 839
    .line 840
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 841
    .line 842
    .line 843
    move-result-object v0

    .line 844
    const/16 v1, 0x1e

    .line 845
    .line 846
    and-int/2addr v3, v1

    .line 847
    if-eqz v3, :cond_e

    .line 848
    .line 849
    move v12, v4

    .line 850
    goto :goto_5

    .line 851
    :cond_e
    move v12, v5

    .line 852
    :goto_5
    and-int/lit8 v3, v1, 0x4

    .line 853
    .line 854
    if-eqz v3, :cond_f

    .line 855
    .line 856
    move v13, v4

    .line 857
    goto :goto_6

    .line 858
    :cond_f
    move v13, v5

    .line 859
    :goto_6
    and-int/lit8 v3, v1, 0x8

    .line 860
    .line 861
    if-eqz v3, :cond_10

    .line 862
    .line 863
    move v14, v5

    .line 864
    goto :goto_7

    .line 865
    :cond_10
    move v14, v4

    .line 866
    :goto_7
    and-int/lit8 v1, v1, 0x10

    .line 867
    .line 868
    if-eqz v1, :cond_11

    .line 869
    .line 870
    move v15, v5

    .line 871
    goto :goto_8

    .line 872
    :cond_11
    move v15, v4

    .line 873
    :goto_8
    const-string v1, "url"

    .line 874
    .line 875
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 876
    .line 877
    .line 878
    iget-object v1, v2, Lbd0/c;->a:Lbd0/a;

    .line 879
    .line 880
    new-instance v11, Ljava/net/URL;

    .line 881
    .line 882
    invoke-direct {v11, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 883
    .line 884
    .line 885
    move-object v10, v1

    .line 886
    check-cast v10, Lzc0/b;

    .line 887
    .line 888
    invoke-virtual/range {v10 .. v15}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 889
    .line 890
    .line 891
    goto :goto_9

    .line 892
    :cond_12
    instance-of v2, v1, Lne0/c;

    .line 893
    .line 894
    if-eqz v2, :cond_13

    .line 895
    .line 896
    sget-object v2, Lw40/s;->I:Lon0/a0;

    .line 897
    .line 898
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 899
    .line 900
    .line 901
    move-result-object v2

    .line 902
    move-object v10, v2

    .line 903
    check-cast v10, Lw40/n;

    .line 904
    .line 905
    check-cast v1, Lne0/c;

    .line 906
    .line 907
    iget-object v2, v0, Lw40/s;->n:Lij0/a;

    .line 908
    .line 909
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 910
    .line 911
    .line 912
    move-result-object v37

    .line 913
    const/16 v39, 0x0

    .line 914
    .line 915
    const v40, 0x3bffffff

    .line 916
    .line 917
    .line 918
    const/4 v11, 0x0

    .line 919
    const/4 v12, 0x0

    .line 920
    const/4 v13, 0x0

    .line 921
    const/4 v14, 0x0

    .line 922
    const/4 v15, 0x0

    .line 923
    const/16 v16, 0x0

    .line 924
    .line 925
    const/16 v17, 0x0

    .line 926
    .line 927
    const/16 v18, 0x0

    .line 928
    .line 929
    const/16 v19, 0x0

    .line 930
    .line 931
    const/16 v20, 0x0

    .line 932
    .line 933
    const/16 v21, 0x0

    .line 934
    .line 935
    const/16 v22, 0x0

    .line 936
    .line 937
    const/16 v23, 0x0

    .line 938
    .line 939
    const/16 v24, 0x0

    .line 940
    .line 941
    const/16 v25, 0x0

    .line 942
    .line 943
    const/16 v26, 0x0

    .line 944
    .line 945
    const/16 v27, 0x0

    .line 946
    .line 947
    const/16 v28, 0x0

    .line 948
    .line 949
    const/16 v29, 0x0

    .line 950
    .line 951
    const/16 v30, 0x0

    .line 952
    .line 953
    const/16 v31, 0x0

    .line 954
    .line 955
    const/16 v32, 0x0

    .line 956
    .line 957
    const/16 v33, 0x0

    .line 958
    .line 959
    const/16 v34, 0x0

    .line 960
    .line 961
    const/16 v35, 0x0

    .line 962
    .line 963
    const/16 v36, 0x0

    .line 964
    .line 965
    const/16 v38, 0x0

    .line 966
    .line 967
    invoke-static/range {v10 .. v40}, Lw40/n;->a(Lw40/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lv40/e;Lmy0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/a0;Ljava/util/List;Ljava/lang/String;ZZZZZZZLjava/lang/String;ZZZZZLql0/g;ZZI)Lw40/n;

    .line 968
    .line 969
    .line 970
    move-result-object v1

    .line 971
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 972
    .line 973
    .line 974
    :goto_9
    return-object v9

    .line 975
    :cond_13
    new-instance v0, La8/r0;

    .line 976
    .line 977
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 978
    .line 979
    .line 980
    throw v0

    .line 981
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
