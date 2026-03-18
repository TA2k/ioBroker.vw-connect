.class public final synthetic Li40/u2;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Li40/u2;->d:I

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
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/u2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    const-string v0, "p0"

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw v1

    .line 17
    :cond_0
    new-instance v0, Ljava/lang/ClassCastException;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw v0

    .line 23
    :pswitch_0
    move-object/from16 v1, p1

    .line 24
    .line 25
    check-cast v1, Lig/d;

    .line 26
    .line 27
    const-string v2, "p0"

    .line 28
    .line 29
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lig/i;

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    sget-object v2, Lig/c;->a:Lig/c;

    .line 40
    .line 41
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-eqz v2, :cond_1

    .line 46
    .line 47
    invoke-virtual {v0}, Lig/i;->a()V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    sget-object v2, Lig/b;->a:Lig/b;

    .line 52
    .line 53
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-eqz v1, :cond_2

    .line 58
    .line 59
    invoke-virtual {v0}, Lig/i;->a()V

    .line 60
    .line 61
    .line 62
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object v0

    .line 65
    :cond_2
    new-instance v0, La8/r0;

    .line 66
    .line 67
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :pswitch_1
    move-object/from16 v1, p1

    .line 72
    .line 73
    check-cast v1, Lid/d;

    .line 74
    .line 75
    const-string v2, "p0"

    .line 76
    .line 77
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v0, Lid/f;

    .line 83
    .line 84
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    instance-of v2, v1, Lid/c;

    .line 88
    .line 89
    if-eqz v2, :cond_3

    .line 90
    .line 91
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    new-instance v2, Lh40/w3;

    .line 96
    .line 97
    const/16 v3, 0x1d

    .line 98
    .line 99
    const/4 v4, 0x0

    .line 100
    invoke-direct {v2, v0, v4, v3}, Lh40/w3;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 101
    .line 102
    .line 103
    const/4 v0, 0x3

    .line 104
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    instance-of v2, v1, Lid/b;

    .line 109
    .line 110
    if-eqz v2, :cond_4

    .line 111
    .line 112
    iget-object v0, v0, Lid/f;->f:Lzb/s0;

    .line 113
    .line 114
    check-cast v1, Lid/b;

    .line 115
    .line 116
    iget-object v1, v1, Lid/b;->a:Ljava/lang/String;

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Lzb/s0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 122
    .line 123
    return-object v0

    .line 124
    :cond_4
    new-instance v0, La8/r0;

    .line 125
    .line 126
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 127
    .line 128
    .line 129
    throw v0

    .line 130
    :pswitch_2
    move-object/from16 v1, p1

    .line 131
    .line 132
    check-cast v1, Lic/j;

    .line 133
    .line 134
    const-string v2, "p0"

    .line 135
    .line 136
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v0, Lic/q;

    .line 142
    .line 143
    iget-object v2, v0, Lic/q;->k:Lyy0/c2;

    .line 144
    .line 145
    iget-object v3, v0, Lic/q;->n:Lyy0/c2;

    .line 146
    .line 147
    iget-object v4, v0, Lic/q;->l:Lyy0/c2;

    .line 148
    .line 149
    new-instance v5, Li40/e1;

    .line 150
    .line 151
    const/4 v6, 0x6

    .line 152
    invoke-direct {v5, v1, v6}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 153
    .line 154
    .line 155
    sget-object v6, Lgi/b;->e:Lgi/b;

    .line 156
    .line 157
    sget-object v7, Lgi/a;->e:Lgi/a;

    .line 158
    .line 159
    const-string v8, "Kt"

    .line 160
    .line 161
    const/16 v9, 0x2e

    .line 162
    .line 163
    const/16 v10, 0x24

    .line 164
    .line 165
    const-class v11, Lic/q;

    .line 166
    .line 167
    invoke-virtual {v11}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v12

    .line 171
    invoke-static {v12, v10}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v13

    .line 175
    invoke-static {v9, v13, v13}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v13

    .line 179
    invoke-virtual {v13}, Ljava/lang/String;->length()I

    .line 180
    .line 181
    .line 182
    move-result v14

    .line 183
    if-nez v14, :cond_5

    .line 184
    .line 185
    goto :goto_2

    .line 186
    :cond_5
    invoke-static {v13, v8}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v12

    .line 190
    :goto_2
    const/4 v13, 0x0

    .line 191
    invoke-static {v12, v7, v6, v13, v5}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 192
    .line 193
    .line 194
    instance-of v5, v1, Lic/a;

    .line 195
    .line 196
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 197
    .line 198
    if-eqz v5, :cond_8

    .line 199
    .line 200
    check-cast v1, Lic/a;

    .line 201
    .line 202
    iget v1, v1, Lic/a;->a:I

    .line 203
    .line 204
    invoke-virtual {v4}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v2

    .line 208
    check-cast v2, Ldc/t;

    .line 209
    .line 210
    iget-object v2, v2, Ldc/t;->b:Ljava/util/List;

    .line 211
    .line 212
    invoke-static {v1, v2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    check-cast v2, Lac/a0;

    .line 217
    .line 218
    if-nez v2, :cond_7

    .line 219
    .line 220
    sget-object v0, Lgi/b;->h:Lgi/b;

    .line 221
    .line 222
    new-instance v2, Lac/g;

    .line 223
    .line 224
    const/4 v3, 0x4

    .line 225
    invoke-direct {v2, v1, v3}, Lac/g;-><init>(II)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v11}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v1

    .line 232
    invoke-static {v1, v10}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object v3

    .line 236
    invoke-static {v9, v3, v3}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v3

    .line 240
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 241
    .line 242
    .line 243
    move-result v4

    .line 244
    if-nez v4, :cond_6

    .line 245
    .line 246
    goto :goto_3

    .line 247
    :cond_6
    invoke-static {v3, v8}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    :goto_3
    invoke-static {v1, v7, v0, v13, v2}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 252
    .line 253
    .line 254
    goto/16 :goto_4

    .line 255
    .line 256
    :cond_7
    iget-object v0, v0, Lic/q;->m:Lyy0/c2;

    .line 257
    .line 258
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 259
    .line 260
    .line 261
    invoke-virtual {v0, v13, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    goto/16 :goto_4

    .line 265
    .line 266
    :cond_8
    sget-object v5, Lic/b;->a:Lic/b;

    .line 267
    .line 268
    invoke-virtual {v1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 269
    .line 270
    .line 271
    move-result v5

    .line 272
    if-eqz v5, :cond_9

    .line 273
    .line 274
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 275
    .line 276
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 277
    .line 278
    .line 279
    invoke-virtual {v3, v13, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 280
    .line 281
    .line 282
    goto/16 :goto_4

    .line 283
    .line 284
    :cond_9
    sget-object v5, Lic/c;->a:Lic/c;

    .line 285
    .line 286
    invoke-virtual {v1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v5

    .line 290
    const/4 v7, 0x3

    .line 291
    if-eqz v5, :cond_a

    .line 292
    .line 293
    new-instance v1, Llc/q;

    .line 294
    .line 295
    sget-object v3, Llc/a;->c:Llc/c;

    .line 296
    .line 297
    invoke-direct {v1, v3}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 301
    .line 302
    .line 303
    invoke-virtual {v2, v13, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 304
    .line 305
    .line 306
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 307
    .line 308
    .line 309
    move-result-object v1

    .line 310
    new-instance v2, Lic/o;

    .line 311
    .line 312
    const/4 v3, 0x1

    .line 313
    invoke-direct {v2, v0, v13, v3}, Lic/o;-><init>(Lic/q;Lkotlin/coroutines/Continuation;I)V

    .line 314
    .line 315
    .line 316
    invoke-static {v1, v13, v13, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 317
    .line 318
    .line 319
    goto/16 :goto_4

    .line 320
    .line 321
    :cond_a
    sget-object v5, Lic/d;->a:Lic/d;

    .line 322
    .line 323
    invoke-virtual {v1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 324
    .line 325
    .line 326
    move-result v5

    .line 327
    if-eqz v5, :cond_b

    .line 328
    .line 329
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 330
    .line 331
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 332
    .line 333
    .line 334
    invoke-virtual {v3, v13, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 335
    .line 336
    .line 337
    goto :goto_4

    .line 338
    :cond_b
    sget-object v3, Lic/f;->a:Lic/f;

    .line 339
    .line 340
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v3

    .line 344
    if-eqz v3, :cond_c

    .line 345
    .line 346
    sget-object v1, Ldc/e;->e:Ldc/e;

    .line 347
    .line 348
    invoke-virtual {v0, v1}, Lic/q;->d(Ldc/e;)V

    .line 349
    .line 350
    .line 351
    goto :goto_4

    .line 352
    :cond_c
    instance-of v3, v1, Lic/g;

    .line 353
    .line 354
    if-eqz v3, :cond_d

    .line 355
    .line 356
    check-cast v1, Lic/g;

    .line 357
    .line 358
    iget-object v1, v1, Lic/g;->a:Lic/l;

    .line 359
    .line 360
    iget-object v1, v1, Lic/l;->d:Ldc/e;

    .line 361
    .line 362
    invoke-virtual {v0, v1}, Lic/q;->d(Ldc/e;)V

    .line 363
    .line 364
    .line 365
    goto :goto_4

    .line 366
    :cond_d
    sget-object v3, Lic/h;->a:Lic/h;

    .line 367
    .line 368
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 369
    .line 370
    .line 371
    move-result v3

    .line 372
    if-eqz v3, :cond_e

    .line 373
    .line 374
    iget-object v1, v0, Lic/q;->f:Lxh/e;

    .line 375
    .line 376
    iget-object v0, v0, Lic/q;->j:Lic/s;

    .line 377
    .line 378
    invoke-virtual {v4}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v2

    .line 382
    check-cast v2, Ldc/t;

    .line 383
    .line 384
    iget-object v2, v2, Ldc/t;->a:Ljava/util/List;

    .line 385
    .line 386
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v2

    .line 390
    check-cast v2, Ldc/n;

    .line 391
    .line 392
    iget-object v2, v2, Ldc/n;->h:Ljava/util/List;

    .line 393
    .line 394
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 395
    .line 396
    .line 397
    invoke-static {v2}, Lic/s;->a(Ljava/util/List;)Lhc/a;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    invoke-virtual {v1, v0}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    goto :goto_4

    .line 405
    :cond_e
    sget-object v3, Lic/i;->a:Lic/i;

    .line 406
    .line 407
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    move-result v1

    .line 411
    if-eqz v1, :cond_10

    .line 412
    .line 413
    invoke-virtual {v4}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v1

    .line 417
    sget-object v3, Lic/r;->a:Ldc/t;

    .line 418
    .line 419
    if-ne v1, v3, :cond_f

    .line 420
    .line 421
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 422
    .line 423
    .line 424
    move-result-object v1

    .line 425
    new-instance v2, Lic/o;

    .line 426
    .line 427
    const/4 v3, 0x0

    .line 428
    invoke-direct {v2, v0, v13, v3}, Lic/o;-><init>(Lic/q;Lkotlin/coroutines/Continuation;I)V

    .line 429
    .line 430
    .line 431
    invoke-static {v1, v13, v13, v2, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 432
    .line 433
    .line 434
    goto :goto_4

    .line 435
    :cond_f
    new-instance v0, Llc/q;

    .line 436
    .line 437
    invoke-direct {v0, v6}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 438
    .line 439
    .line 440
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 441
    .line 442
    .line 443
    invoke-virtual {v2, v13, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 444
    .line 445
    .line 446
    :goto_4
    return-object v6

    .line 447
    :cond_10
    new-instance v0, La8/r0;

    .line 448
    .line 449
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 450
    .line 451
    .line 452
    throw v0

    .line 453
    :pswitch_3
    move-object/from16 v1, p1

    .line 454
    .line 455
    check-cast v1, Ljava/lang/String;

    .line 456
    .line 457
    const-string v2, "p0"

    .line 458
    .line 459
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast v0, Lh80/j;

    .line 465
    .line 466
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 467
    .line 468
    .line 469
    iget-object v2, v0, Lh80/j;->k:Ljava/util/ArrayList;

    .line 470
    .line 471
    const/4 v3, 0x0

    .line 472
    if-eqz v2, :cond_14

    .line 473
    .line 474
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 475
    .line 476
    .line 477
    move-result-object v2

    .line 478
    :cond_11
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 479
    .line 480
    .line 481
    move-result v4

    .line 482
    if-eqz v4, :cond_12

    .line 483
    .line 484
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object v4

    .line 488
    move-object v5, v4

    .line 489
    check-cast v5, Lg80/a;

    .line 490
    .line 491
    iget-object v5, v5, Lg80/a;->a:Ljava/lang/String;

    .line 492
    .line 493
    invoke-static {v5, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 494
    .line 495
    .line 496
    move-result v5

    .line 497
    if-eqz v5, :cond_11

    .line 498
    .line 499
    move-object v3, v4

    .line 500
    :cond_12
    check-cast v3, Lg80/a;

    .line 501
    .line 502
    if-eqz v3, :cond_13

    .line 503
    .line 504
    new-instance v1, Lh50/q0;

    .line 505
    .line 506
    const/4 v2, 0x1

    .line 507
    invoke-direct {v1, v3, v2}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 508
    .line 509
    .line 510
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 511
    .line 512
    .line 513
    iget-object v1, v0, Lh80/j;->j:Lf80/h;

    .line 514
    .line 515
    iget-object v1, v1, Lf80/h;->a:Lf80/f;

    .line 516
    .line 517
    check-cast v1, Le80/a;

    .line 518
    .line 519
    iput-object v3, v1, Le80/a;->c:Lg80/a;

    .line 520
    .line 521
    iget-object v0, v0, Lh80/j;->h:Lq80/h;

    .line 522
    .line 523
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 524
    .line 525
    .line 526
    :cond_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 527
    .line 528
    return-object v0

    .line 529
    :cond_14
    const-string v0, "loyaltyProducts"

    .line 530
    .line 531
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 532
    .line 533
    .line 534
    throw v3

    .line 535
    :pswitch_4
    move-object/from16 v1, p1

    .line 536
    .line 537
    check-cast v1, Ljava/lang/Boolean;

    .line 538
    .line 539
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 540
    .line 541
    .line 542
    move-result v7

    .line 543
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 544
    .line 545
    check-cast v0, Lh80/b;

    .line 546
    .line 547
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 548
    .line 549
    .line 550
    move-result-object v1

    .line 551
    move-object v2, v1

    .line 552
    check-cast v2, Lh80/a;

    .line 553
    .line 554
    const/4 v8, 0x0

    .line 555
    const/16 v9, 0x2f

    .line 556
    .line 557
    const/4 v3, 0x0

    .line 558
    const/4 v4, 0x0

    .line 559
    const/4 v5, 0x0

    .line 560
    const/4 v6, 0x0

    .line 561
    invoke-static/range {v2 .. v9}, Lh80/a;->a(Lh80/a;Lql0/g;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZI)Lh80/a;

    .line 562
    .line 563
    .line 564
    move-result-object v1

    .line 565
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 566
    .line 567
    .line 568
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 569
    .line 570
    return-object v0

    .line 571
    :pswitch_5
    move-object/from16 v1, p1

    .line 572
    .line 573
    check-cast v1, Ljava/lang/Number;

    .line 574
    .line 575
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 576
    .line 577
    .line 578
    move-result v1

    .line 579
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 580
    .line 581
    check-cast v0, Lh50/s0;

    .line 582
    .line 583
    iget-object v0, v0, Lh50/s0;->k:Lpp0/o0;

    .line 584
    .line 585
    invoke-virtual {v0, v1}, Lpp0/o0;->a(I)V

    .line 586
    .line 587
    .line 588
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 589
    .line 590
    return-object v0

    .line 591
    :pswitch_6
    move-object/from16 v1, p1

    .line 592
    .line 593
    check-cast v1, Lt4/f;

    .line 594
    .line 595
    iget v1, v1, Lt4/f;->d:F

    .line 596
    .line 597
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast v0, Li91/r2;

    .line 600
    .line 601
    invoke-virtual {v0, v1}, Li91/r2;->e(F)V

    .line 602
    .line 603
    .line 604
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 605
    .line 606
    return-object v0

    .line 607
    :pswitch_7
    move-object/from16 v1, p1

    .line 608
    .line 609
    check-cast v1, Lt4/f;

    .line 610
    .line 611
    iget v1, v1, Lt4/f;->d:F

    .line 612
    .line 613
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 614
    .line 615
    check-cast v0, Li91/r2;

    .line 616
    .line 617
    invoke-virtual {v0, v1}, Li91/r2;->d(F)V

    .line 618
    .line 619
    .line 620
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 621
    .line 622
    return-object v0

    .line 623
    :pswitch_8
    move-object/from16 v1, p1

    .line 624
    .line 625
    check-cast v1, Ljava/lang/Number;

    .line 626
    .line 627
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 628
    .line 629
    .line 630
    move-result v1

    .line 631
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 632
    .line 633
    check-cast v0, Lh50/d0;

    .line 634
    .line 635
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 636
    .line 637
    .line 638
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 639
    .line 640
    .line 641
    move-result-object v2

    .line 642
    new-instance v3, Lci0/a;

    .line 643
    .line 644
    const/4 v4, 0x0

    .line 645
    invoke-direct {v3, v1, v0, v4}, Lci0/a;-><init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V

    .line 646
    .line 647
    .line 648
    const/4 v0, 0x3

    .line 649
    invoke-static {v2, v4, v4, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 650
    .line 651
    .line 652
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 653
    .line 654
    return-object v0

    .line 655
    :pswitch_9
    move-object/from16 v1, p1

    .line 656
    .line 657
    check-cast v1, Ljava/lang/Number;

    .line 658
    .line 659
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 660
    .line 661
    .line 662
    move-result v1

    .line 663
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 664
    .line 665
    check-cast v0, Lh50/d0;

    .line 666
    .line 667
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 668
    .line 669
    .line 670
    move-result-object v2

    .line 671
    move-object v3, v2

    .line 672
    check-cast v3, Lh50/v;

    .line 673
    .line 674
    const/16 v33, 0x0

    .line 675
    .line 676
    const/16 v34, -0x3

    .line 677
    .line 678
    const/4 v4, 0x0

    .line 679
    const/4 v5, 0x1

    .line 680
    const/4 v6, 0x0

    .line 681
    const/4 v7, 0x0

    .line 682
    const/4 v8, 0x0

    .line 683
    const/4 v9, 0x0

    .line 684
    const/4 v10, 0x0

    .line 685
    const/4 v11, 0x0

    .line 686
    const/4 v12, 0x0

    .line 687
    const/4 v13, 0x0

    .line 688
    const/4 v14, 0x0

    .line 689
    const/4 v15, 0x0

    .line 690
    const/16 v16, 0x0

    .line 691
    .line 692
    const/16 v17, 0x0

    .line 693
    .line 694
    const/16 v18, 0x0

    .line 695
    .line 696
    const/16 v19, 0x0

    .line 697
    .line 698
    const/16 v20, 0x0

    .line 699
    .line 700
    const/16 v21, 0x0

    .line 701
    .line 702
    const/16 v22, 0x0

    .line 703
    .line 704
    const/16 v23, 0x0

    .line 705
    .line 706
    const/16 v24, 0x0

    .line 707
    .line 708
    const/16 v25, 0x0

    .line 709
    .line 710
    const/16 v26, 0x0

    .line 711
    .line 712
    const/16 v27, 0x0

    .line 713
    .line 714
    const/16 v28, 0x0

    .line 715
    .line 716
    const/16 v29, 0x0

    .line 717
    .line 718
    const/16 v30, 0x0

    .line 719
    .line 720
    const/16 v31, 0x0

    .line 721
    .line 722
    const/16 v32, 0x0

    .line 723
    .line 724
    invoke-static/range {v3 .. v34}, Lh50/v;->a(Lh50/v;ZZZZZZIZZLjava/lang/String;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ler0/g;Ljava/lang/String;Lql0/g;Lqp0/b0;ZZLjava/lang/String;ZZZI)Lh50/v;

    .line 725
    .line 726
    .line 727
    move-result-object v2

    .line 728
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 729
    .line 730
    .line 731
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 732
    .line 733
    .line 734
    move-result-object v1

    .line 735
    iput-object v1, v0, Lh50/d0;->N:Ljava/lang/Integer;

    .line 736
    .line 737
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 738
    .line 739
    return-object v0

    .line 740
    :pswitch_a
    move-object/from16 v1, p1

    .line 741
    .line 742
    check-cast v1, Ljava/lang/Number;

    .line 743
    .line 744
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 745
    .line 746
    .line 747
    move-result v1

    .line 748
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 749
    .line 750
    check-cast v0, Lh50/d0;

    .line 751
    .line 752
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 753
    .line 754
    .line 755
    new-instance v2, Lh50/p;

    .line 756
    .line 757
    const/4 v3, 0x1

    .line 758
    invoke-direct {v2, v3}, Lh50/p;-><init>(I)V

    .line 759
    .line 760
    .line 761
    invoke-static {v0, v2}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 762
    .line 763
    .line 764
    iget-object v2, v0, Lh50/d0;->M:Ljava/util/List;

    .line 765
    .line 766
    invoke-static {v1, v2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 767
    .line 768
    .line 769
    move-result-object v1

    .line 770
    check-cast v1, Lqp0/b0;

    .line 771
    .line 772
    if-eqz v1, :cond_15

    .line 773
    .line 774
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 775
    .line 776
    .line 777
    move-result-object v2

    .line 778
    new-instance v3, Lh50/w;

    .line 779
    .line 780
    const/4 v4, 0x1

    .line 781
    const/4 v5, 0x0

    .line 782
    invoke-direct {v3, v0, v1, v5, v4}, Lh50/w;-><init>(Lh50/d0;Lqp0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 783
    .line 784
    .line 785
    const/4 v0, 0x3

    .line 786
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 787
    .line 788
    .line 789
    :cond_15
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 790
    .line 791
    return-object v0

    .line 792
    :pswitch_b
    move-object/from16 v1, p1

    .line 793
    .line 794
    check-cast v1, Lqp0/e;

    .line 795
    .line 796
    const-string v2, "p0"

    .line 797
    .line 798
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 799
    .line 800
    .line 801
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 802
    .line 803
    check-cast v0, Lh50/d0;

    .line 804
    .line 805
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 806
    .line 807
    .line 808
    new-instance v2, Lgz0/e0;

    .line 809
    .line 810
    const/16 v3, 0x1b

    .line 811
    .line 812
    invoke-direct {v2, v3}, Lgz0/e0;-><init>(I)V

    .line 813
    .line 814
    .line 815
    invoke-static {v0, v2}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 816
    .line 817
    .line 818
    iget-object v0, v0, Lh50/d0;->t:Lf50/i;

    .line 819
    .line 820
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 821
    .line 822
    .line 823
    iget-object v2, v0, Lf50/i;->b:Lf50/p;

    .line 824
    .line 825
    iget-object v2, v2, Lf50/p;->a:Lf50/d;

    .line 826
    .line 827
    check-cast v2, Lc50/a;

    .line 828
    .line 829
    iput-object v1, v2, Lc50/a;->a:Lqp0/e;

    .line 830
    .line 831
    iget-object v0, v0, Lf50/i;->a:Lf50/n;

    .line 832
    .line 833
    check-cast v0, Liy/b;

    .line 834
    .line 835
    sget-object v1, Lly/b;->X1:Lly/b;

    .line 836
    .line 837
    invoke-interface {v0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 838
    .line 839
    .line 840
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 841
    .line 842
    return-object v0

    .line 843
    :pswitch_c
    move-object/from16 v1, p1

    .line 844
    .line 845
    check-cast v1, Ljava/lang/Number;

    .line 846
    .line 847
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 848
    .line 849
    .line 850
    move-result v1

    .line 851
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 852
    .line 853
    check-cast v0, Lh50/o;

    .line 854
    .line 855
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 856
    .line 857
    .line 858
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 859
    .line 860
    .line 861
    move-result-object v2

    .line 862
    new-instance v3, Lh50/m;

    .line 863
    .line 864
    const/4 v4, 0x0

    .line 865
    invoke-direct {v3, v0, v1, v4}, Lh50/m;-><init>(Lh50/o;ILkotlin/coroutines/Continuation;)V

    .line 866
    .line 867
    .line 868
    const/4 v0, 0x3

    .line 869
    invoke-static {v2, v4, v4, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 870
    .line 871
    .line 872
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 873
    .line 874
    return-object v0

    .line 875
    :pswitch_d
    move-object/from16 v4, p1

    .line 876
    .line 877
    check-cast v4, Ljava/lang/String;

    .line 878
    .line 879
    const-string v1, "p0"

    .line 880
    .line 881
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 882
    .line 883
    .line 884
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 885
    .line 886
    check-cast v0, Lh50/h;

    .line 887
    .line 888
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 889
    .line 890
    .line 891
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 892
    .line 893
    .line 894
    move-result-object v1

    .line 895
    check-cast v1, Lh50/e;

    .line 896
    .line 897
    iget-object v2, v0, Lh50/h;->h:Lij0/a;

    .line 898
    .line 899
    invoke-static {v2}, Lh50/h;->h(Lij0/a;)Lyj0/a;

    .line 900
    .line 901
    .line 902
    move-result-object v5

    .line 903
    const/4 v6, 0x3

    .line 904
    const/4 v2, 0x0

    .line 905
    const/4 v3, 0x0

    .line 906
    invoke-static/range {v1 .. v6}, Lh50/e;->a(Lh50/e;ZZLjava/lang/String;Lyj0/a;I)Lh50/e;

    .line 907
    .line 908
    .line 909
    move-result-object v1

    .line 910
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 911
    .line 912
    .line 913
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 914
    .line 915
    return-object v0

    .line 916
    :pswitch_e
    move-object/from16 v1, p1

    .line 917
    .line 918
    check-cast v1, Lh40/w;

    .line 919
    .line 920
    const-string v2, "p0"

    .line 921
    .line 922
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 923
    .line 924
    .line 925
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 926
    .line 927
    check-cast v0, Lh40/i4;

    .line 928
    .line 929
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 930
    .line 931
    .line 932
    iget-object v0, v0, Lh40/i4;->p:Lbd0/c;

    .line 933
    .line 934
    iget-object v1, v1, Lh40/w;->g:Ljava/lang/String;

    .line 935
    .line 936
    const/16 v2, 0x1e

    .line 937
    .line 938
    and-int/lit8 v3, v2, 0x2

    .line 939
    .line 940
    const/4 v4, 0x0

    .line 941
    const/4 v5, 0x1

    .line 942
    if-eqz v3, :cond_16

    .line 943
    .line 944
    move v8, v5

    .line 945
    goto :goto_5

    .line 946
    :cond_16
    move v8, v4

    .line 947
    :goto_5
    and-int/lit8 v3, v2, 0x4

    .line 948
    .line 949
    if-eqz v3, :cond_17

    .line 950
    .line 951
    move v9, v5

    .line 952
    goto :goto_6

    .line 953
    :cond_17
    move v9, v4

    .line 954
    :goto_6
    and-int/lit8 v3, v2, 0x8

    .line 955
    .line 956
    if-eqz v3, :cond_18

    .line 957
    .line 958
    move v10, v4

    .line 959
    goto :goto_7

    .line 960
    :cond_18
    move v10, v5

    .line 961
    :goto_7
    and-int/lit8 v2, v2, 0x10

    .line 962
    .line 963
    if-eqz v2, :cond_19

    .line 964
    .line 965
    move v11, v4

    .line 966
    goto :goto_8

    .line 967
    :cond_19
    move v11, v5

    .line 968
    :goto_8
    const-string v2, "url"

    .line 969
    .line 970
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 971
    .line 972
    .line 973
    iget-object v0, v0, Lbd0/c;->a:Lbd0/a;

    .line 974
    .line 975
    new-instance v7, Ljava/net/URL;

    .line 976
    .line 977
    invoke-direct {v7, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 978
    .line 979
    .line 980
    move-object v6, v0

    .line 981
    check-cast v6, Lzc0/b;

    .line 982
    .line 983
    invoke-virtual/range {v6 .. v11}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 984
    .line 985
    .line 986
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 987
    .line 988
    return-object v0

    .line 989
    :pswitch_f
    move-object/from16 v1, p1

    .line 990
    .line 991
    check-cast v1, Ljava/lang/String;

    .line 992
    .line 993
    const-string v2, "p0"

    .line 994
    .line 995
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 996
    .line 997
    .line 998
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 999
    .line 1000
    check-cast v0, Lh40/i4;

    .line 1001
    .line 1002
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1003
    .line 1004
    .line 1005
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v2

    .line 1009
    new-instance v3, Lh40/f4;

    .line 1010
    .line 1011
    const/4 v4, 0x6

    .line 1012
    const/4 v5, 0x0

    .line 1013
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/f4;-><init>(Lh40/i4;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1014
    .line 1015
    .line 1016
    const/4 v0, 0x3

    .line 1017
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1018
    .line 1019
    .line 1020
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1021
    .line 1022
    return-object v0

    .line 1023
    :pswitch_10
    move-object/from16 v1, p1

    .line 1024
    .line 1025
    check-cast v1, Ljava/lang/String;

    .line 1026
    .line 1027
    const-string v2, "p0"

    .line 1028
    .line 1029
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1030
    .line 1031
    .line 1032
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1033
    .line 1034
    check-cast v0, Lh40/i4;

    .line 1035
    .line 1036
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1037
    .line 1038
    .line 1039
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1040
    .line 1041
    .line 1042
    move-result-object v2

    .line 1043
    new-instance v3, Lh40/f4;

    .line 1044
    .line 1045
    const/4 v4, 0x5

    .line 1046
    const/4 v5, 0x0

    .line 1047
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/f4;-><init>(Lh40/i4;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1048
    .line 1049
    .line 1050
    const/4 v0, 0x3

    .line 1051
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1052
    .line 1053
    .line 1054
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1055
    .line 1056
    return-object v0

    .line 1057
    :pswitch_11
    move-object/from16 v1, p1

    .line 1058
    .line 1059
    check-cast v1, Ljava/lang/String;

    .line 1060
    .line 1061
    const-string v2, "p0"

    .line 1062
    .line 1063
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1064
    .line 1065
    .line 1066
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1067
    .line 1068
    check-cast v0, Lh40/i4;

    .line 1069
    .line 1070
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1071
    .line 1072
    .line 1073
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1074
    .line 1075
    .line 1076
    move-result-object v2

    .line 1077
    new-instance v3, Lh40/f4;

    .line 1078
    .line 1079
    const/4 v4, 0x3

    .line 1080
    const/4 v5, 0x0

    .line 1081
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/f4;-><init>(Lh40/i4;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1082
    .line 1083
    .line 1084
    const/4 v0, 0x3

    .line 1085
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1086
    .line 1087
    .line 1088
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1089
    .line 1090
    return-object v0

    .line 1091
    :pswitch_12
    move-object/from16 v1, p1

    .line 1092
    .line 1093
    check-cast v1, Ljava/lang/String;

    .line 1094
    .line 1095
    const-string v2, "p0"

    .line 1096
    .line 1097
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1098
    .line 1099
    .line 1100
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1101
    .line 1102
    check-cast v0, Lh40/i4;

    .line 1103
    .line 1104
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1105
    .line 1106
    .line 1107
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1108
    .line 1109
    .line 1110
    move-result-object v2

    .line 1111
    new-instance v3, Lh40/f4;

    .line 1112
    .line 1113
    const/4 v4, 0x4

    .line 1114
    const/4 v5, 0x0

    .line 1115
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/f4;-><init>(Lh40/i4;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1116
    .line 1117
    .line 1118
    const/4 v0, 0x3

    .line 1119
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1120
    .line 1121
    .line 1122
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1123
    .line 1124
    return-object v0

    .line 1125
    :pswitch_13
    move-object/from16 v10, p1

    .line 1126
    .line 1127
    check-cast v10, Lh40/b4;

    .line 1128
    .line 1129
    const-string v1, "p0"

    .line 1130
    .line 1131
    invoke-static {v10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1132
    .line 1133
    .line 1134
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1135
    .line 1136
    check-cast v0, Lh40/i4;

    .line 1137
    .line 1138
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1139
    .line 1140
    .line 1141
    sget-object v1, Lh40/b4;->f:Lh40/b4;

    .line 1142
    .line 1143
    if-ne v10, v1, :cond_1a

    .line 1144
    .line 1145
    sget-object v1, Lh40/a4;->e:Lh40/a4;

    .line 1146
    .line 1147
    :goto_9
    move-object v11, v1

    .line 1148
    goto :goto_a

    .line 1149
    :cond_1a
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1150
    .line 1151
    .line 1152
    move-result-object v1

    .line 1153
    check-cast v1, Lh40/d4;

    .line 1154
    .line 1155
    iget-object v1, v1, Lh40/d4;->j:Lh40/a4;

    .line 1156
    .line 1157
    goto :goto_9

    .line 1158
    :goto_a
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v1

    .line 1162
    check-cast v1, Lh40/d4;

    .line 1163
    .line 1164
    const/16 v20, 0x0

    .line 1165
    .line 1166
    const v21, 0xffcff

    .line 1167
    .line 1168
    .line 1169
    const/4 v2, 0x0

    .line 1170
    const/4 v3, 0x0

    .line 1171
    const/4 v4, 0x0

    .line 1172
    const/4 v5, 0x0

    .line 1173
    const/4 v6, 0x0

    .line 1174
    const/4 v7, 0x0

    .line 1175
    const/4 v8, 0x0

    .line 1176
    const/4 v9, 0x0

    .line 1177
    const/4 v12, 0x0

    .line 1178
    const/4 v13, 0x0

    .line 1179
    const/4 v14, 0x0

    .line 1180
    const/4 v15, 0x0

    .line 1181
    const/16 v16, 0x0

    .line 1182
    .line 1183
    const/16 v17, 0x0

    .line 1184
    .line 1185
    const/16 v18, 0x0

    .line 1186
    .line 1187
    const/16 v19, 0x0

    .line 1188
    .line 1189
    invoke-static/range {v1 .. v21}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v1

    .line 1193
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1194
    .line 1195
    .line 1196
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1197
    .line 1198
    return-object v0

    .line 1199
    :pswitch_14
    move-object/from16 v11, p1

    .line 1200
    .line 1201
    check-cast v11, Lh40/a4;

    .line 1202
    .line 1203
    const-string v1, "p0"

    .line 1204
    .line 1205
    invoke-static {v11, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1206
    .line 1207
    .line 1208
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1209
    .line 1210
    check-cast v0, Lh40/i4;

    .line 1211
    .line 1212
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1213
    .line 1214
    .line 1215
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1216
    .line 1217
    .line 1218
    move-result-object v1

    .line 1219
    check-cast v1, Lh40/d4;

    .line 1220
    .line 1221
    const/16 v20, 0x0

    .line 1222
    .line 1223
    const v21, 0xffdff

    .line 1224
    .line 1225
    .line 1226
    const/4 v2, 0x0

    .line 1227
    const/4 v3, 0x0

    .line 1228
    const/4 v4, 0x0

    .line 1229
    const/4 v5, 0x0

    .line 1230
    const/4 v6, 0x0

    .line 1231
    const/4 v7, 0x0

    .line 1232
    const/4 v8, 0x0

    .line 1233
    const/4 v9, 0x0

    .line 1234
    const/4 v10, 0x0

    .line 1235
    const/4 v12, 0x0

    .line 1236
    const/4 v13, 0x0

    .line 1237
    const/4 v14, 0x0

    .line 1238
    const/4 v15, 0x0

    .line 1239
    const/16 v16, 0x0

    .line 1240
    .line 1241
    const/16 v17, 0x0

    .line 1242
    .line 1243
    const/16 v18, 0x0

    .line 1244
    .line 1245
    const/16 v19, 0x0

    .line 1246
    .line 1247
    invoke-static/range {v1 .. v21}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v1

    .line 1251
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1252
    .line 1253
    .line 1254
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1255
    .line 1256
    return-object v0

    .line 1257
    :pswitch_15
    move-object/from16 v1, p1

    .line 1258
    .line 1259
    check-cast v1, Lh40/z;

    .line 1260
    .line 1261
    const-string v2, "p0"

    .line 1262
    .line 1263
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1264
    .line 1265
    .line 1266
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1267
    .line 1268
    check-cast v0, Lh40/i4;

    .line 1269
    .line 1270
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1271
    .line 1272
    .line 1273
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1274
    .line 1275
    .line 1276
    move-result-object v2

    .line 1277
    new-instance v3, Lh40/w3;

    .line 1278
    .line 1279
    const/4 v4, 0x2

    .line 1280
    const/4 v5, 0x0

    .line 1281
    invoke-direct {v3, v4, v1, v0, v5}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1282
    .line 1283
    .line 1284
    const/4 v0, 0x3

    .line 1285
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1286
    .line 1287
    .line 1288
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1289
    .line 1290
    return-object v0

    .line 1291
    :pswitch_16
    move-object/from16 v1, p1

    .line 1292
    .line 1293
    check-cast v1, Ljava/lang/String;

    .line 1294
    .line 1295
    const-string v2, "p0"

    .line 1296
    .line 1297
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1298
    .line 1299
    .line 1300
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1301
    .line 1302
    check-cast v0, Lh40/i4;

    .line 1303
    .line 1304
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1305
    .line 1306
    .line 1307
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1308
    .line 1309
    .line 1310
    move-result-object v2

    .line 1311
    new-instance v3, Lh40/f4;

    .line 1312
    .line 1313
    const/4 v4, 0x1

    .line 1314
    const/4 v5, 0x0

    .line 1315
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/f4;-><init>(Lh40/i4;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1316
    .line 1317
    .line 1318
    const/4 v0, 0x3

    .line 1319
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1320
    .line 1321
    .line 1322
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1323
    .line 1324
    return-object v0

    .line 1325
    :pswitch_17
    move-object/from16 v1, p1

    .line 1326
    .line 1327
    check-cast v1, Ljava/lang/String;

    .line 1328
    .line 1329
    const-string v2, "p0"

    .line 1330
    .line 1331
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1332
    .line 1333
    .line 1334
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1335
    .line 1336
    check-cast v0, Lh40/i4;

    .line 1337
    .line 1338
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1339
    .line 1340
    .line 1341
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1342
    .line 1343
    .line 1344
    move-result-object v2

    .line 1345
    new-instance v3, Lh40/f4;

    .line 1346
    .line 1347
    const/4 v4, 0x0

    .line 1348
    const/4 v5, 0x0

    .line 1349
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/f4;-><init>(Lh40/i4;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1350
    .line 1351
    .line 1352
    const/4 v0, 0x3

    .line 1353
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1354
    .line 1355
    .line 1356
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1357
    .line 1358
    return-object v0

    .line 1359
    :pswitch_18
    move-object/from16 v13, p1

    .line 1360
    .line 1361
    check-cast v13, Ljava/lang/String;

    .line 1362
    .line 1363
    const-string v1, "p0"

    .line 1364
    .line 1365
    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1366
    .line 1367
    .line 1368
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1369
    .line 1370
    check-cast v0, Lh40/i4;

    .line 1371
    .line 1372
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1373
    .line 1374
    .line 1375
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v1

    .line 1379
    check-cast v1, Lh40/d4;

    .line 1380
    .line 1381
    const/16 v20, 0x0

    .line 1382
    .line 1383
    const v21, 0xfe7ff

    .line 1384
    .line 1385
    .line 1386
    const/4 v2, 0x0

    .line 1387
    const/4 v3, 0x0

    .line 1388
    const/4 v4, 0x0

    .line 1389
    const/4 v5, 0x0

    .line 1390
    const/4 v6, 0x0

    .line 1391
    const/4 v7, 0x0

    .line 1392
    const/4 v8, 0x0

    .line 1393
    const/4 v9, 0x0

    .line 1394
    const/4 v10, 0x0

    .line 1395
    const/4 v11, 0x0

    .line 1396
    const/4 v12, 0x1

    .line 1397
    const/4 v14, 0x0

    .line 1398
    const/4 v15, 0x0

    .line 1399
    const/16 v16, 0x0

    .line 1400
    .line 1401
    const/16 v17, 0x0

    .line 1402
    .line 1403
    const/16 v18, 0x0

    .line 1404
    .line 1405
    const/16 v19, 0x0

    .line 1406
    .line 1407
    invoke-static/range {v1 .. v21}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v1

    .line 1411
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1412
    .line 1413
    .line 1414
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1415
    .line 1416
    return-object v0

    .line 1417
    :pswitch_19
    move-object/from16 v1, p1

    .line 1418
    .line 1419
    check-cast v1, Ljava/lang/String;

    .line 1420
    .line 1421
    const-string v2, "p0"

    .line 1422
    .line 1423
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1424
    .line 1425
    .line 1426
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1427
    .line 1428
    check-cast v0, Lh40/x3;

    .line 1429
    .line 1430
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1431
    .line 1432
    .line 1433
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1434
    .line 1435
    .line 1436
    move-result-object v2

    .line 1437
    new-instance v3, Lh40/v3;

    .line 1438
    .line 1439
    const/4 v4, 0x0

    .line 1440
    const/4 v5, 0x0

    .line 1441
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/v3;-><init>(Lh40/x3;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1442
    .line 1443
    .line 1444
    const/4 v0, 0x3

    .line 1445
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1446
    .line 1447
    .line 1448
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1449
    .line 1450
    return-object v0

    .line 1451
    :pswitch_1a
    move-object/from16 v1, p1

    .line 1452
    .line 1453
    check-cast v1, Ljava/lang/Boolean;

    .line 1454
    .line 1455
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1456
    .line 1457
    .line 1458
    move-result v23

    .line 1459
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1460
    .line 1461
    check-cast v0, Lh40/x3;

    .line 1462
    .line 1463
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1464
    .line 1465
    .line 1466
    move-result-object v1

    .line 1467
    move-object v2, v1

    .line 1468
    check-cast v2, Lh40/s3;

    .line 1469
    .line 1470
    const/16 v26, 0x0

    .line 1471
    .line 1472
    const v27, 0x1dfffff

    .line 1473
    .line 1474
    .line 1475
    const/4 v3, 0x0

    .line 1476
    const/4 v4, 0x0

    .line 1477
    const/4 v5, 0x0

    .line 1478
    const/4 v6, 0x0

    .line 1479
    const/4 v7, 0x0

    .line 1480
    const/4 v8, 0x0

    .line 1481
    const/4 v9, 0x0

    .line 1482
    const/4 v10, 0x0

    .line 1483
    const/4 v11, 0x0

    .line 1484
    const/4 v12, 0x0

    .line 1485
    const/4 v13, 0x0

    .line 1486
    const/4 v14, 0x0

    .line 1487
    const/4 v15, 0x0

    .line 1488
    const/16 v16, 0x0

    .line 1489
    .line 1490
    const/16 v17, 0x0

    .line 1491
    .line 1492
    const/16 v18, 0x0

    .line 1493
    .line 1494
    const/16 v19, 0x0

    .line 1495
    .line 1496
    const/16 v20, 0x0

    .line 1497
    .line 1498
    const/16 v21, 0x0

    .line 1499
    .line 1500
    const/16 v22, 0x0

    .line 1501
    .line 1502
    const/16 v24, 0x0

    .line 1503
    .line 1504
    const/16 v25, 0x0

    .line 1505
    .line 1506
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 1507
    .line 1508
    .line 1509
    move-result-object v1

    .line 1510
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1511
    .line 1512
    .line 1513
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1514
    .line 1515
    return-object v0

    .line 1516
    :pswitch_1b
    move-object/from16 v1, p1

    .line 1517
    .line 1518
    check-cast v1, Lh40/m3;

    .line 1519
    .line 1520
    const-string v2, "p0"

    .line 1521
    .line 1522
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1523
    .line 1524
    .line 1525
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1526
    .line 1527
    check-cast v0, Lh40/x3;

    .line 1528
    .line 1529
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1530
    .line 1531
    .line 1532
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1533
    .line 1534
    .line 1535
    move-result-object v2

    .line 1536
    new-instance v3, Lg60/w;

    .line 1537
    .line 1538
    const/16 v4, 0x1d

    .line 1539
    .line 1540
    const/4 v5, 0x0

    .line 1541
    invoke-direct {v3, v4, v0, v1, v5}, Lg60/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1542
    .line 1543
    .line 1544
    const/4 v0, 0x3

    .line 1545
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1546
    .line 1547
    .line 1548
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1549
    .line 1550
    return-object v0

    .line 1551
    :pswitch_1c
    move-object/from16 v1, p1

    .line 1552
    .line 1553
    check-cast v1, Ljava/lang/Boolean;

    .line 1554
    .line 1555
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1556
    .line 1557
    .line 1558
    move-result v21

    .line 1559
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1560
    .line 1561
    check-cast v0, Lh40/x3;

    .line 1562
    .line 1563
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1564
    .line 1565
    .line 1566
    new-instance v1, Lh40/p3;

    .line 1567
    .line 1568
    const/4 v2, 0x0

    .line 1569
    invoke-direct {v1, v0, v2}, Lh40/p3;-><init>(Lh40/x3;I)V

    .line 1570
    .line 1571
    .line 1572
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 1573
    .line 1574
    .line 1575
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1576
    .line 1577
    .line 1578
    move-result-object v1

    .line 1579
    move-object v2, v1

    .line 1580
    check-cast v2, Lh40/s3;

    .line 1581
    .line 1582
    const/16 v26, 0x0

    .line 1583
    .line 1584
    const v27, 0x1f7ffff

    .line 1585
    .line 1586
    .line 1587
    const/4 v3, 0x0

    .line 1588
    const/4 v4, 0x0

    .line 1589
    const/4 v5, 0x0

    .line 1590
    const/4 v6, 0x0

    .line 1591
    const/4 v7, 0x0

    .line 1592
    const/4 v8, 0x0

    .line 1593
    const/4 v9, 0x0

    .line 1594
    const/4 v10, 0x0

    .line 1595
    const/4 v11, 0x0

    .line 1596
    const/4 v12, 0x0

    .line 1597
    const/4 v13, 0x0

    .line 1598
    const/4 v14, 0x0

    .line 1599
    const/4 v15, 0x0

    .line 1600
    const/16 v16, 0x0

    .line 1601
    .line 1602
    const/16 v17, 0x0

    .line 1603
    .line 1604
    const/16 v18, 0x0

    .line 1605
    .line 1606
    const/16 v19, 0x0

    .line 1607
    .line 1608
    const/16 v20, 0x0

    .line 1609
    .line 1610
    const/16 v22, 0x0

    .line 1611
    .line 1612
    const/16 v23, 0x0

    .line 1613
    .line 1614
    const/16 v24, 0x0

    .line 1615
    .line 1616
    const/16 v25, 0x0

    .line 1617
    .line 1618
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 1619
    .line 1620
    .line 1621
    move-result-object v1

    .line 1622
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1623
    .line 1624
    .line 1625
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1626
    .line 1627
    return-object v0

    .line 1628
    nop

    .line 1629
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
