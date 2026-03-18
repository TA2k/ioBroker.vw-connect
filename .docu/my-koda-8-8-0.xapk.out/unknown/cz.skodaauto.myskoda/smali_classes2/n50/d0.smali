.class public final Ln50/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ln50/k0;ZLvy0/b0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ln50/d0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln50/d0;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Ln50/d0;->e:Z

    iput-object p3, p0, Ln50/d0;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvy0/b0;Lwk0/s1;Z)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Ln50/d0;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln50/d0;->g:Ljava/lang/Object;

    iput-object p2, p0, Ln50/d0;->f:Ljava/lang/Object;

    iput-boolean p3, p0, Ln50/d0;->e:Z

    return-void
.end method

.method public constructor <init>(Lyy0/j;Ljava/lang/String;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ln50/d0;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln50/d0;->f:Ljava/lang/Object;

    iput-object p2, p0, Ln50/d0;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Ln50/d0;->e:Z

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Ln50/d0;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    check-cast v2, Lne0/t;

    .line 13
    .line 14
    iget-object v3, v0, Ln50/d0;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v3, Lvy0/b0;

    .line 17
    .line 18
    new-instance v4, Lwk0/j1;

    .line 19
    .line 20
    iget-object v5, v0, Ln50/d0;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v5, Lwk0/s1;

    .line 23
    .line 24
    const/4 v6, 0x3

    .line 25
    const/4 v7, 0x0

    .line 26
    invoke-direct {v4, v5, v7, v6}, Lwk0/j1;-><init>(Lwk0/s1;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {v3, v7, v7, v4, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    instance-of v3, v2, Lne0/c;

    .line 33
    .line 34
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    move-object v6, v0

    .line 43
    check-cast v6, Lwk0/n1;

    .line 44
    .line 45
    const/16 v21, 0x0

    .line 46
    .line 47
    const v22, 0xffef

    .line 48
    .line 49
    .line 50
    const/4 v7, 0x0

    .line 51
    const/4 v8, 0x0

    .line 52
    const/4 v9, 0x0

    .line 53
    const/4 v10, 0x0

    .line 54
    const/4 v11, 0x1

    .line 55
    const/4 v12, 0x0

    .line 56
    const/4 v13, 0x0

    .line 57
    const/4 v14, 0x0

    .line 58
    const/4 v15, 0x0

    .line 59
    const/16 v16, 0x0

    .line 60
    .line 61
    const/16 v17, 0x0

    .line 62
    .line 63
    const/16 v18, 0x0

    .line 64
    .line 65
    const/16 v19, 0x0

    .line 66
    .line 67
    const/16 v20, 0x0

    .line 68
    .line 69
    invoke-static/range {v6 .. v22}, Lwk0/n1;->a(Lwk0/n1;Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lb71/o;ZZZZLwk0/l1;ZI)Lwk0/n1;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 74
    .line 75
    .line 76
    move-object v11, v2

    .line 77
    check-cast v11, Lne0/c;

    .line 78
    .line 79
    iget-object v0, v5, Lwk0/s1;->u:Ljn0/c;

    .line 80
    .line 81
    new-instance v6, Lkn0/e;

    .line 82
    .line 83
    const v9, 0x7f12038c

    .line 84
    .line 85
    .line 86
    const/4 v10, 0x1

    .line 87
    const v7, 0x7f120647

    .line 88
    .line 89
    .line 90
    const v8, 0x7f120648

    .line 91
    .line 92
    .line 93
    invoke-direct/range {v6 .. v11}, Lkn0/e;-><init>(IIIZLne0/c;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0, v6, v1}, Ljn0/c;->b(Lkn0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 101
    .line 102
    if-ne v0, v1, :cond_0

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_0
    move-object v0, v4

    .line 106
    :goto_0
    if-ne v0, v1, :cond_3

    .line 107
    .line 108
    move-object v4, v0

    .line 109
    goto :goto_2

    .line 110
    :cond_1
    instance-of v1, v2, Lne0/e;

    .line 111
    .line 112
    if-eqz v1, :cond_4

    .line 113
    .line 114
    iget-boolean v0, v0, Ln50/d0;->e:Z

    .line 115
    .line 116
    if-nez v0, :cond_2

    .line 117
    .line 118
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    move-object v6, v0

    .line 123
    check-cast v6, Lwk0/n1;

    .line 124
    .line 125
    const/16 v21, 0x0

    .line 126
    .line 127
    const v22, 0xffd7

    .line 128
    .line 129
    .line 130
    const/4 v7, 0x0

    .line 131
    const/4 v8, 0x0

    .line 132
    const/4 v9, 0x0

    .line 133
    const/4 v10, 0x1

    .line 134
    const/4 v11, 0x0

    .line 135
    const/4 v12, 0x1

    .line 136
    const/4 v13, 0x0

    .line 137
    const/4 v14, 0x0

    .line 138
    const/4 v15, 0x0

    .line 139
    const/16 v16, 0x0

    .line 140
    .line 141
    const/16 v17, 0x0

    .line 142
    .line 143
    const/16 v18, 0x0

    .line 144
    .line 145
    const/16 v19, 0x0

    .line 146
    .line 147
    const/16 v20, 0x0

    .line 148
    .line 149
    invoke-static/range {v6 .. v22}, Lwk0/n1;->a(Lwk0/n1;Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lb71/o;ZZZZLwk0/l1;ZI)Lwk0/n1;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    goto :goto_1

    .line 154
    :cond_2
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    move-object v6, v0

    .line 159
    check-cast v6, Lwk0/n1;

    .line 160
    .line 161
    const/16 v21, 0x0

    .line 162
    .line 163
    const v22, 0xffdf

    .line 164
    .line 165
    .line 166
    const/4 v7, 0x0

    .line 167
    const/4 v8, 0x0

    .line 168
    const/4 v9, 0x0

    .line 169
    const/4 v10, 0x0

    .line 170
    const/4 v11, 0x0

    .line 171
    const/4 v12, 0x0

    .line 172
    const/4 v13, 0x0

    .line 173
    const/4 v14, 0x0

    .line 174
    const/4 v15, 0x0

    .line 175
    const/16 v16, 0x0

    .line 176
    .line 177
    const/16 v17, 0x0

    .line 178
    .line 179
    const/16 v18, 0x0

    .line 180
    .line 181
    const/16 v19, 0x0

    .line 182
    .line 183
    const/16 v20, 0x0

    .line 184
    .line 185
    invoke-static/range {v6 .. v22}, Lwk0/n1;->a(Lwk0/n1;Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lb71/o;ZZZZLwk0/l1;ZI)Lwk0/n1;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    :goto_1
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 190
    .line 191
    .line 192
    :cond_3
    :goto_2
    return-object v4

    .line 193
    :cond_4
    new-instance v0, La8/r0;

    .line 194
    .line 195
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 196
    .line 197
    .line 198
    throw v0

    .line 199
    :pswitch_0
    instance-of v2, v1, Lve0/m;

    .line 200
    .line 201
    if-eqz v2, :cond_5

    .line 202
    .line 203
    move-object v2, v1

    .line 204
    check-cast v2, Lve0/m;

    .line 205
    .line 206
    iget v3, v2, Lve0/m;->e:I

    .line 207
    .line 208
    const/high16 v4, -0x80000000

    .line 209
    .line 210
    and-int v5, v3, v4

    .line 211
    .line 212
    if-eqz v5, :cond_5

    .line 213
    .line 214
    sub-int/2addr v3, v4

    .line 215
    iput v3, v2, Lve0/m;->e:I

    .line 216
    .line 217
    goto :goto_3

    .line 218
    :cond_5
    new-instance v2, Lve0/m;

    .line 219
    .line 220
    invoke-direct {v2, v0, v1}, Lve0/m;-><init>(Ln50/d0;Lkotlin/coroutines/Continuation;)V

    .line 221
    .line 222
    .line 223
    :goto_3
    iget-object v1, v2, Lve0/m;->d:Ljava/lang/Object;

    .line 224
    .line 225
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 226
    .line 227
    iget v4, v2, Lve0/m;->e:I

    .line 228
    .line 229
    const/4 v5, 0x1

    .line 230
    if-eqz v4, :cond_7

    .line 231
    .line 232
    if-ne v4, v5, :cond_6

    .line 233
    .line 234
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    goto :goto_5

    .line 238
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 239
    .line 240
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 241
    .line 242
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    throw v0

    .line 246
    :cond_7
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    iget-object v1, v0, Ln50/d0;->f:Ljava/lang/Object;

    .line 250
    .line 251
    check-cast v1, Lyy0/j;

    .line 252
    .line 253
    move-object/from16 v4, p1

    .line 254
    .line 255
    check-cast v4, Lq6/b;

    .line 256
    .line 257
    iget-object v6, v0, Ln50/d0;->g:Ljava/lang/Object;

    .line 258
    .line 259
    check-cast v6, Ljava/lang/String;

    .line 260
    .line 261
    invoke-static {v6}, Llp/m1;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object v6

    .line 265
    invoke-static {v6}, Ljp/ne;->a(Ljava/lang/String;)Lq6/e;

    .line 266
    .line 267
    .line 268
    move-result-object v6

    .line 269
    invoke-virtual {v4, v6}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v4

    .line 273
    check-cast v4, Ljava/lang/Boolean;

    .line 274
    .line 275
    if-eqz v4, :cond_8

    .line 276
    .line 277
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 278
    .line 279
    .line 280
    move-result v0

    .line 281
    goto :goto_4

    .line 282
    :cond_8
    iget-boolean v0, v0, Ln50/d0;->e:Z

    .line 283
    .line 284
    :goto_4
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    iput v5, v2, Lve0/m;->e:I

    .line 289
    .line 290
    invoke-interface {v1, v0, v2}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v0

    .line 294
    if-ne v0, v3, :cond_9

    .line 295
    .line 296
    goto :goto_6

    .line 297
    :cond_9
    :goto_5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 298
    .line 299
    :goto_6
    return-object v3

    .line 300
    :pswitch_1
    move-object/from16 v1, p1

    .line 301
    .line 302
    check-cast v1, Lne0/t;

    .line 303
    .line 304
    iget-object v2, v0, Ln50/d0;->f:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast v2, Ln50/k0;

    .line 307
    .line 308
    instance-of v3, v1, Lne0/c;

    .line 309
    .line 310
    const/4 v4, 0x0

    .line 311
    if-eqz v3, :cond_a

    .line 312
    .line 313
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    iget-object v6, v2, Ln50/k0;->p:Lij0/a;

    .line 318
    .line 319
    check-cast v0, Ln50/b0;

    .line 320
    .line 321
    move-object v5, v1

    .line 322
    check-cast v5, Lne0/c;

    .line 323
    .line 324
    new-array v1, v4, [Ljava/lang/Object;

    .line 325
    .line 326
    move-object v3, v6

    .line 327
    check-cast v3, Ljj0/f;

    .line 328
    .line 329
    const v7, 0x7f120647

    .line 330
    .line 331
    .line 332
    invoke-virtual {v3, v7, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object v7

    .line 336
    new-array v1, v4, [Ljava/lang/Object;

    .line 337
    .line 338
    move-object v3, v6

    .line 339
    check-cast v3, Ljj0/f;

    .line 340
    .line 341
    const v8, 0x7f120648

    .line 342
    .line 343
    .line 344
    invoke-virtual {v3, v8, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 345
    .line 346
    .line 347
    move-result-object v8

    .line 348
    const v1, 0x7f12038c

    .line 349
    .line 350
    .line 351
    new-array v4, v4, [Ljava/lang/Object;

    .line 352
    .line 353
    invoke-virtual {v3, v1, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 354
    .line 355
    .line 356
    move-result-object v9

    .line 357
    const/4 v12, 0x0

    .line 358
    const/16 v13, 0x70

    .line 359
    .line 360
    const/4 v10, 0x0

    .line 361
    const/4 v11, 0x0

    .line 362
    invoke-static/range {v5 .. v13}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 363
    .line 364
    .line 365
    move-result-object v10

    .line 366
    const/16 v18, 0x1

    .line 367
    .line 368
    const/16 v19, 0x7fb

    .line 369
    .line 370
    const/4 v8, 0x0

    .line 371
    const/4 v9, 0x0

    .line 372
    const/4 v11, 0x0

    .line 373
    const/4 v12, 0x0

    .line 374
    const/4 v13, 0x0

    .line 375
    const/4 v14, 0x0

    .line 376
    const/4 v15, 0x0

    .line 377
    const/16 v16, 0x0

    .line 378
    .line 379
    const/16 v17, 0x0

    .line 380
    .line 381
    move-object v7, v0

    .line 382
    invoke-static/range {v7 .. v19}, Ln50/b0;->a(Ln50/b0;ZZLql0/g;Ln50/a0;ZZLn50/z;ZZZZI)Ln50/b0;

    .line 383
    .line 384
    .line 385
    move-result-object v0

    .line 386
    invoke-virtual {v2, v0}, Lql0/j;->g(Lql0/h;)V

    .line 387
    .line 388
    .line 389
    goto :goto_8

    .line 390
    :cond_a
    instance-of v1, v1, Lne0/e;

    .line 391
    .line 392
    if-eqz v1, :cond_e

    .line 393
    .line 394
    iget-boolean v1, v0, Ln50/d0;->e:Z

    .line 395
    .line 396
    const/4 v3, 0x0

    .line 397
    if-nez v1, :cond_c

    .line 398
    .line 399
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 400
    .line 401
    .line 402
    move-result-object v1

    .line 403
    move-object v4, v1

    .line 404
    check-cast v4, Ln50/b0;

    .line 405
    .line 406
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 407
    .line 408
    .line 409
    move-result-object v1

    .line 410
    check-cast v1, Ln50/b0;

    .line 411
    .line 412
    iget-object v1, v1, Ln50/b0;->d:Ln50/a0;

    .line 413
    .line 414
    if-eqz v1, :cond_b

    .line 415
    .line 416
    const/4 v3, 0x1

    .line 417
    invoke-static {v1, v3}, Ln50/a0;->a(Ln50/a0;Z)Ln50/a0;

    .line 418
    .line 419
    .line 420
    move-result-object v3

    .line 421
    :cond_b
    move-object v8, v3

    .line 422
    const/4 v15, 0x0

    .line 423
    const/16 v16, 0xbf7

    .line 424
    .line 425
    const/4 v5, 0x0

    .line 426
    const/4 v6, 0x0

    .line 427
    const/4 v7, 0x0

    .line 428
    const/4 v9, 0x0

    .line 429
    const/4 v10, 0x0

    .line 430
    const/4 v11, 0x0

    .line 431
    const/4 v12, 0x0

    .line 432
    const/4 v13, 0x0

    .line 433
    const/4 v14, 0x1

    .line 434
    invoke-static/range {v4 .. v16}, Ln50/b0;->a(Ln50/b0;ZZLql0/g;Ln50/a0;ZZLn50/z;ZZZZI)Ln50/b0;

    .line 435
    .line 436
    .line 437
    move-result-object v1

    .line 438
    goto :goto_7

    .line 439
    :cond_c
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 440
    .line 441
    .line 442
    move-result-object v1

    .line 443
    move-object v5, v1

    .line 444
    check-cast v5, Ln50/b0;

    .line 445
    .line 446
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    check-cast v1, Ln50/b0;

    .line 451
    .line 452
    iget-object v1, v1, Ln50/b0;->d:Ln50/a0;

    .line 453
    .line 454
    if-eqz v1, :cond_d

    .line 455
    .line 456
    invoke-static {v1, v4}, Ln50/a0;->a(Ln50/a0;Z)Ln50/a0;

    .line 457
    .line 458
    .line 459
    move-result-object v3

    .line 460
    :cond_d
    move-object v9, v3

    .line 461
    const/16 v16, 0x0

    .line 462
    .line 463
    const/16 v17, 0xff7

    .line 464
    .line 465
    const/4 v6, 0x0

    .line 466
    const/4 v7, 0x0

    .line 467
    const/4 v8, 0x0

    .line 468
    const/4 v10, 0x0

    .line 469
    const/4 v11, 0x0

    .line 470
    const/4 v12, 0x0

    .line 471
    const/4 v13, 0x0

    .line 472
    const/4 v14, 0x0

    .line 473
    const/4 v15, 0x0

    .line 474
    invoke-static/range {v5 .. v17}, Ln50/b0;->a(Ln50/b0;ZZLql0/g;Ln50/a0;ZZLn50/z;ZZZZI)Ln50/b0;

    .line 475
    .line 476
    .line 477
    move-result-object v1

    .line 478
    :goto_7
    invoke-virtual {v2, v1}, Lql0/j;->g(Lql0/h;)V

    .line 479
    .line 480
    .line 481
    iget-object v1, v2, Ln50/k0;->s:Ll50/a0;

    .line 482
    .line 483
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    move-result-object v1

    .line 487
    check-cast v1, Lyy0/i;

    .line 488
    .line 489
    invoke-static {v1}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 490
    .line 491
    .line 492
    move-result-object v1

    .line 493
    iget-object v0, v0, Ln50/d0;->g:Ljava/lang/Object;

    .line 494
    .line 495
    check-cast v0, Lvy0/b0;

    .line 496
    .line 497
    invoke-static {v1, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 498
    .line 499
    .line 500
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 501
    .line 502
    return-object v0

    .line 503
    :cond_e
    new-instance v0, La8/r0;

    .line 504
    .line 505
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 506
    .line 507
    .line 508
    throw v0

    .line 509
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
