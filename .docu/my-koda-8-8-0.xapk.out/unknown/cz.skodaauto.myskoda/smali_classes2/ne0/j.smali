.class public final Lne0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lyy0/j;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lne0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lne0/j;->e:Lyy0/j;

    .line 4
    .line 5
    iput-object p2, p0, Lne0/j;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lne0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lq61/q;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lq61/q;

    .line 12
    .line 13
    iget v1, v0, Lq61/q;->e:I

    .line 14
    .line 15
    const/high16 v2, -0x80000000

    .line 16
    .line 17
    and-int v3, v1, v2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    iput v1, v0, Lq61/q;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lq61/q;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lq61/q;-><init>(Lne0/j;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lq61/q;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lq61/q;->e:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    iget-object p2, p0, Lne0/j;->f:Lay0/k;

    .line 57
    .line 58
    invoke-interface {p2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    iput v3, v0, Lq61/q;->e:I

    .line 63
    .line 64
    iget-object p0, p0, Lne0/j;->e:Lyy0/j;

    .line 65
    .line 66
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-ne p0, v1, :cond_3

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_3
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    :goto_2
    return-object v1

    .line 76
    :pswitch_0
    instance-of v0, p2, Lpo0/a;

    .line 77
    .line 78
    if-eqz v0, :cond_4

    .line 79
    .line 80
    move-object v0, p2

    .line 81
    check-cast v0, Lpo0/a;

    .line 82
    .line 83
    iget v1, v0, Lpo0/a;->e:I

    .line 84
    .line 85
    const/high16 v2, -0x80000000

    .line 86
    .line 87
    and-int v3, v1, v2

    .line 88
    .line 89
    if-eqz v3, :cond_4

    .line 90
    .line 91
    sub-int/2addr v1, v2

    .line 92
    iput v1, v0, Lpo0/a;->e:I

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_4
    new-instance v0, Lpo0/a;

    .line 96
    .line 97
    invoke-direct {v0, p0, p2}, Lpo0/a;-><init>(Lne0/j;Lkotlin/coroutines/Continuation;)V

    .line 98
    .line 99
    .line 100
    :goto_3
    iget-object p2, v0, Lpo0/a;->d:Ljava/lang/Object;

    .line 101
    .line 102
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 103
    .line 104
    iget v2, v0, Lpo0/a;->e:I

    .line 105
    .line 106
    const/4 v3, 0x1

    .line 107
    if-eqz v2, :cond_6

    .line 108
    .line 109
    if-ne v2, v3, :cond_5

    .line 110
    .line 111
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    goto :goto_5

    .line 115
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 116
    .line 117
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 118
    .line 119
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_6
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    check-cast p1, Lri/d;

    .line 127
    .line 128
    const-string p2, "<this>"

    .line 129
    .line 130
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    instance-of p2, p1, Lri/b;

    .line 134
    .line 135
    if-eqz p2, :cond_7

    .line 136
    .line 137
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_7
    instance-of p2, p1, Lri/a;

    .line 141
    .line 142
    iget-object v2, p0, Lne0/j;->f:Lay0/k;

    .line 143
    .line 144
    if-eqz p2, :cond_8

    .line 145
    .line 146
    check-cast p1, Lri/a;

    .line 147
    .line 148
    iget-object p1, p1, Lri/a;->a:Ljava/lang/Object;

    .line 149
    .line 150
    invoke-static {p1, v2}, Lkp/l8;->b(Ljava/lang/Object;Lay0/k;)Lne0/t;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-static {p1}, Lbb/j0;->j(Lne0/t;)Lne0/s;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    goto :goto_4

    .line 159
    :cond_8
    instance-of p2, p1, Lri/c;

    .line 160
    .line 161
    if-eqz p2, :cond_a

    .line 162
    .line 163
    check-cast p1, Lri/c;

    .line 164
    .line 165
    iget-object p1, p1, Lri/c;->a:Ljava/lang/Object;

    .line 166
    .line 167
    invoke-static {p1, v2}, Lkp/l8;->b(Ljava/lang/Object;Lay0/k;)Lne0/t;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-static {p1}, Lbb/j0;->j(Lne0/t;)Lne0/s;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    :goto_4
    iput v3, v0, Lpo0/a;->e:I

    .line 176
    .line 177
    iget-object p0, p0, Lne0/j;->e:Lyy0/j;

    .line 178
    .line 179
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    if-ne p0, v1, :cond_9

    .line 184
    .line 185
    goto :goto_6

    .line 186
    :cond_9
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 187
    .line 188
    :goto_6
    return-object v1

    .line 189
    :cond_a
    new-instance p0, La8/r0;

    .line 190
    .line 191
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 192
    .line 193
    .line 194
    throw p0

    .line 195
    :pswitch_1
    instance-of v0, p2, Lne0/o;

    .line 196
    .line 197
    if-eqz v0, :cond_b

    .line 198
    .line 199
    move-object v0, p2

    .line 200
    check-cast v0, Lne0/o;

    .line 201
    .line 202
    iget v1, v0, Lne0/o;->e:I

    .line 203
    .line 204
    const/high16 v2, -0x80000000

    .line 205
    .line 206
    and-int v3, v1, v2

    .line 207
    .line 208
    if-eqz v3, :cond_b

    .line 209
    .line 210
    sub-int/2addr v1, v2

    .line 211
    iput v1, v0, Lne0/o;->e:I

    .line 212
    .line 213
    goto :goto_7

    .line 214
    :cond_b
    new-instance v0, Lne0/o;

    .line 215
    .line 216
    invoke-direct {v0, p0, p2}, Lne0/o;-><init>(Lne0/j;Lkotlin/coroutines/Continuation;)V

    .line 217
    .line 218
    .line 219
    :goto_7
    iget-object p2, v0, Lne0/o;->d:Ljava/lang/Object;

    .line 220
    .line 221
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 222
    .line 223
    iget v2, v0, Lne0/o;->e:I

    .line 224
    .line 225
    const/4 v3, 0x2

    .line 226
    const/4 v4, 0x0

    .line 227
    const/4 v5, 0x1

    .line 228
    if-eqz v2, :cond_e

    .line 229
    .line 230
    if-eq v2, v5, :cond_d

    .line 231
    .line 232
    if-ne v2, v3, :cond_c

    .line 233
    .line 234
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    goto :goto_9

    .line 238
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 239
    .line 240
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 241
    .line 242
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    throw p0

    .line 246
    :cond_d
    iget p0, v0, Lne0/o;->i:I

    .line 247
    .line 248
    iget-object p1, v0, Lne0/o;->h:Lyy0/j;

    .line 249
    .line 250
    iget-object v2, v0, Lne0/o;->g:Ljava/lang/Object;

    .line 251
    .line 252
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    goto :goto_8

    .line 256
    :cond_e
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    move-object p2, p1

    .line 260
    check-cast p2, Lne0/s;

    .line 261
    .line 262
    instance-of p2, p2, Lne0/d;

    .line 263
    .line 264
    iget-object v2, p0, Lne0/j;->e:Lyy0/j;

    .line 265
    .line 266
    if-eqz p2, :cond_10

    .line 267
    .line 268
    iput-object p1, v0, Lne0/o;->g:Ljava/lang/Object;

    .line 269
    .line 270
    iput-object v2, v0, Lne0/o;->h:Lyy0/j;

    .line 271
    .line 272
    iput v4, v0, Lne0/o;->i:I

    .line 273
    .line 274
    iput v5, v0, Lne0/o;->e:I

    .line 275
    .line 276
    iget-object p0, p0, Lne0/j;->f:Lay0/k;

    .line 277
    .line 278
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object p2

    .line 282
    if-ne p2, v1, :cond_f

    .line 283
    .line 284
    goto :goto_a

    .line 285
    :cond_f
    move-object p0, v2

    .line 286
    move-object v2, p1

    .line 287
    move-object p1, p0

    .line 288
    move p0, v4

    .line 289
    :goto_8
    check-cast p2, Ljava/lang/Boolean;

    .line 290
    .line 291
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 292
    .line 293
    .line 294
    move-result p2

    .line 295
    if-nez p2, :cond_11

    .line 296
    .line 297
    move-object v4, v2

    .line 298
    move-object v2, p1

    .line 299
    move-object p1, v4

    .line 300
    move v4, p0

    .line 301
    :cond_10
    move-object p0, v2

    .line 302
    move-object v2, p1

    .line 303
    move-object p1, p0

    .line 304
    move p0, v4

    .line 305
    move v4, v5

    .line 306
    :cond_11
    if-eqz v4, :cond_12

    .line 307
    .line 308
    const/4 p2, 0x0

    .line 309
    iput-object p2, v0, Lne0/o;->g:Ljava/lang/Object;

    .line 310
    .line 311
    iput-object p2, v0, Lne0/o;->h:Lyy0/j;

    .line 312
    .line 313
    iput p0, v0, Lne0/o;->i:I

    .line 314
    .line 315
    iput v3, v0, Lne0/o;->e:I

    .line 316
    .line 317
    invoke-interface {p1, v2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object p0

    .line 321
    if-ne p0, v1, :cond_12

    .line 322
    .line 323
    goto :goto_a

    .line 324
    :cond_12
    :goto_9
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 325
    .line 326
    :goto_a
    return-object v1

    .line 327
    :pswitch_2
    instance-of v0, p2, Lne0/l;

    .line 328
    .line 329
    if-eqz v0, :cond_13

    .line 330
    .line 331
    move-object v0, p2

    .line 332
    check-cast v0, Lne0/l;

    .line 333
    .line 334
    iget v1, v0, Lne0/l;->e:I

    .line 335
    .line 336
    const/high16 v2, -0x80000000

    .line 337
    .line 338
    and-int v3, v1, v2

    .line 339
    .line 340
    if-eqz v3, :cond_13

    .line 341
    .line 342
    sub-int/2addr v1, v2

    .line 343
    iput v1, v0, Lne0/l;->e:I

    .line 344
    .line 345
    goto :goto_b

    .line 346
    :cond_13
    new-instance v0, Lne0/l;

    .line 347
    .line 348
    invoke-direct {v0, p0, p2}, Lne0/l;-><init>(Lne0/j;Lkotlin/coroutines/Continuation;)V

    .line 349
    .line 350
    .line 351
    :goto_b
    iget-object p2, v0, Lne0/l;->d:Ljava/lang/Object;

    .line 352
    .line 353
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 354
    .line 355
    iget v2, v0, Lne0/l;->e:I

    .line 356
    .line 357
    const/4 v3, 0x1

    .line 358
    if-eqz v2, :cond_15

    .line 359
    .line 360
    if-ne v2, v3, :cond_14

    .line 361
    .line 362
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    goto :goto_d

    .line 366
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 367
    .line 368
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 369
    .line 370
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    throw p0

    .line 374
    :cond_15
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 375
    .line 376
    .line 377
    check-cast p1, Lne0/s;

    .line 378
    .line 379
    instance-of p2, p1, Lne0/e;

    .line 380
    .line 381
    if-eqz p2, :cond_16

    .line 382
    .line 383
    goto :goto_c

    .line 384
    :cond_16
    instance-of p2, p1, Lne0/c;

    .line 385
    .line 386
    if-eqz p2, :cond_17

    .line 387
    .line 388
    iget-object p2, p0, Lne0/j;->f:Lay0/k;

    .line 389
    .line 390
    invoke-interface {p2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object p1

    .line 394
    check-cast p1, Lne0/s;

    .line 395
    .line 396
    goto :goto_c

    .line 397
    :cond_17
    instance-of p2, p1, Lne0/d;

    .line 398
    .line 399
    if-eqz p2, :cond_19

    .line 400
    .line 401
    :goto_c
    iput v3, v0, Lne0/l;->e:I

    .line 402
    .line 403
    iget-object p0, p0, Lne0/j;->e:Lyy0/j;

    .line 404
    .line 405
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    move-result-object p0

    .line 409
    if-ne p0, v1, :cond_18

    .line 410
    .line 411
    goto :goto_e

    .line 412
    :cond_18
    :goto_d
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 413
    .line 414
    :goto_e
    return-object v1

    .line 415
    :cond_19
    new-instance p0, La8/r0;

    .line 416
    .line 417
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 418
    .line 419
    .line 420
    throw p0

    .line 421
    :pswitch_3
    instance-of v0, p2, Lne0/i;

    .line 422
    .line 423
    if-eqz v0, :cond_1a

    .line 424
    .line 425
    move-object v0, p2

    .line 426
    check-cast v0, Lne0/i;

    .line 427
    .line 428
    iget v1, v0, Lne0/i;->e:I

    .line 429
    .line 430
    const/high16 v2, -0x80000000

    .line 431
    .line 432
    and-int v3, v1, v2

    .line 433
    .line 434
    if-eqz v3, :cond_1a

    .line 435
    .line 436
    sub-int/2addr v1, v2

    .line 437
    iput v1, v0, Lne0/i;->e:I

    .line 438
    .line 439
    :goto_f
    move-object p2, v0

    .line 440
    goto :goto_10

    .line 441
    :cond_1a
    new-instance v0, Lne0/i;

    .line 442
    .line 443
    invoke-direct {v0, p0, p2}, Lne0/i;-><init>(Lne0/j;Lkotlin/coroutines/Continuation;)V

    .line 444
    .line 445
    .line 446
    goto :goto_f

    .line 447
    :goto_10
    iget-object v0, p2, Lne0/i;->d:Ljava/lang/Object;

    .line 448
    .line 449
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 450
    .line 451
    iget v2, p2, Lne0/i;->e:I

    .line 452
    .line 453
    const/4 v3, 0x1

    .line 454
    if-eqz v2, :cond_1c

    .line 455
    .line 456
    if-ne v2, v3, :cond_1b

    .line 457
    .line 458
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 459
    .line 460
    .line 461
    goto :goto_14

    .line 462
    :cond_1b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 463
    .line 464
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 465
    .line 466
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 467
    .line 468
    .line 469
    throw p0

    .line 470
    :cond_1c
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 471
    .line 472
    .line 473
    check-cast p1, Lne0/s;

    .line 474
    .line 475
    instance-of v0, p1, Lne0/e;

    .line 476
    .line 477
    if-eqz v0, :cond_1e

    .line 478
    .line 479
    :try_start_0
    check-cast p1, Lne0/e;

    .line 480
    .line 481
    new-instance v0, Lne0/e;

    .line 482
    .line 483
    iget-object v2, p0, Lne0/j;->f:Lay0/k;

    .line 484
    .line 485
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 486
    .line 487
    invoke-interface {v2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    move-result-object p1

    .line 491
    invoke-direct {v0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 492
    .line 493
    .line 494
    goto :goto_11

    .line 495
    :catchall_0
    move-exception v0

    .line 496
    move-object p1, v0

    .line 497
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 498
    .line 499
    .line 500
    move-result-object v0

    .line 501
    :goto_11
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 502
    .line 503
    .line 504
    move-result-object v5

    .line 505
    if-nez v5, :cond_1d

    .line 506
    .line 507
    goto :goto_12

    .line 508
    :cond_1d
    new-instance v4, Lne0/c;

    .line 509
    .line 510
    const/4 v8, 0x0

    .line 511
    const/16 v9, 0x1e

    .line 512
    .line 513
    const/4 v6, 0x0

    .line 514
    const/4 v7, 0x0

    .line 515
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 516
    .line 517
    .line 518
    move-object v0, v4

    .line 519
    :goto_12
    move-object p1, v0

    .line 520
    check-cast p1, Lne0/s;

    .line 521
    .line 522
    goto :goto_13

    .line 523
    :cond_1e
    instance-of v0, p1, Lne0/c;

    .line 524
    .line 525
    if-eqz v0, :cond_1f

    .line 526
    .line 527
    goto :goto_13

    .line 528
    :cond_1f
    instance-of v0, p1, Lne0/d;

    .line 529
    .line 530
    if-eqz v0, :cond_21

    .line 531
    .line 532
    :goto_13
    iput v3, p2, Lne0/i;->e:I

    .line 533
    .line 534
    iget-object p0, p0, Lne0/j;->e:Lyy0/j;

    .line 535
    .line 536
    invoke-interface {p0, p1, p2}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 537
    .line 538
    .line 539
    move-result-object p0

    .line 540
    if-ne p0, v1, :cond_20

    .line 541
    .line 542
    goto :goto_15

    .line 543
    :cond_20
    :goto_14
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 544
    .line 545
    :goto_15
    return-object v1

    .line 546
    :cond_21
    new-instance p0, La8/r0;

    .line 547
    .line 548
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 549
    .line 550
    .line 551
    throw p0

    .line 552
    nop

    .line 553
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
