.class public final Lfz/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfz/g;

.field public final b:Lfz/l;

.field public final c:Lfz/e;

.field public final d:Lfz/t;


# direct methods
.method public constructor <init>(Lfz/g;Lfz/l;Lfz/e;Lfz/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfz/c;->a:Lfz/g;

    .line 5
    .line 6
    iput-object p2, p0, Lfz/c;->b:Lfz/l;

    .line 7
    .line 8
    iput-object p3, p0, Lfz/c;->c:Lfz/e;

    .line 9
    .line 10
    iput-object p4, p0, Lfz/c;->d:Lfz/t;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lfz/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 14

    .line 1
    instance-of v0, p1, Lfz/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfz/b;

    .line 7
    .line 8
    iget v1, v0, Lfz/b;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lfz/b;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfz/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lfz/b;-><init>(Lfz/c;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfz/b;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfz/b;->i:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    const-string v5, "PREF_ANALYTIC_EVENT_APP_RATING_VEHICLE_ACTIVE"

    .line 34
    .line 35
    const-string v6, "PREF_ANALYTIC_EVENT_APP_RATING_BACKEND_ERROR"

    .line 36
    .line 37
    const-string v7, "PREF_ANALYTIC_EVENT_APP_RATING_APP_CRASH"

    .line 38
    .line 39
    iget-object v8, p0, Lfz/c;->d:Lfz/t;

    .line 40
    .line 41
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    packed-switch v2, :pswitch_data_0

    .line 44
    .line 45
    .line 46
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    return-object v9

    .line 58
    :pswitch_1
    iget-boolean v2, v0, Lfz/b;->f:Z

    .line 59
    .line 60
    iget-boolean v3, v0, Lfz/b;->e:Z

    .line 61
    .line 62
    iget-boolean v6, v0, Lfz/b;->d:Z

    .line 63
    .line 64
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto/16 :goto_e

    .line 68
    .line 69
    :pswitch_2
    iget-boolean v2, v0, Lfz/b;->f:Z

    .line 70
    .line 71
    iget-boolean v6, v0, Lfz/b;->e:Z

    .line 72
    .line 73
    iget-boolean v7, v0, Lfz/b;->d:Z

    .line 74
    .line 75
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto/16 :goto_c

    .line 79
    .line 80
    :pswitch_3
    iget-boolean v2, v0, Lfz/b;->f:Z

    .line 81
    .line 82
    iget-boolean v7, v0, Lfz/b;->e:Z

    .line 83
    .line 84
    iget-boolean v10, v0, Lfz/b;->d:Z

    .line 85
    .line 86
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto/16 :goto_9

    .line 90
    .line 91
    :pswitch_4
    iget-boolean v2, v0, Lfz/b;->f:Z

    .line 92
    .line 93
    iget-boolean v7, v0, Lfz/b;->e:Z

    .line 94
    .line 95
    iget-boolean v10, v0, Lfz/b;->d:Z

    .line 96
    .line 97
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    goto/16 :goto_7

    .line 101
    .line 102
    :pswitch_5
    iget-boolean v2, v0, Lfz/b;->f:Z

    .line 103
    .line 104
    iget-boolean v10, v0, Lfz/b;->e:Z

    .line 105
    .line 106
    iget-boolean v11, v0, Lfz/b;->d:Z

    .line 107
    .line 108
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    goto/16 :goto_4

    .line 112
    .line 113
    :pswitch_6
    iget-boolean v2, v0, Lfz/b;->e:Z

    .line 114
    .line 115
    iget-boolean v10, v0, Lfz/b;->d:Z

    .line 116
    .line 117
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    goto :goto_3

    .line 121
    :pswitch_7
    iget-boolean v2, v0, Lfz/b;->d:Z

    .line 122
    .line 123
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    move v10, v2

    .line 127
    goto :goto_2

    .line 128
    :pswitch_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :pswitch_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    iput v4, v0, Lfz/b;->i:I

    .line 136
    .line 137
    iget-object p1, p0, Lfz/c;->a:Lfz/g;

    .line 138
    .line 139
    invoke-virtual {p1, v0}, Lfz/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    if-ne p1, v1, :cond_1

    .line 144
    .line 145
    goto/16 :goto_11

    .line 146
    .line 147
    :cond_1
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 148
    .line 149
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    iput-boolean p1, v0, Lfz/b;->d:Z

    .line 154
    .line 155
    const/4 v2, 0x2

    .line 156
    iput v2, v0, Lfz/b;->i:I

    .line 157
    .line 158
    iget-object v2, p0, Lfz/c;->b:Lfz/l;

    .line 159
    .line 160
    invoke-virtual {v2, v0}, Lfz/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    if-ne v2, v1, :cond_2

    .line 165
    .line 166
    goto/16 :goto_11

    .line 167
    .line 168
    :cond_2
    move v10, p1

    .line 169
    move-object p1, v2

    .line 170
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 171
    .line 172
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 173
    .line 174
    .line 175
    move-result v2

    .line 176
    iput-boolean v10, v0, Lfz/b;->d:Z

    .line 177
    .line 178
    iput-boolean v2, v0, Lfz/b;->e:Z

    .line 179
    .line 180
    const/4 p1, 0x3

    .line 181
    iput p1, v0, Lfz/b;->i:I

    .line 182
    .line 183
    iget-object p1, p0, Lfz/c;->c:Lfz/e;

    .line 184
    .line 185
    invoke-virtual {p1, v0}, Lfz/e;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    if-ne p1, v1, :cond_3

    .line 190
    .line 191
    goto/16 :goto_11

    .line 192
    .line 193
    :cond_3
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 194
    .line 195
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 196
    .line 197
    .line 198
    move-result p1

    .line 199
    if-nez v10, :cond_9

    .line 200
    .line 201
    iput-boolean v10, v0, Lfz/b;->d:Z

    .line 202
    .line 203
    iput-boolean v2, v0, Lfz/b;->e:Z

    .line 204
    .line 205
    iput-boolean p1, v0, Lfz/b;->f:Z

    .line 206
    .line 207
    const/4 v11, 0x4

    .line 208
    iput v11, v0, Lfz/b;->i:I

    .line 209
    .line 210
    move-object v11, v8

    .line 211
    check-cast v11, Ldz/a;

    .line 212
    .line 213
    iget-object v11, v11, Ldz/a;->a:Lve0/u;

    .line 214
    .line 215
    invoke-virtual {v11, v3, v7, v0}, Lve0/u;->d(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    if-ne v11, v1, :cond_4

    .line 220
    .line 221
    goto/16 :goto_11

    .line 222
    .line 223
    :cond_4
    move v13, v2

    .line 224
    move v2, p1

    .line 225
    move-object p1, v11

    .line 226
    move v11, v10

    .line 227
    move v10, v13

    .line 228
    :goto_4
    check-cast p1, Ljava/lang/Boolean;

    .line 229
    .line 230
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 231
    .line 232
    .line 233
    move-result p1

    .line 234
    if-nez p1, :cond_8

    .line 235
    .line 236
    new-instance p1, Lf2/h0;

    .line 237
    .line 238
    const/16 v12, 0xc

    .line 239
    .line 240
    invoke-direct {p1, v12}, Lf2/h0;-><init>(I)V

    .line 241
    .line 242
    .line 243
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 244
    .line 245
    .line 246
    iput-boolean v11, v0, Lfz/b;->d:Z

    .line 247
    .line 248
    iput-boolean v10, v0, Lfz/b;->e:Z

    .line 249
    .line 250
    iput-boolean v2, v0, Lfz/b;->f:Z

    .line 251
    .line 252
    const/4 p1, 0x5

    .line 253
    iput p1, v0, Lfz/b;->i:I

    .line 254
    .line 255
    move-object p1, v8

    .line 256
    check-cast p1, Ldz/a;

    .line 257
    .line 258
    iget-object p1, p1, Ldz/a;->a:Lve0/u;

    .line 259
    .line 260
    invoke-virtual {p1, v4, v7, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object p1

    .line 264
    if-ne p1, v1, :cond_5

    .line 265
    .line 266
    goto :goto_5

    .line 267
    :cond_5
    move-object p1, v9

    .line 268
    :goto_5
    if-ne p1, v1, :cond_6

    .line 269
    .line 270
    goto :goto_6

    .line 271
    :cond_6
    move-object p1, v9

    .line 272
    :goto_6
    if-ne p1, v1, :cond_7

    .line 273
    .line 274
    goto/16 :goto_11

    .line 275
    .line 276
    :cond_7
    move v7, v10

    .line 277
    move v10, v11

    .line 278
    :goto_7
    move p1, v2

    .line 279
    move v2, v7

    .line 280
    goto :goto_8

    .line 281
    :cond_8
    move p1, v2

    .line 282
    move v2, v10

    .line 283
    move v10, v11

    .line 284
    :cond_9
    :goto_8
    if-nez v2, :cond_f

    .line 285
    .line 286
    iput-boolean v10, v0, Lfz/b;->d:Z

    .line 287
    .line 288
    iput-boolean v2, v0, Lfz/b;->e:Z

    .line 289
    .line 290
    iput-boolean p1, v0, Lfz/b;->f:Z

    .line 291
    .line 292
    const/4 v7, 0x6

    .line 293
    iput v7, v0, Lfz/b;->i:I

    .line 294
    .line 295
    move-object v7, v8

    .line 296
    check-cast v7, Ldz/a;

    .line 297
    .line 298
    iget-object v7, v7, Ldz/a;->a:Lve0/u;

    .line 299
    .line 300
    invoke-virtual {v7, v3, v6, v0}, Lve0/u;->d(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v7

    .line 304
    if-ne v7, v1, :cond_a

    .line 305
    .line 306
    goto/16 :goto_11

    .line 307
    .line 308
    :cond_a
    move v13, v2

    .line 309
    move v2, p1

    .line 310
    move-object p1, v7

    .line 311
    move v7, v13

    .line 312
    :goto_9
    check-cast p1, Ljava/lang/Boolean;

    .line 313
    .line 314
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 315
    .line 316
    .line 317
    move-result p1

    .line 318
    if-nez p1, :cond_e

    .line 319
    .line 320
    new-instance p1, Lf2/h0;

    .line 321
    .line 322
    const/16 v11, 0xd

    .line 323
    .line 324
    invoke-direct {p1, v11}, Lf2/h0;-><init>(I)V

    .line 325
    .line 326
    .line 327
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 328
    .line 329
    .line 330
    iput-boolean v10, v0, Lfz/b;->d:Z

    .line 331
    .line 332
    iput-boolean v7, v0, Lfz/b;->e:Z

    .line 333
    .line 334
    iput-boolean v2, v0, Lfz/b;->f:Z

    .line 335
    .line 336
    const/4 p1, 0x7

    .line 337
    iput p1, v0, Lfz/b;->i:I

    .line 338
    .line 339
    move-object p1, v8

    .line 340
    check-cast p1, Ldz/a;

    .line 341
    .line 342
    iget-object p1, p1, Ldz/a;->a:Lve0/u;

    .line 343
    .line 344
    invoke-virtual {p1, v4, v6, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object p1

    .line 348
    if-ne p1, v1, :cond_b

    .line 349
    .line 350
    goto :goto_a

    .line 351
    :cond_b
    move-object p1, v9

    .line 352
    :goto_a
    if-ne p1, v1, :cond_c

    .line 353
    .line 354
    goto :goto_b

    .line 355
    :cond_c
    move-object p1, v9

    .line 356
    :goto_b
    if-ne p1, v1, :cond_d

    .line 357
    .line 358
    goto :goto_11

    .line 359
    :cond_d
    move v6, v7

    .line 360
    move v7, v10

    .line 361
    :goto_c
    move v10, v7

    .line 362
    goto :goto_d

    .line 363
    :cond_e
    move v6, v7

    .line 364
    goto :goto_d

    .line 365
    :cond_f
    move v6, v2

    .line 366
    move v2, p1

    .line 367
    :goto_d
    if-eqz v2, :cond_13

    .line 368
    .line 369
    iput-boolean v10, v0, Lfz/b;->d:Z

    .line 370
    .line 371
    iput-boolean v6, v0, Lfz/b;->e:Z

    .line 372
    .line 373
    iput-boolean v2, v0, Lfz/b;->f:Z

    .line 374
    .line 375
    const/16 p1, 0x8

    .line 376
    .line 377
    iput p1, v0, Lfz/b;->i:I

    .line 378
    .line 379
    move-object p1, v8

    .line 380
    check-cast p1, Ldz/a;

    .line 381
    .line 382
    iget-object p1, p1, Ldz/a;->a:Lve0/u;

    .line 383
    .line 384
    invoke-virtual {p1, v3, v5, v0}, Lve0/u;->d(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object p1

    .line 388
    if-ne p1, v1, :cond_10

    .line 389
    .line 390
    goto :goto_11

    .line 391
    :cond_10
    move v3, v6

    .line 392
    move v6, v10

    .line 393
    :goto_e
    check-cast p1, Ljava/lang/Boolean;

    .line 394
    .line 395
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 396
    .line 397
    .line 398
    move-result p1

    .line 399
    if-nez p1, :cond_13

    .line 400
    .line 401
    new-instance p1, Lf2/h0;

    .line 402
    .line 403
    const/16 v7, 0xe

    .line 404
    .line 405
    invoke-direct {p1, v7}, Lf2/h0;-><init>(I)V

    .line 406
    .line 407
    .line 408
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 409
    .line 410
    .line 411
    iput-boolean v6, v0, Lfz/b;->d:Z

    .line 412
    .line 413
    iput-boolean v3, v0, Lfz/b;->e:Z

    .line 414
    .line 415
    iput-boolean v2, v0, Lfz/b;->f:Z

    .line 416
    .line 417
    const/16 p0, 0x9

    .line 418
    .line 419
    iput p0, v0, Lfz/b;->i:I

    .line 420
    .line 421
    check-cast v8, Ldz/a;

    .line 422
    .line 423
    iget-object p0, v8, Ldz/a;->a:Lve0/u;

    .line 424
    .line 425
    invoke-virtual {p0, v4, v5, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object p0

    .line 429
    if-ne p0, v1, :cond_11

    .line 430
    .line 431
    goto :goto_f

    .line 432
    :cond_11
    move-object p0, v9

    .line 433
    :goto_f
    if-ne p0, v1, :cond_12

    .line 434
    .line 435
    goto :goto_10

    .line 436
    :cond_12
    move-object p0, v9

    .line 437
    :goto_10
    if-ne p0, v1, :cond_13

    .line 438
    .line 439
    :goto_11
    return-object v1

    .line 440
    :cond_13
    return-object v9

    .line 441
    :pswitch_data_0
    .packed-switch 0x0
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
