.class public final Lw30/f;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzd0/b;

.field public final i:Lu30/e0;

.field public final j:Lkc0/t0;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lzd0/b;Lu30/e0;Lkc0/t0;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lw30/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lw30/d;-><init>(Lae0/a;Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lw30/f;->h:Lzd0/b;

    .line 11
    .line 12
    iput-object p2, p0, Lw30/f;->i:Lu30/e0;

    .line 13
    .line 14
    iput-object p3, p0, Lw30/f;->j:Lkc0/t0;

    .line 15
    .line 16
    iput-object p4, p0, Lw30/f;->k:Lij0/a;

    .line 17
    .line 18
    new-instance p1, Lw30/c;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-direct {p1, p0, v1, p2}, Lw30/c;-><init>(Lw30/f;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lw30/c;

    .line 32
    .line 33
    const/4 p3, 0x1

    .line 34
    invoke-direct {p2, p0, v1, p3}, Lw30/c;-><init>(Lw30/f;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x3

    .line 38
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static final h(Lw30/f;Lrx0/c;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lw30/f;->k:Lij0/a;

    .line 6
    .line 7
    instance-of v3, v1, Lw30/e;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lw30/e;

    .line 13
    .line 14
    iget v4, v3, Lw30/e;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lw30/e;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lw30/e;

    .line 27
    .line 28
    invoke-direct {v3, v0, v1}, Lw30/e;-><init>(Lw30/f;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v1, v3, Lw30/e;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lw30/e;->g:I

    .line 36
    .line 37
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    const/4 v7, 0x2

    .line 40
    const/4 v8, 0x1

    .line 41
    if-eqz v5, :cond_3

    .line 42
    .line 43
    if-eq v5, v8, :cond_2

    .line 44
    .line 45
    if-ne v5, v7, :cond_1

    .line 46
    .line 47
    iget-object v2, v3, Lw30/e;->d:Lw30/f;

    .line 48
    .line 49
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto/16 :goto_5

    .line 53
    .line 54
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    :cond_4
    iget-object v1, v0, Lw30/f;->i:Lu30/e0;

    .line 70
    .line 71
    iput v8, v3, Lw30/e;->g:I

    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1, v3}, Lu30/e0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    if-ne v1, v4, :cond_5

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    :goto_1
    check-cast v1, Lne0/t;

    .line 84
    .line 85
    instance-of v5, v1, Lne0/c;

    .line 86
    .line 87
    const/4 v9, 0x0

    .line 88
    if-eqz v5, :cond_6

    .line 89
    .line 90
    move-object v10, v1

    .line 91
    check-cast v10, Lne0/c;

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_6
    move-object v10, v9

    .line 95
    :goto_2
    if-eqz v10, :cond_7

    .line 96
    .line 97
    iget-object v10, v10, Lne0/c;->a:Ljava/lang/Throwable;

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_7
    move-object v10, v9

    .line 101
    :goto_3
    instance-of v10, v10, Lcd0/a;

    .line 102
    .line 103
    if-nez v10, :cond_4

    .line 104
    .line 105
    if-eqz v5, :cond_d

    .line 106
    .line 107
    move-object v11, v1

    .line 108
    check-cast v11, Lne0/c;

    .line 109
    .line 110
    iget-object v1, v11, Lne0/c;->e:Lne0/b;

    .line 111
    .line 112
    iget-object v5, v11, Lne0/c;->a:Ljava/lang/Throwable;

    .line 113
    .line 114
    instance-of v10, v5, Lxi0/a;

    .line 115
    .line 116
    const/4 v12, 0x0

    .line 117
    if-eqz v10, :cond_9

    .line 118
    .line 119
    new-instance v1, Lne0/e;

    .line 120
    .line 121
    new-instance v5, Llc0/j;

    .line 122
    .line 123
    new-array v8, v12, [Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v2, Ljj0/f;

    .line 126
    .line 127
    const v9, 0x7f1204fb

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2, v9, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v8

    .line 134
    const v9, 0x7f1204fa

    .line 135
    .line 136
    .line 137
    new-array v10, v12, [Ljava/lang/Object;

    .line 138
    .line 139
    invoke-virtual {v2, v9, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v9

    .line 143
    const v10, 0x7f120382

    .line 144
    .line 145
    .line 146
    new-array v11, v12, [Ljava/lang/Object;

    .line 147
    .line 148
    invoke-virtual {v2, v10, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    invoke-direct {v5, v8, v9, v2}, Llc0/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-direct {v1, v5}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    iget-object v2, v0, Lw30/f;->j:Lkc0/t0;

    .line 159
    .line 160
    iput-object v0, v3, Lw30/e;->d:Lw30/f;

    .line 161
    .line 162
    iput v7, v3, Lw30/e;->g:I

    .line 163
    .line 164
    invoke-virtual {v2, v1, v3}, Lkc0/t0;->b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    if-ne v1, v4, :cond_8

    .line 169
    .line 170
    :goto_4
    return-object v4

    .line 171
    :cond_8
    move-object v2, v0

    .line 172
    :goto_5
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    check-cast v0, Lw30/d;

    .line 177
    .line 178
    move-object v1, v0

    .line 179
    move-object v0, v2

    .line 180
    goto/16 :goto_6

    .line 181
    .line 182
    :cond_9
    instance-of v3, v5, Lbm0/a;

    .line 183
    .line 184
    const v4, 0x7f120380

    .line 185
    .line 186
    .line 187
    const v5, 0x7f12038c

    .line 188
    .line 189
    .line 190
    if-eqz v3, :cond_a

    .line 191
    .line 192
    sget-object v7, Lne0/b;->g:Lne0/b;

    .line 193
    .line 194
    if-ne v1, v7, :cond_a

    .line 195
    .line 196
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    check-cast v1, Lw30/d;

    .line 201
    .line 202
    iget-object v3, v0, Lw30/f;->k:Lij0/a;

    .line 203
    .line 204
    new-array v7, v12, [Ljava/lang/Object;

    .line 205
    .line 206
    move-object v10, v3

    .line 207
    check-cast v10, Ljj0/f;

    .line 208
    .line 209
    const v13, 0x7f1202c3

    .line 210
    .line 211
    .line 212
    invoke-virtual {v10, v13, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v13

    .line 216
    new-array v7, v12, [Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v2, Ljj0/f;

    .line 219
    .line 220
    const v10, 0x7f1202c2

    .line 221
    .line 222
    .line 223
    invoke-virtual {v2, v10, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v14

    .line 227
    new-array v7, v12, [Ljava/lang/Object;

    .line 228
    .line 229
    invoke-virtual {v2, v5, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v15

    .line 233
    new-array v5, v12, [Ljava/lang/Object;

    .line 234
    .line 235
    invoke-virtual {v2, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v16

    .line 239
    const/16 v18, 0x0

    .line 240
    .line 241
    const/16 v19, 0x60

    .line 242
    .line 243
    const/16 v17, 0x0

    .line 244
    .line 245
    move-object v12, v3

    .line 246
    invoke-static/range {v11 .. v19}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 247
    .line 248
    .line 249
    move-result-object v2

    .line 250
    invoke-static {v1, v9, v2, v8}, Lw30/d;->a(Lw30/d;Lae0/a;Lql0/g;I)Lw30/d;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    goto/16 :goto_6

    .line 255
    .line 256
    :cond_a
    if-eqz v3, :cond_b

    .line 257
    .line 258
    sget-object v7, Lne0/b;->f:Lne0/b;

    .line 259
    .line 260
    if-ne v1, v7, :cond_b

    .line 261
    .line 262
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    check-cast v1, Lw30/d;

    .line 267
    .line 268
    iget-object v3, v0, Lw30/f;->k:Lij0/a;

    .line 269
    .line 270
    new-array v7, v12, [Ljava/lang/Object;

    .line 271
    .line 272
    move-object v10, v3

    .line 273
    check-cast v10, Ljj0/f;

    .line 274
    .line 275
    const v13, 0x7f1202c9

    .line 276
    .line 277
    .line 278
    invoke-virtual {v10, v13, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v13

    .line 282
    new-array v7, v12, [Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v2, Ljj0/f;

    .line 285
    .line 286
    const v10, 0x7f1202c8

    .line 287
    .line 288
    .line 289
    invoke-virtual {v2, v10, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object v14

    .line 293
    new-array v7, v12, [Ljava/lang/Object;

    .line 294
    .line 295
    invoke-virtual {v2, v5, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v15

    .line 299
    new-array v5, v12, [Ljava/lang/Object;

    .line 300
    .line 301
    invoke-virtual {v2, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object v16

    .line 305
    const/16 v18, 0x0

    .line 306
    .line 307
    const/16 v19, 0x60

    .line 308
    .line 309
    const/16 v17, 0x0

    .line 310
    .line 311
    move-object v12, v3

    .line 312
    invoke-static/range {v11 .. v19}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 313
    .line 314
    .line 315
    move-result-object v2

    .line 316
    invoke-static {v1, v9, v2, v8}, Lw30/d;->a(Lw30/d;Lae0/a;Lql0/g;I)Lw30/d;

    .line 317
    .line 318
    .line 319
    move-result-object v1

    .line 320
    goto :goto_6

    .line 321
    :cond_b
    if-eqz v3, :cond_c

    .line 322
    .line 323
    sget-object v3, Lne0/b;->e:Lne0/b;

    .line 324
    .line 325
    if-ne v1, v3, :cond_c

    .line 326
    .line 327
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 328
    .line 329
    .line 330
    move-result-object v1

    .line 331
    check-cast v1, Lw30/d;

    .line 332
    .line 333
    iget-object v3, v0, Lw30/f;->k:Lij0/a;

    .line 334
    .line 335
    new-array v7, v12, [Ljava/lang/Object;

    .line 336
    .line 337
    move-object v10, v3

    .line 338
    check-cast v10, Ljj0/f;

    .line 339
    .line 340
    const v13, 0x7f1202be

    .line 341
    .line 342
    .line 343
    invoke-virtual {v10, v13, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v13

    .line 347
    new-array v7, v12, [Ljava/lang/Object;

    .line 348
    .line 349
    check-cast v2, Ljj0/f;

    .line 350
    .line 351
    const v10, 0x7f1202bc

    .line 352
    .line 353
    .line 354
    invoke-virtual {v2, v10, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 355
    .line 356
    .line 357
    move-result-object v14

    .line 358
    new-array v7, v12, [Ljava/lang/Object;

    .line 359
    .line 360
    invoke-virtual {v2, v5, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v15

    .line 364
    new-array v5, v12, [Ljava/lang/Object;

    .line 365
    .line 366
    invoke-virtual {v2, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v16

    .line 370
    const/16 v18, 0x0

    .line 371
    .line 372
    const/16 v19, 0x60

    .line 373
    .line 374
    const/16 v17, 0x0

    .line 375
    .line 376
    move-object v12, v3

    .line 377
    invoke-static/range {v11 .. v19}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 378
    .line 379
    .line 380
    move-result-object v2

    .line 381
    invoke-static {v1, v9, v2, v8}, Lw30/d;->a(Lw30/d;Lae0/a;Lql0/g;I)Lw30/d;

    .line 382
    .line 383
    .line 384
    move-result-object v1

    .line 385
    goto :goto_6

    .line 386
    :cond_c
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 387
    .line 388
    .line 389
    move-result-object v1

    .line 390
    check-cast v1, Lw30/d;

    .line 391
    .line 392
    invoke-static {v11, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 393
    .line 394
    .line 395
    move-result-object v2

    .line 396
    invoke-static {v1, v9, v2, v8}, Lw30/d;->a(Lw30/d;Lae0/a;Lql0/g;I)Lw30/d;

    .line 397
    .line 398
    .line 399
    move-result-object v1

    .line 400
    :goto_6
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 401
    .line 402
    .line 403
    :cond_d
    return-object v6
.end method
