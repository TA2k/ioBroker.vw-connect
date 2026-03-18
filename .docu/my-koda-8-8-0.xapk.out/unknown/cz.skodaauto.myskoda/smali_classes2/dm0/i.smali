.class public final Ldm0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ld01/r;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Ldm0/i;->a:I

    const-string v0, "cookieJar"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Ldm0/i;->b:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ldm0/i;->a:I

    iput-object p1, p0, Ldm0/i;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 45

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ldm0/i;->a:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    packed-switch v1, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    const-string v1, "Content-Encoding"

    .line 10
    .line 11
    const-string v2, "User-Agent"

    .line 12
    .line 13
    iget-object v0, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Ld01/r;

    .line 16
    .line 17
    const-string v7, "gzip"

    .line 18
    .line 19
    const-string v8, "Accept-Encoding"

    .line 20
    .line 21
    const-string v9, "Connection"

    .line 22
    .line 23
    const-string v10, "Host"

    .line 24
    .line 25
    const-string v11, "Transfer-Encoding"

    .line 26
    .line 27
    const-string v12, "Content-Type"

    .line 28
    .line 29
    const-string v13, "Content-Length"

    .line 30
    .line 31
    move-object/from16 v14, p1

    .line 32
    .line 33
    check-cast v14, Li01/f;

    .line 34
    .line 35
    iget-object v15, v14, Li01/f;->e:Ld01/k0;

    .line 36
    .line 37
    invoke-virtual {v15}, Ld01/k0;->b()Ld01/j0;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    const-wide/16 v17, -0x1

    .line 42
    .line 43
    iget-object v3, v15, Ld01/k0;->c:Ld01/y;

    .line 44
    .line 45
    iget-object v4, v15, Ld01/k0;->a:Ld01/a0;

    .line 46
    .line 47
    iget-object v15, v15, Ld01/k0;->d:Ld01/r0;

    .line 48
    .line 49
    if-eqz v15, :cond_2

    .line 50
    .line 51
    invoke-virtual {v15}, Ld01/r0;->contentType()Ld01/d0;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    if-eqz v6, :cond_0

    .line 56
    .line 57
    iget-object v6, v6, Ld01/d0;->a:Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {v5, v12, v6}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    :cond_0
    invoke-virtual {v15}, Ld01/r0;->contentLength()J

    .line 63
    .line 64
    .line 65
    move-result-wide v19

    .line 66
    cmp-long v6, v19, v17

    .line 67
    .line 68
    if-eqz v6, :cond_1

    .line 69
    .line 70
    invoke-static/range {v19 .. v20}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    invoke-virtual {v5, v13, v6}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    iget-object v6, v5, Ld01/j0;->c:Ld01/x;

    .line 78
    .line 79
    invoke-virtual {v6, v11}, Ld01/x;->o(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    const-string v6, "chunked"

    .line 84
    .line 85
    invoke-virtual {v5, v11, v6}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object v6, v5, Ld01/j0;->c:Ld01/x;

    .line 89
    .line 90
    invoke-virtual {v6, v13}, Ld01/x;->o(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    :cond_2
    :goto_0
    invoke-virtual {v3, v10}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    if-nez v6, :cond_3

    .line 98
    .line 99
    const/4 v6, 0x0

    .line 100
    invoke-static {v4, v6}, Le01/g;->i(Ld01/a0;Z)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v11

    .line 104
    invoke-virtual {v5, v10, v11}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    :cond_3
    invoke-virtual {v3, v9}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v6

    .line 111
    if-nez v6, :cond_4

    .line 112
    .line 113
    const-string v6, "Keep-Alive"

    .line 114
    .line 115
    invoke-virtual {v5, v9, v6}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    :cond_4
    invoke-virtual {v3, v8}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v6

    .line 122
    if-nez v6, :cond_5

    .line 123
    .line 124
    const-string v6, "Range"

    .line 125
    .line 126
    invoke-virtual {v3, v6}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    if-nez v6, :cond_5

    .line 131
    .line 132
    invoke-virtual {v5, v8, v7}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    const/16 v16, 0x1

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_5
    const/16 v16, 0x0

    .line 139
    .line 140
    :goto_1
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    const-string v6, "url"

    .line 144
    .line 145
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v3, v2}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    if-nez v3, :cond_6

    .line 153
    .line 154
    const-string v3, "okhttp/5.3.0"

    .line 155
    .line 156
    invoke-virtual {v5, v2, v3}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    :cond_6
    new-instance v2, Ld01/k0;

    .line 160
    .line 161
    invoke-direct {v2, v5}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v14, v2}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    iget-object v4, v3, Ld01/t0;->i:Ld01/y;

    .line 169
    .line 170
    iget-object v5, v2, Ld01/k0;->a:Ld01/a0;

    .line 171
    .line 172
    invoke-static {v0, v5, v4}, Li01/e;->b(Ld01/r;Ld01/a0;Ld01/y;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v3}, Ld01/t0;->d()Ld01/s0;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    iput-object v2, v0, Ld01/s0;->a:Ld01/k0;

    .line 180
    .line 181
    if-eqz v16, :cond_7

    .line 182
    .line 183
    invoke-static {v3, v1}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    invoke-virtual {v7, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 188
    .line 189
    .line 190
    move-result v2

    .line 191
    if-eqz v2, :cond_7

    .line 192
    .line 193
    invoke-static {v3}, Li01/e;->a(Ld01/t0;)Z

    .line 194
    .line 195
    .line 196
    move-result v2

    .line 197
    if-eqz v2, :cond_7

    .line 198
    .line 199
    iget-object v2, v3, Ld01/t0;->j:Ld01/v0;

    .line 200
    .line 201
    if-eqz v2, :cond_7

    .line 202
    .line 203
    new-instance v5, Lu01/p;

    .line 204
    .line 205
    invoke-virtual {v2}, Ld01/v0;->p0()Lu01/h;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    invoke-direct {v5, v2}, Lu01/p;-><init>(Lu01/h;)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v4}, Ld01/y;->g()Ld01/x;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    invoke-virtual {v2, v1}, Ld01/x;->o(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v2, v13}, Ld01/x;->o(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v2}, Ld01/x;->j()Ld01/y;

    .line 223
    .line 224
    .line 225
    move-result-object v1

    .line 226
    invoke-virtual {v0, v1}, Ld01/s0;->c(Ld01/y;)V

    .line 227
    .line 228
    .line 229
    invoke-static {v3, v12}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v1

    .line 233
    new-instance v2, Li01/g;

    .line 234
    .line 235
    invoke-static {v5}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 236
    .line 237
    .line 238
    move-result-object v3

    .line 239
    move-wide/from16 v4, v17

    .line 240
    .line 241
    invoke-direct {v2, v1, v4, v5, v3}, Li01/g;-><init>(Ljava/lang/String;JLu01/b0;)V

    .line 242
    .line 243
    .line 244
    iput-object v2, v0, Ld01/s0;->g:Ld01/v0;

    .line 245
    .line 246
    :cond_7
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    return-object v0

    .line 251
    :pswitch_0
    move-object/from16 v1, p1

    .line 252
    .line 253
    check-cast v1, Li01/f;

    .line 254
    .line 255
    iget-object v3, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v3, Ld01/g;

    .line 258
    .line 259
    if-eqz v3, :cond_d

    .line 260
    .line 261
    iget-object v4, v1, Li01/f;->e:Ld01/k0;

    .line 262
    .line 263
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 264
    .line 265
    .line 266
    iget-object v5, v4, Ld01/k0;->a:Ld01/a0;

    .line 267
    .line 268
    invoke-static {v5}, Ljp/pe;->b(Ld01/a0;)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v6

    .line 272
    :try_start_0
    iget-object v3, v3, Ld01/g;->d:Lf01/g;

    .line 273
    .line 274
    invoke-virtual {v3, v6}, Lf01/g;->f(Ljava/lang/String;)Lf01/d;

    .line 275
    .line 276
    .line 277
    move-result-object v3
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 278
    if-nez v3, :cond_8

    .line 279
    .line 280
    goto/16 :goto_3

    .line 281
    .line 282
    :cond_8
    :try_start_1
    new-instance v6, Ld01/e;

    .line 283
    .line 284
    iget-object v7, v3, Lf01/d;->f:Ljava/util/ArrayList;

    .line 285
    .line 286
    const/4 v8, 0x0

    .line 287
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v7

    .line 291
    check-cast v7, Lu01/h0;

    .line 292
    .line 293
    invoke-direct {v6, v7}, Ld01/e;-><init>(Lu01/h0;)V

    .line 294
    .line 295
    .line 296
    iget-object v7, v6, Ld01/e;->c:Ljava/lang/String;

    .line 297
    .line 298
    iget-object v8, v6, Ld01/e;->b:Ld01/y;

    .line 299
    .line 300
    iget-object v9, v6, Ld01/e;->a:Ld01/a0;
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 301
    .line 302
    iget-object v10, v6, Ld01/e;->g:Ld01/y;

    .line 303
    .line 304
    const-string v11, "Content-Type"

    .line 305
    .line 306
    invoke-virtual {v10, v11}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v11

    .line 310
    const-string v12, "Content-Length"

    .line 311
    .line 312
    invoke-virtual {v10, v12}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object v12

    .line 316
    new-instance v13, Ld01/k0;

    .line 317
    .line 318
    const-string v14, "\u0000"

    .line 319
    .line 320
    const-string v15, "url"

    .line 321
    .line 322
    invoke-static {v9, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    const-string v15, "headers"

    .line 326
    .line 327
    invoke-static {v8, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    const-string v15, "method"

    .line 331
    .line 332
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    new-instance v15, Ld01/j0;

    .line 336
    .line 337
    invoke-direct {v15}, Ld01/j0;-><init>()V

    .line 338
    .line 339
    .line 340
    iput-object v9, v15, Ld01/j0;->a:Ld01/a0;

    .line 341
    .line 342
    invoke-virtual {v15, v8}, Ld01/j0;->d(Ld01/y;)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v7, v14}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 346
    .line 347
    .line 348
    move-result v14

    .line 349
    if-nez v14, :cond_9

    .line 350
    .line 351
    move-object v14, v7

    .line 352
    goto :goto_2

    .line 353
    :cond_9
    const-string v14, "GET"

    .line 354
    .line 355
    :goto_2
    invoke-virtual {v15, v14, v2}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 356
    .line 357
    .line 358
    invoke-direct {v13, v15}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 359
    .line 360
    .line 361
    new-instance v14, Ld01/s0;

    .line 362
    .line 363
    invoke-direct {v14}, Ld01/s0;-><init>()V

    .line 364
    .line 365
    .line 366
    iput-object v13, v14, Ld01/s0;->a:Ld01/k0;

    .line 367
    .line 368
    iget-object v13, v6, Ld01/e;->d:Ld01/i0;

    .line 369
    .line 370
    const-string v15, "protocol"

    .line 371
    .line 372
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    iput-object v13, v14, Ld01/s0;->b:Ld01/i0;

    .line 376
    .line 377
    iget v13, v6, Ld01/e;->e:I

    .line 378
    .line 379
    iput v13, v14, Ld01/s0;->c:I

    .line 380
    .line 381
    iget-object v13, v6, Ld01/e;->f:Ljava/lang/String;

    .line 382
    .line 383
    const-string v15, "message"

    .line 384
    .line 385
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    iput-object v13, v14, Ld01/s0;->d:Ljava/lang/String;

    .line 389
    .line 390
    invoke-virtual {v14, v10}, Ld01/s0;->c(Ld01/y;)V

    .line 391
    .line 392
    .line 393
    new-instance v10, Ld01/d;

    .line 394
    .line 395
    invoke-direct {v10, v3, v11, v12}, Ld01/d;-><init>(Lf01/d;Ljava/lang/String;Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    iput-object v10, v14, Ld01/s0;->g:Ld01/v0;

    .line 399
    .line 400
    iget-object v3, v6, Ld01/e;->h:Ld01/w;

    .line 401
    .line 402
    iput-object v3, v14, Ld01/s0;->e:Ld01/w;

    .line 403
    .line 404
    iget-wide v10, v6, Ld01/e;->i:J

    .line 405
    .line 406
    iput-wide v10, v14, Ld01/s0;->l:J

    .line 407
    .line 408
    iget-wide v10, v6, Ld01/e;->j:J

    .line 409
    .line 410
    iput-wide v10, v14, Ld01/s0;->m:J

    .line 411
    .line 412
    invoke-virtual {v14}, Ld01/s0;->a()Ld01/t0;

    .line 413
    .line 414
    .line 415
    move-result-object v3

    .line 416
    invoke-virtual {v9, v5}, Ld01/a0;->equals(Ljava/lang/Object;)Z

    .line 417
    .line 418
    .line 419
    move-result v5

    .line 420
    if-eqz v5, :cond_c

    .line 421
    .line 422
    iget-object v5, v4, Ld01/k0;->b:Ljava/lang/String;

    .line 423
    .line 424
    invoke-virtual {v7, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 425
    .line 426
    .line 427
    move-result v5

    .line 428
    if-eqz v5, :cond_c

    .line 429
    .line 430
    iget-object v5, v3, Ld01/t0;->i:Ld01/y;

    .line 431
    .line 432
    invoke-static {v5}, Ljp/pe;->d(Ld01/y;)Ljava/util/Set;

    .line 433
    .line 434
    .line 435
    move-result-object v5

    .line 436
    check-cast v5, Ljava/lang/Iterable;

    .line 437
    .line 438
    instance-of v6, v5, Ljava/util/Collection;

    .line 439
    .line 440
    if-eqz v6, :cond_a

    .line 441
    .line 442
    move-object v6, v5

    .line 443
    check-cast v6, Ljava/util/Collection;

    .line 444
    .line 445
    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    .line 446
    .line 447
    .line 448
    move-result v6

    .line 449
    if-eqz v6, :cond_a

    .line 450
    .line 451
    goto :goto_4

    .line 452
    :cond_a
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 453
    .line 454
    .line 455
    move-result-object v5

    .line 456
    :cond_b
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 457
    .line 458
    .line 459
    move-result v6

    .line 460
    if-eqz v6, :cond_e

    .line 461
    .line 462
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v6

    .line 466
    check-cast v6, Ljava/lang/String;

    .line 467
    .line 468
    invoke-virtual {v8, v6}, Ld01/y;->m(Ljava/lang/String;)Ljava/util/List;

    .line 469
    .line 470
    .line 471
    move-result-object v7

    .line 472
    iget-object v9, v4, Ld01/k0;->c:Ld01/y;

    .line 473
    .line 474
    invoke-virtual {v9, v6}, Ld01/y;->m(Ljava/lang/String;)Ljava/util/List;

    .line 475
    .line 476
    .line 477
    move-result-object v6

    .line 478
    invoke-virtual {v7, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 479
    .line 480
    .line 481
    move-result v6

    .line 482
    if-nez v6, :cond_b

    .line 483
    .line 484
    :cond_c
    iget-object v3, v3, Ld01/t0;->j:Ld01/v0;

    .line 485
    .line 486
    invoke-static {v3}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 487
    .line 488
    .line 489
    goto :goto_3

    .line 490
    :catch_0
    invoke-static {v3}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 491
    .line 492
    .line 493
    :catch_1
    :cond_d
    :goto_3
    move-object v3, v2

    .line 494
    :cond_e
    :goto_4
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 495
    .line 496
    .line 497
    move-result-wide v4

    .line 498
    iget-object v6, v1, Li01/f;->e:Ld01/k0;

    .line 499
    .line 500
    const-string v7, "request"

    .line 501
    .line 502
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 503
    .line 504
    .line 505
    if-eqz v3, :cond_15

    .line 506
    .line 507
    iget-wide v10, v3, Ld01/t0;->o:J

    .line 508
    .line 509
    iget-wide v12, v3, Ld01/t0;->p:J

    .line 510
    .line 511
    iget-object v14, v3, Ld01/t0;->i:Ld01/y;

    .line 512
    .line 513
    invoke-virtual {v14}, Ld01/y;->size()I

    .line 514
    .line 515
    .line 516
    move-result v15

    .line 517
    move-object v9, v2

    .line 518
    move-object/from16 v21, v9

    .line 519
    .line 520
    move-object/from16 v22, v21

    .line 521
    .line 522
    move-object/from16 v24, v22

    .line 523
    .line 524
    move-object/from16 v25, v24

    .line 525
    .line 526
    move-object/from16 v26, v25

    .line 527
    .line 528
    const/4 v8, 0x0

    .line 529
    const/16 v23, -0x1

    .line 530
    .line 531
    :goto_5
    if-ge v8, v15, :cond_14

    .line 532
    .line 533
    invoke-virtual {v14, v8}, Ld01/y;->e(I)Ljava/lang/String;

    .line 534
    .line 535
    .line 536
    move-result-object v2

    .line 537
    invoke-virtual {v14, v8}, Ld01/y;->k(I)Ljava/lang/String;

    .line 538
    .line 539
    .line 540
    move-result-object v7

    .line 541
    move-wide/from16 v28, v4

    .line 542
    .line 543
    const-string v4, "Date"

    .line 544
    .line 545
    invoke-virtual {v2, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 546
    .line 547
    .line 548
    move-result v4

    .line 549
    if-eqz v4, :cond_f

    .line 550
    .line 551
    invoke-static {v7}, Li01/b;->a(Ljava/lang/String;)Ljava/util/Date;

    .line 552
    .line 553
    .line 554
    move-result-object v22

    .line 555
    move-object/from16 v26, v7

    .line 556
    .line 557
    goto :goto_6

    .line 558
    :cond_f
    const-string v4, "Expires"

    .line 559
    .line 560
    invoke-virtual {v2, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 561
    .line 562
    .line 563
    move-result v4

    .line 564
    if-eqz v4, :cond_10

    .line 565
    .line 566
    invoke-static {v7}, Li01/b;->a(Ljava/lang/String;)Ljava/util/Date;

    .line 567
    .line 568
    .line 569
    move-result-object v9

    .line 570
    goto :goto_6

    .line 571
    :cond_10
    const-string v4, "Last-Modified"

    .line 572
    .line 573
    invoke-virtual {v2, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 574
    .line 575
    .line 576
    move-result v4

    .line 577
    if-eqz v4, :cond_11

    .line 578
    .line 579
    invoke-static {v7}, Li01/b;->a(Ljava/lang/String;)Ljava/util/Date;

    .line 580
    .line 581
    .line 582
    move-result-object v21

    .line 583
    move-object/from16 v25, v7

    .line 584
    .line 585
    goto :goto_6

    .line 586
    :cond_11
    const-string v4, "ETag"

    .line 587
    .line 588
    invoke-virtual {v2, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 589
    .line 590
    .line 591
    move-result v4

    .line 592
    if-eqz v4, :cond_12

    .line 593
    .line 594
    move-object/from16 v24, v7

    .line 595
    .line 596
    goto :goto_6

    .line 597
    :cond_12
    const-string v4, "Age"

    .line 598
    .line 599
    invoke-virtual {v2, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 600
    .line 601
    .line 602
    move-result v2

    .line 603
    if-eqz v2, :cond_13

    .line 604
    .line 605
    const/4 v2, -0x1

    .line 606
    invoke-static {v2, v7}, Le01/e;->p(ILjava/lang/String;)I

    .line 607
    .line 608
    .line 609
    move-result v23

    .line 610
    :cond_13
    :goto_6
    add-int/lit8 v8, v8, 0x1

    .line 611
    .line 612
    move-wide/from16 v4, v28

    .line 613
    .line 614
    const/4 v2, 0x0

    .line 615
    goto :goto_5

    .line 616
    :cond_14
    move/from16 v2, v23

    .line 617
    .line 618
    :goto_7
    move-wide/from16 v28, v4

    .line 619
    .line 620
    goto :goto_8

    .line 621
    :cond_15
    const/4 v2, -0x1

    .line 622
    const/4 v9, 0x0

    .line 623
    const-wide/16 v10, 0x0

    .line 624
    .line 625
    const-wide/16 v12, 0x0

    .line 626
    .line 627
    const/16 v21, 0x0

    .line 628
    .line 629
    const/16 v22, 0x0

    .line 630
    .line 631
    const/16 v24, 0x0

    .line 632
    .line 633
    const/16 v25, 0x0

    .line 634
    .line 635
    const/16 v26, 0x0

    .line 636
    .line 637
    goto :goto_7

    .line 638
    :goto_8
    const-string v4, "If-None-Match"

    .line 639
    .line 640
    const-string v5, "If-Modified-Since"

    .line 641
    .line 642
    const/4 v7, 0x5

    .line 643
    if-nez v3, :cond_16

    .line 644
    .line 645
    new-instance v2, Lb81/c;

    .line 646
    .line 647
    const/4 v8, 0x0

    .line 648
    invoke-direct {v2, v7, v6, v8}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 649
    .line 650
    .line 651
    :goto_9
    move v15, v7

    .line 652
    goto/16 :goto_17

    .line 653
    .line 654
    :cond_16
    const/4 v8, 0x0

    .line 655
    iget-object v14, v6, Ld01/k0;->a:Ld01/a0;

    .line 656
    .line 657
    invoke-virtual {v14}, Ld01/a0;->f()Z

    .line 658
    .line 659
    .line 660
    move-result v14

    .line 661
    if-eqz v14, :cond_17

    .line 662
    .line 663
    iget-object v14, v3, Ld01/t0;->h:Ld01/w;

    .line 664
    .line 665
    if-nez v14, :cond_17

    .line 666
    .line 667
    new-instance v2, Lb81/c;

    .line 668
    .line 669
    invoke-direct {v2, v7, v6, v8}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 670
    .line 671
    .line 672
    goto :goto_9

    .line 673
    :cond_17
    invoke-static {v3, v6}, Lkp/a7;->e(Ld01/t0;Ld01/k0;)Z

    .line 674
    .line 675
    .line 676
    move-result v14

    .line 677
    if-nez v14, :cond_18

    .line 678
    .line 679
    new-instance v2, Lb81/c;

    .line 680
    .line 681
    invoke-direct {v2, v7, v6, v8}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 682
    .line 683
    .line 684
    goto :goto_9

    .line 685
    :cond_18
    invoke-virtual {v6}, Ld01/k0;->a()Ld01/h;

    .line 686
    .line 687
    .line 688
    move-result-object v8

    .line 689
    iget-boolean v14, v8, Ld01/h;->a:Z

    .line 690
    .line 691
    if-nez v14, :cond_2d

    .line 692
    .line 693
    iget-object v14, v6, Ld01/k0;->c:Ld01/y;

    .line 694
    .line 695
    invoke-virtual {v14, v5}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 696
    .line 697
    .line 698
    move-result-object v14

    .line 699
    if-nez v14, :cond_2d

    .line 700
    .line 701
    iget-object v14, v6, Ld01/k0;->c:Ld01/y;

    .line 702
    .line 703
    invoke-virtual {v14, v4}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 704
    .line 705
    .line 706
    move-result-object v14

    .line 707
    if-eqz v14, :cond_19

    .line 708
    .line 709
    goto/16 :goto_16

    .line 710
    .line 711
    :cond_19
    invoke-virtual {v3}, Ld01/t0;->a()Ld01/h;

    .line 712
    .line 713
    .line 714
    move-result-object v14

    .line 715
    if-eqz v22, :cond_1a

    .line 716
    .line 717
    invoke-virtual/range {v22 .. v22}, Ljava/util/Date;->getTime()J

    .line 718
    .line 719
    .line 720
    move-result-wide v30

    .line 721
    move-object/from16 v23, v8

    .line 722
    .line 723
    sub-long v7, v12, v30

    .line 724
    .line 725
    move-object/from16 v30, v4

    .line 726
    .line 727
    move-object/from16 v31, v5

    .line 728
    .line 729
    const-wide/16 v4, 0x0

    .line 730
    .line 731
    invoke-static {v4, v5, v7, v8}, Ljava/lang/Math;->max(JJ)J

    .line 732
    .line 733
    .line 734
    move-result-wide v19

    .line 735
    move-wide/from16 v7, v19

    .line 736
    .line 737
    :goto_a
    const/4 v15, -0x1

    .line 738
    goto :goto_b

    .line 739
    :cond_1a
    move-object/from16 v30, v4

    .line 740
    .line 741
    move-object/from16 v31, v5

    .line 742
    .line 743
    move-object/from16 v23, v8

    .line 744
    .line 745
    const-wide/16 v4, 0x0

    .line 746
    .line 747
    move-wide v7, v4

    .line 748
    goto :goto_a

    .line 749
    :goto_b
    if-eq v2, v15, :cond_1b

    .line 750
    .line 751
    sget-object v15, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 752
    .line 753
    int-to-long v4, v2

    .line 754
    invoke-virtual {v15, v4, v5}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 755
    .line 756
    .line 757
    move-result-wide v4

    .line 758
    invoke-static {v7, v8, v4, v5}, Ljava/lang/Math;->max(JJ)J

    .line 759
    .line 760
    .line 761
    move-result-wide v7

    .line 762
    :cond_1b
    sub-long v4, v12, v10

    .line 763
    .line 764
    move-wide/from16 v33, v7

    .line 765
    .line 766
    const-wide/16 v7, 0x0

    .line 767
    .line 768
    invoke-static {v7, v8, v4, v5}, Ljava/lang/Math;->max(JJ)J

    .line 769
    .line 770
    .line 771
    move-result-wide v4

    .line 772
    move-wide/from16 v35, v4

    .line 773
    .line 774
    sub-long v4, v28, v12

    .line 775
    .line 776
    invoke-static {v7, v8, v4, v5}, Ljava/lang/Math;->max(JJ)J

    .line 777
    .line 778
    .line 779
    move-result-wide v4

    .line 780
    add-long v7, v33, v35

    .line 781
    .line 782
    add-long/2addr v7, v4

    .line 783
    invoke-virtual {v3}, Ld01/t0;->a()Ld01/h;

    .line 784
    .line 785
    .line 786
    move-result-object v2

    .line 787
    iget v2, v2, Ld01/h;->c:I

    .line 788
    .line 789
    const/4 v15, -0x1

    .line 790
    if-eq v2, v15, :cond_1c

    .line 791
    .line 792
    sget-object v4, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 793
    .line 794
    int-to-long v10, v2

    .line 795
    invoke-virtual {v4, v10, v11}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 796
    .line 797
    .line 798
    move-result-wide v4

    .line 799
    :goto_c
    move-object/from16 v2, v23

    .line 800
    .line 801
    :goto_d
    const-wide/16 v19, 0x0

    .line 802
    .line 803
    goto :goto_11

    .line 804
    :cond_1c
    if-eqz v9, :cond_1f

    .line 805
    .line 806
    if-eqz v22, :cond_1d

    .line 807
    .line 808
    invoke-virtual/range {v22 .. v22}, Ljava/util/Date;->getTime()J

    .line 809
    .line 810
    .line 811
    move-result-wide v12

    .line 812
    :cond_1d
    invoke-virtual {v9}, Ljava/util/Date;->getTime()J

    .line 813
    .line 814
    .line 815
    move-result-wide v4

    .line 816
    sub-long/2addr v4, v12

    .line 817
    const-wide/16 v19, 0x0

    .line 818
    .line 819
    cmp-long v2, v4, v19

    .line 820
    .line 821
    if-lez v2, :cond_1e

    .line 822
    .line 823
    goto :goto_c

    .line 824
    :cond_1e
    move-object/from16 v2, v23

    .line 825
    .line 826
    const-wide/16 v4, 0x0

    .line 827
    .line 828
    goto :goto_d

    .line 829
    :cond_1f
    if-eqz v21, :cond_23

    .line 830
    .line 831
    iget-object v2, v3, Ld01/t0;->d:Ld01/k0;

    .line 832
    .line 833
    iget-object v2, v2, Ld01/k0;->a:Ld01/a0;

    .line 834
    .line 835
    iget-object v2, v2, Ld01/a0;->g:Ljava/util/List;

    .line 836
    .line 837
    if-nez v2, :cond_20

    .line 838
    .line 839
    const/4 v2, 0x0

    .line 840
    goto :goto_e

    .line 841
    :cond_20
    new-instance v4, Ljava/lang/StringBuilder;

    .line 842
    .line 843
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 844
    .line 845
    .line 846
    invoke-static {v2, v4}, Ld01/r;->b(Ljava/util/List;Ljava/lang/StringBuilder;)V

    .line 847
    .line 848
    .line 849
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 850
    .line 851
    .line 852
    move-result-object v2

    .line 853
    :goto_e
    if-nez v2, :cond_23

    .line 854
    .line 855
    if-eqz v22, :cond_21

    .line 856
    .line 857
    invoke-virtual/range {v22 .. v22}, Ljava/util/Date;->getTime()J

    .line 858
    .line 859
    .line 860
    move-result-wide v10

    .line 861
    :cond_21
    invoke-virtual/range {v21 .. v21}, Ljava/util/Date;->getTime()J

    .line 862
    .line 863
    .line 864
    move-result-wide v4

    .line 865
    sub-long/2addr v10, v4

    .line 866
    const-wide/16 v19, 0x0

    .line 867
    .line 868
    cmp-long v2, v10, v19

    .line 869
    .line 870
    if-lez v2, :cond_22

    .line 871
    .line 872
    const/16 v2, 0xa

    .line 873
    .line 874
    int-to-long v4, v2

    .line 875
    div-long v4, v10, v4

    .line 876
    .line 877
    :goto_f
    move-object/from16 v2, v23

    .line 878
    .line 879
    goto :goto_11

    .line 880
    :cond_22
    :goto_10
    move-wide/from16 v4, v19

    .line 881
    .line 882
    goto :goto_f

    .line 883
    :cond_23
    const-wide/16 v19, 0x0

    .line 884
    .line 885
    goto :goto_10

    .line 886
    :goto_11
    iget v10, v2, Ld01/h;->c:I

    .line 887
    .line 888
    const/4 v15, -0x1

    .line 889
    if-eq v10, v15, :cond_24

    .line 890
    .line 891
    sget-object v11, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 892
    .line 893
    int-to-long v12, v10

    .line 894
    invoke-virtual {v11, v12, v13}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 895
    .line 896
    .line 897
    move-result-wide v10

    .line 898
    invoke-static {v4, v5, v10, v11}, Ljava/lang/Math;->min(JJ)J

    .line 899
    .line 900
    .line 901
    move-result-wide v4

    .line 902
    :cond_24
    iget v10, v2, Ld01/h;->i:I

    .line 903
    .line 904
    if-eq v10, v15, :cond_25

    .line 905
    .line 906
    sget-object v11, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 907
    .line 908
    int-to-long v12, v10

    .line 909
    invoke-virtual {v11, v12, v13}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 910
    .line 911
    .line 912
    move-result-wide v10

    .line 913
    goto :goto_12

    .line 914
    :cond_25
    move-wide/from16 v10, v19

    .line 915
    .line 916
    :goto_12
    iget-boolean v12, v14, Ld01/h;->g:Z

    .line 917
    .line 918
    if-nez v12, :cond_26

    .line 919
    .line 920
    iget v2, v2, Ld01/h;->h:I

    .line 921
    .line 922
    if-eq v2, v15, :cond_26

    .line 923
    .line 924
    sget-object v12, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 925
    .line 926
    move-wide/from16 v28, v4

    .line 927
    .line 928
    int-to-long v4, v2

    .line 929
    invoke-virtual {v12, v4, v5}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 930
    .line 931
    .line 932
    move-result-wide v4

    .line 933
    goto :goto_13

    .line 934
    :cond_26
    move-wide/from16 v28, v4

    .line 935
    .line 936
    move-wide/from16 v4, v19

    .line 937
    .line 938
    :goto_13
    iget-boolean v2, v14, Ld01/h;->a:Z

    .line 939
    .line 940
    if-nez v2, :cond_29

    .line 941
    .line 942
    add-long/2addr v10, v7

    .line 943
    add-long v4, v28, v4

    .line 944
    .line 945
    cmp-long v2, v10, v4

    .line 946
    .line 947
    if-gez v2, :cond_29

    .line 948
    .line 949
    invoke-virtual {v3}, Ld01/t0;->d()Ld01/s0;

    .line 950
    .line 951
    .line 952
    move-result-object v2

    .line 953
    cmp-long v4, v10, v28

    .line 954
    .line 955
    if-ltz v4, :cond_27

    .line 956
    .line 957
    const-string v4, "110 HttpURLConnection \"Response is stale\""

    .line 958
    .line 959
    const-string v5, "Warning"

    .line 960
    .line 961
    iget-object v10, v2, Ld01/s0;->f:Ld01/x;

    .line 962
    .line 963
    invoke-virtual {v10, v5, v4}, Ld01/x;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 964
    .line 965
    .line 966
    :cond_27
    const-wide/32 v4, 0x5265c00

    .line 967
    .line 968
    .line 969
    cmp-long v4, v7, v4

    .line 970
    .line 971
    if-lez v4, :cond_28

    .line 972
    .line 973
    invoke-virtual {v3}, Ld01/t0;->a()Ld01/h;

    .line 974
    .line 975
    .line 976
    move-result-object v4

    .line 977
    iget v4, v4, Ld01/h;->c:I

    .line 978
    .line 979
    const/4 v15, -0x1

    .line 980
    if-ne v4, v15, :cond_28

    .line 981
    .line 982
    if-nez v9, :cond_28

    .line 983
    .line 984
    const-string v4, "113 HttpURLConnection \"Heuristic expiration\""

    .line 985
    .line 986
    const-string v5, "Warning"

    .line 987
    .line 988
    iget-object v7, v2, Ld01/s0;->f:Ld01/x;

    .line 989
    .line 990
    invoke-virtual {v7, v5, v4}, Ld01/x;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 991
    .line 992
    .line 993
    :cond_28
    new-instance v4, Lb81/c;

    .line 994
    .line 995
    invoke-virtual {v2}, Ld01/s0;->a()Ld01/t0;

    .line 996
    .line 997
    .line 998
    move-result-object v2

    .line 999
    const/4 v8, 0x0

    .line 1000
    const/4 v15, 0x5

    .line 1001
    invoke-direct {v4, v15, v8, v2}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1002
    .line 1003
    .line 1004
    move-object v2, v4

    .line 1005
    const/4 v15, 0x5

    .line 1006
    goto :goto_17

    .line 1007
    :cond_29
    if-eqz v24, :cond_2a

    .line 1008
    .line 1009
    move-object/from16 v2, v24

    .line 1010
    .line 1011
    move-object/from16 v4, v30

    .line 1012
    .line 1013
    goto :goto_15

    .line 1014
    :cond_2a
    if-eqz v21, :cond_2b

    .line 1015
    .line 1016
    move-object/from16 v2, v25

    .line 1017
    .line 1018
    :goto_14
    move-object/from16 v4, v31

    .line 1019
    .line 1020
    goto :goto_15

    .line 1021
    :cond_2b
    if-eqz v22, :cond_2c

    .line 1022
    .line 1023
    move-object/from16 v2, v26

    .line 1024
    .line 1025
    goto :goto_14

    .line 1026
    :goto_15
    iget-object v5, v6, Ld01/k0;->c:Ld01/y;

    .line 1027
    .line 1028
    invoke-virtual {v5}, Ld01/y;->g()Ld01/x;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v5

    .line 1032
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1033
    .line 1034
    .line 1035
    invoke-virtual {v5, v4, v2}, Ld01/x;->f(Ljava/lang/String;Ljava/lang/String;)V

    .line 1036
    .line 1037
    .line 1038
    invoke-virtual {v6}, Ld01/k0;->b()Ld01/j0;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v2

    .line 1042
    invoke-virtual {v5}, Ld01/x;->j()Ld01/y;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v4

    .line 1046
    invoke-virtual {v2, v4}, Ld01/j0;->d(Ld01/y;)V

    .line 1047
    .line 1048
    .line 1049
    new-instance v4, Ld01/k0;

    .line 1050
    .line 1051
    invoke-direct {v4, v2}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 1052
    .line 1053
    .line 1054
    new-instance v2, Lb81/c;

    .line 1055
    .line 1056
    const/4 v15, 0x5

    .line 1057
    invoke-direct {v2, v15, v4, v3}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1058
    .line 1059
    .line 1060
    const/4 v8, 0x0

    .line 1061
    goto :goto_17

    .line 1062
    :cond_2c
    const/4 v15, 0x5

    .line 1063
    new-instance v2, Lb81/c;

    .line 1064
    .line 1065
    const/4 v8, 0x0

    .line 1066
    invoke-direct {v2, v15, v6, v8}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1067
    .line 1068
    .line 1069
    goto :goto_17

    .line 1070
    :cond_2d
    :goto_16
    move v15, v7

    .line 1071
    const/4 v8, 0x0

    .line 1072
    new-instance v2, Lb81/c;

    .line 1073
    .line 1074
    invoke-direct {v2, v15, v6, v8}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1075
    .line 1076
    .line 1077
    :goto_17
    iget-object v4, v2, Lb81/c;->e:Ljava/lang/Object;

    .line 1078
    .line 1079
    check-cast v4, Ld01/k0;

    .line 1080
    .line 1081
    if-eqz v4, :cond_2e

    .line 1082
    .line 1083
    invoke-virtual {v6}, Ld01/k0;->a()Ld01/h;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v4

    .line 1087
    iget-boolean v4, v4, Ld01/h;->j:Z

    .line 1088
    .line 1089
    if-eqz v4, :cond_2e

    .line 1090
    .line 1091
    new-instance v2, Lb81/c;

    .line 1092
    .line 1093
    invoke-direct {v2, v15, v8, v8}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1094
    .line 1095
    .line 1096
    :cond_2e
    iget-object v4, v2, Lb81/c;->e:Ljava/lang/Object;

    .line 1097
    .line 1098
    check-cast v4, Ld01/k0;

    .line 1099
    .line 1100
    iget-object v2, v2, Lb81/c;->f:Ljava/lang/Object;

    .line 1101
    .line 1102
    check-cast v2, Ld01/t0;

    .line 1103
    .line 1104
    iget-object v5, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 1105
    .line 1106
    check-cast v5, Ld01/g;

    .line 1107
    .line 1108
    if-eqz v5, :cond_2f

    .line 1109
    .line 1110
    monitor-enter v5

    .line 1111
    monitor-exit v5

    .line 1112
    :cond_2f
    if-eqz v3, :cond_30

    .line 1113
    .line 1114
    if-nez v2, :cond_30

    .line 1115
    .line 1116
    iget-object v5, v3, Ld01/t0;->j:Ld01/v0;

    .line 1117
    .line 1118
    invoke-static {v5}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 1119
    .line 1120
    .line 1121
    :cond_30
    if-nez v4, :cond_31

    .line 1122
    .line 1123
    if-nez v2, :cond_31

    .line 1124
    .line 1125
    sget-object v34, Ld01/v0;->d:Ld01/u0;

    .line 1126
    .line 1127
    sget-object v44, Ld01/y0;->v0:Ld01/r;

    .line 1128
    .line 1129
    new-instance v0, Ljava/util/ArrayList;

    .line 1130
    .line 1131
    const/16 v2, 0x14

    .line 1132
    .line 1133
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1134
    .line 1135
    .line 1136
    iget-object v1, v1, Li01/f;->e:Ld01/k0;

    .line 1137
    .line 1138
    const-string v2, "request"

    .line 1139
    .line 1140
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1141
    .line 1142
    .line 1143
    sget-object v29, Ld01/i0;->g:Ld01/i0;

    .line 1144
    .line 1145
    const-string v30, "Unsatisfiable Request (only-if-cached)"

    .line 1146
    .line 1147
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1148
    .line 1149
    .line 1150
    move-result-wide v41

    .line 1151
    new-instance v2, Ld01/y;

    .line 1152
    .line 1153
    const/4 v6, 0x0

    .line 1154
    new-array v3, v6, [Ljava/lang/String;

    .line 1155
    .line 1156
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v0

    .line 1160
    check-cast v0, [Ljava/lang/String;

    .line 1161
    .line 1162
    invoke-direct {v2, v0}, Ld01/y;-><init>([Ljava/lang/String;)V

    .line 1163
    .line 1164
    .line 1165
    new-instance v27, Ld01/t0;

    .line 1166
    .line 1167
    const/16 v31, 0x1f8

    .line 1168
    .line 1169
    const/16 v32, 0x0

    .line 1170
    .line 1171
    const/16 v35, 0x0

    .line 1172
    .line 1173
    const/16 v36, 0x0

    .line 1174
    .line 1175
    const/16 v37, 0x0

    .line 1176
    .line 1177
    const/16 v38, 0x0

    .line 1178
    .line 1179
    const-wide/16 v39, -0x1

    .line 1180
    .line 1181
    const/16 v43, 0x0

    .line 1182
    .line 1183
    move-object/from16 v28, v1

    .line 1184
    .line 1185
    move-object/from16 v33, v2

    .line 1186
    .line 1187
    invoke-direct/range {v27 .. v44}, Ld01/t0;-><init>(Ld01/k0;Ld01/i0;Ljava/lang/String;ILd01/w;Ld01/y;Ld01/v0;Lu01/g0;Ld01/t0;Ld01/t0;Ld01/t0;JJLh01/g;Ld01/y0;)V

    .line 1188
    .line 1189
    .line 1190
    goto/16 :goto_22

    .line 1191
    .line 1192
    :cond_31
    if-nez v4, :cond_32

    .line 1193
    .line 1194
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1195
    .line 1196
    .line 1197
    invoke-virtual {v2}, Ld01/t0;->d()Ld01/s0;

    .line 1198
    .line 1199
    .line 1200
    move-result-object v0

    .line 1201
    invoke-static {v2}, Ljp/qg;->b(Ld01/t0;)Ld01/t0;

    .line 1202
    .line 1203
    .line 1204
    move-result-object v1

    .line 1205
    const-string v2, "cacheResponse"

    .line 1206
    .line 1207
    invoke-static {v1, v2}, Ld01/s0;->b(Ld01/t0;Ljava/lang/String;)V

    .line 1208
    .line 1209
    .line 1210
    iput-object v1, v0, Ld01/s0;->j:Ld01/t0;

    .line 1211
    .line 1212
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 1213
    .line 1214
    .line 1215
    move-result-object v27

    .line 1216
    goto/16 :goto_22

    .line 1217
    .line 1218
    :cond_32
    :try_start_2
    move-object/from16 v1, p1

    .line 1219
    .line 1220
    check-cast v1, Li01/f;

    .line 1221
    .line 1222
    invoke-virtual {v1, v4}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 1223
    .line 1224
    .line 1225
    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 1226
    if-eqz v2, :cond_3e

    .line 1227
    .line 1228
    iget v3, v1, Ld01/t0;->g:I

    .line 1229
    .line 1230
    const/16 v5, 0x130

    .line 1231
    .line 1232
    if-ne v3, v5, :cond_3d

    .line 1233
    .line 1234
    invoke-virtual {v2}, Ld01/t0;->d()Ld01/s0;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v3

    .line 1238
    iget-object v4, v2, Ld01/t0;->i:Ld01/y;

    .line 1239
    .line 1240
    iget-object v5, v1, Ld01/t0;->i:Ld01/y;

    .line 1241
    .line 1242
    new-instance v6, Ld01/x;

    .line 1243
    .line 1244
    const/4 v8, 0x0

    .line 1245
    invoke-direct {v6, v8, v8}, Ld01/x;-><init>(BI)V

    .line 1246
    .line 1247
    .line 1248
    invoke-virtual {v4}, Ld01/y;->size()I

    .line 1249
    .line 1250
    .line 1251
    move-result v7

    .line 1252
    move v9, v8

    .line 1253
    :goto_18
    if-ge v9, v7, :cond_37

    .line 1254
    .line 1255
    invoke-virtual {v4, v9}, Ld01/y;->e(I)Ljava/lang/String;

    .line 1256
    .line 1257
    .line 1258
    move-result-object v10

    .line 1259
    invoke-virtual {v4, v9}, Ld01/y;->k(I)Ljava/lang/String;

    .line 1260
    .line 1261
    .line 1262
    move-result-object v11

    .line 1263
    const-string v12, "Warning"

    .line 1264
    .line 1265
    invoke-virtual {v12, v10}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1266
    .line 1267
    .line 1268
    move-result v12

    .line 1269
    if-eqz v12, :cond_33

    .line 1270
    .line 1271
    const-string v12, "1"

    .line 1272
    .line 1273
    invoke-static {v11, v12, v8}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 1274
    .line 1275
    .line 1276
    move-result v12

    .line 1277
    if-eqz v12, :cond_33

    .line 1278
    .line 1279
    goto :goto_1a

    .line 1280
    :cond_33
    const-string v8, "Content-Length"

    .line 1281
    .line 1282
    invoke-virtual {v8, v10}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1283
    .line 1284
    .line 1285
    move-result v8

    .line 1286
    if-nez v8, :cond_35

    .line 1287
    .line 1288
    const-string v8, "Content-Encoding"

    .line 1289
    .line 1290
    invoke-virtual {v8, v10}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1291
    .line 1292
    .line 1293
    move-result v8

    .line 1294
    if-nez v8, :cond_35

    .line 1295
    .line 1296
    const-string v8, "Content-Type"

    .line 1297
    .line 1298
    invoke-virtual {v8, v10}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1299
    .line 1300
    .line 1301
    move-result v8

    .line 1302
    if-eqz v8, :cond_34

    .line 1303
    .line 1304
    goto :goto_19

    .line 1305
    :cond_34
    invoke-static {v10}, Lkp/y6;->a(Ljava/lang/String;)Z

    .line 1306
    .line 1307
    .line 1308
    move-result v8

    .line 1309
    if-eqz v8, :cond_35

    .line 1310
    .line 1311
    invoke-virtual {v5, v10}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 1312
    .line 1313
    .line 1314
    move-result-object v8

    .line 1315
    if-nez v8, :cond_36

    .line 1316
    .line 1317
    :cond_35
    :goto_19
    invoke-virtual {v6, v10, v11}, Ld01/x;->f(Ljava/lang/String;Ljava/lang/String;)V

    .line 1318
    .line 1319
    .line 1320
    :cond_36
    :goto_1a
    add-int/lit8 v9, v9, 0x1

    .line 1321
    .line 1322
    const/4 v8, 0x0

    .line 1323
    goto :goto_18

    .line 1324
    :cond_37
    invoke-virtual {v5}, Ld01/y;->size()I

    .line 1325
    .line 1326
    .line 1327
    move-result v4

    .line 1328
    const/4 v7, 0x0

    .line 1329
    :goto_1b
    if-ge v7, v4, :cond_3a

    .line 1330
    .line 1331
    invoke-virtual {v5, v7}, Ld01/y;->e(I)Ljava/lang/String;

    .line 1332
    .line 1333
    .line 1334
    move-result-object v8

    .line 1335
    const-string v9, "Content-Length"

    .line 1336
    .line 1337
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1338
    .line 1339
    .line 1340
    move-result v9

    .line 1341
    if-nez v9, :cond_39

    .line 1342
    .line 1343
    const-string v9, "Content-Encoding"

    .line 1344
    .line 1345
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1346
    .line 1347
    .line 1348
    move-result v9

    .line 1349
    if-nez v9, :cond_39

    .line 1350
    .line 1351
    const-string v9, "Content-Type"

    .line 1352
    .line 1353
    invoke-virtual {v9, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1354
    .line 1355
    .line 1356
    move-result v9

    .line 1357
    if-eqz v9, :cond_38

    .line 1358
    .line 1359
    goto :goto_1c

    .line 1360
    :cond_38
    invoke-static {v8}, Lkp/y6;->a(Ljava/lang/String;)Z

    .line 1361
    .line 1362
    .line 1363
    move-result v9

    .line 1364
    if-eqz v9, :cond_39

    .line 1365
    .line 1366
    invoke-virtual {v5, v7}, Ld01/y;->k(I)Ljava/lang/String;

    .line 1367
    .line 1368
    .line 1369
    move-result-object v9

    .line 1370
    invoke-virtual {v6, v8, v9}, Ld01/x;->f(Ljava/lang/String;Ljava/lang/String;)V

    .line 1371
    .line 1372
    .line 1373
    :cond_39
    :goto_1c
    add-int/lit8 v7, v7, 0x1

    .line 1374
    .line 1375
    goto :goto_1b

    .line 1376
    :cond_3a
    invoke-virtual {v6}, Ld01/x;->j()Ld01/y;

    .line 1377
    .line 1378
    .line 1379
    move-result-object v4

    .line 1380
    invoke-virtual {v3, v4}, Ld01/s0;->c(Ld01/y;)V

    .line 1381
    .line 1382
    .line 1383
    iget-wide v4, v1, Ld01/t0;->o:J

    .line 1384
    .line 1385
    iput-wide v4, v3, Ld01/s0;->l:J

    .line 1386
    .line 1387
    iget-wide v4, v1, Ld01/t0;->p:J

    .line 1388
    .line 1389
    iput-wide v4, v3, Ld01/s0;->m:J

    .line 1390
    .line 1391
    invoke-static {v2}, Ljp/qg;->b(Ld01/t0;)Ld01/t0;

    .line 1392
    .line 1393
    .line 1394
    move-result-object v4

    .line 1395
    const-string v5, "cacheResponse"

    .line 1396
    .line 1397
    invoke-static {v4, v5}, Ld01/s0;->b(Ld01/t0;Ljava/lang/String;)V

    .line 1398
    .line 1399
    .line 1400
    iput-object v4, v3, Ld01/s0;->j:Ld01/t0;

    .line 1401
    .line 1402
    invoke-static {v1}, Ljp/qg;->b(Ld01/t0;)Ld01/t0;

    .line 1403
    .line 1404
    .line 1405
    move-result-object v4

    .line 1406
    const-string v5, "networkResponse"

    .line 1407
    .line 1408
    invoke-static {v4, v5}, Ld01/s0;->b(Ld01/t0;Ljava/lang/String;)V

    .line 1409
    .line 1410
    .line 1411
    iput-object v4, v3, Ld01/s0;->i:Ld01/t0;

    .line 1412
    .line 1413
    invoke-virtual {v3}, Ld01/s0;->a()Ld01/t0;

    .line 1414
    .line 1415
    .line 1416
    move-result-object v3

    .line 1417
    iget-object v1, v1, Ld01/t0;->j:Ld01/v0;

    .line 1418
    .line 1419
    invoke-virtual {v1}, Ld01/v0;->close()V

    .line 1420
    .line 1421
    .line 1422
    iget-object v1, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 1423
    .line 1424
    check-cast v1, Ld01/g;

    .line 1425
    .line 1426
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1427
    .line 1428
    .line 1429
    monitor-enter v1

    .line 1430
    monitor-exit v1

    .line 1431
    iget-object v0, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 1432
    .line 1433
    check-cast v0, Ld01/g;

    .line 1434
    .line 1435
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1436
    .line 1437
    .line 1438
    new-instance v0, Ld01/e;

    .line 1439
    .line 1440
    invoke-direct {v0, v3}, Ld01/e;-><init>(Ld01/t0;)V

    .line 1441
    .line 1442
    .line 1443
    iget-object v1, v2, Ld01/t0;->j:Ld01/v0;

    .line 1444
    .line 1445
    const-string v2, "null cannot be cast to non-null type okhttp3.Cache.CacheResponseBody"

    .line 1446
    .line 1447
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1448
    .line 1449
    .line 1450
    check-cast v1, Ld01/d;

    .line 1451
    .line 1452
    iget-object v1, v1, Ld01/d;->e:Lf01/d;

    .line 1453
    .line 1454
    :try_start_3
    iget-object v2, v1, Lf01/d;->g:Lf01/g;

    .line 1455
    .line 1456
    iget-object v4, v1, Lf01/d;->d:Ljava/lang/String;

    .line 1457
    .line 1458
    iget-wide v5, v1, Lf01/d;->e:J

    .line 1459
    .line 1460
    invoke-virtual {v2, v5, v6, v4}, Lf01/g;->d(JLjava/lang/String;)La8/b;

    .line 1461
    .line 1462
    .line 1463
    move-result-object v2
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_2

    .line 1464
    if-nez v2, :cond_3b

    .line 1465
    .line 1466
    goto :goto_1d

    .line 1467
    :cond_3b
    :try_start_4
    invoke-virtual {v0, v2}, Ld01/e;->c(La8/b;)V

    .line 1468
    .line 1469
    .line 1470
    invoke-virtual {v2}, La8/b;->d()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3

    .line 1471
    .line 1472
    .line 1473
    goto :goto_1d

    .line 1474
    :catch_2
    const/4 v2, 0x0

    .line 1475
    :catch_3
    if-eqz v2, :cond_3c

    .line 1476
    .line 1477
    :try_start_5
    invoke-virtual {v2}, La8/b;->b()V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_4

    .line 1478
    .line 1479
    .line 1480
    :catch_4
    :cond_3c
    :goto_1d
    move-object/from16 v27, v3

    .line 1481
    .line 1482
    goto/16 :goto_22

    .line 1483
    .line 1484
    :cond_3d
    iget-object v3, v2, Ld01/t0;->j:Ld01/v0;

    .line 1485
    .line 1486
    invoke-static {v3}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 1487
    .line 1488
    .line 1489
    :cond_3e
    invoke-virtual {v1}, Ld01/t0;->d()Ld01/s0;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v3

    .line 1493
    if-eqz v2, :cond_3f

    .line 1494
    .line 1495
    invoke-static {v2}, Ljp/qg;->b(Ld01/t0;)Ld01/t0;

    .line 1496
    .line 1497
    .line 1498
    move-result-object v8

    .line 1499
    goto :goto_1e

    .line 1500
    :cond_3f
    const/4 v8, 0x0

    .line 1501
    :goto_1e
    const-string v2, "cacheResponse"

    .line 1502
    .line 1503
    invoke-static {v8, v2}, Ld01/s0;->b(Ld01/t0;Ljava/lang/String;)V

    .line 1504
    .line 1505
    .line 1506
    iput-object v8, v3, Ld01/s0;->j:Ld01/t0;

    .line 1507
    .line 1508
    invoke-static {v1}, Ljp/qg;->b(Ld01/t0;)Ld01/t0;

    .line 1509
    .line 1510
    .line 1511
    move-result-object v1

    .line 1512
    const-string v2, "networkResponse"

    .line 1513
    .line 1514
    invoke-static {v1, v2}, Ld01/s0;->b(Ld01/t0;Ljava/lang/String;)V

    .line 1515
    .line 1516
    .line 1517
    iput-object v1, v3, Ld01/s0;->i:Ld01/t0;

    .line 1518
    .line 1519
    invoke-virtual {v3}, Ld01/s0;->a()Ld01/t0;

    .line 1520
    .line 1521
    .line 1522
    move-result-object v1

    .line 1523
    iget-object v2, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 1524
    .line 1525
    check-cast v2, Ld01/g;

    .line 1526
    .line 1527
    if-eqz v2, :cond_47

    .line 1528
    .line 1529
    invoke-static {v1}, Li01/e;->a(Ld01/t0;)Z

    .line 1530
    .line 1531
    .line 1532
    move-result v2

    .line 1533
    if-eqz v2, :cond_46

    .line 1534
    .line 1535
    invoke-static {v1, v4}, Lkp/a7;->e(Ld01/t0;Ld01/k0;)Z

    .line 1536
    .line 1537
    .line 1538
    move-result v2

    .line 1539
    if-eqz v2, :cond_46

    .line 1540
    .line 1541
    iget-object v0, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 1542
    .line 1543
    check-cast v0, Ld01/g;

    .line 1544
    .line 1545
    invoke-virtual {v1}, Ld01/t0;->d()Ld01/s0;

    .line 1546
    .line 1547
    .line 1548
    move-result-object v2

    .line 1549
    iput-object v4, v2, Ld01/s0;->a:Ld01/k0;

    .line 1550
    .line 1551
    invoke-virtual {v2}, Ld01/s0;->a()Ld01/t0;

    .line 1552
    .line 1553
    .line 1554
    move-result-object v2

    .line 1555
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1556
    .line 1557
    .line 1558
    iget-object v3, v2, Ld01/t0;->d:Ld01/k0;

    .line 1559
    .line 1560
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 1561
    .line 1562
    invoke-static {v4}, Llp/l1;->b(Ljava/lang/String;)Z

    .line 1563
    .line 1564
    .line 1565
    move-result v5

    .line 1566
    if-eqz v5, :cond_41

    .line 1567
    .line 1568
    :try_start_6
    invoke-virtual {v0, v3}, Ld01/g;->a(Ld01/k0;)V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_5

    .line 1569
    .line 1570
    .line 1571
    :catch_5
    :cond_40
    :goto_1f
    const/4 v2, 0x0

    .line 1572
    goto :goto_20

    .line 1573
    :cond_41
    const-string v5, "GET"

    .line 1574
    .line 1575
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1576
    .line 1577
    .line 1578
    move-result v4

    .line 1579
    if-nez v4, :cond_42

    .line 1580
    .line 1581
    goto :goto_1f

    .line 1582
    :cond_42
    iget-object v4, v2, Ld01/t0;->i:Ld01/y;

    .line 1583
    .line 1584
    invoke-static {v4}, Ljp/pe;->d(Ld01/y;)Ljava/util/Set;

    .line 1585
    .line 1586
    .line 1587
    move-result-object v4

    .line 1588
    const-string v5, "*"

    .line 1589
    .line 1590
    invoke-interface {v4, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1591
    .line 1592
    .line 1593
    move-result v4

    .line 1594
    if-eqz v4, :cond_43

    .line 1595
    .line 1596
    goto :goto_1f

    .line 1597
    :cond_43
    new-instance v4, Ld01/e;

    .line 1598
    .line 1599
    invoke-direct {v4, v2}, Ld01/e;-><init>(Ld01/t0;)V

    .line 1600
    .line 1601
    .line 1602
    :try_start_7
    iget-object v2, v0, Ld01/g;->d:Lf01/g;

    .line 1603
    .line 1604
    iget-object v3, v3, Ld01/k0;->a:Ld01/a0;

    .line 1605
    .line 1606
    invoke-static {v3}, Ljp/pe;->b(Ld01/a0;)Ljava/lang/String;

    .line 1607
    .line 1608
    .line 1609
    move-result-object v3

    .line 1610
    sget-object v5, Lf01/g;->w:Lly0/n;

    .line 1611
    .line 1612
    const-wide/16 v5, -0x1

    .line 1613
    .line 1614
    invoke-virtual {v2, v5, v6, v3}, Lf01/g;->d(JLjava/lang/String;)La8/b;

    .line 1615
    .line 1616
    .line 1617
    move-result-object v8
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_6

    .line 1618
    if-nez v8, :cond_44

    .line 1619
    .line 1620
    goto :goto_1f

    .line 1621
    :cond_44
    :try_start_8
    invoke-virtual {v4, v8}, Ld01/e;->c(La8/b;)V

    .line 1622
    .line 1623
    .line 1624
    new-instance v2, Lvv0/d;

    .line 1625
    .line 1626
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 1627
    .line 1628
    .line 1629
    iput-object v0, v2, Lvv0/d;->e:Ljava/lang/Object;

    .line 1630
    .line 1631
    iput-object v8, v2, Lvv0/d;->b:Ljava/lang/Object;

    .line 1632
    .line 1633
    const/4 v3, 0x1

    .line 1634
    invoke-virtual {v8, v3}, La8/b;->n(I)Lu01/f0;

    .line 1635
    .line 1636
    .line 1637
    move-result-object v3

    .line 1638
    iput-object v3, v2, Lvv0/d;->c:Ljava/lang/Object;

    .line 1639
    .line 1640
    new-instance v4, Ld01/f;

    .line 1641
    .line 1642
    invoke-direct {v4, v0, v2, v3}, Ld01/f;-><init>(Ld01/g;Lvv0/d;Lu01/f0;)V

    .line 1643
    .line 1644
    .line 1645
    iput-object v4, v2, Lvv0/d;->d:Ljava/lang/Object;
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_7

    .line 1646
    .line 1647
    goto :goto_20

    .line 1648
    :catch_6
    const/4 v8, 0x0

    .line 1649
    :catch_7
    if-eqz v8, :cond_40

    .line 1650
    .line 1651
    :try_start_9
    invoke-virtual {v8}, La8/b;->b()V
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_5

    .line 1652
    .line 1653
    .line 1654
    goto :goto_1f

    .line 1655
    :goto_20
    if-nez v2, :cond_45

    .line 1656
    .line 1657
    goto :goto_21

    .line 1658
    :cond_45
    iget-object v0, v2, Lvv0/d;->d:Ljava/lang/Object;

    .line 1659
    .line 1660
    check-cast v0, Ld01/f;

    .line 1661
    .line 1662
    iget-object v3, v1, Ld01/t0;->j:Ld01/v0;

    .line 1663
    .line 1664
    invoke-virtual {v3}, Ld01/v0;->p0()Lu01/h;

    .line 1665
    .line 1666
    .line 1667
    move-result-object v3

    .line 1668
    invoke-static {v0}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 1669
    .line 1670
    .line 1671
    move-result-object v0

    .line 1672
    new-instance v4, Lf01/a;

    .line 1673
    .line 1674
    invoke-direct {v4, v3, v2, v0}, Lf01/a;-><init>(Lu01/h;Lvv0/d;Lu01/a0;)V

    .line 1675
    .line 1676
    .line 1677
    const-string v0, "Content-Type"

    .line 1678
    .line 1679
    invoke-static {v1, v0}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 1680
    .line 1681
    .line 1682
    move-result-object v0

    .line 1683
    iget-object v2, v1, Ld01/t0;->j:Ld01/v0;

    .line 1684
    .line 1685
    invoke-virtual {v2}, Ld01/v0;->b()J

    .line 1686
    .line 1687
    .line 1688
    move-result-wide v2

    .line 1689
    invoke-virtual {v1}, Ld01/t0;->d()Ld01/s0;

    .line 1690
    .line 1691
    .line 1692
    move-result-object v1

    .line 1693
    new-instance v5, Li01/g;

    .line 1694
    .line 1695
    invoke-static {v4}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 1696
    .line 1697
    .line 1698
    move-result-object v4

    .line 1699
    invoke-direct {v5, v0, v2, v3, v4}, Li01/g;-><init>(Ljava/lang/String;JLu01/b0;)V

    .line 1700
    .line 1701
    .line 1702
    iput-object v5, v1, Ld01/s0;->g:Ld01/v0;

    .line 1703
    .line 1704
    invoke-virtual {v1}, Ld01/s0;->a()Ld01/t0;

    .line 1705
    .line 1706
    .line 1707
    move-result-object v0

    .line 1708
    move-object/from16 v27, v0

    .line 1709
    .line 1710
    goto :goto_22

    .line 1711
    :cond_46
    iget-object v2, v4, Ld01/k0;->b:Ljava/lang/String;

    .line 1712
    .line 1713
    invoke-static {v2}, Llp/l1;->b(Ljava/lang/String;)Z

    .line 1714
    .line 1715
    .line 1716
    move-result v2

    .line 1717
    if-eqz v2, :cond_47

    .line 1718
    .line 1719
    :try_start_a
    iget-object v0, v0, Ldm0/i;->b:Ljava/lang/Object;

    .line 1720
    .line 1721
    check-cast v0, Ld01/g;

    .line 1722
    .line 1723
    invoke-virtual {v0, v4}, Ld01/g;->a(Ld01/k0;)V
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_8

    .line 1724
    .line 1725
    .line 1726
    :catch_8
    :cond_47
    :goto_21
    move-object/from16 v27, v1

    .line 1727
    .line 1728
    :goto_22
    return-object v27

    .line 1729
    :catchall_0
    move-exception v0

    .line 1730
    if-eqz v3, :cond_48

    .line 1731
    .line 1732
    iget-object v1, v3, Ld01/t0;->j:Ld01/v0;

    .line 1733
    .line 1734
    invoke-static {v1}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 1735
    .line 1736
    .line 1737
    :cond_48
    throw v0

    .line 1738
    :pswitch_1
    new-instance v1, Ldm0/h;

    .line 1739
    .line 1740
    const/4 v6, 0x0

    .line 1741
    const/4 v8, 0x0

    .line 1742
    invoke-direct {v1, v0, v8, v6}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 1743
    .line 1744
    .line 1745
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 1746
    .line 1747
    invoke-static {v0, v1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 1748
    .line 1749
    .line 1750
    move-result-object v0

    .line 1751
    check-cast v0, Ljava/lang/String;

    .line 1752
    .line 1753
    move-object/from16 v1, p1

    .line 1754
    .line 1755
    check-cast v1, Li01/f;

    .line 1756
    .line 1757
    iget-object v2, v1, Li01/f;->e:Ld01/k0;

    .line 1758
    .line 1759
    invoke-virtual {v2}, Ld01/k0;->b()Ld01/j0;

    .line 1760
    .line 1761
    .line 1762
    move-result-object v2

    .line 1763
    const-string v3, "X-DEMO-MODE"

    .line 1764
    .line 1765
    invoke-virtual {v2, v3, v0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1766
    .line 1767
    .line 1768
    new-instance v0, Ld01/k0;

    .line 1769
    .line 1770
    invoke-direct {v0, v2}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 1771
    .line 1772
    .line 1773
    invoke-virtual {v1, v0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 1774
    .line 1775
    .line 1776
    move-result-object v0

    .line 1777
    return-object v0

    .line 1778
    nop

    .line 1779
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
