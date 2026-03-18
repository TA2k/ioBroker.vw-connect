.class public abstract Llp/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;Luv/q;Ll2/o;I)V
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p2, Ll2/t;

    .line 7
    .line 8
    const v0, -0x719e1906

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p3, 0xe

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int/2addr v0, p3

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v0, p3

    .line 30
    :goto_1
    and-int/lit8 v1, p3, 0x70

    .line 31
    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    const/16 v1, 0x20

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v1, 0x10

    .line 44
    .line 45
    :goto_2
    or-int/2addr v0, v1

    .line 46
    :cond_3
    and-int/lit8 v1, v0, 0x5b

    .line 47
    .line 48
    const/16 v2, 0x12

    .line 49
    .line 50
    if-ne v1, v2, :cond_5

    .line 51
    .line 52
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_4

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 60
    .line 61
    .line 62
    goto :goto_4

    .line 63
    :cond_5
    :goto_3
    and-int/lit8 v0, v0, 0x7e

    .line 64
    .line 65
    invoke-static {p0, p1, p2, v0}, Llp/i0;->b(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 66
    .line 67
    .line 68
    :goto_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    if-eqz p2, :cond_6

    .line 73
    .line 74
    new-instance v0, Ltv/b;

    .line 75
    .line 76
    const/4 v1, 0x0

    .line 77
    invoke-direct {v0, p0, p1, p3, v1}, Ltv/b;-><init>(Lvv/m0;Luv/q;II)V

    .line 78
    .line 79
    .line 80
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 81
    .line 82
    :cond_6
    return-void
.end method

.method public static final b(Lvv/m0;Luv/q;Ll2/o;I)V
    .locals 12

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v6, p2

    .line 7
    check-cast v6, Ll2/t;

    .line 8
    .line 9
    const p2, 0x6f4df6ca

    .line 10
    .line 11
    .line 12
    invoke-virtual {v6, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p2, p3, 0xe

    .line 16
    .line 17
    if-nez p2, :cond_1

    .line 18
    .line 19
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    const/4 p2, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p2, 0x2

    .line 28
    :goto_0
    or-int/2addr p2, p3

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move p2, p3

    .line 31
    :goto_1
    and-int/lit8 v0, p3, 0x70

    .line 32
    .line 33
    const/16 v1, 0x10

    .line 34
    .line 35
    if-nez v0, :cond_3

    .line 36
    .line 37
    invoke-virtual {v6, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    const/16 v0, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    move v0, v1

    .line 47
    :goto_2
    or-int/2addr p2, v0

    .line 48
    :cond_3
    and-int/lit8 v0, p2, 0x5b

    .line 49
    .line 50
    const/16 v2, 0x12

    .line 51
    .line 52
    if-ne v0, v2, :cond_5

    .line 53
    .line 54
    invoke-virtual {v6}, Ll2/t;->A()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_4

    .line 59
    .line 60
    goto :goto_4

    .line 61
    :cond_4
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    :goto_3
    move-object v1, p0

    .line 65
    goto/16 :goto_9

    .line 66
    .line 67
    :cond_5
    :goto_4
    if-nez p1, :cond_6

    .line 68
    .line 69
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    if-eqz p2, :cond_1a

    .line 74
    .line 75
    new-instance v0, Ltv/b;

    .line 76
    .line 77
    const/4 v1, 0x1

    .line 78
    invoke-direct {v0, p0, p1, p3, v1}, Ltv/b;-><init>(Lvv/m0;Luv/q;II)V

    .line 79
    .line 80
    .line 81
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 82
    .line 83
    return-void

    .line 84
    :cond_6
    iget-object v0, p1, Luv/q;->a:Llp/la;

    .line 85
    .line 86
    instance-of v2, v0, Luv/d;

    .line 87
    .line 88
    const/4 v11, 0x0

    .line 89
    if-eqz v2, :cond_7

    .line 90
    .line 91
    const v0, 0x39f34a8c

    .line 92
    .line 93
    .line 94
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 95
    .line 96
    .line 97
    and-int/lit8 p2, p2, 0x7e

    .line 98
    .line 99
    invoke-static {p0, p1, v6, p2}, Llp/i0;->d(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 103
    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_7
    instance-of v2, v0, Luv/a;

    .line 107
    .line 108
    if-eqz v2, :cond_8

    .line 109
    .line 110
    const v0, 0x39f34ac2

    .line 111
    .line 112
    .line 113
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 114
    .line 115
    .line 116
    new-instance v0, Ltv/d;

    .line 117
    .line 118
    const/4 v1, 0x0

    .line 119
    invoke-direct {v0, p1, v1}, Ltv/d;-><init>(Luv/q;I)V

    .line 120
    .line 121
    .line 122
    const v1, -0x3917071e

    .line 123
    .line 124
    .line 125
    invoke-static {v1, v6, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    and-int/lit8 p2, p2, 0xe

    .line 130
    .line 131
    or-int/lit8 p2, p2, 0x30

    .line 132
    .line 133
    invoke-static {p0, v0, v6, p2}, Lvv/g;->a(Lvv/m0;Lt2/b;Ll2/o;I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_8
    instance-of v2, v0, Luv/f0;

    .line 141
    .line 142
    if-eqz v2, :cond_9

    .line 143
    .line 144
    const v0, 0x39f34b1f

    .line 145
    .line 146
    .line 147
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 148
    .line 149
    .line 150
    sget-object v2, Lvv/g0;->e:Lvv/g0;

    .line 151
    .line 152
    sget-object v0, Ltv/c;->g:Ltv/c;

    .line 153
    .line 154
    invoke-static {p1, v0}, Llp/m0;->b(Luv/q;Lay0/k;)Lky0/g;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-static {v0}, Lky0/l;->p(Lky0/j;)Ljava/util/List;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    sget-object v5, Ltv/g;->a:Lt2/b;

    .line 163
    .line 164
    and-int/lit8 p2, p2, 0xe

    .line 165
    .line 166
    or-int/lit16 v7, p2, 0x6230

    .line 167
    .line 168
    const/4 v8, 0x4

    .line 169
    const/4 v4, 0x0

    .line 170
    move-object v1, p0

    .line 171
    invoke-static/range {v1 .. v8}, Lvv/x;->a(Lvv/m0;Lvv/g0;Ljava/util/List;ILt2/b;Ll2/o;II)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 175
    .line 176
    .line 177
    goto/16 :goto_9

    .line 178
    .line 179
    :cond_9
    instance-of v2, v0, Luv/s;

    .line 180
    .line 181
    const/4 v3, 0x1

    .line 182
    if-eqz v2, :cond_a

    .line 183
    .line 184
    const v1, 0x39f34cbd

    .line 185
    .line 186
    .line 187
    invoke-virtual {v6, v1}, Ll2/t;->Z(I)V

    .line 188
    .line 189
    .line 190
    sget-object v2, Lvv/g0;->d:Lvv/g0;

    .line 191
    .line 192
    invoke-static {p1, v11}, Llp/m0;->a(Luv/q;Z)Lky0/j;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    invoke-static {v1}, Lky0/l;->p(Lky0/j;)Ljava/util/List;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    check-cast v0, Luv/s;

    .line 201
    .line 202
    iget v0, v0, Luv/s;->a:I

    .line 203
    .line 204
    add-int/lit8 v4, v0, -0x1

    .line 205
    .line 206
    sget-object v5, Ltv/g;->b:Lt2/b;

    .line 207
    .line 208
    and-int/lit8 p2, p2, 0xe

    .line 209
    .line 210
    or-int/lit16 v7, p2, 0x6230

    .line 211
    .line 212
    const/4 v8, 0x0

    .line 213
    move-object v3, v1

    .line 214
    move-object v1, p0

    .line 215
    invoke-static/range {v1 .. v8}, Lvv/x;->a(Lvv/m0;Lvv/g0;Ljava/util/List;ILt2/b;Ll2/o;II)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 219
    .line 220
    .line 221
    goto/16 :goto_9

    .line 222
    .line 223
    :cond_a
    instance-of v2, v0, Luv/e0;

    .line 224
    .line 225
    if-eqz v2, :cond_b

    .line 226
    .line 227
    const v0, 0x39f34e7f

    .line 228
    .line 229
    .line 230
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 231
    .line 232
    .line 233
    and-int/lit8 p2, p2, 0xe

    .line 234
    .line 235
    invoke-static {p0, v6, p2}, Llp/gc;->a(Lvv/m0;Ll2/o;I)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 239
    .line 240
    .line 241
    goto/16 :goto_3

    .line 242
    .line 243
    :cond_b
    instance-of v2, v0, Luv/h;

    .line 244
    .line 245
    if-eqz v2, :cond_c

    .line 246
    .line 247
    const v1, 0x39f34eb3

    .line 248
    .line 249
    .line 250
    invoke-virtual {v6, v1}, Ll2/t;->Z(I)V

    .line 251
    .line 252
    .line 253
    check-cast v0, Luv/h;

    .line 254
    .line 255
    iget v0, v0, Luv/h;->a:I

    .line 256
    .line 257
    new-instance v1, Ltv/d;

    .line 258
    .line 259
    const/4 v2, 0x1

    .line 260
    invoke-direct {v1, p1, v2}, Ltv/d;-><init>(Luv/q;I)V

    .line 261
    .line 262
    .line 263
    const v2, 0xff8e806

    .line 264
    .line 265
    .line 266
    invoke-static {v2, v6, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 267
    .line 268
    .line 269
    move-result-object v1

    .line 270
    and-int/lit8 p2, p2, 0xe

    .line 271
    .line 272
    or-int/lit16 p2, p2, 0x180

    .line 273
    .line 274
    invoke-static {p0, v0, v1, v6, p2}, Llp/fc;->a(Lvv/m0;ILt2/b;Ll2/o;I)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 278
    .line 279
    .line 280
    goto/16 :goto_3

    .line 281
    .line 282
    :cond_c
    instance-of v2, v0, Luv/l;

    .line 283
    .line 284
    if-eqz v2, :cond_d

    .line 285
    .line 286
    const v1, 0x39f34f52

    .line 287
    .line 288
    .line 289
    invoke-virtual {v6, v1}, Ll2/t;->Z(I)V

    .line 290
    .line 291
    .line 292
    check-cast v0, Luv/l;

    .line 293
    .line 294
    iget-object v0, v0, Luv/l;->a:Ljava/lang/String;

    .line 295
    .line 296
    invoke-static {v0}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    and-int/lit8 p2, p2, 0xe

    .line 305
    .line 306
    invoke-static {p0, v0, v6, p2}, Lvv/j;->a(Lvv/m0;Ljava/lang/String;Ll2/o;I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 310
    .line 311
    .line 312
    goto/16 :goto_3

    .line 313
    .line 314
    :cond_d
    instance-of v2, v0, Luv/f;

    .line 315
    .line 316
    if-eqz v2, :cond_e

    .line 317
    .line 318
    const v1, 0x39f34faa

    .line 319
    .line 320
    .line 321
    invoke-virtual {v6, v1}, Ll2/t;->Z(I)V

    .line 322
    .line 323
    .line 324
    check-cast v0, Luv/f;

    .line 325
    .line 326
    iget-object v0, v0, Luv/f;->e:Ljava/lang/String;

    .line 327
    .line 328
    invoke-static {v0}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object v0

    .line 336
    and-int/lit8 p2, p2, 0xe

    .line 337
    .line 338
    invoke-static {p0, v0, v6, p2}, Lvv/j;->a(Lvv/m0;Ljava/lang/String;Ll2/o;I)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 342
    .line 343
    .line 344
    goto/16 :goto_3

    .line 345
    .line 346
    :cond_e
    instance-of v2, v0, Luv/i;

    .line 347
    .line 348
    if-eqz v2, :cond_f

    .line 349
    .line 350
    const v2, 0x39f34ffc

    .line 351
    .line 352
    .line 353
    invoke-virtual {v6, v2}, Ll2/t;->Z(I)V

    .line 354
    .line 355
    .line 356
    new-instance v2, Lg4/d;

    .line 357
    .line 358
    invoke-direct {v2, v1}, Lg4/d;-><init>(I)V

    .line 359
    .line 360
    .line 361
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 362
    .line 363
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 364
    .line 365
    .line 366
    new-instance v3, Lxv/a;

    .line 367
    .line 368
    new-instance v4, Ltv/e;

    .line 369
    .line 370
    const/4 v5, 0x0

    .line 371
    invoke-direct {v4, v5, p0, v0}, Ltv/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 372
    .line 373
    .line 374
    const v0, 0x582e84a2

    .line 375
    .line 376
    .line 377
    invoke-static {v0, v6, v4}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 378
    .line 379
    .line 380
    move-result-object v0

    .line 381
    const/4 v4, 0x3

    .line 382
    invoke-direct {v3, v0, v4}, Lxv/a;-><init>(Lt2/b;I)V

    .line 383
    .line 384
    .line 385
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 386
    .line 387
    .line 388
    move-result-object v0

    .line 389
    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    const-string v4, "toString(...)"

    .line 394
    .line 395
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    const-string v4, "inline:"

    .line 399
    .line 400
    invoke-virtual {v4, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    invoke-interface {v1, v4, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    const-string v3, "androidx.compose.foundation.text.inlineContent"

    .line 408
    .line 409
    invoke-virtual {v2, v3, v0}, Lg4/d;->g(Ljava/lang/String;Ljava/lang/String;)I

    .line 410
    .line 411
    .line 412
    const-string v0, "\ufffd"

    .line 413
    .line 414
    invoke-virtual {v2, v0}, Lg4/d;->d(Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    invoke-virtual {v2}, Lg4/d;->e()V

    .line 418
    .line 419
    .line 420
    move-object v0, v2

    .line 421
    new-instance v2, Lxv/o;

    .line 422
    .line 423
    invoke-virtual {v0}, Lg4/d;->j()Lg4/g;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    invoke-static {v1}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    invoke-direct {v2, v0, v1}, Lxv/o;-><init>(Lg4/g;Ljava/util/Map;)V

    .line 432
    .line 433
    .line 434
    and-int/lit8 v9, p2, 0xe

    .line 435
    .line 436
    const/16 v10, 0x3e

    .line 437
    .line 438
    const/4 v3, 0x0

    .line 439
    const/4 v4, 0x0

    .line 440
    move-object v8, v6

    .line 441
    const/4 v6, 0x0

    .line 442
    const/4 v7, 0x0

    .line 443
    move-object v1, p0

    .line 444
    invoke-static/range {v1 .. v10}, Llp/ff;->a(Lvv/m0;Lxv/o;Lx2/s;Lay0/k;ZIILl2/o;II)V

    .line 445
    .line 446
    .line 447
    move-object v6, v8

    .line 448
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 449
    .line 450
    .line 451
    goto/16 :goto_9

    .line 452
    .line 453
    :cond_f
    instance-of v2, v0, Luv/o;

    .line 454
    .line 455
    if-eqz v2, :cond_10

    .line 456
    .line 457
    const p2, 0x39f350bf

    .line 458
    .line 459
    .line 460
    invoke-virtual {v6, p2}, Ll2/t;->Z(I)V

    .line 461
    .line 462
    .line 463
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 464
    .line 465
    .line 466
    goto/16 :goto_3

    .line 467
    .line 468
    :cond_10
    instance-of v2, v0, Luv/t;

    .line 469
    .line 470
    if-eqz v2, :cond_11

    .line 471
    .line 472
    const v0, 0x39f3510c

    .line 473
    .line 474
    .line 475
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 476
    .line 477
    .line 478
    and-int/lit8 v5, p2, 0x7e

    .line 479
    .line 480
    move-object v8, v6

    .line 481
    const/4 v6, 0x2

    .line 482
    const/4 v3, 0x0

    .line 483
    move-object v1, p0

    .line 484
    move-object v2, p1

    .line 485
    move-object v4, v8

    .line 486
    invoke-static/range {v1 .. v6}, Llp/k0;->a(Lvv/m0;Luv/q;Lx2/s;Ll2/o;II)V

    .line 487
    .line 488
    .line 489
    move-object v6, v4

    .line 490
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 491
    .line 492
    .line 493
    goto/16 :goto_9

    .line 494
    .line 495
    :cond_11
    instance-of v2, v0, Luv/b0;

    .line 496
    .line 497
    if-eqz v2, :cond_12

    .line 498
    .line 499
    const v0, 0x39f3514b

    .line 500
    .line 501
    .line 502
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 503
    .line 504
    .line 505
    and-int/lit8 p2, p2, 0x7e

    .line 506
    .line 507
    invoke-static {p0, p1, v6, p2}, Llp/l0;->a(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 508
    .line 509
    .line 510
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 511
    .line 512
    .line 513
    goto/16 :goto_3

    .line 514
    .line 515
    :cond_12
    instance-of v2, v0, Luv/d0;

    .line 516
    .line 517
    if-eqz v2, :cond_14

    .line 518
    .line 519
    const v2, 0x39f35261

    .line 520
    .line 521
    .line 522
    invoke-virtual {v6, v2}, Ll2/t;->Z(I)V

    .line 523
    .line 524
    .line 525
    const-string v2, "Unexpected raw text while traversing the Abstract Syntax Tree."

    .line 526
    .line 527
    sget-object v3, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 528
    .line 529
    invoke-virtual {v3, v2}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 530
    .line 531
    .line 532
    new-instance v2, Ljava/lang/StringBuilder;

    .line 533
    .line 534
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 535
    .line 536
    .line 537
    new-instance v1, Ljava/util/ArrayList;

    .line 538
    .line 539
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 540
    .line 541
    .line 542
    new-instance v1, Ljava/util/ArrayList;

    .line 543
    .line 544
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 545
    .line 546
    .line 547
    new-instance v3, Ljava/util/ArrayList;

    .line 548
    .line 549
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 550
    .line 551
    .line 552
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 553
    .line 554
    invoke-direct {v3}, Ljava/util/LinkedHashMap;-><init>()V

    .line 555
    .line 556
    .line 557
    check-cast v0, Luv/d0;

    .line 558
    .line 559
    iget-object v0, v0, Luv/d0;->a:Ljava/lang/String;

    .line 560
    .line 561
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 562
    .line 563
    .line 564
    move-object v0, v2

    .line 565
    new-instance v2, Lxv/o;

    .line 566
    .line 567
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 568
    .line 569
    .line 570
    move-result-object v4

    .line 571
    new-instance v5, Ljava/util/ArrayList;

    .line 572
    .line 573
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 574
    .line 575
    .line 576
    move-result v7

    .line 577
    invoke-direct {v5, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 578
    .line 579
    .line 580
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 581
    .line 582
    .line 583
    move-result v7

    .line 584
    move v8, v11

    .line 585
    :goto_5
    if-ge v8, v7, :cond_13

    .line 586
    .line 587
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 588
    .line 589
    .line 590
    move-result-object v9

    .line 591
    check-cast v9, Lg4/c;

    .line 592
    .line 593
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 594
    .line 595
    .line 596
    move-result v10

    .line 597
    invoke-virtual {v9, v10}, Lg4/c;->a(I)Lg4/e;

    .line 598
    .line 599
    .line 600
    move-result-object v9

    .line 601
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 602
    .line 603
    .line 604
    add-int/lit8 v8, v8, 0x1

    .line 605
    .line 606
    goto :goto_5

    .line 607
    :cond_13
    new-instance v0, Lg4/g;

    .line 608
    .line 609
    invoke-direct {v0, v4, v5}, Lg4/g;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 610
    .line 611
    .line 612
    invoke-static {v3}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 613
    .line 614
    .line 615
    move-result-object v1

    .line 616
    invoke-direct {v2, v0, v1}, Lxv/o;-><init>(Lg4/g;Ljava/util/Map;)V

    .line 617
    .line 618
    .line 619
    and-int/lit8 v9, p2, 0xe

    .line 620
    .line 621
    const/16 v10, 0x3e

    .line 622
    .line 623
    const/4 v3, 0x0

    .line 624
    const/4 v4, 0x0

    .line 625
    const/4 v5, 0x0

    .line 626
    move-object v8, v6

    .line 627
    const/4 v6, 0x0

    .line 628
    const/4 v7, 0x0

    .line 629
    move-object v1, p0

    .line 630
    invoke-static/range {v1 .. v10}, Llp/ff;->a(Lvv/m0;Lxv/o;Lx2/s;Lay0/k;ZIILl2/o;II)V

    .line 631
    .line 632
    .line 633
    move-object v6, v8

    .line 634
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 635
    .line 636
    .line 637
    goto/16 :goto_9

    .line 638
    .line 639
    :cond_14
    move-object v1, p0

    .line 640
    instance-of p0, v0, Luv/p;

    .line 641
    .line 642
    if-eqz p0, :cond_15

    .line 643
    .line 644
    const p0, 0x39f35352

    .line 645
    .line 646
    .line 647
    invoke-virtual {v6, p0}, Ll2/t;->Z(I)V

    .line 648
    .line 649
    .line 650
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 651
    .line 652
    .line 653
    const-string p0, "MarkdownRichText: Unexpected AstListItem while traversing the Abstract Syntax Tree."

    .line 654
    .line 655
    sget-object p2, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 656
    .line 657
    invoke-virtual {p2, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 658
    .line 659
    .line 660
    goto :goto_9

    .line 661
    :cond_15
    instance-of p0, v0, Luv/m;

    .line 662
    .line 663
    if-eqz p0, :cond_16

    .line 664
    .line 665
    const p0, 0x39f353db

    .line 666
    .line 667
    .line 668
    invoke-virtual {v6, p0}, Ll2/t;->Z(I)V

    .line 669
    .line 670
    .line 671
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 672
    .line 673
    .line 674
    new-instance p0, Ljava/lang/StringBuilder;

    .line 675
    .line 676
    const-string p2, "MarkdownRichText: Unexpected AstInlineNodeType "

    .line 677
    .line 678
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 679
    .line 680
    .line 681
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 682
    .line 683
    .line 684
    const-string p2, " while traversing the Abstract Syntax Tree."

    .line 685
    .line 686
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 687
    .line 688
    .line 689
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 690
    .line 691
    .line 692
    move-result-object p0

    .line 693
    sget-object p2, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 694
    .line 695
    invoke-virtual {p2, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 696
    .line 697
    .line 698
    goto :goto_9

    .line 699
    :cond_16
    sget-object p0, Luv/x;->a:Luv/x;

    .line 700
    .line 701
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 702
    .line 703
    .line 704
    move-result p0

    .line 705
    if-eqz p0, :cond_17

    .line 706
    .line 707
    move p0, v3

    .line 708
    goto :goto_6

    .line 709
    :cond_17
    sget-object p0, Luv/a0;->a:Luv/a0;

    .line 710
    .line 711
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 712
    .line 713
    .line 714
    move-result p0

    .line 715
    :goto_6
    if-eqz p0, :cond_18

    .line 716
    .line 717
    move p0, v3

    .line 718
    goto :goto_7

    .line 719
    :cond_18
    sget-object p0, Luv/c0;->a:Luv/c0;

    .line 720
    .line 721
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 722
    .line 723
    .line 724
    move-result p0

    .line 725
    :goto_7
    if-eqz p0, :cond_19

    .line 726
    .line 727
    goto :goto_8

    .line 728
    :cond_19
    instance-of v3, v0, Luv/y;

    .line 729
    .line 730
    :goto_8
    if-eqz v3, :cond_1b

    .line 731
    .line 732
    const p0, 0x39f354b9

    .line 733
    .line 734
    .line 735
    invoke-virtual {v6, p0}, Ll2/t;->Z(I)V

    .line 736
    .line 737
    .line 738
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 739
    .line 740
    .line 741
    const-string p0, "MarkdownRichText: Unexpected Table node while traversing the Abstract Syntax Tree."

    .line 742
    .line 743
    sget-object p2, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 744
    .line 745
    invoke-virtual {p2, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 746
    .line 747
    .line 748
    :goto_9
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 749
    .line 750
    .line 751
    move-result-object p0

    .line 752
    if-eqz p0, :cond_1a

    .line 753
    .line 754
    new-instance p2, Ltv/b;

    .line 755
    .line 756
    const/4 v0, 0x2

    .line 757
    invoke-direct {p2, v1, p1, p3, v0}, Ltv/b;-><init>(Lvv/m0;Luv/q;II)V

    .line 758
    .line 759
    .line 760
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 761
    .line 762
    :cond_1a
    return-void

    .line 763
    :cond_1b
    const p0, 0x39f33b59

    .line 764
    .line 765
    .line 766
    invoke-virtual {v6, p0}, Ll2/t;->Z(I)V

    .line 767
    .line 768
    .line 769
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 770
    .line 771
    .line 772
    new-instance p0, La8/r0;

    .line 773
    .line 774
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 775
    .line 776
    .line 777
    throw p0
.end method

.method public static final c(Lss0/b;Lij0/a;)Ljava/lang/String;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lss0/e;->A1:Lss0/e;

    .line 12
    .line 13
    invoke-static {p0, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x0

    .line 18
    if-nez v0, :cond_2

    .line 19
    .line 20
    sget-object v0, Lss0/e;->E:Lss0/e;

    .line 21
    .line 22
    invoke-static {p0, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    sget-object v0, Lss0/e;->B:Lss0/e;

    .line 30
    .line 31
    invoke-static {p0, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    const/4 v2, 0x0

    .line 36
    if-eqz v0, :cond_1

    .line 37
    .line 38
    new-array p0, v2, [Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p1, Ljj0/f;

    .line 41
    .line 42
    const v0, 0x7f1206c9

    .line 43
    .line 44
    .line 45
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    :cond_1
    sget-object v0, Lss0/e;->C:Lss0/e;

    .line 51
    .line 52
    invoke-static {p0, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-eqz p0, :cond_2

    .line 57
    .line 58
    new-array p0, v2, [Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p1, Ljj0/f;

    .line 61
    .line 62
    const v0, 0x7f1206c8

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :cond_2
    :goto_0
    return-object v1
.end method

.method public static final d(Lvv/m0;Luv/q;Ll2/o;I)V
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p2, Ll2/t;

    .line 7
    .line 8
    const v0, -0x64dab179

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p3, 0xe

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int/2addr v0, p3

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v0, p3

    .line 30
    :goto_1
    and-int/lit8 v1, p3, 0x70

    .line 31
    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    const/16 v1, 0x20

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v1, 0x10

    .line 44
    .line 45
    :goto_2
    or-int/2addr v0, v1

    .line 46
    :cond_3
    and-int/lit8 v1, v0, 0x5b

    .line 47
    .line 48
    const/16 v2, 0x12

    .line 49
    .line 50
    if-ne v1, v2, :cond_5

    .line 51
    .line 52
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_4

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 60
    .line 61
    .line 62
    goto :goto_6

    .line 63
    :cond_5
    :goto_3
    if-eqz p1, :cond_6

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-static {p1, v1}, Llp/m0;->a(Luv/q;Z)Lky0/j;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    goto :goto_4

    .line 71
    :cond_6
    const/4 v1, 0x0

    .line 72
    :goto_4
    if-nez v1, :cond_7

    .line 73
    .line 74
    goto :goto_6

    .line 75
    :cond_7
    invoke-interface {v1}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    if-eqz v2, :cond_8

    .line 84
    .line 85
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    check-cast v2, Luv/q;

    .line 90
    .line 91
    and-int/lit8 v3, v0, 0xe

    .line 92
    .line 93
    invoke-static {p0, v2, p2, v3}, Llp/i0;->b(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 94
    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_8
    :goto_6
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    if-eqz p2, :cond_9

    .line 102
    .line 103
    new-instance v0, Ltv/b;

    .line 104
    .line 105
    const/4 v1, 0x3

    .line 106
    invoke-direct {v0, p0, p1, p3, v1}, Ltv/b;-><init>(Lvv/m0;Luv/q;II)V

    .line 107
    .line 108
    .line 109
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 110
    .line 111
    :cond_9
    return-void
.end method
