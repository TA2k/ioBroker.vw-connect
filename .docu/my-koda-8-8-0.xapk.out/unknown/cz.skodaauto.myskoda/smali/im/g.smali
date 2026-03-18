.class public abstract Lim/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/ArrayList;)Ly6/q;
    .locals 2

    .line 1
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Ly6/o;->a:Ly6/o;

    .line 6
    .line 7
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_2

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Ly6/q;

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-interface {v0, v1}, Ly6/q;->d(Ly6/q;)Ly6/q;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    move-object v0, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_2
    return-object v0
.end method

.method public static final b(Lij0/a;Lqr0/s;Ll70/p;Ljava/lang/Integer;Ll70/q;)Ljava/util/List;
    .locals 10

    .line 1
    const v0, 0x7f12025b

    .line 2
    .line 3
    .line 4
    const-string v1, ""

    .line 5
    .line 6
    const/4 v2, 0x3

    .line 7
    const/4 v3, 0x2

    .line 8
    const/4 v4, 0x1

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v6, 0x0

    .line 11
    const v7, 0x7f1201aa

    .line 12
    .line 13
    .line 14
    if-eqz p3, :cond_3

    .line 15
    .line 16
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p3

    .line 20
    const-string v8, "<this>"

    .line 21
    .line 22
    invoke-static {p2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v8, "stringResources"

    .line 26
    .line 27
    invoke-static {p0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string v8, "dataType"

    .line 31
    .line 32
    invoke-static {p4, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p2, p2, Ll70/p;->k:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-static {p3, p2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    check-cast p2, Ll70/r;

    .line 42
    .line 43
    if-eqz p2, :cond_0

    .line 44
    .line 45
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 46
    .line 47
    .line 48
    move-result p3

    .line 49
    packed-switch p3, :pswitch_data_0

    .line 50
    .line 51
    .line 52
    new-instance p0, La8/r0;

    .line 53
    .line 54
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :pswitch_0
    iget-wide p2, p2, Ll70/r;->h:D

    .line 59
    .line 60
    invoke-static {p2, p3, p1}, Lkp/o6;->d(DLqr0/s;)Llx0/l;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    goto :goto_0

    .line 69
    :pswitch_1
    iget p1, p2, Ll70/r;->d:I

    .line 70
    .line 71
    sget-object p2, Lmy0/e;->i:Lmy0/e;

    .line 72
    .line 73
    invoke-static {p1, p2}, Lmy0/h;->s(ILmy0/e;)J

    .line 74
    .line 75
    .line 76
    move-result-wide p1

    .line 77
    invoke-static {p1, p2, p0, v6, v4}, Ljp/d1;->g(JLij0/a;ZZ)Ljava/util/ArrayList;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    goto :goto_0

    .line 82
    :pswitch_2
    iget-wide p2, p2, Ll70/r;->c:D

    .line 83
    .line 84
    sget-object v5, Lqr0/e;->e:Lqr0/e;

    .line 85
    .line 86
    invoke-static {p2, p3, p1, v5}, Lkp/f6;->c(DLqr0/s;Lqr0/e;)Llx0/l;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    goto :goto_0

    .line 95
    :pswitch_3
    iget-wide p2, p2, Ll70/r;->f:D

    .line 96
    .line 97
    invoke-static {p2, p3, p1}, Lkp/g6;->e(DLqr0/s;)Llx0/l;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    goto :goto_0

    .line 106
    :pswitch_4
    iget-wide p2, p2, Ll70/r;->e:D

    .line 107
    .line 108
    invoke-static {p2, p3, p1}, Lkp/i6;->e(DLqr0/s;)Llx0/l;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    goto :goto_0

    .line 117
    :pswitch_5
    iget-wide p1, p2, Ll70/r;->g:D

    .line 118
    .line 119
    invoke-static {p1, p2}, Lkp/j6;->c(D)Llx0/l;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    goto :goto_0

    .line 128
    :pswitch_6
    iget-object p1, p2, Ll70/r;->i:Ll70/u;

    .line 129
    .line 130
    if-eqz p1, :cond_0

    .line 131
    .line 132
    invoke-static {p1}, Ljp/p0;->d(Ll70/u;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    new-instance p2, Llx0/l;

    .line 137
    .line 138
    invoke-direct {p2, p1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    invoke-static {p2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    :cond_0
    :goto_0
    if-nez v5, :cond_2

    .line 146
    .line 147
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 148
    .line 149
    .line 150
    move-result p1

    .line 151
    if-eqz p1, :cond_1

    .line 152
    .line 153
    if-eq p1, v4, :cond_1

    .line 154
    .line 155
    if-eq p1, v3, :cond_1

    .line 156
    .line 157
    if-eq p1, v2, :cond_1

    .line 158
    .line 159
    new-array p1, v6, [Ljava/lang/Object;

    .line 160
    .line 161
    move-object p2, p0

    .line 162
    check-cast p2, Ljj0/f;

    .line 163
    .line 164
    invoke-virtual {p2, v7, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    new-array p3, v6, [Ljava/lang/Object;

    .line 169
    .line 170
    invoke-virtual {p2, v7, p3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p2

    .line 174
    new-instance p3, Llx0/l;

    .line 175
    .line 176
    invoke-direct {p3, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    invoke-static {p3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    goto :goto_1

    .line 184
    :cond_1
    new-array p1, v6, [Ljava/lang/Object;

    .line 185
    .line 186
    move-object p2, p0

    .line 187
    check-cast p2, Ljj0/f;

    .line 188
    .line 189
    invoke-virtual {p2, v7, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object p1

    .line 193
    new-instance p2, Llx0/l;

    .line 194
    .line 195
    invoke-direct {p2, p1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    invoke-static {p2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    :cond_2
    :goto_1
    new-instance p1, Lm70/y;

    .line 203
    .line 204
    new-array p2, v6, [Ljava/lang/Object;

    .line 205
    .line 206
    check-cast p0, Ljj0/f;

    .line 207
    .line 208
    invoke-virtual {p0, v0, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    invoke-direct {p1, p0, v5}, Lm70/y;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 213
    .line 214
    .line 215
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    return-object p0

    .line 220
    :cond_3
    new-instance p3, Ljava/util/ArrayList;

    .line 221
    .line 222
    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    .line 223
    .line 224
    .line 225
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 226
    .line 227
    .line 228
    move-result v8

    .line 229
    if-eqz v8, :cond_7

    .line 230
    .line 231
    if-eq v8, v4, :cond_7

    .line 232
    .line 233
    if-eq v8, v3, :cond_7

    .line 234
    .line 235
    if-eq v8, v2, :cond_7

    .line 236
    .line 237
    const/4 v1, 0x7

    .line 238
    if-eq v8, v1, :cond_5

    .line 239
    .line 240
    const/16 v1, 0x8

    .line 241
    .line 242
    if-eq v8, v1, :cond_5

    .line 243
    .line 244
    invoke-static {p2, p0, p4, p1}, Ljb0/b;->a(Ll70/p;Lij0/a;Ll70/q;Lqr0/s;)Ljava/util/List;

    .line 245
    .line 246
    .line 247
    move-result-object p1

    .line 248
    if-nez p1, :cond_4

    .line 249
    .line 250
    new-array p1, v6, [Ljava/lang/Object;

    .line 251
    .line 252
    move-object p2, p0

    .line 253
    check-cast p2, Ljj0/f;

    .line 254
    .line 255
    invoke-virtual {p2, v7, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object p1

    .line 259
    new-array p4, v6, [Ljava/lang/Object;

    .line 260
    .line 261
    invoke-virtual {p2, v7, p4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object p2

    .line 265
    new-instance p4, Llx0/l;

    .line 266
    .line 267
    invoke-direct {p4, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    invoke-static {p4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 271
    .line 272
    .line 273
    move-result-object p1

    .line 274
    :cond_4
    move-object v9, v5

    .line 275
    move-object v5, p1

    .line 276
    move-object p1, v9

    .line 277
    goto :goto_2

    .line 278
    :cond_5
    invoke-static {p2, p0, p4, p1}, Ljb0/b;->a(Ll70/p;Lij0/a;Ll70/q;Lqr0/s;)Ljava/util/List;

    .line 279
    .line 280
    .line 281
    move-result-object v1

    .line 282
    if-nez v1, :cond_6

    .line 283
    .line 284
    new-array v1, v6, [Ljava/lang/Object;

    .line 285
    .line 286
    move-object v2, p0

    .line 287
    check-cast v2, Ljj0/f;

    .line 288
    .line 289
    invoke-virtual {v2, v7, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    new-array v3, v6, [Ljava/lang/Object;

    .line 294
    .line 295
    invoke-virtual {v2, v7, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v2

    .line 299
    new-instance v3, Llx0/l;

    .line 300
    .line 301
    invoke-direct {v3, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    :cond_6
    move-object v5, v1

    .line 309
    invoke-static {p2, p0, p4, p1}, Ljb0/b;->g(Ll70/p;Lij0/a;Ll70/q;Lqr0/s;)Ljava/util/List;

    .line 310
    .line 311
    .line 312
    move-result-object p1

    .line 313
    if-nez p1, :cond_8

    .line 314
    .line 315
    new-array p1, v6, [Ljava/lang/Object;

    .line 316
    .line 317
    move-object p2, p0

    .line 318
    check-cast p2, Ljj0/f;

    .line 319
    .line 320
    invoke-virtual {p2, v7, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object p1

    .line 324
    new-array p4, v6, [Ljava/lang/Object;

    .line 325
    .line 326
    invoke-virtual {p2, v7, p4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object p2

    .line 330
    new-instance p4, Llx0/l;

    .line 331
    .line 332
    invoke-direct {p4, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    invoke-static {p4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 336
    .line 337
    .line 338
    move-result-object p1

    .line 339
    goto :goto_2

    .line 340
    :cond_7
    invoke-static {p2, p0, p4, p1}, Ljb0/b;->g(Ll70/p;Lij0/a;Ll70/q;Lqr0/s;)Ljava/util/List;

    .line 341
    .line 342
    .line 343
    move-result-object p1

    .line 344
    if-nez p1, :cond_8

    .line 345
    .line 346
    new-array p1, v6, [Ljava/lang/Object;

    .line 347
    .line 348
    move-object p2, p0

    .line 349
    check-cast p2, Ljj0/f;

    .line 350
    .line 351
    invoke-virtual {p2, v7, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object p1

    .line 355
    new-instance p2, Llx0/l;

    .line 356
    .line 357
    invoke-direct {p2, p1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 358
    .line 359
    .line 360
    invoke-static {p2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 361
    .line 362
    .line 363
    move-result-object p1

    .line 364
    :cond_8
    :goto_2
    if-eqz v5, :cond_9

    .line 365
    .line 366
    new-instance p2, Lm70/y;

    .line 367
    .line 368
    new-array p4, v6, [Ljava/lang/Object;

    .line 369
    .line 370
    move-object v1, p0

    .line 371
    check-cast v1, Ljj0/f;

    .line 372
    .line 373
    const v2, 0x7f120248

    .line 374
    .line 375
    .line 376
    invoke-virtual {v1, v2, p4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object p4

    .line 380
    invoke-direct {p2, p4, v5}, Lm70/y;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 381
    .line 382
    .line 383
    invoke-virtual {p3, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 384
    .line 385
    .line 386
    :cond_9
    if-eqz p1, :cond_a

    .line 387
    .line 388
    new-instance p2, Lm70/y;

    .line 389
    .line 390
    new-array p4, v6, [Ljava/lang/Object;

    .line 391
    .line 392
    check-cast p0, Ljj0/f;

    .line 393
    .line 394
    invoke-virtual {p0, v0, p4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 395
    .line 396
    .line 397
    move-result-object p0

    .line 398
    invoke-direct {p2, p0, p1}, Lm70/y;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 399
    .line 400
    .line 401
    invoke-virtual {p3, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 402
    .line 403
    .line 404
    :cond_a
    return-object p3

    .line 405
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_6
        :pswitch_6
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final c(Ljava/lang/Number;)I
    .locals 6

    .line 1
    invoke-virtual {p0}, Ljava/lang/Number;->doubleValue()D

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const/4 p0, 0x1

    .line 6
    :goto_0
    const-wide/high16 v2, 0x4059000000000000L    # 100.0

    .line 7
    .line 8
    cmpl-double v2, v0, v2

    .line 9
    .line 10
    if-ltz v2, :cond_0

    .line 11
    .line 12
    const-wide/high16 v2, 0x4024000000000000L    # 10.0

    .line 13
    .line 14
    div-double/2addr v0, v2

    .line 15
    mul-int/lit8 p0, p0, 0xa

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-wide/16 v2, 0x0

    .line 19
    .line 20
    cmpg-double v2, v0, v2

    .line 21
    .line 22
    const/4 v3, 0x2

    .line 23
    if-gtz v2, :cond_1

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const-wide/high16 v4, 0x4000000000000000L    # 2.0

    .line 27
    .line 28
    div-double/2addr v0, v4

    .line 29
    invoke-static {v0, v1}, Ljava/lang/Math;->ceil(D)D

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    int-to-double v2, v3

    .line 34
    mul-double/2addr v0, v2

    .line 35
    invoke-static {v0, v1}, Lcy0/a;->h(D)I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_1
    mul-int/2addr v3, p0

    .line 40
    return v3
.end method

.method public static final d(La7/q1;)V
    .locals 5

    .line 1
    iget-object v0, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x1

    .line 8
    if-nez v1, :cond_4

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    :cond_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_2

    .line 28
    .line 29
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Ly6/l;

    .line 34
    .line 35
    instance-of v3, v3, La7/d0;

    .line 36
    .line 37
    if-nez v3, :cond_1

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    :goto_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_6

    .line 49
    .line 50
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    check-cast v1, Ly6/l;

    .line 55
    .line 56
    const-string v3, "null cannot be cast to non-null type androidx.glance.appwidget.EmittableSizeBox"

    .line 57
    .line 58
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    check-cast v1, La7/d0;

    .line 62
    .line 63
    iget-object v1, v1, Ly6/n;->b:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-eq v3, v2, :cond_3

    .line 70
    .line 71
    new-instance v3, Lf7/k;

    .line 72
    .line 73
    invoke-direct {v3}, Lf7/k;-><init>()V

    .line 74
    .line 75
    .line 76
    iget-object v4, v3, Ly6/n;->b:Ljava/util/ArrayList;

    .line 77
    .line 78
    invoke-static {v1, v4}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_4
    :goto_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-ne v1, v2, :cond_5

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_5
    new-instance v1, Lf7/k;

    .line 96
    .line 97
    invoke-direct {v1}, Lf7/k;-><init>()V

    .line 98
    .line 99
    .line 100
    iget-object v2, v1, Ly6/n;->b:Ljava/util/ArrayList;

    .line 101
    .line 102
    invoke-static {v0, v2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    :cond_6
    :goto_3
    invoke-static {p0}, Lim/g;->e(Ly6/n;)V

    .line 112
    .line 113
    .line 114
    invoke-static {p0}, Lim/g;->i(Ly6/n;)V

    .line 115
    .line 116
    .line 117
    return-void
.end method

.method public static final e(Ly6/n;)V
    .locals 6

    .line 1
    iget-object v0, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Ly6/l;

    .line 18
    .line 19
    instance-of v3, v2, Ly6/n;

    .line 20
    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    check-cast v2, Ly6/n;

    .line 24
    .line 25
    invoke-static {v2}, Lim/g;->e(Ly6/n;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    invoke-interface {p0}, Ly6/l;->b()Ly6/q;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    sget-object v2, La7/i1;->r:La7/i1;

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    invoke-interface {v1, v3, v2}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Lf7/n;

    .line 41
    .line 42
    sget-object v2, Lk7/f;->a:Lk7/f;

    .line 43
    .line 44
    if-eqz v1, :cond_2

    .line 45
    .line 46
    iget-object v1, v1, Lf7/n;->a:Lk7/g;

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    move-object v1, v2

    .line 50
    :goto_1
    instance-of v1, v1, Lk7/f;

    .line 51
    .line 52
    if-eqz v1, :cond_6

    .line 53
    .line 54
    if-eqz v0, :cond_3

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eqz v1, :cond_3

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    :cond_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-eqz v4, :cond_6

    .line 72
    .line 73
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Ly6/l;

    .line 78
    .line 79
    invoke-interface {v4}, Ly6/l;->b()Ly6/q;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    sget-object v5, La7/i1;->t:La7/i1;

    .line 84
    .line 85
    invoke-interface {v4, v3, v5}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    check-cast v4, Lf7/n;

    .line 90
    .line 91
    if-eqz v4, :cond_5

    .line 92
    .line 93
    iget-object v4, v4, Lf7/n;->a:Lk7/g;

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_5
    move-object v4, v3

    .line 97
    :goto_2
    instance-of v4, v4, Lk7/e;

    .line 98
    .line 99
    if-eqz v4, :cond_4

    .line 100
    .line 101
    invoke-interface {p0}, Ly6/l;->b()Ly6/q;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-static {v1}, Lkp/p7;->a(Ly6/q;)Ly6/q;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    invoke-interface {p0, v1}, Ly6/l;->a(Ly6/q;)V

    .line 110
    .line 111
    .line 112
    :cond_6
    :goto_3
    invoke-interface {p0}, Ly6/l;->b()Ly6/q;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    sget-object v4, La7/i1;->s:La7/i1;

    .line 117
    .line 118
    invoke-interface {v1, v3, v4}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    check-cast v1, Lf7/t;

    .line 123
    .line 124
    if-eqz v1, :cond_7

    .line 125
    .line 126
    iget-object v2, v1, Lf7/t;->a:Lk7/g;

    .line 127
    .line 128
    :cond_7
    instance-of v1, v2, Lk7/f;

    .line 129
    .line 130
    if-eqz v1, :cond_b

    .line 131
    .line 132
    if-eqz v0, :cond_8

    .line 133
    .line 134
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    if-eqz v1, :cond_8

    .line 139
    .line 140
    goto :goto_5

    .line 141
    :cond_8
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    :cond_9
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-eqz v1, :cond_b

    .line 150
    .line 151
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    check-cast v1, Ly6/l;

    .line 156
    .line 157
    invoke-interface {v1}, Ly6/l;->b()Ly6/q;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    sget-object v2, La7/i1;->u:La7/i1;

    .line 162
    .line 163
    invoke-interface {v1, v3, v2}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    check-cast v1, Lf7/t;

    .line 168
    .line 169
    if-eqz v1, :cond_a

    .line 170
    .line 171
    iget-object v1, v1, Lf7/t;->a:Lk7/g;

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_a
    move-object v1, v3

    .line 175
    :goto_4
    instance-of v1, v1, Lk7/e;

    .line 176
    .line 177
    if-eqz v1, :cond_9

    .line 178
    .line 179
    invoke-interface {p0}, Ly6/l;->b()Ly6/q;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    invoke-static {v0}, Lkp/p7;->c(Ly6/q;)Ly6/q;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    invoke-interface {p0, v0}, Ly6/l;->a(Ly6/q;)V

    .line 188
    .line 189
    .line 190
    :cond_b
    :goto_5
    return-void
.end method

.method public static final f(Ljava/time/LocalDate;Ll70/w;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "selectedInterval"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p1, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p1, v0, :cond_0

    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    invoke-static {p0, p1}, Ljp/e1;->c(Ljava/time/LocalDate;Z)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_0
    new-instance p0, La8/r0;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p0}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :cond_2
    invoke-static {p0}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public static final g(Ljava/time/LocalDate;Ll70/w;)Ljava/lang/String;
    .locals 7

    .line 1
    const-string v0, "selectedInterval"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    const-string v0, "%s - %s"

    .line 11
    .line 12
    const-string v1, "getDefault(...)"

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x2

    .line 16
    if-eqz p1, :cond_4

    .line 17
    .line 18
    const/4 v4, 0x1

    .line 19
    if-eq p1, v4, :cond_3

    .line 20
    .line 21
    if-ne p1, v3, :cond_2

    .line 22
    .line 23
    invoke-virtual {p0, v4}, Ljava/time/LocalDate;->withMonth(I)Ljava/time/LocalDate;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    const/16 v4, 0xc

    .line 28
    .line 29
    invoke-virtual {p0, v4}, Ljava/time/LocalDate;->withMonth(I)Ljava/time/LocalDate;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    invoke-virtual {v4, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    if-nez v4, :cond_0

    .line 42
    .line 43
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    :cond_0
    const-string v5, "MMM yyyy"

    .line 51
    .line 52
    invoke-static {v5, v4}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    invoke-virtual {v4, p1}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    invoke-virtual {v4, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    if-nez v2, :cond_1

    .line 69
    .line 70
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    :cond_1
    invoke-static {v5, v2}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-virtual {v1, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    filled-new-array {p1, p0}, [Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-static {p0, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0

    .line 98
    :cond_2
    new-instance p0, La8/r0;

    .line 99
    .line 100
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :cond_3
    invoke-static {p0, v2}, Ljp/e1;->c(Ljava/time/LocalDate;Z)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0

    .line 109
    :cond_4
    sget-object p1, Ljava/time/DayOfWeek;->MONDAY:Ljava/time/DayOfWeek;

    .line 110
    .line 111
    invoke-static {p1}, Ljava/time/temporal/TemporalAdjusters;->previousOrSame(Ljava/time/DayOfWeek;)Ljava/time/temporal/TemporalAdjuster;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-virtual {p0, p1}, Ljava/time/LocalDate;->with(Ljava/time/temporal/TemporalAdjuster;)Ljava/time/LocalDate;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    sget-object v4, Ljava/time/DayOfWeek;->SUNDAY:Ljava/time/DayOfWeek;

    .line 120
    .line 121
    invoke-static {v4}, Ljava/time/temporal/TemporalAdjusters;->nextOrSame(Ljava/time/DayOfWeek;)Ljava/time/temporal/TemporalAdjuster;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    invoke-virtual {p0, v4}, Ljava/time/LocalDate;->with(Ljava/time/temporal/TemporalAdjuster;)Ljava/time/LocalDate;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-virtual {p1}, Ljava/time/LocalDate;->getYear()I

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 134
    .line 135
    .line 136
    move-result v5

    .line 137
    const-string v6, "dd MMM yyyy"

    .line 138
    .line 139
    if-eq v4, v5, :cond_7

    .line 140
    .line 141
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    invoke-virtual {v4, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    if-nez v4, :cond_5

    .line 150
    .line 151
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    :cond_5
    invoke-static {v6, v4}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 159
    .line 160
    .line 161
    move-result-object v4

    .line 162
    invoke-virtual {v4, p1}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    invoke-virtual {v4, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 171
    .line 172
    .line 173
    move-result-object v2

    .line 174
    if-nez v2, :cond_6

    .line 175
    .line 176
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    :cond_6
    invoke-static {v6, v2}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    invoke-virtual {v1, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    filled-new-array {p1, p0}, [Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    invoke-static {p0, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    return-object p0

    .line 204
    :cond_7
    invoke-virtual {p1}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 205
    .line 206
    .line 207
    move-result-object v4

    .line 208
    invoke-virtual {p0}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 209
    .line 210
    .line 211
    move-result-object v5

    .line 212
    if-eq v4, v5, :cond_a

    .line 213
    .line 214
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    invoke-virtual {v4, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 219
    .line 220
    .line 221
    move-result-object v4

    .line 222
    if-nez v4, :cond_8

    .line 223
    .line 224
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 225
    .line 226
    .line 227
    move-result-object v4

    .line 228
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    :cond_8
    const-string v5, "dd MMM"

    .line 232
    .line 233
    invoke-static {v5, v4}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 234
    .line 235
    .line 236
    move-result-object v4

    .line 237
    invoke-virtual {v4, p1}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object p1

    .line 241
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 242
    .line 243
    .line 244
    move-result-object v4

    .line 245
    invoke-virtual {v4, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 246
    .line 247
    .line 248
    move-result-object v2

    .line 249
    if-nez v2, :cond_9

    .line 250
    .line 251
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    :cond_9
    invoke-static {v6, v2}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 259
    .line 260
    .line 261
    move-result-object v1

    .line 262
    invoke-virtual {v1, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    filled-new-array {p1, p0}, [Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    invoke-static {p0, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object p0

    .line 278
    return-object p0

    .line 279
    :cond_a
    invoke-virtual {p1}, Ljava/time/LocalDate;->getDayOfMonth()I

    .line 280
    .line 281
    .line 282
    move-result p1

    .line 283
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 284
    .line 285
    .line 286
    move-result-object p1

    .line 287
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    invoke-virtual {v0, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    if-nez v0, :cond_b

    .line 296
    .line 297
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 298
    .line 299
    .line 300
    move-result-object v0

    .line 301
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    :cond_b
    invoke-static {v6, v0}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    invoke-virtual {v0, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object p0

    .line 312
    filled-new-array {p1, p0}, [Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object p0

    .line 316
    invoke-static {p0, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object p0

    .line 320
    const-string p1, "%s-%s"

    .line 321
    .line 322
    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object p0

    .line 326
    return-object p0
.end method

.method public static final h(Ls51/b;Lrx0/c;)Ljava/io/Serializable;
    .locals 6

    .line 1
    instance-of v0, p1, Lz41/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lz41/f;

    .line 7
    .line 8
    iget v1, v0, Lz41/f;->g:I

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
    iput v1, v0, Lz41/f;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lz41/f;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lz41/f;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lz41/f;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lz41/f;->e:Ljava/lang/Throwable;

    .line 37
    .line 38
    iget-object v0, v0, Lz41/f;->d:Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object p1, p0, Ls51/b;->e:Ljava/lang/String;

    .line 56
    .line 57
    if-nez p1, :cond_3

    .line 58
    .line 59
    const-string p1, "Unknown error"

    .line 60
    .line 61
    :cond_3
    iget-object p0, p0, Ls51/b;->f:Ljava/lang/Throwable;

    .line 62
    .line 63
    instance-of v2, p0, Lfw0/c1;

    .line 64
    .line 65
    if-eqz v2, :cond_4

    .line 66
    .line 67
    move-object v2, p0

    .line 68
    check-cast v2, Lfw0/c1;

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_4
    const/4 v2, 0x0

    .line 72
    :goto_1
    if-eqz v2, :cond_6

    .line 73
    .line 74
    sget-object v4, Lf61/j;->Companion:Lf61/i;

    .line 75
    .line 76
    iget-object v2, v2, Lfw0/c1;->d:Law0/h;

    .line 77
    .line 78
    iput-object p1, v0, Lz41/f;->d:Ljava/lang/String;

    .line 79
    .line 80
    iput-object p0, v0, Lz41/f;->e:Ljava/lang/Throwable;

    .line 81
    .line 82
    iput v3, v0, Lz41/f;->g:I

    .line 83
    .line 84
    invoke-virtual {v4, v2, v0}, Lf61/i;->a(Law0/h;Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    if-ne v0, v1, :cond_5

    .line 89
    .line 90
    return-object v1

    .line 91
    :cond_5
    move-object v5, v0

    .line 92
    move-object v0, p1

    .line 93
    move-object p1, v5

    .line 94
    :goto_2
    check-cast p1, Lf61/j;

    .line 95
    .line 96
    move-object p1, v0

    .line 97
    :cond_6
    new-instance v0, Lz41/b;

    .line 98
    .line 99
    const-string v1, "reason"

    .line 100
    .line 101
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-direct {v0, p1, p0}, Lz41/e;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 105
    .line 106
    .line 107
    return-object v0
.end method

.method public static final i(Ly6/n;)V
    .locals 6

    .line 1
    sget-object v0, La7/s;->k:La7/s;

    .line 2
    .line 3
    iget-object v1, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/4 v2, 0x0

    .line 10
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-eqz v3, :cond_2

    .line 15
    .line 16
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    add-int/lit8 v4, v2, 0x1

    .line 21
    .line 22
    if-ltz v2, :cond_1

    .line 23
    .line 24
    check-cast v3, Ly6/l;

    .line 25
    .line 26
    invoke-virtual {v0, v3}, La7/s;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    check-cast v3, Ly6/l;

    .line 31
    .line 32
    iget-object v5, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-virtual {v5, v2, v3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    instance-of v2, v3, Ly6/n;

    .line 38
    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    check-cast v3, Ly6/n;

    .line 42
    .line 43
    invoke-static {v3}, Lim/g;->i(Ly6/n;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    move v2, v4

    .line 47
    goto :goto_0

    .line 48
    :cond_1
    invoke-static {}, Ljp/k1;->r()V

    .line 49
    .line 50
    .line 51
    const/4 p0, 0x0

    .line 52
    throw p0

    .line 53
    :cond_2
    return-void
.end method

.method public static final j(Ly6/n;)Ljava/util/LinkedHashMap;
    .locals 7

    .line 1
    iget-object p0, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_6

    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    add-int/lit8 v3, v1, 0x1

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    if-ltz v1, :cond_5

    .line 27
    .line 28
    check-cast v2, Ly6/l;

    .line 29
    .line 30
    invoke-interface {v2}, Ly6/l;->b()Ly6/q;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    sget-object v5, La7/s;->i:La7/s;

    .line 35
    .line 36
    invoke-interface {v1, v5}, Ly6/q;->b(Lay0/k;)Z

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-eqz v5, :cond_0

    .line 41
    .line 42
    new-instance v5, Llx0/l;

    .line 43
    .line 44
    sget-object v6, Ly6/o;->a:Ly6/o;

    .line 45
    .line 46
    invoke-direct {v5, v4, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    sget-object v6, La7/i1;->p:La7/i1;

    .line 50
    .line 51
    invoke-interface {v1, v5, v6}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Llx0/l;

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_0
    new-instance v5, Llx0/l;

    .line 59
    .line 60
    invoke-direct {v5, v4, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    move-object v1, v5

    .line 64
    :goto_1
    iget-object v5, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v5, Lz6/b;

    .line 67
    .line 68
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v1, Ly6/q;

    .line 71
    .line 72
    if-eqz v5, :cond_1

    .line 73
    .line 74
    iget-object v5, v5, Lz6/b;->a:Lz6/a;

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_1
    move-object v5, v4

    .line 78
    :goto_2
    instance-of v6, v5, Lz6/e;

    .line 79
    .line 80
    if-eqz v6, :cond_2

    .line 81
    .line 82
    new-instance v4, Llx0/l;

    .line 83
    .line 84
    invoke-direct {v4, v5, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_2
    new-instance v5, Llx0/l;

    .line 89
    .line 90
    invoke-direct {v5, v4, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    move-object v4, v5

    .line 94
    :goto_3
    iget-object v1, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v1, Lz6/e;

    .line 97
    .line 98
    iget-object v1, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v1, Ly6/q;

    .line 101
    .line 102
    instance-of v1, v2, Ly6/n;

    .line 103
    .line 104
    if-eqz v1, :cond_4

    .line 105
    .line 106
    check-cast v2, Ly6/n;

    .line 107
    .line 108
    invoke-static {v2}, Lim/g;->j(Ly6/n;)Ljava/util/LinkedHashMap;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    if-eqz v2, :cond_4

    .line 125
    .line 126
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    check-cast v2, Ljava/util/Map$Entry;

    .line 131
    .line 132
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    check-cast v4, Ljava/lang/String;

    .line 137
    .line 138
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    check-cast v2, Ljava/util/List;

    .line 143
    .line 144
    invoke-virtual {v0, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v5

    .line 148
    if-nez v5, :cond_3

    .line 149
    .line 150
    new-instance v5, Ljava/util/ArrayList;

    .line 151
    .line 152
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 153
    .line 154
    .line 155
    invoke-interface {v0, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    :cond_3
    check-cast v5, Ljava/util/List;

    .line 159
    .line 160
    check-cast v2, Ljava/util/Collection;

    .line 161
    .line 162
    invoke-interface {v5, v2}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 163
    .line 164
    .line 165
    goto :goto_4

    .line 166
    :cond_4
    move v1, v3

    .line 167
    goto/16 :goto_0

    .line 168
    .line 169
    :cond_5
    invoke-static {}, Ljp/k1;->r()V

    .line 170
    .line 171
    .line 172
    throw v4

    .line 173
    :cond_6
    return-object v0
.end method
