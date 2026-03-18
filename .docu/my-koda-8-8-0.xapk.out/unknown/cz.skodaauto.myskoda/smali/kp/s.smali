.class public abstract Lkp/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Le2/w;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Le2/w;

    .line 7
    .line 8
    iget v1, v0, Le2/w;->f:I

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
    iput v1, v0, Le2/w;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Le2/w;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Le2/w;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Le2/w;->f:I

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
    iget-object p0, v0, Le2/w;->d:Lp3/i0;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :goto_1
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 54
    .line 55
    iput-object p0, v0, Le2/w;->d:Lp3/i0;

    .line 56
    .line 57
    iput v3, v0, Le2/w;->f:I

    .line 58
    .line 59
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-ne p1, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_2
    check-cast p1, Lp3/k;

    .line 67
    .line 68
    iget-object v2, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v4, v2

    .line 71
    check-cast v4, Ljava/util/Collection;

    .line 72
    .line 73
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    const/4 v5, 0x0

    .line 78
    :goto_3
    if-ge v5, v4, :cond_5

    .line 79
    .line 80
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    check-cast v6, Lp3/t;

    .line 85
    .line 86
    invoke-static {v6}, Lp3/s;->b(Lp3/t;)Z

    .line 87
    .line 88
    .line 89
    move-result v6

    .line 90
    if-nez v6, :cond_4

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_4
    add-int/lit8 v5, v5, 0x1

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_5
    return-object p1
.end method

.method public static final b(Lp3/i0;Lcom/google/android/gms/internal/measurement/i4;Lbb/g0;Lp3/k;Lrx0/a;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    sget-object v7, Le2/t;->d:Lc1/y;

    .line 12
    .line 13
    instance-of v5, v4, Le2/x;

    .line 14
    .line 15
    if-eqz v5, :cond_0

    .line 16
    .line 17
    move-object v5, v4

    .line 18
    check-cast v5, Le2/x;

    .line 19
    .line 20
    iget v6, v5, Le2/x;->h:I

    .line 21
    .line 22
    const/high16 v8, -0x80000000

    .line 23
    .line 24
    and-int v9, v6, v8

    .line 25
    .line 26
    if-eqz v9, :cond_0

    .line 27
    .line 28
    sub-int/2addr v6, v8

    .line 29
    iput v6, v5, Le2/x;->h:I

    .line 30
    .line 31
    :goto_0
    move-object v8, v5

    .line 32
    goto :goto_1

    .line 33
    :cond_0
    new-instance v5, Le2/x;

    .line 34
    .line 35
    invoke-direct {v5, v4}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :goto_1
    iget-object v4, v8, Le2/x;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 42
    .line 43
    iget v5, v8, Le2/x;->h:I

    .line 44
    .line 45
    const/4 v10, 0x2

    .line 46
    const/4 v11, 0x0

    .line 47
    const/4 v12, 0x1

    .line 48
    if-eqz v5, :cond_5

    .line 49
    .line 50
    if-eq v5, v12, :cond_2

    .line 51
    .line 52
    if-ne v5, v10, :cond_1

    .line 53
    .line 54
    iget-object v0, v8, Le2/x;->f:Lkotlin/jvm/internal/b0;

    .line 55
    .line 56
    iget-object v1, v8, Le2/x;->e:Lcom/google/android/gms/internal/measurement/i4;

    .line 57
    .line 58
    iget-object v2, v8, Le2/x;->d:Lp3/i0;

    .line 59
    .line 60
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    move-object v15, v2

    .line 64
    move-object v2, v0

    .line 65
    move-object v0, v15

    .line 66
    move v15, v11

    .line 67
    goto/16 :goto_8

    .line 68
    .line 69
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    iget-object v0, v8, Le2/x;->e:Lcom/google/android/gms/internal/measurement/i4;

    .line 78
    .line 79
    iget-object v1, v8, Le2/x;->d:Lp3/i0;

    .line 80
    .line 81
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    check-cast v4, Ljava/lang/Boolean;

    .line 85
    .line 86
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-eqz v2, :cond_4

    .line 91
    .line 92
    iget-object v1, v1, Lp3/i0;->i:Lp3/j0;

    .line 93
    .line 94
    iget-object v1, v1, Lp3/j0;->w:Lp3/k;

    .line 95
    .line 96
    iget-object v1, v1, Lp3/k;->a:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v2, v1

    .line 99
    check-cast v2, Ljava/util/Collection;

    .line 100
    .line 101
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    :goto_2
    if-ge v11, v2, :cond_4

    .line 106
    .line 107
    invoke-interface {v1, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v3

    .line 111
    check-cast v3, Lp3/t;

    .line 112
    .line 113
    invoke-static {v3}, Lp3/s;->c(Lp3/t;)Z

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-eqz v4, :cond_3

    .line 118
    .line 119
    invoke-virtual {v3}, Lp3/t;->a()V

    .line 120
    .line 121
    .line 122
    :cond_3
    add-int/lit8 v11, v11, 0x1

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_4
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/i4;->t()V

    .line 126
    .line 127
    .line 128
    goto/16 :goto_a

    .line 129
    .line 130
    :cond_5
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    iget-object v4, v2, Lbb/g0;->f:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v4, Lw3/h2;

    .line 136
    .line 137
    iget-object v5, v2, Lbb/g0;->g:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v5, Lp3/t;

    .line 140
    .line 141
    iget-object v6, v3, Lp3/k;->a:Ljava/lang/Object;

    .line 142
    .line 143
    invoke-interface {v6, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v6

    .line 147
    check-cast v6, Lp3/t;

    .line 148
    .line 149
    if-eqz v5, :cond_6

    .line 150
    .line 151
    iget-wide v13, v6, Lp3/t;->b:J

    .line 152
    .line 153
    iget-wide v10, v5, Lp3/t;->b:J

    .line 154
    .line 155
    sub-long/2addr v13, v10

    .line 156
    invoke-interface {v4}, Lw3/h2;->a()J

    .line 157
    .line 158
    .line 159
    move-result-wide v10

    .line 160
    cmp-long v10, v13, v10

    .line 161
    .line 162
    if-gez v10, :cond_6

    .line 163
    .line 164
    iget v10, v5, Lp3/t;->i:I

    .line 165
    .line 166
    invoke-static {v4, v10}, Lg1/w0;->h(Lw3/h2;I)F

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    iget-wide v10, v5, Lp3/t;->c:J

    .line 171
    .line 172
    iget-wide v13, v6, Lp3/t;->c:J

    .line 173
    .line 174
    invoke-static {v10, v11, v13, v14}, Ld3/b;->g(JJ)J

    .line 175
    .line 176
    .line 177
    move-result-wide v10

    .line 178
    invoke-static {v10, v11}, Ld3/b;->d(J)F

    .line 179
    .line 180
    .line 181
    move-result v5

    .line 182
    cmpg-float v4, v5, v4

    .line 183
    .line 184
    if-gez v4, :cond_6

    .line 185
    .line 186
    iget v4, v2, Lbb/g0;->e:I

    .line 187
    .line 188
    add-int/2addr v4, v12

    .line 189
    iput v4, v2, Lbb/g0;->e:I

    .line 190
    .line 191
    goto :goto_3

    .line 192
    :cond_6
    iput v12, v2, Lbb/g0;->e:I

    .line 193
    .line 194
    :goto_3
    iput-object v6, v2, Lbb/g0;->g:Ljava/lang/Object;

    .line 195
    .line 196
    iget-object v3, v3, Lp3/k;->a:Ljava/lang/Object;

    .line 197
    .line 198
    const/4 v15, 0x0

    .line 199
    invoke-interface {v3, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v3

    .line 203
    move-object v10, v3

    .line 204
    check-cast v10, Lp3/t;

    .line 205
    .line 206
    iget v11, v2, Lbb/g0;->e:I

    .line 207
    .line 208
    if-eq v11, v12, :cond_8

    .line 209
    .line 210
    const/4 v2, 0x2

    .line 211
    if-eq v11, v2, :cond_7

    .line 212
    .line 213
    sget-object v2, Le2/t;->f:Lc1/y;

    .line 214
    .line 215
    :goto_4
    move-object v6, v2

    .line 216
    goto :goto_5

    .line 217
    :cond_7
    sget-object v2, Le2/t;->e:Lc1/y;

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_8
    move-object v6, v7

    .line 221
    :goto_5
    iget-wide v2, v10, Lp3/t;->c:J

    .line 222
    .line 223
    iget-object v4, v1, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v4, Le2/w0;

    .line 226
    .line 227
    invoke-virtual {v4}, Le2/w0;->j()Z

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    if-eqz v5, :cond_c

    .line 232
    .line 233
    invoke-virtual {v4}, Le2/w0;->m()Ll4/v;

    .line 234
    .line 235
    .line 236
    move-result-object v5

    .line 237
    iget-object v5, v5, Ll4/v;->a:Lg4/g;

    .line 238
    .line 239
    iget-object v5, v5, Lg4/g;->e:Ljava/lang/String;

    .line 240
    .line 241
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 242
    .line 243
    .line 244
    move-result v5

    .line 245
    if-nez v5, :cond_9

    .line 246
    .line 247
    goto :goto_6

    .line 248
    :cond_9
    iget-object v5, v4, Le2/w0;->d:Lt1/p0;

    .line 249
    .line 250
    if-eqz v5, :cond_c

    .line 251
    .line 252
    invoke-virtual {v5}, Lt1/p0;->d()Lt1/j1;

    .line 253
    .line 254
    .line 255
    move-result-object v5

    .line 256
    if-nez v5, :cond_a

    .line 257
    .line 258
    goto :goto_6

    .line 259
    :cond_a
    iget-object v5, v4, Le2/w0;->k:Lc3/q;

    .line 260
    .line 261
    if-eqz v5, :cond_b

    .line 262
    .line 263
    invoke-static {v5}, Lc3/q;->b(Lc3/q;)V

    .line 264
    .line 265
    .line 266
    :cond_b
    iput-wide v2, v4, Le2/w0;->n:J

    .line 267
    .line 268
    const/4 v2, -0x1

    .line 269
    iput v2, v4, Le2/w0;->s:I

    .line 270
    .line 271
    const/4 v13, 0x1

    .line 272
    invoke-virtual {v4, v13}, Le2/w0;->h(Z)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v4}, Le2/w0;->m()Ll4/v;

    .line 276
    .line 277
    .line 278
    move-result-object v2

    .line 279
    iget-wide v3, v4, Le2/w0;->n:J

    .line 280
    .line 281
    const/4 v5, 0x1

    .line 282
    invoke-virtual/range {v1 .. v6}, Lcom/google/android/gms/internal/measurement/i4;->x(Ll4/v;JZLc1/y;)J

    .line 283
    .line 284
    .line 285
    move-result-wide v2

    .line 286
    const/4 v4, 0x2

    .line 287
    if-lt v11, v4, :cond_d

    .line 288
    .line 289
    iput-boolean v13, v1, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 290
    .line 291
    new-instance v4, Lg4/o0;

    .line 292
    .line 293
    invoke-direct {v4, v2, v3}, Lg4/o0;-><init>(J)V

    .line 294
    .line 295
    .line 296
    iput-object v4, v1, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_c
    :goto_6
    const/4 v13, 0x0

    .line 300
    :cond_d
    :goto_7
    if-eqz v13, :cond_11

    .line 301
    .line 302
    new-instance v2, Lkotlin/jvm/internal/b0;

    .line 303
    .line 304
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 305
    .line 306
    .line 307
    invoke-virtual {v6, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    move-result v3

    .line 311
    xor-int/2addr v3, v12

    .line 312
    iput-boolean v3, v2, Lkotlin/jvm/internal/b0;->d:Z

    .line 313
    .line 314
    iget-wide v3, v10, Lp3/t;->a:J

    .line 315
    .line 316
    new-instance v5, Laa/o;

    .line 317
    .line 318
    const/16 v7, 0x9

    .line 319
    .line 320
    invoke-direct {v5, v1, v6, v2, v7}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 321
    .line 322
    .line 323
    iput-object v0, v8, Le2/x;->d:Lp3/i0;

    .line 324
    .line 325
    iput-object v1, v8, Le2/x;->e:Lcom/google/android/gms/internal/measurement/i4;

    .line 326
    .line 327
    iput-object v2, v8, Le2/x;->f:Lkotlin/jvm/internal/b0;

    .line 328
    .line 329
    const/4 v6, 0x2

    .line 330
    iput v6, v8, Le2/x;->h:I

    .line 331
    .line 332
    invoke-static {v0, v3, v4, v5, v8}, Lg1/w0;->e(Lp3/i0;JLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v4

    .line 336
    if-ne v4, v9, :cond_e

    .line 337
    .line 338
    return-object v9

    .line 339
    :cond_e
    :goto_8
    check-cast v4, Ljava/lang/Boolean;

    .line 340
    .line 341
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 342
    .line 343
    .line 344
    move-result v3

    .line 345
    if-eqz v3, :cond_10

    .line 346
    .line 347
    iget-boolean v2, v2, Lkotlin/jvm/internal/b0;->d:Z

    .line 348
    .line 349
    if-eqz v2, :cond_10

    .line 350
    .line 351
    iget-object v0, v0, Lp3/i0;->i:Lp3/j0;

    .line 352
    .line 353
    iget-object v0, v0, Lp3/j0;->w:Lp3/k;

    .line 354
    .line 355
    iget-object v0, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 356
    .line 357
    move-object v2, v0

    .line 358
    check-cast v2, Ljava/util/Collection;

    .line 359
    .line 360
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 361
    .line 362
    .line 363
    move-result v2

    .line 364
    move v11, v15

    .line 365
    :goto_9
    if-ge v11, v2, :cond_10

    .line 366
    .line 367
    invoke-interface {v0, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 368
    .line 369
    .line 370
    move-result-object v3

    .line 371
    check-cast v3, Lp3/t;

    .line 372
    .line 373
    invoke-static {v3}, Lp3/s;->c(Lp3/t;)Z

    .line 374
    .line 375
    .line 376
    move-result v4

    .line 377
    if-eqz v4, :cond_f

    .line 378
    .line 379
    invoke-virtual {v3}, Lp3/t;->a()V

    .line 380
    .line 381
    .line 382
    :cond_f
    add-int/lit8 v11, v11, 0x1

    .line 383
    .line 384
    goto :goto_9

    .line 385
    :cond_10
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/i4;->t()V

    .line 386
    .line 387
    .line 388
    :cond_11
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 389
    .line 390
    return-object v0
.end method

.method public static final c(Lp3/i0;Lt1/w0;Lp3/k;Lrx0/a;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Le2/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Le2/z;

    .line 7
    .line 8
    iget v1, v0, Le2/z;->h:I

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
    iput v1, v0, Le2/z;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Le2/z;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Le2/z;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Le2/z;->h:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    iget-object p1, v0, Le2/z;->e:Lt1/w0;

    .line 41
    .line 42
    iget-object p0, v0, Le2/z;->d:Lp3/i0;

    .line 43
    .line 44
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    .line 46
    .line 47
    goto/16 :goto_4

    .line 48
    .line 49
    :catch_0
    move-exception p0

    .line 50
    goto/16 :goto_7

    .line 51
    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget-object p0, v0, Le2/z;->f:Lp3/t;

    .line 61
    .line 62
    iget-object p1, v0, Le2/z;->e:Lt1/w0;

    .line 63
    .line 64
    iget-object p2, v0, Le2/z;->d:Lp3/i0;

    .line 65
    .line 66
    :try_start_1
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 67
    .line 68
    .line 69
    move-object v10, p2

    .line 70
    move-object p2, p0

    .line 71
    move-object p0, v10

    .line 72
    goto :goto_1

    .line 73
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :try_start_2
    iget-object p2, p2, Lp3/k;->a:Ljava/lang/Object;

    .line 77
    .line 78
    invoke-static {p2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    check-cast p2, Lp3/t;

    .line 83
    .line 84
    iget-wide v6, p2, Lp3/t;->a:J

    .line 85
    .line 86
    iput-object p0, v0, Le2/z;->d:Lp3/i0;

    .line 87
    .line 88
    iput-object p1, v0, Le2/z;->e:Lt1/w0;

    .line 89
    .line 90
    iput-object p2, v0, Le2/z;->f:Lp3/t;

    .line 91
    .line 92
    iput v5, v0, Le2/z;->h:I

    .line 93
    .line 94
    invoke-static {p0, v6, v7, v0}, Lg1/w0;->c(Lp3/i0;JLrx0/c;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p3

    .line 98
    if-ne p3, v1, :cond_4

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_4
    :goto_1
    check-cast p3, Lp3/t;

    .line 102
    .line 103
    if-eqz p3, :cond_a

    .line 104
    .line 105
    iget-wide v6, p3, Lp3/t;->c:J

    .line 106
    .line 107
    invoke-virtual {p0}, Lp3/i0;->f()Lw3/h2;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    iget v8, p2, Lp3/t;->i:I

    .line 112
    .line 113
    invoke-static {v2, v8}, Lg1/w0;->h(Lw3/h2;I)F

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    iget-wide v8, p2, Lp3/t;->c:J

    .line 118
    .line 119
    invoke-static {v8, v9, v6, v7}, Ld3/b;->g(JJ)J

    .line 120
    .line 121
    .line 122
    move-result-wide v8

    .line 123
    invoke-static {v8, v9}, Ld3/b;->d(J)F

    .line 124
    .line 125
    .line 126
    move-result p2

    .line 127
    cmpg-float p2, p2, v2

    .line 128
    .line 129
    if-gez p2, :cond_5

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_5
    move v5, v3

    .line 133
    :goto_2
    if-eqz v5, :cond_a

    .line 134
    .line 135
    invoke-interface {p1, v6, v7}, Lt1/w0;->b(J)V

    .line 136
    .line 137
    .line 138
    iget-wide p2, p3, Lp3/t;->a:J

    .line 139
    .line 140
    new-instance v2, Le2/v;

    .line 141
    .line 142
    const/4 v5, 0x0

    .line 143
    invoke-direct {v2, p1, v5}, Le2/v;-><init>(Lt1/w0;I)V

    .line 144
    .line 145
    .line 146
    iput-object p0, v0, Le2/z;->d:Lp3/i0;

    .line 147
    .line 148
    iput-object p1, v0, Le2/z;->e:Lt1/w0;

    .line 149
    .line 150
    const/4 v5, 0x0

    .line 151
    iput-object v5, v0, Le2/z;->f:Lp3/t;

    .line 152
    .line 153
    iput v4, v0, Le2/z;->h:I

    .line 154
    .line 155
    invoke-static {p0, p2, p3, v2, v0}, Lg1/w0;->e(Lp3/i0;JLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p3

    .line 159
    if-ne p3, v1, :cond_6

    .line 160
    .line 161
    :goto_3
    return-object v1

    .line 162
    :cond_6
    :goto_4
    check-cast p3, Ljava/lang/Boolean;

    .line 163
    .line 164
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 165
    .line 166
    .line 167
    move-result p2

    .line 168
    if-eqz p2, :cond_9

    .line 169
    .line 170
    iget-object p0, p0, Lp3/i0;->i:Lp3/j0;

    .line 171
    .line 172
    iget-object p0, p0, Lp3/j0;->w:Lp3/k;

    .line 173
    .line 174
    iget-object p0, p0, Lp3/k;->a:Ljava/lang/Object;

    .line 175
    .line 176
    move-object p2, p0

    .line 177
    check-cast p2, Ljava/util/Collection;

    .line 178
    .line 179
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    .line 180
    .line 181
    .line 182
    move-result p2

    .line 183
    :goto_5
    if-ge v3, p2, :cond_8

    .line 184
    .line 185
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p3

    .line 189
    check-cast p3, Lp3/t;

    .line 190
    .line 191
    invoke-static {p3}, Lp3/s;->c(Lp3/t;)Z

    .line 192
    .line 193
    .line 194
    move-result v0

    .line 195
    if-eqz v0, :cond_7

    .line 196
    .line 197
    invoke-virtual {p3}, Lp3/t;->a()V

    .line 198
    .line 199
    .line 200
    :cond_7
    add-int/lit8 v3, v3, 0x1

    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_8
    invoke-interface {p1}, Lt1/w0;->c()V

    .line 204
    .line 205
    .line 206
    goto :goto_6

    .line 207
    :cond_9
    invoke-interface {p1}, Lt1/w0;->onCancel()V
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_0

    .line 208
    .line 209
    .line 210
    :cond_a
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 211
    .line 212
    return-object p0

    .line 213
    :goto_7
    invoke-interface {p1}, Lt1/w0;->onCancel()V

    .line 214
    .line 215
    .line 216
    throw p0
.end method

.method public static final d(Lp3/k;)Z
    .locals 5

    .line 1
    iget-object p0, p0, Lp3/k;->a:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Ljava/util/Collection;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    move v2, v1

    .line 12
    :goto_0
    if-ge v2, v0, :cond_1

    .line 13
    .line 14
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    check-cast v3, Lp3/t;

    .line 19
    .line 20
    iget v3, v3, Lp3/t;->i:I

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    if-ne v3, v4, :cond_0

    .line 24
    .line 25
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    return v1

    .line 29
    :cond_1
    const/4 p0, 0x1

    .line 30
    return p0
.end method

.method public static e(Lr9/g;[Ljava/lang/String;Ljava/util/Map;)Lr9/g;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-nez p0, :cond_3

    .line 4
    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    array-length v2, p1

    .line 10
    if-ne v2, v1, :cond_1

    .line 11
    .line 12
    aget-object p0, p1, v0

    .line 13
    .line 14
    invoke-interface {p2, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Lr9/g;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_1
    array-length v2, p1

    .line 22
    if-le v2, v1, :cond_5

    .line 23
    .line 24
    new-instance p0, Lr9/g;

    .line 25
    .line 26
    invoke-direct {p0}, Lr9/g;-><init>()V

    .line 27
    .line 28
    .line 29
    array-length v1, p1

    .line 30
    :goto_0
    if-ge v0, v1, :cond_2

    .line 31
    .line 32
    aget-object v2, p1, v0

    .line 33
    .line 34
    invoke-interface {p2, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Lr9/g;

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Lr9/g;->a(Lr9/g;)V

    .line 41
    .line 42
    .line 43
    add-int/lit8 v0, v0, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    return-object p0

    .line 47
    :cond_3
    if-eqz p1, :cond_4

    .line 48
    .line 49
    array-length v2, p1

    .line 50
    if-ne v2, v1, :cond_4

    .line 51
    .line 52
    aget-object p1, p1, v0

    .line 53
    .line 54
    invoke-interface {p2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    check-cast p1, Lr9/g;

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Lr9/g;->a(Lr9/g;)V

    .line 61
    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_4
    if-eqz p1, :cond_5

    .line 65
    .line 66
    array-length v2, p1

    .line 67
    if-le v2, v1, :cond_5

    .line 68
    .line 69
    array-length v1, p1

    .line 70
    :goto_1
    if-ge v0, v1, :cond_5

    .line 71
    .line 72
    aget-object v2, p1, v0

    .line 73
    .line 74
    invoke-interface {p2, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Lr9/g;

    .line 79
    .line 80
    invoke-virtual {p0, v2}, Lr9/g;->a(Lr9/g;)V

    .line 81
    .line 82
    .line 83
    add-int/lit8 v0, v0, 0x1

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_5
    return-object p0
.end method
