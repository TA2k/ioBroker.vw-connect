.class public final Lio/ktor/utils/io/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lio/ktor/utils/io/t;

.field public final b:Loz0/a;

.field public final c:Lio/ktor/utils/io/d0;

.field public final d:J

.field public final e:Lnz0/i;

.field public final f:[I

.field public final g:Lnz0/a;

.field public h:J

.field public i:I


# direct methods
.method public constructor <init>(Lio/ktor/utils/io/t;Loz0/a;Lio/ktor/utils/io/d0;J)V
    .locals 2

    .line 1
    const-string v0, "channel"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "matchString"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "writeChannel"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lio/ktor/utils/io/q;->a:Lio/ktor/utils/io/t;

    .line 20
    .line 21
    iput-object p2, p0, Lio/ktor/utils/io/q;->b:Loz0/a;

    .line 22
    .line 23
    iput-object p3, p0, Lio/ktor/utils/io/q;->c:Lio/ktor/utils/io/d0;

    .line 24
    .line 25
    iput-wide p4, p0, Lio/ktor/utils/io/q;->d:J

    .line 26
    .line 27
    iget-object p3, p2, Loz0/a;->d:[B

    .line 28
    .line 29
    array-length p4, p3

    .line 30
    if-lez p4, :cond_3

    .line 31
    .line 32
    invoke-interface {p1}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lio/ktor/utils/io/q;->e:Lnz0/i;

    .line 37
    .line 38
    array-length p1, p3

    .line 39
    new-array p1, p1, [I

    .line 40
    .line 41
    array-length p3, p3

    .line 42
    const/4 p4, 0x0

    .line 43
    const/4 p5, 0x1

    .line 44
    :goto_0
    if-ge p5, p3, :cond_2

    .line 45
    .line 46
    :goto_1
    if-lez p4, :cond_0

    .line 47
    .line 48
    invoke-virtual {p2, p5}, Loz0/a;->a(I)B

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-virtual {p2, p4}, Loz0/a;->a(I)B

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eq v0, v1, :cond_0

    .line 57
    .line 58
    add-int/lit8 p4, p4, -0x1

    .line 59
    .line 60
    aget p4, p1, p4

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_0
    invoke-virtual {p2, p5}, Loz0/a;->a(I)B

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    invoke-virtual {p2, p4}, Loz0/a;->a(I)B

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-ne v0, v1, :cond_1

    .line 72
    .line 73
    add-int/lit8 p4, p4, 0x1

    .line 74
    .line 75
    :cond_1
    aput p4, p1, p5

    .line 76
    .line 77
    add-int/lit8 p5, p5, 0x1

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_2
    iput-object p1, p0, Lio/ktor/utils/io/q;->f:[I

    .line 81
    .line 82
    new-instance p1, Lnz0/a;

    .line 83
    .line 84
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 85
    .line 86
    .line 87
    iput-object p1, p0, Lio/ktor/utils/io/q;->g:Lnz0/a;

    .line 88
    .line 89
    return-void

    .line 90
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 91
    .line 92
    const-string p1, "Empty match string not permitted for scanning"

    .line 93
    .line 94
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lio/ktor/utils/io/n;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lio/ktor/utils/io/n;

    .line 11
    .line 12
    iget v3, v2, Lio/ktor/utils/io/n;->f:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lio/ktor/utils/io/n;->f:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lio/ktor/utils/io/n;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lio/ktor/utils/io/n;-><init>(Lio/ktor/utils/io/q;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lio/ktor/utils/io/n;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lio/ktor/utils/io/n;->f:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    iget-object v9, v0, Lio/ktor/utils/io/q;->e:Lnz0/i;

    .line 41
    .line 42
    if-eqz v4, :cond_4

    .line 43
    .line 44
    if-eq v4, v8, :cond_3

    .line 45
    .line 46
    if-eq v4, v7, :cond_2

    .line 47
    .line 48
    if-ne v4, v6, :cond_1

    .line 49
    .line 50
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object v5

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
    move-object v13, v5

    .line 66
    move-object/from16 v21, v9

    .line 67
    .line 68
    move v9, v7

    .line 69
    goto/16 :goto_c

    .line 70
    .line 71
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :goto_1
    invoke-interface {v9}, Lnz0/i;->Z()Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_7

    .line 83
    .line 84
    iput v8, v2, Lio/ktor/utils/io/n;->f:I

    .line 85
    .line 86
    sget-object v1, Lio/ktor/utils/io/t;->a:Lio/ktor/utils/io/s;

    .line 87
    .line 88
    iget-object v1, v0, Lio/ktor/utils/io/q;->a:Lio/ktor/utils/io/t;

    .line 89
    .line 90
    invoke-interface {v1, v8, v2}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    if-ne v1, v3, :cond_5

    .line 95
    .line 96
    goto/16 :goto_d

    .line 97
    .line 98
    :cond_5
    :goto_2
    check-cast v1, Ljava/lang/Boolean;

    .line 99
    .line 100
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-eqz v1, :cond_6

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_6
    move-object v13, v5

    .line 108
    goto/16 :goto_e

    .line 109
    .line 110
    :cond_7
    :goto_3
    iget-object v1, v0, Lio/ktor/utils/io/q;->b:Loz0/a;

    .line 111
    .line 112
    const/4 v4, 0x0

    .line 113
    invoke-virtual {v1, v4}, Loz0/a;->a(I)B

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    const-string v10, "<this>"

    .line 118
    .line 119
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const-wide/16 v15, 0x0

    .line 123
    .line 124
    :goto_4
    const-wide v13, 0x7fffffffffffffffL

    .line 125
    .line 126
    .line 127
    .line 128
    .line 129
    cmp-long v17, v15, v13

    .line 130
    .line 131
    const-wide/16 v19, -0x1

    .line 132
    .line 133
    if-gez v17, :cond_17

    .line 134
    .line 135
    const-wide/16 v17, 0x1

    .line 136
    .line 137
    add-long v11, v15, v17

    .line 138
    .line 139
    invoke-interface {v9, v11, v12}, Lnz0/i;->c(J)Z

    .line 140
    .line 141
    .line 142
    move-result v11

    .line 143
    if-eqz v11, :cond_17

    .line 144
    .line 145
    invoke-interface {v9}, Lnz0/i;->n()Lnz0/a;

    .line 146
    .line 147
    .line 148
    move-result-object v11

    .line 149
    invoke-interface {v9}, Lnz0/i;->n()Lnz0/a;

    .line 150
    .line 151
    .line 152
    move-result-object v12

    .line 153
    move-object/from16 v21, v9

    .line 154
    .line 155
    iget-wide v8, v12, Lnz0/a;->f:J

    .line 156
    .line 157
    invoke-static {v13, v14, v8, v9}, Ljava/lang/Math;->min(JJ)J

    .line 158
    .line 159
    .line 160
    move-result-wide v8

    .line 161
    invoke-static {v11, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    iget-wide v12, v11, Lnz0/a;->f:J

    .line 165
    .line 166
    invoke-static {v8, v9, v12, v13}, Ljava/lang/Math;->min(JJ)J

    .line 167
    .line 168
    .line 169
    move-result-wide v17

    .line 170
    iget-wide v13, v11, Lnz0/a;->f:J

    .line 171
    .line 172
    invoke-static/range {v13 .. v18}, Lnz0/j;->a(JJJ)V

    .line 173
    .line 174
    .line 175
    cmp-long v8, v15, v17

    .line 176
    .line 177
    if-nez v8, :cond_a

    .line 178
    .line 179
    :cond_8
    :goto_5
    move-object v13, v5

    .line 180
    :cond_9
    :goto_6
    move-wide/from16 v4, v19

    .line 181
    .line 182
    goto/16 :goto_a

    .line 183
    .line 184
    :cond_a
    iget-object v8, v11, Lnz0/a;->d:Lnz0/g;

    .line 185
    .line 186
    if-nez v8, :cond_b

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_b
    iget-wide v12, v11, Lnz0/a;->f:J

    .line 190
    .line 191
    sub-long v22, v12, v15

    .line 192
    .line 193
    cmp-long v9, v22, v15

    .line 194
    .line 195
    const-string v14, "Check failed."

    .line 196
    .line 197
    if-gez v9, :cond_10

    .line 198
    .line 199
    iget-object v8, v11, Lnz0/a;->e:Lnz0/g;

    .line 200
    .line 201
    :goto_7
    if-eqz v8, :cond_c

    .line 202
    .line 203
    cmp-long v9, v12, v15

    .line 204
    .line 205
    if-lez v9, :cond_c

    .line 206
    .line 207
    iget v9, v8, Lnz0/g;->c:I

    .line 208
    .line 209
    iget v11, v8, Lnz0/g;->b:I

    .line 210
    .line 211
    sub-int/2addr v9, v11

    .line 212
    int-to-long v6, v9

    .line 213
    sub-long/2addr v12, v6

    .line 214
    cmp-long v6, v12, v15

    .line 215
    .line 216
    if-lez v6, :cond_c

    .line 217
    .line 218
    iget-object v8, v8, Lnz0/g;->g:Lnz0/g;

    .line 219
    .line 220
    const/4 v7, 0x2

    .line 221
    goto :goto_7

    .line 222
    :cond_c
    cmp-long v6, v12, v19

    .line 223
    .line 224
    if-nez v6, :cond_d

    .line 225
    .line 226
    goto :goto_5

    .line 227
    :cond_d
    cmp-long v6, v17, v12

    .line 228
    .line 229
    if-lez v6, :cond_f

    .line 230
    .line 231
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    sub-long v6, v15, v12

    .line 235
    .line 236
    long-to-int v6, v6

    .line 237
    invoke-static {v6, v4}, Ljava/lang/Math;->max(II)I

    .line 238
    .line 239
    .line 240
    move-result v6

    .line 241
    invoke-virtual {v8}, Lnz0/g;->b()I

    .line 242
    .line 243
    .line 244
    move-result v7

    .line 245
    move-wide/from16 v24, v12

    .line 246
    .line 247
    sub-long v11, v17, v24

    .line 248
    .line 249
    long-to-int v11, v11

    .line 250
    invoke-static {v7, v11}, Ljava/lang/Math;->min(II)I

    .line 251
    .line 252
    .line 253
    move-result v7

    .line 254
    invoke-static {v8, v1, v6, v7}, Lnz0/j;->c(Lnz0/g;BII)I

    .line 255
    .line 256
    .line 257
    move-result v6

    .line 258
    const/4 v7, -0x1

    .line 259
    if-eq v6, v7, :cond_e

    .line 260
    .line 261
    int-to-long v6, v6

    .line 262
    add-long v12, v24, v6

    .line 263
    .line 264
    move-wide/from16 v26, v12

    .line 265
    .line 266
    move-object v13, v5

    .line 267
    move-wide/from16 v4, v26

    .line 268
    .line 269
    goto/16 :goto_a

    .line 270
    .line 271
    :cond_e
    invoke-virtual {v8}, Lnz0/g;->b()I

    .line 272
    .line 273
    .line 274
    move-result v6

    .line 275
    int-to-long v6, v6

    .line 276
    add-long v12, v24, v6

    .line 277
    .line 278
    iget-object v8, v8, Lnz0/g;->f:Lnz0/g;

    .line 279
    .line 280
    if-eqz v8, :cond_8

    .line 281
    .line 282
    cmp-long v6, v12, v17

    .line 283
    .line 284
    if-ltz v6, :cond_d

    .line 285
    .line 286
    goto :goto_5

    .line 287
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 288
    .line 289
    invoke-direct {v0, v14}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    throw v0

    .line 293
    :cond_10
    const-wide/16 v6, 0x0

    .line 294
    .line 295
    :goto_8
    if-eqz v8, :cond_11

    .line 296
    .line 297
    iget v11, v8, Lnz0/g;->c:I

    .line 298
    .line 299
    iget v12, v8, Lnz0/g;->b:I

    .line 300
    .line 301
    sub-int/2addr v11, v12

    .line 302
    int-to-long v11, v11

    .line 303
    add-long/2addr v11, v6

    .line 304
    cmp-long v13, v11, v15

    .line 305
    .line 306
    if-gtz v13, :cond_11

    .line 307
    .line 308
    iget-object v8, v8, Lnz0/g;->f:Lnz0/g;

    .line 309
    .line 310
    move-wide v6, v11

    .line 311
    goto :goto_8

    .line 312
    :cond_11
    cmp-long v11, v6, v19

    .line 313
    .line 314
    if-nez v11, :cond_12

    .line 315
    .line 316
    goto/16 :goto_5

    .line 317
    .line 318
    :cond_12
    :goto_9
    cmp-long v11, v17, v6

    .line 319
    .line 320
    if-lez v11, :cond_16

    .line 321
    .line 322
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    sub-long v11, v15, v6

    .line 326
    .line 327
    long-to-int v11, v11

    .line 328
    invoke-static {v11, v4}, Ljava/lang/Math;->max(II)I

    .line 329
    .line 330
    .line 331
    move-result v11

    .line 332
    invoke-virtual {v8}, Lnz0/g;->b()I

    .line 333
    .line 334
    .line 335
    move-result v12

    .line 336
    move-object v13, v5

    .line 337
    sub-long v4, v17, v6

    .line 338
    .line 339
    long-to-int v4, v4

    .line 340
    invoke-static {v12, v4}, Ljava/lang/Math;->min(II)I

    .line 341
    .line 342
    .line 343
    move-result v4

    .line 344
    invoke-static {v8, v1, v11, v4}, Lnz0/j;->c(Lnz0/g;BII)I

    .line 345
    .line 346
    .line 347
    move-result v4

    .line 348
    const/4 v5, -0x1

    .line 349
    if-eq v4, v5, :cond_13

    .line 350
    .line 351
    int-to-long v4, v4

    .line 352
    add-long/2addr v4, v6

    .line 353
    goto :goto_a

    .line 354
    :cond_13
    invoke-virtual {v8}, Lnz0/g;->b()I

    .line 355
    .line 356
    .line 357
    move-result v4

    .line 358
    int-to-long v11, v4

    .line 359
    add-long/2addr v6, v11

    .line 360
    iget-object v8, v8, Lnz0/g;->f:Lnz0/g;

    .line 361
    .line 362
    if-eqz v8, :cond_9

    .line 363
    .line 364
    cmp-long v4, v6, v17

    .line 365
    .line 366
    if-ltz v4, :cond_14

    .line 367
    .line 368
    goto/16 :goto_6

    .line 369
    .line 370
    :cond_14
    move-object v5, v13

    .line 371
    const/4 v4, 0x0

    .line 372
    goto :goto_9

    .line 373
    :goto_a
    cmp-long v6, v4, v19

    .line 374
    .line 375
    if-eqz v6, :cond_15

    .line 376
    .line 377
    goto :goto_b

    .line 378
    :cond_15
    invoke-interface/range {v21 .. v21}, Lnz0/i;->n()Lnz0/a;

    .line 379
    .line 380
    .line 381
    move-result-object v4

    .line 382
    iget-wide v4, v4, Lnz0/a;->f:J

    .line 383
    .line 384
    move-wide v15, v4

    .line 385
    move-object v5, v13

    .line 386
    move-object/from16 v9, v21

    .line 387
    .line 388
    const/4 v4, 0x0

    .line 389
    const/4 v6, 0x3

    .line 390
    const/4 v7, 0x2

    .line 391
    const/4 v8, 0x1

    .line 392
    goto/16 :goto_4

    .line 393
    .line 394
    :cond_16
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 395
    .line 396
    invoke-direct {v0, v14}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 397
    .line 398
    .line 399
    throw v0

    .line 400
    :cond_17
    move-object v13, v5

    .line 401
    move-object/from16 v21, v9

    .line 402
    .line 403
    move-wide/from16 v4, v19

    .line 404
    .line 405
    :goto_b
    cmp-long v1, v4, v19

    .line 406
    .line 407
    iget-object v6, v0, Lio/ktor/utils/io/q;->c:Lio/ktor/utils/io/d0;

    .line 408
    .line 409
    if-nez v1, :cond_19

    .line 410
    .line 411
    move-object/from16 v1, v21

    .line 412
    .line 413
    check-cast v1, Lnz0/a;

    .line 414
    .line 415
    iget-wide v4, v1, Lnz0/a;->f:J

    .line 416
    .line 417
    invoke-virtual {v0, v4, v5}, Lio/ktor/utils/io/q;->b(J)V

    .line 418
    .line 419
    .line 420
    iget-wide v4, v0, Lio/ktor/utils/io/q;->h:J

    .line 421
    .line 422
    move-object v7, v6

    .line 423
    check-cast v7, Lio/ktor/utils/io/m;

    .line 424
    .line 425
    invoke-virtual {v7}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 426
    .line 427
    .line 428
    move-result-object v7

    .line 429
    invoke-virtual {v1, v7}, Lnz0/a;->h(Lnz0/a;)J

    .line 430
    .line 431
    .line 432
    move-result-wide v7

    .line 433
    add-long/2addr v7, v4

    .line 434
    iput-wide v7, v0, Lio/ktor/utils/io/q;->h:J

    .line 435
    .line 436
    const/4 v9, 0x2

    .line 437
    iput v9, v2, Lio/ktor/utils/io/n;->f:I

    .line 438
    .line 439
    invoke-static {v6, v2}, Lio/ktor/utils/io/h0;->e(Lio/ktor/utils/io/d0;Lrx0/c;)Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v1

    .line 443
    if-ne v1, v3, :cond_18

    .line 444
    .line 445
    goto :goto_d

    .line 446
    :cond_18
    :goto_c
    move v7, v9

    .line 447
    move-object v5, v13

    .line 448
    move-object/from16 v9, v21

    .line 449
    .line 450
    const/4 v6, 0x3

    .line 451
    const/4 v8, 0x1

    .line 452
    goto/16 :goto_1

    .line 453
    .line 454
    :cond_19
    invoke-virtual {v0, v4, v5}, Lio/ktor/utils/io/q;->b(J)V

    .line 455
    .line 456
    .line 457
    iget-wide v7, v0, Lio/ktor/utils/io/q;->h:J

    .line 458
    .line 459
    move-object v1, v6

    .line 460
    check-cast v1, Lio/ktor/utils/io/m;

    .line 461
    .line 462
    invoke-virtual {v1}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    move-object/from16 v9, v21

    .line 467
    .line 468
    invoke-interface {v9, v1, v4, v5}, Lnz0/d;->I(Lnz0/a;J)J

    .line 469
    .line 470
    .line 471
    move-result-wide v4

    .line 472
    add-long/2addr v4, v7

    .line 473
    iput-wide v4, v0, Lio/ktor/utils/io/q;->h:J

    .line 474
    .line 475
    const/4 v0, 0x3

    .line 476
    iput v0, v2, Lio/ktor/utils/io/n;->f:I

    .line 477
    .line 478
    invoke-static {v6, v2}, Lio/ktor/utils/io/h0;->e(Lio/ktor/utils/io/d0;Lrx0/c;)Ljava/lang/Object;

    .line 479
    .line 480
    .line 481
    move-result-object v0

    .line 482
    if-ne v0, v3, :cond_1a

    .line 483
    .line 484
    :goto_d
    return-object v3

    .line 485
    :cond_1a
    :goto_e
    return-object v13
.end method

.method public final b(J)V
    .locals 3

    .line 1
    iget-wide v0, p0, Lio/ktor/utils/io/q;->h:J

    .line 2
    .line 3
    add-long/2addr v0, p1

    .line 4
    iget-wide p1, p0, Lio/ktor/utils/io/q;->d:J

    .line 5
    .line 6
    cmp-long v0, v0, p1

    .line 7
    .line 8
    if-gtz v0, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    new-instance v0, Ljava/io/IOException;

    .line 12
    .line 13
    const-string v1, "Limit of "

    .line 14
    .line 15
    const-string v2, " bytes exceeded while searching for \""

    .line 16
    .line 17
    invoke-static {p1, p2, v1, v2}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    const-string p2, "<this>"

    .line 22
    .line 23
    iget-object p0, p0, Lio/ktor/utils/io/q;->b:Loz0/a;

    .line 24
    .line 25
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Loz0/a;->d:[B

    .line 29
    .line 30
    invoke-static {p0}, Lly0/w;->l([B)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const-string p2, "\\n"

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    const-string v2, "\n"

    .line 38
    .line 39
    invoke-static {v1, p0, v2, p2}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const/16 p0, 0x22

    .line 47
    .line 48
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p1, Lio/ktor/utils/io/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lio/ktor/utils/io/o;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/o;->f:I

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
    iput v1, v0, Lio/ktor/utils/io/o;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lio/ktor/utils/io/o;-><init>(Lio/ktor/utils/io/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lio/ktor/utils/io/o;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/o;->f:I

    .line 30
    .line 31
    iget-object v3, p0, Lio/ktor/utils/io/q;->e:Lnz0/i;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto/16 :goto_7

    .line 45
    .line 46
    :cond_1
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
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :goto_1
    invoke-interface {v3}, Lnz0/i;->Z()Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-eqz p1, :cond_6

    .line 66
    .line 67
    iput v5, v0, Lio/ktor/utils/io/o;->f:I

    .line 68
    .line 69
    sget-object p1, Lio/ktor/utils/io/t;->a:Lio/ktor/utils/io/s;

    .line 70
    .line 71
    iget-object p1, p0, Lio/ktor/utils/io/q;->a:Lio/ktor/utils/io/t;

    .line 72
    .line 73
    invoke-interface {p1, v5, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-ne p1, v1, :cond_4

    .line 78
    .line 79
    goto/16 :goto_6

    .line 80
    .line 81
    :cond_4
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    if-eqz p1, :cond_5

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_5
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 91
    .line 92
    return-object p0

    .line 93
    :cond_6
    :goto_3
    invoke-interface {v3}, Lnz0/i;->readByte()B

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    iget v2, p0, Lio/ktor/utils/io/q;->i:I

    .line 98
    .line 99
    iget-object v6, p0, Lio/ktor/utils/io/q;->g:Lnz0/a;

    .line 100
    .line 101
    iget-object v7, p0, Lio/ktor/utils/io/q;->b:Loz0/a;

    .line 102
    .line 103
    if-lez v2, :cond_a

    .line 104
    .line 105
    invoke-virtual {v7, v2}, Loz0/a;->a(I)B

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eq p1, v2, :cond_a

    .line 110
    .line 111
    iget v2, p0, Lio/ktor/utils/io/q;->i:I

    .line 112
    .line 113
    :goto_4
    iget v8, p0, Lio/ktor/utils/io/q;->i:I

    .line 114
    .line 115
    if-lez v8, :cond_7

    .line 116
    .line 117
    invoke-virtual {v7, v8}, Loz0/a;->a(I)B

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    if-eq p1, v8, :cond_7

    .line 122
    .line 123
    iget v8, p0, Lio/ktor/utils/io/q;->i:I

    .line 124
    .line 125
    sub-int/2addr v8, v5

    .line 126
    iget-object v9, p0, Lio/ktor/utils/io/q;->f:[I

    .line 127
    .line 128
    aget v8, v9, v8

    .line 129
    .line 130
    iput v8, p0, Lio/ktor/utils/io/q;->i:I

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_7
    iget v8, p0, Lio/ktor/utils/io/q;->i:I

    .line 134
    .line 135
    sub-int/2addr v2, v8

    .line 136
    int-to-long v8, v2

    .line 137
    invoke-virtual {p0, v8, v9}, Lio/ktor/utils/io/q;->b(J)V

    .line 138
    .line 139
    .line 140
    iget-wide v10, p0, Lio/ktor/utils/io/q;->h:J

    .line 141
    .line 142
    iget-object v2, p0, Lio/ktor/utils/io/q;->c:Lio/ktor/utils/io/d0;

    .line 143
    .line 144
    check-cast v2, Lio/ktor/utils/io/m;

    .line 145
    .line 146
    invoke-virtual {v2}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 147
    .line 148
    .line 149
    move-result-object v12

    .line 150
    invoke-virtual {v6, v12, v8, v9}, Lnz0/a;->I(Lnz0/a;J)J

    .line 151
    .line 152
    .line 153
    move-result-wide v8

    .line 154
    add-long/2addr v8, v10

    .line 155
    iput-wide v8, p0, Lio/ktor/utils/io/q;->h:J

    .line 156
    .line 157
    iget v8, p0, Lio/ktor/utils/io/q;->i:I

    .line 158
    .line 159
    if-nez v8, :cond_a

    .line 160
    .line 161
    invoke-virtual {v7, v8}, Loz0/a;->a(I)B

    .line 162
    .line 163
    .line 164
    move-result v8

    .line 165
    if-eq p1, v8, :cond_a

    .line 166
    .line 167
    int-to-byte p1, p1

    .line 168
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 169
    .line 170
    .line 171
    iput v4, v0, Lio/ktor/utils/io/o;->f:I

    .line 172
    .line 173
    invoke-virtual {v2}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    invoke-virtual {v3, p1}, Lnz0/a;->q(B)V

    .line 178
    .line 179
    .line 180
    invoke-static {v2, v0}, Lio/ktor/utils/io/h0;->e(Lio/ktor/utils/io/d0;Lrx0/c;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 185
    .line 186
    if-ne p1, v0, :cond_8

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_8
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    :goto_5
    if-ne p1, v1, :cond_9

    .line 192
    .line 193
    :goto_6
    return-object v1

    .line 194
    :cond_9
    :goto_7
    iget-wide v0, p0, Lio/ktor/utils/io/q;->h:J

    .line 195
    .line 196
    const-wide/16 v2, 0x1

    .line 197
    .line 198
    add-long/2addr v0, v2

    .line 199
    iput-wide v0, p0, Lio/ktor/utils/io/q;->h:J

    .line 200
    .line 201
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 202
    .line 203
    return-object p0

    .line 204
    :cond_a
    iget v2, p0, Lio/ktor/utils/io/q;->i:I

    .line 205
    .line 206
    add-int/2addr v2, v5

    .line 207
    iput v2, p0, Lio/ktor/utils/io/q;->i:I

    .line 208
    .line 209
    iget-object v7, v7, Loz0/a;->d:[B

    .line 210
    .line 211
    array-length v7, v7

    .line 212
    if-ne v2, v7, :cond_b

    .line 213
    .line 214
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 215
    .line 216
    return-object p0

    .line 217
    :cond_b
    int-to-byte p1, p1

    .line 218
    invoke-virtual {v6, p1}, Lnz0/a;->q(B)V

    .line 219
    .line 220
    .line 221
    goto/16 :goto_1
.end method

.method public final d(ZLrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Lio/ktor/utils/io/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lio/ktor/utils/io/p;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/p;->g:I

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
    iput v1, v0, Lio/ktor/utils/io/p;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lio/ktor/utils/io/p;-><init>(Lio/ktor/utils/io/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lio/ktor/utils/io/p;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/p;->g:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eqz v2, :cond_5

    .line 36
    .line 37
    if-eq v2, v6, :cond_4

    .line 38
    .line 39
    if-eq v2, v5, :cond_3

    .line 40
    .line 41
    if-eq v2, v4, :cond_2

    .line 42
    .line 43
    if-ne v2, v3, :cond_1

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-boolean p1, v0, Lio/ktor/utils/io/p;->d:Z

    .line 58
    .line 59
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto/16 :goto_6

    .line 63
    .line 64
    :cond_3
    iget-boolean p1, v0, Lio/ktor/utils/io/p;->d:Z

    .line 65
    .line 66
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_4

    .line 70
    .line 71
    :cond_4
    iget-boolean p1, v0, Lio/ktor/utils/io/p;->d:Z

    .line 72
    .line 73
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_5
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    const-wide/16 v7, 0x0

    .line 81
    .line 82
    iput-wide v7, p0, Lio/ktor/utils/io/q;->h:J

    .line 83
    .line 84
    :cond_6
    iget-object p2, p0, Lio/ktor/utils/io/q;->e:Lnz0/i;

    .line 85
    .line 86
    invoke-interface {p2}, Lnz0/i;->Z()Z

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    if-eqz p2, :cond_b

    .line 91
    .line 92
    iput-boolean p1, v0, Lio/ktor/utils/io/p;->d:Z

    .line 93
    .line 94
    iput v6, v0, Lio/ktor/utils/io/p;->g:I

    .line 95
    .line 96
    sget-object p2, Lio/ktor/utils/io/t;->a:Lio/ktor/utils/io/s;

    .line 97
    .line 98
    iget-object p2, p0, Lio/ktor/utils/io/q;->a:Lio/ktor/utils/io/t;

    .line 99
    .line 100
    invoke-interface {p2, v6, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    if-ne p2, v1, :cond_7

    .line 105
    .line 106
    goto/16 :goto_5

    .line 107
    .line 108
    :cond_7
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 109
    .line 110
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 111
    .line 112
    .line 113
    move-result p2

    .line 114
    if-eqz p2, :cond_8

    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_8
    if-eqz p1, :cond_a

    .line 118
    .line 119
    iget-wide v4, p0, Lio/ktor/utils/io/q;->h:J

    .line 120
    .line 121
    iget-object p2, p0, Lio/ktor/utils/io/q;->c:Lio/ktor/utils/io/d0;

    .line 122
    .line 123
    check-cast p2, Lio/ktor/utils/io/m;

    .line 124
    .line 125
    invoke-virtual {p2}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    iget-object v6, p0, Lio/ktor/utils/io/q;->g:Lnz0/a;

    .line 130
    .line 131
    invoke-virtual {v6, v2}, Lnz0/a;->h(Lnz0/a;)J

    .line 132
    .line 133
    .line 134
    move-result-wide v6

    .line 135
    add-long/2addr v6, v4

    .line 136
    iput-wide v6, p0, Lio/ktor/utils/io/q;->h:J

    .line 137
    .line 138
    iput-boolean p1, v0, Lio/ktor/utils/io/p;->d:Z

    .line 139
    .line 140
    iput v3, v0, Lio/ktor/utils/io/p;->g:I

    .line 141
    .line 142
    invoke-virtual {p2, v0}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    if-ne p1, v1, :cond_9

    .line 147
    .line 148
    goto :goto_5

    .line 149
    :cond_9
    :goto_2
    iget-wide p0, p0, Lio/ktor/utils/io/q;->h:J

    .line 150
    .line 151
    new-instance p2, Ljava/lang/Long;

    .line 152
    .line 153
    invoke-direct {p2, p0, p1}, Ljava/lang/Long;-><init>(J)V

    .line 154
    .line 155
    .line 156
    return-object p2

    .line 157
    :cond_a
    new-instance p1, Ljava/io/IOException;

    .line 158
    .line 159
    new-instance p2, Ljava/lang/StringBuilder;

    .line 160
    .line 161
    const-string v0, "Expected \""

    .line 162
    .line 163
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    const-string v0, "<this>"

    .line 167
    .line 168
    iget-object p0, p0, Lio/ktor/utils/io/q;->b:Loz0/a;

    .line 169
    .line 170
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    iget-object p0, p0, Loz0/a;->d:[B

    .line 174
    .line 175
    invoke-static {p0}, Lly0/w;->l([B)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    const-string v0, "\\n"

    .line 180
    .line 181
    const/4 v1, 0x0

    .line 182
    const-string v2, "\n"

    .line 183
    .line 184
    invoke-static {v1, p0, v2, v0}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    const-string p0, "\" but encountered end of input"

    .line 192
    .line 193
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p1

    .line 204
    :cond_b
    :goto_3
    iput-boolean p1, v0, Lio/ktor/utils/io/p;->d:Z

    .line 205
    .line 206
    iput v5, v0, Lio/ktor/utils/io/p;->g:I

    .line 207
    .line 208
    invoke-virtual {p0, v0}, Lio/ktor/utils/io/q;->a(Lrx0/c;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object p2

    .line 212
    if-ne p2, v1, :cond_c

    .line 213
    .line 214
    goto :goto_5

    .line 215
    :cond_c
    :goto_4
    iput-boolean p1, v0, Lio/ktor/utils/io/p;->d:Z

    .line 216
    .line 217
    iput v4, v0, Lio/ktor/utils/io/p;->g:I

    .line 218
    .line 219
    invoke-virtual {p0, v0}, Lio/ktor/utils/io/q;->c(Lrx0/c;)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object p2

    .line 223
    if-ne p2, v1, :cond_d

    .line 224
    .line 225
    :goto_5
    return-object v1

    .line 226
    :cond_d
    :goto_6
    check-cast p2, Ljava/lang/Boolean;

    .line 227
    .line 228
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 229
    .line 230
    .line 231
    move-result p2

    .line 232
    if-eqz p2, :cond_6

    .line 233
    .line 234
    iget-wide p0, p0, Lio/ktor/utils/io/q;->h:J

    .line 235
    .line 236
    new-instance p2, Ljava/lang/Long;

    .line 237
    .line 238
    invoke-direct {p2, p0, p1}, Ljava/lang/Long;-><init>(J)V

    .line 239
    .line 240
    .line 241
    return-object p2
.end method
