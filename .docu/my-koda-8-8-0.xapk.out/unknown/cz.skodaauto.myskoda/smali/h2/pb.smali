.class public final Lh2/pb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final a:Z

.field public final b:Lh2/nb;

.field public final c:Li2/g1;

.field public final d:Lk1/z0;

.field public final e:F


# direct methods
.method public constructor <init>(ZLh2/nb;Li2/g1;Lk1/z0;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lh2/pb;->a:Z

    .line 5
    .line 6
    iput-object p2, p0, Lh2/pb;->b:Lh2/nb;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/pb;->c:Li2/g1;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/pb;->d:Lk1/z0;

    .line 11
    .line 12
    iput p5, p0, Lh2/pb;->e:F

    .line 13
    .line 14
    return-void
.end method

.method public static k(Ljava/util/List;ILay0/n;)I
    .locals 13

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/util/Collection;

    .line 3
    .line 4
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    const/4 v2, 0x0

    .line 9
    move v3, v2

    .line 10
    :goto_0
    if-ge v3, v1, :cond_13

    .line 11
    .line 12
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    move-object v5, v4

    .line 17
    check-cast v5, Lt3/p0;

    .line 18
    .line 19
    invoke-static {v5}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v5

    .line 23
    const-string v6, "TextField"

    .line 24
    .line 25
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    if-eqz v5, :cond_12

    .line 30
    .line 31
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-interface {p2, v4, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, Ljava/lang/Number;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    move v4, v2

    .line 50
    :goto_1
    const/4 v5, 0x0

    .line 51
    if-ge v4, v3, :cond_1

    .line 52
    .line 53
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    move-object v7, v6

    .line 58
    check-cast v7, Lt3/p0;

    .line 59
    .line 60
    invoke-static {v7}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v7

    .line 64
    const-string v8, "Label"

    .line 65
    .line 66
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    if-eqz v7, :cond_0

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_0
    add-int/lit8 v4, v4, 0x1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    move-object v6, v5

    .line 77
    :goto_2
    check-cast v6, Lt3/p0;

    .line 78
    .line 79
    if-eqz v6, :cond_2

    .line 80
    .line 81
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    invoke-interface {p2, v6, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    check-cast v3, Ljava/lang/Number;

    .line 90
    .line 91
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    goto :goto_3

    .line 96
    :cond_2
    move v3, v2

    .line 97
    :goto_3
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 98
    .line 99
    .line 100
    move-result v4

    .line 101
    move v6, v2

    .line 102
    :goto_4
    if-ge v6, v4, :cond_4

    .line 103
    .line 104
    invoke-interface {p0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    move-object v8, v7

    .line 109
    check-cast v8, Lt3/p0;

    .line 110
    .line 111
    invoke-static {v8}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v8

    .line 115
    const-string v9, "Trailing"

    .line 116
    .line 117
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    if-eqz v8, :cond_3

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_4
    move-object v7, v5

    .line 128
    :goto_5
    check-cast v7, Lt3/p0;

    .line 129
    .line 130
    if-eqz v7, :cond_5

    .line 131
    .line 132
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    invoke-interface {p2, v7, v4}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    check-cast v4, Ljava/lang/Number;

    .line 141
    .line 142
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    goto :goto_6

    .line 147
    :cond_5
    move v4, v2

    .line 148
    :goto_6
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 149
    .line 150
    .line 151
    move-result v6

    .line 152
    move v7, v2

    .line 153
    :goto_7
    if-ge v7, v6, :cond_7

    .line 154
    .line 155
    invoke-interface {p0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v8

    .line 159
    move-object v9, v8

    .line 160
    check-cast v9, Lt3/p0;

    .line 161
    .line 162
    invoke-static {v9}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v9

    .line 166
    const-string v10, "Prefix"

    .line 167
    .line 168
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v9

    .line 172
    if-eqz v9, :cond_6

    .line 173
    .line 174
    goto :goto_8

    .line 175
    :cond_6
    add-int/lit8 v7, v7, 0x1

    .line 176
    .line 177
    goto :goto_7

    .line 178
    :cond_7
    move-object v8, v5

    .line 179
    :goto_8
    check-cast v8, Lt3/p0;

    .line 180
    .line 181
    if-eqz v8, :cond_8

    .line 182
    .line 183
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 184
    .line 185
    .line 186
    move-result-object v6

    .line 187
    invoke-interface {p2, v8, v6}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v6

    .line 191
    check-cast v6, Ljava/lang/Number;

    .line 192
    .line 193
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 194
    .line 195
    .line 196
    move-result v6

    .line 197
    goto :goto_9

    .line 198
    :cond_8
    move v6, v2

    .line 199
    :goto_9
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 200
    .line 201
    .line 202
    move-result v7

    .line 203
    move v8, v2

    .line 204
    :goto_a
    if-ge v8, v7, :cond_a

    .line 205
    .line 206
    invoke-interface {p0, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v9

    .line 210
    move-object v10, v9

    .line 211
    check-cast v10, Lt3/p0;

    .line 212
    .line 213
    invoke-static {v10}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v10

    .line 217
    const-string v11, "Suffix"

    .line 218
    .line 219
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v10

    .line 223
    if-eqz v10, :cond_9

    .line 224
    .line 225
    goto :goto_b

    .line 226
    :cond_9
    add-int/lit8 v8, v8, 0x1

    .line 227
    .line 228
    goto :goto_a

    .line 229
    :cond_a
    move-object v9, v5

    .line 230
    :goto_b
    check-cast v9, Lt3/p0;

    .line 231
    .line 232
    if-eqz v9, :cond_b

    .line 233
    .line 234
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 235
    .line 236
    .line 237
    move-result-object v7

    .line 238
    invoke-interface {p2, v9, v7}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v7

    .line 242
    check-cast v7, Ljava/lang/Number;

    .line 243
    .line 244
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 245
    .line 246
    .line 247
    move-result v7

    .line 248
    goto :goto_c

    .line 249
    :cond_b
    move v7, v2

    .line 250
    :goto_c
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 251
    .line 252
    .line 253
    move-result v8

    .line 254
    move v9, v2

    .line 255
    :goto_d
    if-ge v9, v8, :cond_d

    .line 256
    .line 257
    invoke-interface {p0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v10

    .line 261
    move-object v11, v10

    .line 262
    check-cast v11, Lt3/p0;

    .line 263
    .line 264
    invoke-static {v11}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v11

    .line 268
    const-string v12, "Leading"

    .line 269
    .line 270
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    move-result v11

    .line 274
    if-eqz v11, :cond_c

    .line 275
    .line 276
    goto :goto_e

    .line 277
    :cond_c
    add-int/lit8 v9, v9, 0x1

    .line 278
    .line 279
    goto :goto_d

    .line 280
    :cond_d
    move-object v10, v5

    .line 281
    :goto_e
    check-cast v10, Lt3/p0;

    .line 282
    .line 283
    if-eqz v10, :cond_e

    .line 284
    .line 285
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 286
    .line 287
    .line 288
    move-result-object v8

    .line 289
    invoke-interface {p2, v10, v8}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v8

    .line 293
    check-cast v8, Ljava/lang/Number;

    .line 294
    .line 295
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 296
    .line 297
    .line 298
    move-result v8

    .line 299
    goto :goto_f

    .line 300
    :cond_e
    move v8, v2

    .line 301
    :goto_f
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 302
    .line 303
    .line 304
    move-result v0

    .line 305
    move v9, v2

    .line 306
    :goto_10
    if-ge v9, v0, :cond_10

    .line 307
    .line 308
    invoke-interface {p0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v10

    .line 312
    move-object v11, v10

    .line 313
    check-cast v11, Lt3/p0;

    .line 314
    .line 315
    invoke-static {v11}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v11

    .line 319
    const-string v12, "Hint"

    .line 320
    .line 321
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 322
    .line 323
    .line 324
    move-result v11

    .line 325
    if-eqz v11, :cond_f

    .line 326
    .line 327
    move-object v5, v10

    .line 328
    goto :goto_11

    .line 329
    :cond_f
    add-int/lit8 v9, v9, 0x1

    .line 330
    .line 331
    goto :goto_10

    .line 332
    :cond_10
    :goto_11
    check-cast v5, Lt3/p0;

    .line 333
    .line 334
    if-eqz v5, :cond_11

    .line 335
    .line 336
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 337
    .line 338
    .line 339
    move-result-object p0

    .line 340
    invoke-interface {p2, v5, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object p0

    .line 344
    check-cast p0, Ljava/lang/Number;

    .line 345
    .line 346
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 347
    .line 348
    .line 349
    move-result p0

    .line 350
    goto :goto_12

    .line 351
    :cond_11
    move p0, v2

    .line 352
    :goto_12
    const/16 p1, 0xf

    .line 353
    .line 354
    invoke-static {v2, v2, p1}, Lt4/b;->b(III)J

    .line 355
    .line 356
    .line 357
    move-result-wide p1

    .line 358
    add-int/2addr v6, v7

    .line 359
    add-int/2addr v1, v6

    .line 360
    add-int/2addr p0, v6

    .line 361
    invoke-static {p0, v3}, Ljava/lang/Math;->max(II)I

    .line 362
    .line 363
    .line 364
    move-result p0

    .line 365
    invoke-static {v1, p0}, Ljava/lang/Math;->max(II)I

    .line 366
    .line 367
    .line 368
    move-result p0

    .line 369
    add-int/2addr p0, v8

    .line 370
    add-int/2addr p0, v4

    .line 371
    invoke-static {p0, p1, p2}, Lt4/b;->g(IJ)I

    .line 372
    .line 373
    .line 374
    move-result p0

    .line 375
    return p0

    .line 376
    :cond_12
    add-int/lit8 v3, v3, 0x1

    .line 377
    .line 378
    goto/16 :goto_0

    .line 379
    .line 380
    :cond_13
    const-string p0, "Collection contains no element matching the predicate."

    .line 381
    .line 382
    invoke-static {p0}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 383
    .line 384
    .line 385
    move-result-object p0

    .line 386
    throw p0
.end method

.method public static final l(Lh2/pb;IILt3/e1;)I
    .locals 0

    .line 1
    iget-boolean p0, p0, Lh2/pb;->a:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget p0, p3, Lt3/e1;->e:I

    .line 6
    .line 7
    sub-int/2addr p1, p0

    .line 8
    int-to-float p0, p1

    .line 9
    const/high16 p1, 0x40000000    # 2.0f

    .line 10
    .line 11
    div-float/2addr p0, p1

    .line 12
    const/4 p1, 0x1

    .line 13
    int-to-float p1, p1

    .line 14
    const/4 p2, 0x0

    .line 15
    add-float/2addr p1, p2

    .line 16
    mul-float/2addr p1, p0

    .line 17
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0

    .line 22
    :cond_0
    return p2
.end method


# virtual methods
.method public final a(Lt3/t;Ljava/util/List;I)I
    .locals 1

    .line 1
    new-instance p0, Lgv0/a;

    .line 2
    .line 3
    const/16 p1, 0xe

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-direct {p0, v0, p1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-static {p2, p3, p0}, Lh2/pb;->k(Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v13, p2

    .line 6
    .line 7
    iget-object v2, v0, Lh2/pb;->c:Li2/g1;

    .line 8
    .line 9
    invoke-virtual {v2}, Li2/g1;->invoke()F

    .line 10
    .line 11
    .line 12
    move-result v12

    .line 13
    iget-object v2, v0, Lh2/pb;->d:Lk1/z0;

    .line 14
    .line 15
    invoke-interface {v2}, Lk1/z0;->d()F

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-interface {v1, v3}, Lt4/c;->Q(F)I

    .line 20
    .line 21
    .line 22
    move-result v14

    .line 23
    invoke-interface {v2}, Lk1/z0;->c()F

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    invoke-interface {v1, v2}, Lt4/c;->Q(F)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    const/4 v8, 0x0

    .line 32
    const/16 v9, 0xa

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    const/4 v6, 0x0

    .line 36
    const/4 v7, 0x0

    .line 37
    move-wide/from16 v3, p3

    .line 38
    .line 39
    invoke-static/range {v3 .. v9}, Lt4/a;->a(JIIIII)J

    .line 40
    .line 41
    .line 42
    move-result-wide v5

    .line 43
    move-object v3, v13

    .line 44
    check-cast v3, Ljava/util/Collection;

    .line 45
    .line 46
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    move v8, v7

    .line 51
    :goto_0
    if-ge v8, v4, :cond_1

    .line 52
    .line 53
    invoke-interface {v13, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v10

    .line 57
    move-object v11, v10

    .line 58
    check-cast v11, Lt3/p0;

    .line 59
    .line 60
    invoke-static {v11}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v11

    .line 64
    const-string v15, "Leading"

    .line 65
    .line 66
    invoke-static {v11, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v11

    .line 70
    if-eqz v11, :cond_0

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_0
    add-int/lit8 v8, v8, 0x1

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_1
    const/4 v10, 0x0

    .line 77
    :goto_1
    check-cast v10, Lt3/p0;

    .line 78
    .line 79
    if-eqz v10, :cond_2

    .line 80
    .line 81
    invoke-interface {v10, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    goto :goto_2

    .line 86
    :cond_2
    const/4 v4, 0x0

    .line 87
    :goto_2
    if-eqz v4, :cond_3

    .line 88
    .line 89
    iget v8, v4, Lt3/e1;->d:I

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_3
    move v8, v7

    .line 93
    :goto_3
    if-eqz v4, :cond_4

    .line 94
    .line 95
    iget v10, v4, Lt3/e1;->e:I

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_4
    move v10, v7

    .line 99
    :goto_4
    invoke-static {v7, v10}, Ljava/lang/Math;->max(II)I

    .line 100
    .line 101
    .line 102
    move-result v10

    .line 103
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 104
    .line 105
    .line 106
    move-result v11

    .line 107
    move v15, v7

    .line 108
    :goto_5
    if-ge v15, v11, :cond_6

    .line 109
    .line 110
    invoke-interface {v13, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v16

    .line 114
    move-object/from16 v17, v16

    .line 115
    .line 116
    check-cast v17, Lt3/p0;

    .line 117
    .line 118
    invoke-static/range {v17 .. v17}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v9

    .line 122
    const-string v7, "Trailing"

    .line 123
    .line 124
    invoke-static {v9, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v7

    .line 128
    if-eqz v7, :cond_5

    .line 129
    .line 130
    goto :goto_6

    .line 131
    :cond_5
    add-int/lit8 v15, v15, 0x1

    .line 132
    .line 133
    const/4 v7, 0x0

    .line 134
    goto :goto_5

    .line 135
    :cond_6
    const/16 v16, 0x0

    .line 136
    .line 137
    :goto_6
    move-object/from16 v7, v16

    .line 138
    .line 139
    check-cast v7, Lt3/p0;

    .line 140
    .line 141
    const/4 v9, 0x2

    .line 142
    if-eqz v7, :cond_7

    .line 143
    .line 144
    neg-int v11, v8

    .line 145
    const/4 v15, 0x0

    .line 146
    invoke-static {v5, v6, v11, v15, v9}, Lt4/b;->j(JIII)J

    .line 147
    .line 148
    .line 149
    move-result-wide v0

    .line 150
    invoke-interface {v7, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    goto :goto_7

    .line 155
    :cond_7
    const/4 v0, 0x0

    .line 156
    :goto_7
    if-eqz v0, :cond_8

    .line 157
    .line 158
    iget v1, v0, Lt3/e1;->d:I

    .line 159
    .line 160
    goto :goto_8

    .line 161
    :cond_8
    const/4 v1, 0x0

    .line 162
    :goto_8
    add-int/2addr v8, v1

    .line 163
    if-eqz v0, :cond_9

    .line 164
    .line 165
    iget v1, v0, Lt3/e1;->e:I

    .line 166
    .line 167
    goto :goto_9

    .line 168
    :cond_9
    const/4 v1, 0x0

    .line 169
    :goto_9
    invoke-static {v10, v1}, Ljava/lang/Math;->max(II)I

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 174
    .line 175
    .line 176
    move-result v7

    .line 177
    const/4 v10, 0x0

    .line 178
    :goto_a
    if-ge v10, v7, :cond_b

    .line 179
    .line 180
    invoke-interface {v13, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v11

    .line 184
    move-object v15, v11

    .line 185
    check-cast v15, Lt3/p0;

    .line 186
    .line 187
    invoke-static {v15}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v15

    .line 191
    const-string v9, "Prefix"

    .line 192
    .line 193
    invoke-static {v15, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v9

    .line 197
    if-eqz v9, :cond_a

    .line 198
    .line 199
    goto :goto_b

    .line 200
    :cond_a
    add-int/lit8 v10, v10, 0x1

    .line 201
    .line 202
    const/4 v9, 0x2

    .line 203
    goto :goto_a

    .line 204
    :cond_b
    const/4 v11, 0x0

    .line 205
    :goto_b
    check-cast v11, Lt3/p0;

    .line 206
    .line 207
    if-eqz v11, :cond_c

    .line 208
    .line 209
    neg-int v7, v8

    .line 210
    move v10, v8

    .line 211
    const/4 v9, 0x2

    .line 212
    const/4 v15, 0x0

    .line 213
    invoke-static {v5, v6, v7, v15, v9}, Lt4/b;->j(JIII)J

    .line 214
    .line 215
    .line 216
    move-result-wide v7

    .line 217
    invoke-interface {v11, v7, v8}, Lt3/p0;->L(J)Lt3/e1;

    .line 218
    .line 219
    .line 220
    move-result-object v7

    .line 221
    goto :goto_c

    .line 222
    :cond_c
    move v10, v8

    .line 223
    const/4 v7, 0x0

    .line 224
    :goto_c
    if-eqz v7, :cond_d

    .line 225
    .line 226
    iget v8, v7, Lt3/e1;->d:I

    .line 227
    .line 228
    goto :goto_d

    .line 229
    :cond_d
    const/4 v8, 0x0

    .line 230
    :goto_d
    add-int/2addr v8, v10

    .line 231
    if-eqz v7, :cond_e

    .line 232
    .line 233
    iget v9, v7, Lt3/e1;->e:I

    .line 234
    .line 235
    goto :goto_e

    .line 236
    :cond_e
    const/4 v9, 0x0

    .line 237
    :goto_e
    invoke-static {v1, v9}, Ljava/lang/Math;->max(II)I

    .line 238
    .line 239
    .line 240
    move-result v1

    .line 241
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 242
    .line 243
    .line 244
    move-result v9

    .line 245
    const/4 v10, 0x0

    .line 246
    :goto_f
    if-ge v10, v9, :cond_10

    .line 247
    .line 248
    invoke-interface {v13, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v11

    .line 252
    move-object v15, v11

    .line 253
    check-cast v15, Lt3/p0;

    .line 254
    .line 255
    invoke-static {v15}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v15

    .line 259
    move-object/from16 v24, v3

    .line 260
    .line 261
    const-string v3, "Suffix"

    .line 262
    .line 263
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    move-result v3

    .line 267
    if-eqz v3, :cond_f

    .line 268
    .line 269
    goto :goto_10

    .line 270
    :cond_f
    add-int/lit8 v10, v10, 0x1

    .line 271
    .line 272
    move-object/from16 v3, v24

    .line 273
    .line 274
    goto :goto_f

    .line 275
    :cond_10
    move-object/from16 v24, v3

    .line 276
    .line 277
    const/4 v11, 0x0

    .line 278
    :goto_10
    check-cast v11, Lt3/p0;

    .line 279
    .line 280
    if-eqz v11, :cond_11

    .line 281
    .line 282
    neg-int v3, v8

    .line 283
    const/4 v9, 0x2

    .line 284
    const/4 v15, 0x0

    .line 285
    invoke-static {v5, v6, v3, v15, v9}, Lt4/b;->j(JIII)J

    .line 286
    .line 287
    .line 288
    move-result-wide v9

    .line 289
    invoke-interface {v11, v9, v10}, Lt3/p0;->L(J)Lt3/e1;

    .line 290
    .line 291
    .line 292
    move-result-object v3

    .line 293
    goto :goto_11

    .line 294
    :cond_11
    const/4 v3, 0x0

    .line 295
    :goto_11
    if-eqz v3, :cond_12

    .line 296
    .line 297
    iget v15, v3, Lt3/e1;->d:I

    .line 298
    .line 299
    goto :goto_12

    .line 300
    :cond_12
    const/4 v15, 0x0

    .line 301
    :goto_12
    add-int/2addr v8, v15

    .line 302
    if-eqz v3, :cond_13

    .line 303
    .line 304
    iget v15, v3, Lt3/e1;->e:I

    .line 305
    .line 306
    goto :goto_13

    .line 307
    :cond_13
    const/4 v15, 0x0

    .line 308
    :goto_13
    invoke-static {v1, v15}, Ljava/lang/Math;->max(II)I

    .line 309
    .line 310
    .line 311
    move-result v1

    .line 312
    invoke-interface/range {v24 .. v24}, Ljava/util/Collection;->size()I

    .line 313
    .line 314
    .line 315
    move-result v9

    .line 316
    const/4 v15, 0x0

    .line 317
    :goto_14
    if-ge v15, v9, :cond_15

    .line 318
    .line 319
    invoke-interface {v13, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v10

    .line 323
    move-object v11, v10

    .line 324
    check-cast v11, Lt3/p0;

    .line 325
    .line 326
    invoke-static {v11}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v11

    .line 330
    move/from16 v16, v9

    .line 331
    .line 332
    const-string v9, "Label"

    .line 333
    .line 334
    invoke-static {v11, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 335
    .line 336
    .line 337
    move-result v9

    .line 338
    if-eqz v9, :cond_14

    .line 339
    .line 340
    goto :goto_15

    .line 341
    :cond_14
    add-int/lit8 v15, v15, 0x1

    .line 342
    .line 343
    move/from16 v9, v16

    .line 344
    .line 345
    goto :goto_14

    .line 346
    :cond_15
    const/4 v10, 0x0

    .line 347
    :goto_15
    check-cast v10, Lt3/p0;

    .line 348
    .line 349
    new-instance v9, Lkotlin/jvm/internal/f0;

    .line 350
    .line 351
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 352
    .line 353
    .line 354
    neg-int v11, v2

    .line 355
    neg-int v8, v8

    .line 356
    move/from16 v25, v12

    .line 357
    .line 358
    invoke-static {v5, v6, v8, v11}, Lt4/b;->i(JII)J

    .line 359
    .line 360
    .line 361
    move-result-wide v11

    .line 362
    if-eqz v10, :cond_16

    .line 363
    .line 364
    invoke-interface {v10, v11, v12}, Lt3/p0;->L(J)Lt3/e1;

    .line 365
    .line 366
    .line 367
    move-result-object v10

    .line 368
    goto :goto_16

    .line 369
    :cond_16
    const/4 v10, 0x0

    .line 370
    :goto_16
    iput-object v10, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 371
    .line 372
    invoke-interface/range {v24 .. v24}, Ljava/util/Collection;->size()I

    .line 373
    .line 374
    .line 375
    move-result v10

    .line 376
    const/4 v15, 0x0

    .line 377
    :goto_17
    if-ge v15, v10, :cond_18

    .line 378
    .line 379
    invoke-interface {v13, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v11

    .line 383
    move-object v12, v11

    .line 384
    check-cast v12, Lt3/p0;

    .line 385
    .line 386
    invoke-static {v12}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v12

    .line 390
    move/from16 v26, v2

    .line 391
    .line 392
    const-string v2, "Supporting"

    .line 393
    .line 394
    invoke-static {v12, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 395
    .line 396
    .line 397
    move-result v2

    .line 398
    if-eqz v2, :cond_17

    .line 399
    .line 400
    goto :goto_18

    .line 401
    :cond_17
    add-int/lit8 v15, v15, 0x1

    .line 402
    .line 403
    move/from16 v2, v26

    .line 404
    .line 405
    goto :goto_17

    .line 406
    :cond_18
    move/from16 v26, v2

    .line 407
    .line 408
    const/4 v11, 0x0

    .line 409
    :goto_18
    check-cast v11, Lt3/p0;

    .line 410
    .line 411
    if-eqz v11, :cond_19

    .line 412
    .line 413
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 414
    .line 415
    .line 416
    move-result v2

    .line 417
    invoke-interface {v11, v2}, Lt3/p0;->A(I)I

    .line 418
    .line 419
    .line 420
    move-result v15

    .line 421
    move v2, v15

    .line 422
    goto :goto_19

    .line 423
    :cond_19
    const/4 v2, 0x0

    .line 424
    :goto_19
    iget-object v10, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 425
    .line 426
    check-cast v10, Lt3/e1;

    .line 427
    .line 428
    if-eqz v10, :cond_1a

    .line 429
    .line 430
    iget v15, v10, Lt3/e1;->e:I

    .line 431
    .line 432
    goto :goto_1a

    .line 433
    :cond_1a
    const/4 v15, 0x0

    .line 434
    :goto_1a
    add-int v10, v14, v15

    .line 435
    .line 436
    const/16 v20, 0x0

    .line 437
    .line 438
    const/16 v21, 0xb

    .line 439
    .line 440
    const/16 v17, 0x0

    .line 441
    .line 442
    const/16 v18, 0x0

    .line 443
    .line 444
    const/16 v19, 0x0

    .line 445
    .line 446
    move-wide/from16 v15, p3

    .line 447
    .line 448
    move-object/from16 v27, v11

    .line 449
    .line 450
    invoke-static/range {v15 .. v21}, Lt4/a;->a(JIIIII)J

    .line 451
    .line 452
    .line 453
    move-result-wide v11

    .line 454
    neg-int v15, v10

    .line 455
    sub-int v15, v15, v26

    .line 456
    .line 457
    sub-int/2addr v15, v2

    .line 458
    invoke-static {v11, v12, v8, v15}, Lt4/b;->i(JII)J

    .line 459
    .line 460
    .line 461
    move-result-wide v11

    .line 462
    invoke-interface/range {v24 .. v24}, Ljava/util/Collection;->size()I

    .line 463
    .line 464
    .line 465
    move-result v2

    .line 466
    const/4 v15, 0x0

    .line 467
    :goto_1b
    const-string v16, "Collection contains no element matching the predicate."

    .line 468
    .line 469
    if-ge v15, v2, :cond_33

    .line 470
    .line 471
    invoke-interface {v13, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 472
    .line 473
    .line 474
    move-result-object v8

    .line 475
    check-cast v8, Lt3/p0;

    .line 476
    .line 477
    move/from16 v17, v2

    .line 478
    .line 479
    invoke-static {v8}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v2

    .line 483
    move/from16 v18, v10

    .line 484
    .line 485
    const-string v10, "TextField"

    .line 486
    .line 487
    invoke-static {v2, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 488
    .line 489
    .line 490
    move-result v2

    .line 491
    if-eqz v2, :cond_32

    .line 492
    .line 493
    invoke-interface {v8, v11, v12}, Lt3/p0;->L(J)Lt3/e1;

    .line 494
    .line 495
    .line 496
    move-result-object v15

    .line 497
    const/16 v33, 0x0

    .line 498
    .line 499
    const/16 v34, 0xe

    .line 500
    .line 501
    const/16 v30, 0x0

    .line 502
    .line 503
    const/16 v31, 0x0

    .line 504
    .line 505
    const/16 v32, 0x0

    .line 506
    .line 507
    move-wide/from16 v28, v11

    .line 508
    .line 509
    invoke-static/range {v28 .. v34}, Lt4/a;->a(JIIIII)J

    .line 510
    .line 511
    .line 512
    move-result-wide v10

    .line 513
    move-object/from16 v17, v13

    .line 514
    .line 515
    check-cast v17, Ljava/util/Collection;

    .line 516
    .line 517
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 518
    .line 519
    .line 520
    move-result v2

    .line 521
    const/4 v8, 0x0

    .line 522
    :goto_1c
    if-ge v8, v2, :cond_1c

    .line 523
    .line 524
    invoke-interface {v13, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 525
    .line 526
    .line 527
    move-result-object v12

    .line 528
    move-object/from16 v19, v12

    .line 529
    .line 530
    check-cast v19, Lt3/p0;

    .line 531
    .line 532
    move/from16 v20, v2

    .line 533
    .line 534
    invoke-static/range {v19 .. v19}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 535
    .line 536
    .line 537
    move-result-object v2

    .line 538
    move/from16 v19, v8

    .line 539
    .line 540
    const-string v8, "Hint"

    .line 541
    .line 542
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 543
    .line 544
    .line 545
    move-result v2

    .line 546
    if-eqz v2, :cond_1b

    .line 547
    .line 548
    goto :goto_1d

    .line 549
    :cond_1b
    add-int/lit8 v8, v19, 0x1

    .line 550
    .line 551
    move/from16 v2, v20

    .line 552
    .line 553
    goto :goto_1c

    .line 554
    :cond_1c
    const/4 v12, 0x0

    .line 555
    :goto_1d
    check-cast v12, Lt3/p0;

    .line 556
    .line 557
    if-eqz v12, :cond_1d

    .line 558
    .line 559
    invoke-interface {v12, v10, v11}, Lt3/p0;->L(J)Lt3/e1;

    .line 560
    .line 561
    .line 562
    move-result-object v2

    .line 563
    goto :goto_1e

    .line 564
    :cond_1d
    const/4 v2, 0x0

    .line 565
    :goto_1e
    iget v8, v15, Lt3/e1;->e:I

    .line 566
    .line 567
    if-eqz v2, :cond_1e

    .line 568
    .line 569
    iget v10, v2, Lt3/e1;->e:I

    .line 570
    .line 571
    goto :goto_1f

    .line 572
    :cond_1e
    const/4 v10, 0x0

    .line 573
    :goto_1f
    invoke-static {v8, v10}, Ljava/lang/Math;->max(II)I

    .line 574
    .line 575
    .line 576
    move-result v8

    .line 577
    add-int v8, v8, v18

    .line 578
    .line 579
    add-int v8, v8, v26

    .line 580
    .line 581
    invoke-static {v1, v8}, Ljava/lang/Math;->max(II)I

    .line 582
    .line 583
    .line 584
    move-result v1

    .line 585
    if-eqz v4, :cond_1f

    .line 586
    .line 587
    iget v8, v4, Lt3/e1;->d:I

    .line 588
    .line 589
    goto :goto_20

    .line 590
    :cond_1f
    const/4 v8, 0x0

    .line 591
    :goto_20
    if-eqz v0, :cond_20

    .line 592
    .line 593
    iget v10, v0, Lt3/e1;->d:I

    .line 594
    .line 595
    goto :goto_21

    .line 596
    :cond_20
    const/4 v10, 0x0

    .line 597
    :goto_21
    if-eqz v7, :cond_21

    .line 598
    .line 599
    iget v11, v7, Lt3/e1;->d:I

    .line 600
    .line 601
    goto :goto_22

    .line 602
    :cond_21
    const/4 v11, 0x0

    .line 603
    :goto_22
    if-eqz v3, :cond_22

    .line 604
    .line 605
    iget v12, v3, Lt3/e1;->d:I

    .line 606
    .line 607
    :goto_23
    move/from16 v18, v8

    .line 608
    .line 609
    goto :goto_24

    .line 610
    :cond_22
    const/4 v12, 0x0

    .line 611
    goto :goto_23

    .line 612
    :goto_24
    iget v8, v15, Lt3/e1;->d:I

    .line 613
    .line 614
    move/from16 v19, v8

    .line 615
    .line 616
    iget-object v8, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 617
    .line 618
    check-cast v8, Lt3/e1;

    .line 619
    .line 620
    if-eqz v8, :cond_23

    .line 621
    .line 622
    iget v8, v8, Lt3/e1;->d:I

    .line 623
    .line 624
    goto :goto_25

    .line 625
    :cond_23
    const/4 v8, 0x0

    .line 626
    :goto_25
    move/from16 v20, v10

    .line 627
    .line 628
    if-eqz v2, :cond_24

    .line 629
    .line 630
    iget v10, v2, Lt3/e1;->d:I

    .line 631
    .line 632
    goto :goto_26

    .line 633
    :cond_24
    const/4 v10, 0x0

    .line 634
    :goto_26
    add-int/2addr v11, v12

    .line 635
    add-int v12, v19, v11

    .line 636
    .line 637
    add-int/2addr v10, v11

    .line 638
    invoke-static {v10, v8}, Ljava/lang/Math;->max(II)I

    .line 639
    .line 640
    .line 641
    move-result v8

    .line 642
    invoke-static {v12, v8}, Ljava/lang/Math;->max(II)I

    .line 643
    .line 644
    .line 645
    move-result v8

    .line 646
    add-int v8, v8, v18

    .line 647
    .line 648
    add-int v8, v8, v20

    .line 649
    .line 650
    move-wide/from16 v10, p3

    .line 651
    .line 652
    invoke-static {v8, v10, v11}, Lt4/b;->g(IJ)I

    .line 653
    .line 654
    .line 655
    move-result v31

    .line 656
    neg-int v1, v1

    .line 657
    const/4 v8, 0x1

    .line 658
    const/4 v12, 0x0

    .line 659
    invoke-static {v5, v6, v12, v1, v8}, Lt4/b;->j(JIII)J

    .line 660
    .line 661
    .line 662
    move-result-wide v28

    .line 663
    const/16 v33, 0x0

    .line 664
    .line 665
    const/16 v34, 0x9

    .line 666
    .line 667
    const/16 v30, 0x0

    .line 668
    .line 669
    const/16 v32, 0x0

    .line 670
    .line 671
    invoke-static/range {v28 .. v34}, Lt4/a;->a(JIIIII)J

    .line 672
    .line 673
    .line 674
    move-result-wide v5

    .line 675
    if-eqz v27, :cond_25

    .line 676
    .line 677
    move-object/from16 v8, v27

    .line 678
    .line 679
    invoke-interface {v8, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 680
    .line 681
    .line 682
    move-result-object v1

    .line 683
    goto :goto_27

    .line 684
    :cond_25
    const/4 v1, 0x0

    .line 685
    :goto_27
    if-eqz v1, :cond_26

    .line 686
    .line 687
    iget v5, v1, Lt3/e1;->e:I

    .line 688
    .line 689
    move/from16 v18, v5

    .line 690
    .line 691
    goto :goto_28

    .line 692
    :cond_26
    move/from16 v18, v12

    .line 693
    .line 694
    :goto_28
    iget v5, v15, Lt3/e1;->e:I

    .line 695
    .line 696
    iget-object v6, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 697
    .line 698
    check-cast v6, Lt3/e1;

    .line 699
    .line 700
    if-eqz v6, :cond_27

    .line 701
    .line 702
    iget v6, v6, Lt3/e1;->e:I

    .line 703
    .line 704
    goto :goto_29

    .line 705
    :cond_27
    move v6, v12

    .line 706
    :goto_29
    if-eqz v4, :cond_28

    .line 707
    .line 708
    iget v8, v4, Lt3/e1;->e:I

    .line 709
    .line 710
    move/from16 v35, v8

    .line 711
    .line 712
    move-object v8, v4

    .line 713
    move/from16 v4, v35

    .line 714
    .line 715
    goto :goto_2a

    .line 716
    :cond_28
    move-object v8, v4

    .line 717
    move v4, v12

    .line 718
    :goto_2a
    if-eqz v0, :cond_29

    .line 719
    .line 720
    iget v12, v0, Lt3/e1;->e:I

    .line 721
    .line 722
    move/from16 v35, v12

    .line 723
    .line 724
    move v12, v5

    .line 725
    move/from16 v5, v35

    .line 726
    .line 727
    goto :goto_2b

    .line 728
    :cond_29
    move v12, v5

    .line 729
    const/4 v5, 0x0

    .line 730
    :goto_2b
    move-object/from16 v19, v0

    .line 731
    .line 732
    if-eqz v7, :cond_2a

    .line 733
    .line 734
    iget v0, v7, Lt3/e1;->e:I

    .line 735
    .line 736
    move/from16 v35, v6

    .line 737
    .line 738
    move v6, v0

    .line 739
    move/from16 v0, v35

    .line 740
    .line 741
    goto :goto_2c

    .line 742
    :cond_2a
    move v0, v6

    .line 743
    const/4 v6, 0x0

    .line 744
    :goto_2c
    move/from16 v20, v0

    .line 745
    .line 746
    if-eqz v3, :cond_2b

    .line 747
    .line 748
    iget v0, v3, Lt3/e1;->e:I

    .line 749
    .line 750
    move-object/from16 v22, v7

    .line 751
    .line 752
    move v7, v0

    .line 753
    goto :goto_2d

    .line 754
    :cond_2b
    move-object/from16 v22, v7

    .line 755
    .line 756
    const/4 v7, 0x0

    .line 757
    :goto_2d
    if-eqz v2, :cond_2c

    .line 758
    .line 759
    iget v0, v2, Lt3/e1;->e:I

    .line 760
    .line 761
    move-object/from16 v35, v8

    .line 762
    .line 763
    move v8, v0

    .line 764
    move-object/from16 v0, v35

    .line 765
    .line 766
    goto :goto_2e

    .line 767
    :cond_2c
    move-object v0, v8

    .line 768
    const/4 v8, 0x0

    .line 769
    :goto_2e
    if-eqz v1, :cond_2d

    .line 770
    .line 771
    move-object/from16 v21, v0

    .line 772
    .line 773
    iget v0, v1, Lt3/e1;->e:I

    .line 774
    .line 775
    move/from16 v23, v25

    .line 776
    .line 777
    move-object/from16 v25, v2

    .line 778
    .line 779
    move v2, v12

    .line 780
    move/from16 v12, v23

    .line 781
    .line 782
    move/from16 v23, v20

    .line 783
    .line 784
    move-object/from16 v20, v3

    .line 785
    .line 786
    move/from16 v3, v23

    .line 787
    .line 788
    move-object/from16 v24, v9

    .line 789
    .line 790
    move v9, v0

    .line 791
    move/from16 v27, v14

    .line 792
    .line 793
    move-object/from16 v26, v15

    .line 794
    .line 795
    move/from16 v14, v31

    .line 796
    .line 797
    const/16 v23, 0x0

    .line 798
    .line 799
    move-object v15, v1

    .line 800
    move-object/from16 v0, p0

    .line 801
    .line 802
    :goto_2f
    move-object/from16 v1, p1

    .line 803
    .line 804
    goto :goto_30

    .line 805
    :cond_2d
    move/from16 v21, v25

    .line 806
    .line 807
    move-object/from16 v25, v2

    .line 808
    .line 809
    move v2, v12

    .line 810
    move/from16 v12, v21

    .line 811
    .line 812
    move/from16 v21, v20

    .line 813
    .line 814
    move-object/from16 v20, v3

    .line 815
    .line 816
    move/from16 v3, v21

    .line 817
    .line 818
    move-object/from16 v21, v0

    .line 819
    .line 820
    move-object/from16 v24, v9

    .line 821
    .line 822
    const/4 v9, 0x0

    .line 823
    move/from16 v27, v14

    .line 824
    .line 825
    move-object/from16 v26, v15

    .line 826
    .line 827
    move/from16 v14, v31

    .line 828
    .line 829
    const/16 v23, 0x0

    .line 830
    .line 831
    move-object/from16 v0, p0

    .line 832
    .line 833
    move-object v15, v1

    .line 834
    goto :goto_2f

    .line 835
    :goto_30
    invoke-virtual/range {v0 .. v12}, Lh2/pb;->f(Lt3/t;IIIIIIIIJF)I

    .line 836
    .line 837
    .line 838
    move-result v7

    .line 839
    sub-int v3, v7, v18

    .line 840
    .line 841
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 842
    .line 843
    .line 844
    move-result v0

    .line 845
    move/from16 v1, v23

    .line 846
    .line 847
    :goto_31
    if-ge v1, v0, :cond_31

    .line 848
    .line 849
    invoke-interface {v13, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 850
    .line 851
    .line 852
    move-result-object v2

    .line 853
    check-cast v2, Lt3/p0;

    .line 854
    .line 855
    invoke-static {v2}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 856
    .line 857
    .line 858
    move-result-object v4

    .line 859
    const-string v5, "Container"

    .line 860
    .line 861
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 862
    .line 863
    .line 864
    move-result v4

    .line 865
    if-eqz v4, :cond_30

    .line 866
    .line 867
    const v0, 0x7fffffff

    .line 868
    .line 869
    .line 870
    if-eq v14, v0, :cond_2e

    .line 871
    .line 872
    move v1, v14

    .line 873
    goto :goto_32

    .line 874
    :cond_2e
    move/from16 v1, v23

    .line 875
    .line 876
    :goto_32
    if-eq v3, v0, :cond_2f

    .line 877
    .line 878
    move v0, v3

    .line 879
    goto :goto_33

    .line 880
    :cond_2f
    move/from16 v0, v23

    .line 881
    .line 882
    :goto_33
    invoke-static {v1, v14, v0, v3}, Lt4/b;->a(IIII)J

    .line 883
    .line 884
    .line 885
    move-result-wide v0

    .line 886
    invoke-interface {v2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 887
    .line 888
    .line 889
    move-result-object v0

    .line 890
    move/from16 v31, v14

    .line 891
    .line 892
    move-object v14, v0

    .line 893
    new-instance v0, Lh2/ob;

    .line 894
    .line 895
    move-object/from16 v2, p0

    .line 896
    .line 897
    move-object/from16 v5, p1

    .line 898
    .line 899
    move/from16 v16, v12

    .line 900
    .line 901
    move-object/from16 v11, v19

    .line 902
    .line 903
    move-object/from16 v13, v20

    .line 904
    .line 905
    move-object/from16 v10, v21

    .line 906
    .line 907
    move-object/from16 v12, v22

    .line 908
    .line 909
    move-object/from16 v1, v24

    .line 910
    .line 911
    move-object/from16 v9, v25

    .line 912
    .line 913
    move-object/from16 v8, v26

    .line 914
    .line 915
    move/from16 v4, v27

    .line 916
    .line 917
    move/from16 v6, v31

    .line 918
    .line 919
    invoke-direct/range {v0 .. v16}, Lh2/ob;-><init>(Lkotlin/jvm/internal/f0;Lh2/pb;IILt3/s0;IILt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;F)V

    .line 920
    .line 921
    .line 922
    move-object v2, v5

    .line 923
    move v14, v6

    .line 924
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 925
    .line 926
    invoke-interface {v2, v14, v7, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 927
    .line 928
    .line 929
    move-result-object v0

    .line 930
    return-object v0

    .line 931
    :cond_30
    move-object/from16 v2, p1

    .line 932
    .line 933
    move v4, v3

    .line 934
    move-object/from16 v3, v22

    .line 935
    .line 936
    move-object/from16 v8, v26

    .line 937
    .line 938
    add-int/lit8 v1, v1, 0x1

    .line 939
    .line 940
    move v3, v4

    .line 941
    goto :goto_31

    .line 942
    :cond_31
    invoke-static/range {v16 .. v16}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 943
    .line 944
    .line 945
    move-result-object v0

    .line 946
    throw v0

    .line 947
    :cond_32
    move-object/from16 v2, p1

    .line 948
    .line 949
    move-object/from16 v19, v0

    .line 950
    .line 951
    move-object/from16 v20, v3

    .line 952
    .line 953
    move-object/from16 v21, v4

    .line 954
    .line 955
    move-object v3, v7

    .line 956
    move-object/from16 v24, v9

    .line 957
    .line 958
    move-wide/from16 v28, v11

    .line 959
    .line 960
    move/from16 v12, v25

    .line 961
    .line 962
    move-object/from16 v8, v27

    .line 963
    .line 964
    const/16 v23, 0x0

    .line 965
    .line 966
    move/from16 v27, v14

    .line 967
    .line 968
    add-int/lit8 v15, v15, 0x1

    .line 969
    .line 970
    move/from16 v2, v17

    .line 971
    .line 972
    move/from16 v10, v18

    .line 973
    .line 974
    move-object/from16 v3, v20

    .line 975
    .line 976
    move-wide/from16 v11, v28

    .line 977
    .line 978
    move-object/from16 v27, v8

    .line 979
    .line 980
    goto/16 :goto_1b

    .line 981
    .line 982
    :cond_33
    invoke-static/range {v16 .. v16}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 983
    .line 984
    .line 985
    move-result-object v0

    .line 986
    throw v0
.end method

.method public final c(Lt3/t;Ljava/util/List;I)I
    .locals 3

    .line 1
    new-instance v0, Lgv0/a;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, v0}, Lh2/pb;->i(Lt3/t;Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final d(Lt3/t;Ljava/util/List;I)I
    .locals 3

    .line 1
    new-instance v0, Lgv0/a;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, v0}, Lh2/pb;->i(Lt3/t;Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 1

    .line 1
    new-instance p0, Lgv0/a;

    .line 2
    .line 3
    const/16 p1, 0xf

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-direct {p0, v0, p1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-static {p2, p3, p0}, Lh2/pb;->k(Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final f(Lt3/t;IIIIIIIIJF)I
    .locals 3

    .line 1
    iget-object v0, p0, Lh2/pb;->d:Lk1/z0;

    .line 2
    .line 3
    invoke-interface {v0}, Lk1/z0;->d()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-interface {v0}, Lk1/z0;->c()F

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    add-float/2addr v0, v1

    .line 12
    invoke-interface {p1, v0}, Lt4/c;->Q(F)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-static {p12, p3, v1}, Llp/wa;->c(FII)I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    filled-new-array {p8, p6, p7, v2}, [I

    .line 22
    .line 23
    .line 24
    move-result-object p6

    .line 25
    move p7, v1

    .line 26
    :goto_0
    const/4 p8, 0x4

    .line 27
    if-ge p7, p8, :cond_0

    .line 28
    .line 29
    aget p8, p6, p7

    .line 30
    .line 31
    invoke-static {p2, p8}, Ljava/lang/Math;->max(II)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    add-int/lit8 p7, p7, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    if-lez p3, :cond_1

    .line 39
    .line 40
    const/4 p6, 0x2

    .line 41
    int-to-float p6, p6

    .line 42
    iget p0, p0, Lh2/pb;->e:F

    .line 43
    .line 44
    mul-float/2addr p0, p6

    .line 45
    invoke-interface {p1, p0}, Lt4/c;->Q(F)I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    sget-object p1, Lk2/x;->a:Lc1/s;

    .line 50
    .line 51
    invoke-virtual {p1, p12}, Lc1/s;->b(F)F

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    invoke-static {p1, v1, p3}, Llp/wa;->c(FII)I

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    invoke-static {p0, p1}, Ljava/lang/Math;->max(II)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    :cond_1
    add-int/2addr v0, v1

    .line 64
    add-int/2addr v0, p2

    .line 65
    invoke-static {p5, v0}, Ljava/lang/Math;->max(II)I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    invoke-static {p4, p0}, Ljava/lang/Math;->max(II)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    add-int/2addr p0, p9

    .line 74
    invoke-static {p0, p10, p11}, Lt4/b;->f(IJ)I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    return p0
.end method

.method public final i(Lt3/t;Ljava/util/List;ILay0/n;)I
    .locals 20

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    move-object/from16 v1, p4

    .line 4
    .line 5
    move-object v2, v0

    .line 6
    check-cast v2, Ljava/util/Collection;

    .line 7
    .line 8
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    const/4 v5, 0x0

    .line 13
    :goto_0
    if-ge v5, v3, :cond_1

    .line 14
    .line 15
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v7

    .line 19
    move-object v8, v7

    .line 20
    check-cast v8, Lt3/p0;

    .line 21
    .line 22
    invoke-static {v8}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v8

    .line 26
    const-string v9, "Leading"

    .line 27
    .line 28
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v8

    .line 32
    if-eqz v8, :cond_0

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_0
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    const/4 v7, 0x0

    .line 39
    :goto_1
    check-cast v7, Lt3/p0;

    .line 40
    .line 41
    const v3, 0x7fffffff

    .line 42
    .line 43
    .line 44
    if-eqz v7, :cond_2

    .line 45
    .line 46
    invoke-interface {v7, v3}, Lt3/p0;->J(I)I

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    move/from16 v8, p3

    .line 51
    .line 52
    invoke-static {v8, v5}, Li2/a1;->m(II)I

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v9

    .line 60
    invoke-interface {v1, v7, v9}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v7

    .line 64
    check-cast v7, Ljava/lang/Number;

    .line 65
    .line 66
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    move v11, v7

    .line 71
    goto :goto_2

    .line 72
    :cond_2
    move/from16 v8, p3

    .line 73
    .line 74
    move v5, v8

    .line 75
    const/4 v11, 0x0

    .line 76
    :goto_2
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    const/4 v9, 0x0

    .line 81
    :goto_3
    if-ge v9, v7, :cond_4

    .line 82
    .line 83
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v10

    .line 87
    move-object v12, v10

    .line 88
    check-cast v12, Lt3/p0;

    .line 89
    .line 90
    invoke-static {v12}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v12

    .line 94
    const-string v13, "Trailing"

    .line 95
    .line 96
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v12

    .line 100
    if-eqz v12, :cond_3

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_3
    add-int/lit8 v9, v9, 0x1

    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_4
    const/4 v10, 0x0

    .line 107
    :goto_4
    check-cast v10, Lt3/p0;

    .line 108
    .line 109
    if-eqz v10, :cond_5

    .line 110
    .line 111
    invoke-interface {v10, v3}, Lt3/p0;->J(I)I

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    invoke-static {v5, v7}, Li2/a1;->m(II)I

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 120
    .line 121
    .line 122
    move-result-object v7

    .line 123
    invoke-interface {v1, v10, v7}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    check-cast v7, Ljava/lang/Number;

    .line 128
    .line 129
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 130
    .line 131
    .line 132
    move-result v7

    .line 133
    move v12, v7

    .line 134
    goto :goto_5

    .line 135
    :cond_5
    const/4 v12, 0x0

    .line 136
    :goto_5
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 137
    .line 138
    .line 139
    move-result v7

    .line 140
    const/4 v9, 0x0

    .line 141
    :goto_6
    if-ge v9, v7, :cond_7

    .line 142
    .line 143
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v10

    .line 147
    move-object v13, v10

    .line 148
    check-cast v13, Lt3/p0;

    .line 149
    .line 150
    invoke-static {v13}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v13

    .line 154
    const-string v14, "Label"

    .line 155
    .line 156
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v13

    .line 160
    if-eqz v13, :cond_6

    .line 161
    .line 162
    goto :goto_7

    .line 163
    :cond_6
    add-int/lit8 v9, v9, 0x1

    .line 164
    .line 165
    goto :goto_6

    .line 166
    :cond_7
    const/4 v10, 0x0

    .line 167
    :goto_7
    check-cast v10, Lt3/p0;

    .line 168
    .line 169
    if-eqz v10, :cond_8

    .line 170
    .line 171
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object v7

    .line 175
    invoke-interface {v1, v10, v7}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v7

    .line 179
    check-cast v7, Ljava/lang/Number;

    .line 180
    .line 181
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 182
    .line 183
    .line 184
    move-result v7

    .line 185
    move v10, v7

    .line 186
    goto :goto_8

    .line 187
    :cond_8
    const/4 v10, 0x0

    .line 188
    :goto_8
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 189
    .line 190
    .line 191
    move-result v7

    .line 192
    const/4 v9, 0x0

    .line 193
    :goto_9
    if-ge v9, v7, :cond_a

    .line 194
    .line 195
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v13

    .line 199
    move-object v14, v13

    .line 200
    check-cast v14, Lt3/p0;

    .line 201
    .line 202
    invoke-static {v14}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v14

    .line 206
    const-string v15, "Prefix"

    .line 207
    .line 208
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v14

    .line 212
    if-eqz v14, :cond_9

    .line 213
    .line 214
    goto :goto_a

    .line 215
    :cond_9
    add-int/lit8 v9, v9, 0x1

    .line 216
    .line 217
    goto :goto_9

    .line 218
    :cond_a
    const/4 v13, 0x0

    .line 219
    :goto_a
    check-cast v13, Lt3/p0;

    .line 220
    .line 221
    if-eqz v13, :cond_b

    .line 222
    .line 223
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 224
    .line 225
    .line 226
    move-result-object v7

    .line 227
    invoke-interface {v1, v13, v7}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v7

    .line 231
    check-cast v7, Ljava/lang/Number;

    .line 232
    .line 233
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 234
    .line 235
    .line 236
    move-result v7

    .line 237
    invoke-interface {v13, v3}, Lt3/p0;->J(I)I

    .line 238
    .line 239
    .line 240
    move-result v9

    .line 241
    invoke-static {v5, v9}, Li2/a1;->m(II)I

    .line 242
    .line 243
    .line 244
    move-result v5

    .line 245
    move v13, v7

    .line 246
    goto :goto_b

    .line 247
    :cond_b
    const/4 v13, 0x0

    .line 248
    :goto_b
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 249
    .line 250
    .line 251
    move-result v7

    .line 252
    const/4 v9, 0x0

    .line 253
    :goto_c
    if-ge v9, v7, :cond_d

    .line 254
    .line 255
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v14

    .line 259
    move-object v15, v14

    .line 260
    check-cast v15, Lt3/p0;

    .line 261
    .line 262
    invoke-static {v15}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v15

    .line 266
    const-string v6, "Suffix"

    .line 267
    .line 268
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 269
    .line 270
    .line 271
    move-result v6

    .line 272
    if-eqz v6, :cond_c

    .line 273
    .line 274
    goto :goto_d

    .line 275
    :cond_c
    add-int/lit8 v9, v9, 0x1

    .line 276
    .line 277
    goto :goto_c

    .line 278
    :cond_d
    const/4 v14, 0x0

    .line 279
    :goto_d
    check-cast v14, Lt3/p0;

    .line 280
    .line 281
    if-eqz v14, :cond_e

    .line 282
    .line 283
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 284
    .line 285
    .line 286
    move-result-object v6

    .line 287
    invoke-interface {v1, v14, v6}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    check-cast v6, Ljava/lang/Number;

    .line 292
    .line 293
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 294
    .line 295
    .line 296
    move-result v6

    .line 297
    invoke-interface {v14, v3}, Lt3/p0;->J(I)I

    .line 298
    .line 299
    .line 300
    move-result v3

    .line 301
    invoke-static {v5, v3}, Li2/a1;->m(II)I

    .line 302
    .line 303
    .line 304
    move-result v5

    .line 305
    move v14, v6

    .line 306
    goto :goto_e

    .line 307
    :cond_e
    const/4 v14, 0x0

    .line 308
    :goto_e
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 309
    .line 310
    .line 311
    move-result v3

    .line 312
    const/4 v6, 0x0

    .line 313
    :goto_f
    if-ge v6, v3, :cond_16

    .line 314
    .line 315
    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v7

    .line 319
    move-object v9, v7

    .line 320
    check-cast v9, Lt3/p0;

    .line 321
    .line 322
    invoke-static {v9}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object v9

    .line 326
    const-string v15, "TextField"

    .line 327
    .line 328
    invoke-static {v9, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 329
    .line 330
    .line 331
    move-result v9

    .line 332
    if-eqz v9, :cond_15

    .line 333
    .line 334
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 335
    .line 336
    .line 337
    move-result-object v3

    .line 338
    invoke-interface {v1, v7, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v3

    .line 342
    check-cast v3, Ljava/lang/Number;

    .line 343
    .line 344
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 345
    .line 346
    .line 347
    move-result v9

    .line 348
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 349
    .line 350
    .line 351
    move-result v3

    .line 352
    const/4 v6, 0x0

    .line 353
    :goto_10
    if-ge v6, v3, :cond_10

    .line 354
    .line 355
    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v7

    .line 359
    move-object v15, v7

    .line 360
    check-cast v15, Lt3/p0;

    .line 361
    .line 362
    invoke-static {v15}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v15

    .line 366
    const-string v4, "Hint"

    .line 367
    .line 368
    invoke-static {v15, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 369
    .line 370
    .line 371
    move-result v4

    .line 372
    if-eqz v4, :cond_f

    .line 373
    .line 374
    goto :goto_11

    .line 375
    :cond_f
    add-int/lit8 v6, v6, 0x1

    .line 376
    .line 377
    goto :goto_10

    .line 378
    :cond_10
    const/4 v7, 0x0

    .line 379
    :goto_11
    check-cast v7, Lt3/p0;

    .line 380
    .line 381
    if-eqz v7, :cond_11

    .line 382
    .line 383
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 384
    .line 385
    .line 386
    move-result-object v3

    .line 387
    invoke-interface {v1, v7, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v3

    .line 391
    check-cast v3, Ljava/lang/Number;

    .line 392
    .line 393
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 394
    .line 395
    .line 396
    move-result v3

    .line 397
    move v15, v3

    .line 398
    goto :goto_12

    .line 399
    :cond_11
    const/4 v15, 0x0

    .line 400
    :goto_12
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 401
    .line 402
    .line 403
    move-result v2

    .line 404
    const/4 v3, 0x0

    .line 405
    :goto_13
    if-ge v3, v2, :cond_13

    .line 406
    .line 407
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v4

    .line 411
    move-object v5, v4

    .line 412
    check-cast v5, Lt3/p0;

    .line 413
    .line 414
    invoke-static {v5}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v5

    .line 418
    const-string v6, "Supporting"

    .line 419
    .line 420
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 421
    .line 422
    .line 423
    move-result v5

    .line 424
    if-eqz v5, :cond_12

    .line 425
    .line 426
    move-object v6, v4

    .line 427
    goto :goto_14

    .line 428
    :cond_12
    add-int/lit8 v3, v3, 0x1

    .line 429
    .line 430
    goto :goto_13

    .line 431
    :cond_13
    const/4 v6, 0x0

    .line 432
    :goto_14
    check-cast v6, Lt3/p0;

    .line 433
    .line 434
    if-eqz v6, :cond_14

    .line 435
    .line 436
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    invoke-interface {v1, v6, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    check-cast v0, Ljava/lang/Number;

    .line 445
    .line 446
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 447
    .line 448
    .line 449
    move-result v0

    .line 450
    move/from16 v16, v0

    .line 451
    .line 452
    goto :goto_15

    .line 453
    :cond_14
    const/16 v16, 0x0

    .line 454
    .line 455
    :goto_15
    const/16 v0, 0xf

    .line 456
    .line 457
    const/4 v4, 0x0

    .line 458
    invoke-static {v4, v4, v0}, Lt4/b;->b(III)J

    .line 459
    .line 460
    .line 461
    move-result-wide v17

    .line 462
    move-object/from16 v7, p0

    .line 463
    .line 464
    iget-object v0, v7, Lh2/pb;->c:Li2/g1;

    .line 465
    .line 466
    invoke-virtual {v0}, Li2/g1;->invoke()F

    .line 467
    .line 468
    .line 469
    move-result v19

    .line 470
    move-object/from16 v8, p1

    .line 471
    .line 472
    invoke-virtual/range {v7 .. v19}, Lh2/pb;->f(Lt3/t;IIIIIIIIJF)I

    .line 473
    .line 474
    .line 475
    move-result v0

    .line 476
    return v0

    .line 477
    :cond_15
    const/4 v4, 0x0

    .line 478
    add-int/lit8 v6, v6, 0x1

    .line 479
    .line 480
    goto/16 :goto_f

    .line 481
    .line 482
    :cond_16
    const-string v0, "Collection contains no element matching the predicate."

    .line 483
    .line 484
    invoke-static {v0}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    throw v0
.end method
