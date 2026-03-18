.class public final Lu2/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu2/g;


# instance fields
.field public final d:Lay0/k;

.field public final e:Landroidx/collection/q0;

.field public f:Landroidx/collection/q0;


# direct methods
.method public constructor <init>(Ljava/util/Map;Lay0/k;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lu2/h;->d:Lay0/k;

    .line 5
    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    new-instance p2, Landroidx/collection/q0;

    .line 16
    .line 17
    invoke-interface {p1}, Ljava/util/Map;->size()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-direct {p2, v0}, Landroidx/collection/q0;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_2

    .line 37
    .line 38
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Ljava/util/Map$Entry;

    .line 43
    .line 44
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-virtual {p2, v1, v0}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    :goto_1
    const/4 p2, 0x0

    .line 57
    :cond_2
    iput-object p2, p0, Lu2/h;->e:Landroidx/collection/q0;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lay0/a;)Lu2/f;
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_3

    .line 7
    .line 8
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-static {v2}, Lry/a;->d(C)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-nez v2, :cond_2

    .line 17
    .line 18
    iget-object v0, p0, Lu2/h;->f:Landroidx/collection/q0;

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    sget-object v0, Landroidx/collection/y0;->a:[J

    .line 23
    .line 24
    new-instance v0, Landroidx/collection/q0;

    .line 25
    .line 26
    invoke-direct {v0}, Landroidx/collection/q0;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Lu2/h;->f:Landroidx/collection/q0;

    .line 30
    .line 31
    :cond_0
    invoke-virtual {v0, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    if-nez p0, :cond_1

    .line 36
    .line 37
    new-instance p0, Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, p1, p0}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    check-cast p0, Ljava/util/List;

    .line 46
    .line 47
    invoke-interface {p0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    new-instance p0, Lrn/i;

    .line 51
    .line 52
    const/16 v1, 0xa

    .line 53
    .line 54
    invoke-direct {p0, v0, p1, p2, v1}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;I)V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    const-string p1, "Registered key is empty or blank"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0
.end method

.method public final d(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/h;->d:Lay0/k;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e()Ljava/util/Map;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lu2/h;->e:Landroidx/collection/q0;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget-object v2, v0, Lu2/h;->f:Landroidx/collection/q0;

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    const/4 v2, 0x0

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    iget v3, v1, Landroidx/collection/q0;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    move v3, v2

    .line 21
    :goto_0
    iget-object v4, v0, Lu2/h;->f:Landroidx/collection/q0;

    .line 22
    .line 23
    if-eqz v4, :cond_2

    .line 24
    .line 25
    iget v4, v4, Landroidx/collection/q0;->e:I

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_2
    move v4, v2

    .line 29
    :goto_1
    add-int/2addr v3, v4

    .line 30
    new-instance v4, Ljava/util/HashMap;

    .line 31
    .line 32
    invoke-direct {v4, v3}, Ljava/util/HashMap;-><init>(I)V

    .line 33
    .line 34
    .line 35
    const/4 v3, 0x7

    .line 36
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    const/16 v11, 0x8

    .line 42
    .line 43
    if-eqz v1, :cond_6

    .line 44
    .line 45
    iget-object v12, v1, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 46
    .line 47
    iget-object v13, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 48
    .line 49
    iget-object v1, v1, Landroidx/collection/q0;->a:[J

    .line 50
    .line 51
    array-length v14, v1

    .line 52
    add-int/lit8 v14, v14, -0x2

    .line 53
    .line 54
    if-ltz v14, :cond_6

    .line 55
    .line 56
    move v15, v2

    .line 57
    const-wide/16 v16, 0x80

    .line 58
    .line 59
    :goto_2
    aget-wide v5, v1, v15

    .line 60
    .line 61
    const-wide/16 v18, 0xff

    .line 62
    .line 63
    not-long v7, v5

    .line 64
    shl-long/2addr v7, v3

    .line 65
    and-long/2addr v7, v5

    .line 66
    and-long/2addr v7, v9

    .line 67
    cmp-long v7, v7, v9

    .line 68
    .line 69
    if-eqz v7, :cond_5

    .line 70
    .line 71
    sub-int v7, v15, v14

    .line 72
    .line 73
    not-int v7, v7

    .line 74
    ushr-int/lit8 v7, v7, 0x1f

    .line 75
    .line 76
    rsub-int/lit8 v7, v7, 0x8

    .line 77
    .line 78
    move v8, v2

    .line 79
    :goto_3
    if-ge v8, v7, :cond_4

    .line 80
    .line 81
    and-long v20, v5, v18

    .line 82
    .line 83
    cmp-long v20, v20, v16

    .line 84
    .line 85
    if-gez v20, :cond_3

    .line 86
    .line 87
    shl-int/lit8 v20, v15, 0x3

    .line 88
    .line 89
    add-int v20, v20, v8

    .line 90
    .line 91
    aget-object v21, v12, v20

    .line 92
    .line 93
    aget-object v20, v13, v20

    .line 94
    .line 95
    move/from16 v22, v3

    .line 96
    .line 97
    move-object/from16 v3, v20

    .line 98
    .line 99
    check-cast v3, Ljava/util/List;

    .line 100
    .line 101
    move-wide/from16 v23, v9

    .line 102
    .line 103
    move-object/from16 v9, v21

    .line 104
    .line 105
    check-cast v9, Ljava/lang/String;

    .line 106
    .line 107
    invoke-interface {v4, v9, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_3
    move/from16 v22, v3

    .line 112
    .line 113
    move-wide/from16 v23, v9

    .line 114
    .line 115
    :goto_4
    shr-long/2addr v5, v11

    .line 116
    add-int/lit8 v8, v8, 0x1

    .line 117
    .line 118
    move/from16 v3, v22

    .line 119
    .line 120
    move-wide/from16 v9, v23

    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_4
    move/from16 v22, v3

    .line 124
    .line 125
    move-wide/from16 v23, v9

    .line 126
    .line 127
    if-ne v7, v11, :cond_7

    .line 128
    .line 129
    goto :goto_5

    .line 130
    :cond_5
    move/from16 v22, v3

    .line 131
    .line 132
    move-wide/from16 v23, v9

    .line 133
    .line 134
    :goto_5
    if-eq v15, v14, :cond_7

    .line 135
    .line 136
    add-int/lit8 v15, v15, 0x1

    .line 137
    .line 138
    move/from16 v3, v22

    .line 139
    .line 140
    move-wide/from16 v9, v23

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_6
    move/from16 v22, v3

    .line 144
    .line 145
    move-wide/from16 v23, v9

    .line 146
    .line 147
    const-wide/16 v16, 0x80

    .line 148
    .line 149
    const-wide/16 v18, 0xff

    .line 150
    .line 151
    :cond_7
    iget-object v1, v0, Lu2/h;->f:Landroidx/collection/q0;

    .line 152
    .line 153
    if-eqz v1, :cond_11

    .line 154
    .line 155
    iget-object v3, v1, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 156
    .line 157
    iget-object v5, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 158
    .line 159
    iget-object v1, v1, Landroidx/collection/q0;->a:[J

    .line 160
    .line 161
    array-length v6, v1

    .line 162
    add-int/lit8 v6, v6, -0x2

    .line 163
    .line 164
    if-ltz v6, :cond_11

    .line 165
    .line 166
    move v7, v2

    .line 167
    :goto_6
    aget-wide v8, v1, v7

    .line 168
    .line 169
    not-long v12, v8

    .line 170
    shl-long v12, v12, v22

    .line 171
    .line 172
    and-long/2addr v12, v8

    .line 173
    and-long v12, v12, v23

    .line 174
    .line 175
    cmp-long v10, v12, v23

    .line 176
    .line 177
    if-eqz v10, :cond_10

    .line 178
    .line 179
    sub-int v10, v7, v6

    .line 180
    .line 181
    not-int v10, v10

    .line 182
    ushr-int/lit8 v10, v10, 0x1f

    .line 183
    .line 184
    rsub-int/lit8 v10, v10, 0x8

    .line 185
    .line 186
    move v12, v2

    .line 187
    :goto_7
    if-ge v12, v10, :cond_f

    .line 188
    .line 189
    and-long v13, v8, v18

    .line 190
    .line 191
    cmp-long v13, v13, v16

    .line 192
    .line 193
    if-gez v13, :cond_e

    .line 194
    .line 195
    shl-int/lit8 v13, v7, 0x3

    .line 196
    .line 197
    add-int/2addr v13, v12

    .line 198
    aget-object v14, v3, v13

    .line 199
    .line 200
    aget-object v13, v5, v13

    .line 201
    .line 202
    check-cast v13, Ljava/util/List;

    .line 203
    .line 204
    check-cast v14, Ljava/lang/String;

    .line 205
    .line 206
    invoke-interface {v13}, Ljava/util/List;->size()I

    .line 207
    .line 208
    .line 209
    move-result v15

    .line 210
    move/from16 v20, v11

    .line 211
    .line 212
    const/4 v11, 0x1

    .line 213
    if-ne v15, v11, :cond_a

    .line 214
    .line 215
    invoke-interface {v13, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    check-cast v11, Lay0/a;

    .line 220
    .line 221
    invoke-interface {v11}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v11

    .line 225
    if-eqz v11, :cond_8

    .line 226
    .line 227
    invoke-virtual {v0, v11}, Lu2/h;->d(Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    move-result v13

    .line 231
    if-eqz v13, :cond_9

    .line 232
    .line 233
    filled-new-array {v11}, [Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v11

    .line 237
    invoke-static {v11}, Ljp/k1;->b([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 238
    .line 239
    .line 240
    move-result-object v11

    .line 241
    invoke-interface {v4, v14, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    :cond_8
    move-object/from16 v26, v1

    .line 245
    .line 246
    goto :goto_a

    .line 247
    :cond_9
    invoke-static {v11}, Lu2/m;->a(Ljava/lang/Object;)Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object v0

    .line 251
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 252
    .line 253
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    throw v1

    .line 261
    :cond_a
    invoke-interface {v13}, Ljava/util/List;->size()I

    .line 262
    .line 263
    .line 264
    move-result v11

    .line 265
    new-instance v15, Ljava/util/ArrayList;

    .line 266
    .line 267
    invoke-direct {v15, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 268
    .line 269
    .line 270
    :goto_8
    if-ge v2, v11, :cond_d

    .line 271
    .line 272
    invoke-interface {v13, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v25

    .line 276
    check-cast v25, Lay0/a;

    .line 277
    .line 278
    move-object/from16 v26, v1

    .line 279
    .line 280
    invoke-interface/range {v25 .. v25}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v1

    .line 284
    if-eqz v1, :cond_c

    .line 285
    .line 286
    invoke-virtual {v0, v1}, Lu2/h;->d(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v25

    .line 290
    if-eqz v25, :cond_b

    .line 291
    .line 292
    goto :goto_9

    .line 293
    :cond_b
    invoke-static {v1}, Lu2/m;->a(Ljava/lang/Object;)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 298
    .line 299
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    throw v1

    .line 307
    :cond_c
    :goto_9
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    add-int/lit8 v2, v2, 0x1

    .line 311
    .line 312
    move-object/from16 v1, v26

    .line 313
    .line 314
    goto :goto_8

    .line 315
    :cond_d
    move-object/from16 v26, v1

    .line 316
    .line 317
    invoke-interface {v4, v14, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    goto :goto_a

    .line 321
    :cond_e
    move-object/from16 v26, v1

    .line 322
    .line 323
    move/from16 v20, v11

    .line 324
    .line 325
    :goto_a
    shr-long v8, v8, v20

    .line 326
    .line 327
    add-int/lit8 v12, v12, 0x1

    .line 328
    .line 329
    move/from16 v11, v20

    .line 330
    .line 331
    move-object/from16 v1, v26

    .line 332
    .line 333
    const/4 v2, 0x0

    .line 334
    goto/16 :goto_7

    .line 335
    .line 336
    :cond_f
    move-object/from16 v26, v1

    .line 337
    .line 338
    move v1, v11

    .line 339
    if-ne v10, v1, :cond_11

    .line 340
    .line 341
    goto :goto_b

    .line 342
    :cond_10
    move-object/from16 v26, v1

    .line 343
    .line 344
    move v1, v11

    .line 345
    :goto_b
    if-eq v7, v6, :cond_11

    .line 346
    .line 347
    add-int/lit8 v7, v7, 0x1

    .line 348
    .line 349
    move v11, v1

    .line 350
    move-object/from16 v1, v26

    .line 351
    .line 352
    const/4 v2, 0x0

    .line 353
    goto/16 :goto_6

    .line 354
    .line 355
    :cond_11
    return-object v4
.end method

.method public final f(Ljava/lang/String;)Ljava/lang/Object;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lu2/h;->e:Landroidx/collection/q0;

    .line 3
    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Ljava/util/List;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object v1, v0

    .line 14
    :goto_0
    move-object v2, v1

    .line 15
    check-cast v2, Ljava/util/Collection;

    .line 16
    .line 17
    if-eqz v2, :cond_4

    .line 18
    .line 19
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_1
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x1

    .line 31
    if-le v0, v2, :cond_3

    .line 32
    .line 33
    if-eqz p0, :cond_3

    .line 34
    .line 35
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-interface {v1, v2, v0}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->f(Ljava/lang/Object;)I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-gez v2, :cond_2

    .line 48
    .line 49
    not-int v2, v2

    .line 50
    :cond_2
    iget-object v3, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 51
    .line 52
    aget-object v4, v3, v2

    .line 53
    .line 54
    iget-object p0, p0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 55
    .line 56
    aput-object p1, p0, v2

    .line 57
    .line 58
    aput-object v0, v3, v2

    .line 59
    .line 60
    check-cast v4, Ljava/util/List;

    .line 61
    .line 62
    :cond_3
    const/4 p0, 0x0

    .line 63
    invoke-interface {v1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :cond_4
    :goto_1
    return-object v0
.end method
