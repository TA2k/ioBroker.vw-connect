.class public final Lh2/fa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 19

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-wide/from16 v2, p3

    .line 6
    .line 7
    invoke-static {v2, v3}, Lt4/a;->h(J)I

    .line 8
    .line 9
    .line 10
    move-result v4

    .line 11
    sget v5, Lh2/ja;->a:F

    .line 12
    .line 13
    invoke-interface {v0, v5}, Lt4/c;->Q(F)I

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    invoke-static {v4, v5}, Ljava/lang/Math;->min(II)I

    .line 18
    .line 19
    .line 20
    move-result v8

    .line 21
    move-object v4, v1

    .line 22
    check-cast v4, Ljava/util/Collection;

    .line 23
    .line 24
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    const/4 v6, 0x0

    .line 29
    :goto_0
    const/4 v7, 0x0

    .line 30
    if-ge v6, v5, :cond_1

    .line 31
    .line 32
    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v10

    .line 36
    move-object v11, v10

    .line 37
    check-cast v11, Lt3/p0;

    .line 38
    .line 39
    invoke-static {v11}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v11

    .line 43
    const-string v12, "action"

    .line 44
    .line 45
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v11

    .line 49
    if-eqz v11, :cond_0

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_0
    add-int/lit8 v6, v6, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    move-object v10, v7

    .line 56
    :goto_1
    check-cast v10, Lt3/p0;

    .line 57
    .line 58
    if-eqz v10, :cond_2

    .line 59
    .line 60
    invoke-interface {v10, v2, v3}, Lt3/p0;->L(J)Lt3/e1;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    move-object v10, v5

    .line 65
    goto :goto_2

    .line 66
    :cond_2
    move-object v10, v7

    .line 67
    :goto_2
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    const/4 v6, 0x0

    .line 72
    :goto_3
    if-ge v6, v5, :cond_4

    .line 73
    .line 74
    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v11

    .line 78
    move-object v12, v11

    .line 79
    check-cast v12, Lt3/p0;

    .line 80
    .line 81
    invoke-static {v12}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v12

    .line 85
    const-string v13, "dismissAction"

    .line 86
    .line 87
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v12

    .line 91
    if-eqz v12, :cond_3

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_4
    move-object v11, v7

    .line 98
    :goto_4
    check-cast v11, Lt3/p0;

    .line 99
    .line 100
    if-eqz v11, :cond_5

    .line 101
    .line 102
    invoke-interface {v11, v2, v3}, Lt3/p0;->L(J)Lt3/e1;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    :cond_5
    move-object v13, v7

    .line 107
    if-eqz v10, :cond_6

    .line 108
    .line 109
    iget v5, v10, Lt3/e1;->d:I

    .line 110
    .line 111
    move v11, v5

    .line 112
    goto :goto_5

    .line 113
    :cond_6
    const/4 v11, 0x0

    .line 114
    :goto_5
    if-eqz v10, :cond_7

    .line 115
    .line 116
    iget v5, v10, Lt3/e1;->e:I

    .line 117
    .line 118
    move v12, v5

    .line 119
    goto :goto_6

    .line 120
    :cond_7
    const/4 v12, 0x0

    .line 121
    :goto_6
    if-eqz v13, :cond_8

    .line 122
    .line 123
    iget v5, v13, Lt3/e1;->d:I

    .line 124
    .line 125
    move v14, v5

    .line 126
    goto :goto_7

    .line 127
    :cond_8
    const/4 v14, 0x0

    .line 128
    :goto_7
    if-eqz v13, :cond_9

    .line 129
    .line 130
    iget v5, v13, Lt3/e1;->e:I

    .line 131
    .line 132
    move v15, v5

    .line 133
    goto :goto_8

    .line 134
    :cond_9
    const/4 v15, 0x0

    .line 135
    :goto_8
    if-nez v14, :cond_a

    .line 136
    .line 137
    sget v5, Lh2/ja;->f:F

    .line 138
    .line 139
    invoke-interface {v0, v5}, Lt4/c;->Q(F)I

    .line 140
    .line 141
    .line 142
    move-result v5

    .line 143
    goto :goto_9

    .line 144
    :cond_a
    const/4 v5, 0x0

    .line 145
    :goto_9
    sub-int v6, v8, v11

    .line 146
    .line 147
    sub-int/2addr v6, v14

    .line 148
    sub-int/2addr v6, v5

    .line 149
    invoke-static {v2, v3}, Lt4/a;->j(J)I

    .line 150
    .line 151
    .line 152
    move-result v5

    .line 153
    if-ge v6, v5, :cond_b

    .line 154
    .line 155
    move v6, v5

    .line 156
    :cond_b
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    const/4 v5, 0x0

    .line 161
    :goto_a
    if-ge v5, v4, :cond_13

    .line 162
    .line 163
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v7

    .line 167
    check-cast v7, Lt3/p0;

    .line 168
    .line 169
    invoke-static {v7}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v9

    .line 173
    const-string v1, "text"

    .line 174
    .line 175
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    if-eqz v1, :cond_12

    .line 180
    .line 181
    move v4, v6

    .line 182
    const/4 v6, 0x0

    .line 183
    move-object v1, v7

    .line 184
    const/16 v7, 0x9

    .line 185
    .line 186
    const/4 v3, 0x0

    .line 187
    const/4 v5, 0x0

    .line 188
    move-object v9, v1

    .line 189
    move-wide/from16 v1, p3

    .line 190
    .line 191
    invoke-static/range {v1 .. v7}, Lt4/a;->a(JIIIII)J

    .line 192
    .line 193
    .line 194
    move-result-wide v1

    .line 195
    invoke-interface {v9, v1, v2}, Lt3/p0;->L(J)Lt3/e1;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    sget-object v2, Lt3/d;->a:Lt3/o;

    .line 200
    .line 201
    invoke-virtual {v1, v2}, Lt3/e1;->a0(Lt3/a;)I

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    sget-object v4, Lt3/d;->b:Lt3/o;

    .line 206
    .line 207
    invoke-virtual {v1, v4}, Lt3/e1;->a0(Lt3/a;)I

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    const/high16 v5, -0x80000000

    .line 212
    .line 213
    const/4 v6, 0x1

    .line 214
    if-eq v3, v5, :cond_c

    .line 215
    .line 216
    if-eq v4, v5, :cond_c

    .line 217
    .line 218
    move v7, v6

    .line 219
    goto :goto_b

    .line 220
    :cond_c
    const/4 v7, 0x0

    .line 221
    :goto_b
    if-eq v3, v4, :cond_e

    .line 222
    .line 223
    if-nez v7, :cond_d

    .line 224
    .line 225
    goto :goto_c

    .line 226
    :cond_d
    const/4 v6, 0x0

    .line 227
    :cond_e
    :goto_c
    sub-int v14, v8, v14

    .line 228
    .line 229
    sub-int v17, v14, v11

    .line 230
    .line 231
    if-eqz v6, :cond_10

    .line 232
    .line 233
    sget v4, Lk2/k0;->i:F

    .line 234
    .line 235
    invoke-interface {v0, v4}, Lt4/c;->Q(F)I

    .line 236
    .line 237
    .line 238
    move-result v4

    .line 239
    invoke-static {v12, v15}, Ljava/lang/Math;->max(II)I

    .line 240
    .line 241
    .line 242
    move-result v6

    .line 243
    invoke-static {v4, v6}, Ljava/lang/Math;->max(II)I

    .line 244
    .line 245
    .line 246
    move-result v4

    .line 247
    iget v6, v1, Lt3/e1;->e:I

    .line 248
    .line 249
    sub-int v6, v4, v6

    .line 250
    .line 251
    div-int/lit8 v6, v6, 0x2

    .line 252
    .line 253
    if-eqz v10, :cond_f

    .line 254
    .line 255
    invoke-virtual {v10, v2}, Lt3/e1;->a0(Lt3/a;)I

    .line 256
    .line 257
    .line 258
    move-result v2

    .line 259
    if-eq v2, v5, :cond_f

    .line 260
    .line 261
    add-int/2addr v3, v6

    .line 262
    sub-int/2addr v3, v2

    .line 263
    goto :goto_d

    .line 264
    :cond_f
    const/4 v3, 0x0

    .line 265
    :goto_d
    move/from16 v18, v3

    .line 266
    .line 267
    move v12, v6

    .line 268
    goto :goto_e

    .line 269
    :cond_10
    sget v2, Lh2/ja;->b:F

    .line 270
    .line 271
    invoke-interface {v0, v2}, Lt4/c;->Q(F)I

    .line 272
    .line 273
    .line 274
    move-result v2

    .line 275
    sub-int v6, v2, v3

    .line 276
    .line 277
    sget v2, Lk2/k0;->j:F

    .line 278
    .line 279
    invoke-interface {v0, v2}, Lt4/c;->Q(F)I

    .line 280
    .line 281
    .line 282
    move-result v2

    .line 283
    iget v3, v1, Lt3/e1;->e:I

    .line 284
    .line 285
    add-int/2addr v3, v6

    .line 286
    invoke-static {v2, v3}, Ljava/lang/Math;->max(II)I

    .line 287
    .line 288
    .line 289
    move-result v4

    .line 290
    if-eqz v10, :cond_f

    .line 291
    .line 292
    iget v2, v10, Lt3/e1;->e:I

    .line 293
    .line 294
    sub-int v2, v4, v2

    .line 295
    .line 296
    div-int/lit8 v2, v2, 0x2

    .line 297
    .line 298
    move v3, v2

    .line 299
    goto :goto_d

    .line 300
    :goto_e
    if-eqz v13, :cond_11

    .line 301
    .line 302
    iget v2, v13, Lt3/e1;->e:I

    .line 303
    .line 304
    sub-int v2, v4, v2

    .line 305
    .line 306
    div-int/lit8 v9, v2, 0x2

    .line 307
    .line 308
    move v15, v9

    .line 309
    :goto_f
    move-object/from16 v16, v10

    .line 310
    .line 311
    goto :goto_10

    .line 312
    :cond_11
    const/4 v15, 0x0

    .line 313
    goto :goto_f

    .line 314
    :goto_10
    new-instance v10, Lh2/ea;

    .line 315
    .line 316
    move-object v11, v1

    .line 317
    invoke-direct/range {v10 .. v18}, Lh2/ea;-><init>(Lt3/e1;ILt3/e1;IILt3/e1;II)V

    .line 318
    .line 319
    .line 320
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 321
    .line 322
    invoke-interface {v0, v8, v4, v1, v10}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 323
    .line 324
    .line 325
    move-result-object v0

    .line 326
    return-object v0

    .line 327
    :cond_12
    move v1, v4

    .line 328
    move v4, v6

    .line 329
    move-object/from16 v16, v10

    .line 330
    .line 331
    add-int/lit8 v5, v5, 0x1

    .line 332
    .line 333
    move-wide/from16 v2, p3

    .line 334
    .line 335
    move v4, v1

    .line 336
    move-object/from16 v1, p2

    .line 337
    .line 338
    goto/16 :goto_a

    .line 339
    .line 340
    :cond_13
    const-string v0, "Collection contains no element matching the predicate."

    .line 341
    .line 342
    invoke-static {v0}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    throw v0
.end method
