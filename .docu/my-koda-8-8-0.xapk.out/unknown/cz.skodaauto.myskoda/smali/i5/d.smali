.class public final Li5/d;
.super Li5/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final k:Ljava/util/ArrayList;

.field public l:I


# direct methods
.method public constructor <init>(Lh5/d;I)V
    .locals 4

    .line 1
    invoke-direct {p0, p1}, Li5/p;-><init>(Lh5/d;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 10
    .line 11
    iput p2, p0, Li5/p;->f:I

    .line 12
    .line 13
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 14
    .line 15
    invoke-virtual {v0, p2}, Lh5/d;->n(I)Lh5/d;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    :goto_0
    move-object v3, v0

    .line 20
    move-object v0, p2

    .line 21
    move-object p2, v3

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    iget p2, p0, Li5/p;->f:I

    .line 25
    .line 26
    invoke-virtual {v0, p2}, Lh5/d;->n(I)Lh5/d;

    .line 27
    .line 28
    .line 29
    move-result-object p2

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iput-object p2, p0, Li5/p;->b:Lh5/d;

    .line 32
    .line 33
    iget v0, p0, Li5/p;->f:I

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    const/4 v2, 0x1

    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    iget-object v0, p2, Lh5/d;->d:Li5/l;

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    if-ne v0, v2, :cond_2

    .line 43
    .line 44
    iget-object v0, p2, Lh5/d;->e:Li5/n;

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    move-object v0, v1

    .line 48
    :goto_1
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    iget v0, p0, Li5/p;->f:I

    .line 52
    .line 53
    invoke-virtual {p2, v0}, Lh5/d;->m(I)Lh5/d;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    :goto_2
    if-eqz p2, :cond_5

    .line 58
    .line 59
    iget v0, p0, Li5/p;->f:I

    .line 60
    .line 61
    if-nez v0, :cond_3

    .line 62
    .line 63
    iget-object v0, p2, Lh5/d;->d:Li5/l;

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    if-ne v0, v2, :cond_4

    .line 67
    .line 68
    iget-object v0, p2, Lh5/d;->e:Li5/n;

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    move-object v0, v1

    .line 72
    :goto_3
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    iget v0, p0, Li5/p;->f:I

    .line 76
    .line 77
    invoke-virtual {p2, v0}, Lh5/d;->m(I)Lh5/d;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    goto :goto_2

    .line 82
    :cond_5
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    :cond_6
    :goto_4
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-eqz v0, :cond_8

    .line 91
    .line 92
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    check-cast v0, Li5/p;

    .line 97
    .line 98
    iget v1, p0, Li5/p;->f:I

    .line 99
    .line 100
    if-nez v1, :cond_7

    .line 101
    .line 102
    iget-object v0, v0, Li5/p;->b:Lh5/d;

    .line 103
    .line 104
    iput-object p0, v0, Lh5/d;->b:Li5/d;

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_7
    if-ne v1, v2, :cond_6

    .line 108
    .line 109
    iget-object v0, v0, Li5/p;->b:Lh5/d;

    .line 110
    .line 111
    iput-object p0, v0, Lh5/d;->c:Li5/d;

    .line 112
    .line 113
    goto :goto_4

    .line 114
    :cond_8
    iget p2, p0, Li5/p;->f:I

    .line 115
    .line 116
    if-nez p2, :cond_9

    .line 117
    .line 118
    iget-object p2, p0, Li5/p;->b:Lh5/d;

    .line 119
    .line 120
    iget-object p2, p2, Lh5/d;->U:Lh5/e;

    .line 121
    .line 122
    iget-boolean p2, p2, Lh5/e;->w0:Z

    .line 123
    .line 124
    if-eqz p2, :cond_9

    .line 125
    .line 126
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 127
    .line 128
    .line 129
    move-result p2

    .line 130
    if-le p2, v2, :cond_9

    .line 131
    .line 132
    invoke-static {p1, v2}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    check-cast p1, Li5/p;

    .line 137
    .line 138
    iget-object p1, p1, Li5/p;->b:Lh5/d;

    .line 139
    .line 140
    iput-object p1, p0, Li5/p;->b:Lh5/d;

    .line 141
    .line 142
    :cond_9
    iget p1, p0, Li5/p;->f:I

    .line 143
    .line 144
    if-nez p1, :cond_a

    .line 145
    .line 146
    iget-object p1, p0, Li5/p;->b:Lh5/d;

    .line 147
    .line 148
    iget p1, p1, Lh5/d;->j0:I

    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_a
    iget-object p1, p0, Li5/p;->b:Lh5/d;

    .line 152
    .line 153
    iget p1, p1, Lh5/d;->k0:I

    .line 154
    .line 155
    :goto_5
    iput p1, p0, Li5/d;->l:I

    .line 156
    .line 157
    return-void
.end method


# virtual methods
.method public final a(Li5/e;)V
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Li5/p;->h:Li5/g;

    .line 4
    .line 5
    iget-boolean v2, v1, Li5/g;->j:Z

    .line 6
    .line 7
    if-eqz v2, :cond_56

    .line 8
    .line 9
    iget-object v2, v0, Li5/p;->i:Li5/g;

    .line 10
    .line 11
    iget-boolean v3, v2, Li5/g;->j:Z

    .line 12
    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    goto/16 :goto_32

    .line 16
    .line 17
    :cond_0
    iget-object v3, v0, Li5/p;->b:Lh5/d;

    .line 18
    .line 19
    iget-object v3, v3, Lh5/d;->U:Lh5/e;

    .line 20
    .line 21
    instance-of v4, v3, Lh5/e;

    .line 22
    .line 23
    if-eqz v4, :cond_1

    .line 24
    .line 25
    iget-boolean v3, v3, Lh5/e;->w0:Z

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const/4 v3, 0x0

    .line 29
    :goto_0
    iget v4, v2, Li5/g;->g:I

    .line 30
    .line 31
    iget v6, v1, Li5/g;->g:I

    .line 32
    .line 33
    sub-int/2addr v4, v6

    .line 34
    iget-object v6, v0, Li5/d;->k:Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    const/4 v8, 0x0

    .line 41
    :goto_1
    const/4 v9, -0x1

    .line 42
    const/16 v10, 0x8

    .line 43
    .line 44
    if-ge v8, v7, :cond_2

    .line 45
    .line 46
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v11

    .line 50
    check-cast v11, Li5/p;

    .line 51
    .line 52
    iget-object v11, v11, Li5/p;->b:Lh5/d;

    .line 53
    .line 54
    iget v11, v11, Lh5/d;->h0:I

    .line 55
    .line 56
    if-ne v11, v10, :cond_3

    .line 57
    .line 58
    add-int/lit8 v8, v8, 0x1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    move v8, v9

    .line 62
    :cond_3
    add-int/lit8 v11, v7, -0x1

    .line 63
    .line 64
    move v12, v11

    .line 65
    :goto_2
    if-ltz v12, :cond_5

    .line 66
    .line 67
    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v13

    .line 71
    check-cast v13, Li5/p;

    .line 72
    .line 73
    iget-object v13, v13, Li5/p;->b:Lh5/d;

    .line 74
    .line 75
    iget v13, v13, Lh5/d;->h0:I

    .line 76
    .line 77
    if-ne v13, v10, :cond_4

    .line 78
    .line 79
    add-int/lit8 v12, v12, -0x1

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    move v9, v12

    .line 83
    :cond_5
    const/4 v12, 0x0

    .line 84
    :goto_3
    const/4 v15, 0x2

    .line 85
    const/16 p1, 0x0

    .line 86
    .line 87
    if-ge v12, v15, :cond_14

    .line 88
    .line 89
    move/from16 v19, p1

    .line 90
    .line 91
    const/4 v5, 0x0

    .line 92
    const/4 v15, 0x0

    .line 93
    const/16 v17, 0x0

    .line 94
    .line 95
    const/16 v18, 0x0

    .line 96
    .line 97
    :goto_4
    if-ge v5, v7, :cond_11

    .line 98
    .line 99
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v20

    .line 103
    move-object/from16 v13, v20

    .line 104
    .line 105
    check-cast v13, Li5/p;

    .line 106
    .line 107
    iget-object v14, v13, Li5/p;->b:Lh5/d;

    .line 108
    .line 109
    move/from16 v22, v3

    .line 110
    .line 111
    iget v3, v14, Lh5/d;->h0:I

    .line 112
    .line 113
    if-ne v3, v10, :cond_6

    .line 114
    .line 115
    move/from16 v24, v12

    .line 116
    .line 117
    goto/16 :goto_a

    .line 118
    .line 119
    :cond_6
    add-int/lit8 v18, v18, 0x1

    .line 120
    .line 121
    if-lez v5, :cond_7

    .line 122
    .line 123
    if-lt v5, v8, :cond_7

    .line 124
    .line 125
    iget-object v3, v13, Li5/p;->h:Li5/g;

    .line 126
    .line 127
    iget v3, v3, Li5/g;->f:I

    .line 128
    .line 129
    add-int/2addr v15, v3

    .line 130
    :cond_7
    iget-object v3, v13, Li5/p;->e:Li5/h;

    .line 131
    .line 132
    iget v10, v3, Li5/g;->g:I

    .line 133
    .line 134
    move/from16 v23, v10

    .line 135
    .line 136
    iget v10, v13, Li5/p;->d:I

    .line 137
    .line 138
    move/from16 v24, v12

    .line 139
    .line 140
    const/4 v12, 0x3

    .line 141
    if-eq v10, v12, :cond_8

    .line 142
    .line 143
    const/4 v10, 0x1

    .line 144
    goto :goto_5

    .line 145
    :cond_8
    const/4 v10, 0x0

    .line 146
    :goto_5
    if-eqz v10, :cond_b

    .line 147
    .line 148
    iget v3, v0, Li5/p;->f:I

    .line 149
    .line 150
    if-nez v3, :cond_9

    .line 151
    .line 152
    iget-object v12, v14, Lh5/d;->d:Li5/l;

    .line 153
    .line 154
    iget-object v12, v12, Li5/p;->e:Li5/h;

    .line 155
    .line 156
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 157
    .line 158
    if-nez v12, :cond_9

    .line 159
    .line 160
    goto/16 :goto_32

    .line 161
    .line 162
    :cond_9
    const/4 v12, 0x1

    .line 163
    if-ne v3, v12, :cond_a

    .line 164
    .line 165
    iget-object v3, v14, Lh5/d;->e:Li5/n;

    .line 166
    .line 167
    iget-object v3, v3, Li5/p;->e:Li5/h;

    .line 168
    .line 169
    iget-boolean v3, v3, Li5/g;->j:Z

    .line 170
    .line 171
    if-nez v3, :cond_a

    .line 172
    .line 173
    goto/16 :goto_32

    .line 174
    .line 175
    :cond_a
    move/from16 v25, v10

    .line 176
    .line 177
    goto :goto_7

    .line 178
    :cond_b
    move/from16 v25, v10

    .line 179
    .line 180
    const/4 v12, 0x1

    .line 181
    iget v10, v13, Li5/p;->a:I

    .line 182
    .line 183
    if-ne v10, v12, :cond_c

    .line 184
    .line 185
    if-nez v24, :cond_c

    .line 186
    .line 187
    iget v10, v3, Li5/h;->m:I

    .line 188
    .line 189
    add-int/lit8 v17, v17, 0x1

    .line 190
    .line 191
    :goto_6
    const/16 v25, 0x1

    .line 192
    .line 193
    goto :goto_8

    .line 194
    :cond_c
    iget-boolean v3, v3, Li5/g;->j:Z

    .line 195
    .line 196
    if-eqz v3, :cond_d

    .line 197
    .line 198
    move/from16 v10, v23

    .line 199
    .line 200
    goto :goto_6

    .line 201
    :cond_d
    :goto_7
    move/from16 v10, v23

    .line 202
    .line 203
    :goto_8
    if-nez v25, :cond_e

    .line 204
    .line 205
    add-int/lit8 v17, v17, 0x1

    .line 206
    .line 207
    iget-object v3, v14, Lh5/d;->l0:[F

    .line 208
    .line 209
    iget v10, v0, Li5/p;->f:I

    .line 210
    .line 211
    aget v3, v3, v10

    .line 212
    .line 213
    cmpl-float v10, v3, p1

    .line 214
    .line 215
    if-ltz v10, :cond_f

    .line 216
    .line 217
    add-float v19, v19, v3

    .line 218
    .line 219
    goto :goto_9

    .line 220
    :cond_e
    add-int/2addr v15, v10

    .line 221
    :cond_f
    :goto_9
    if-ge v5, v11, :cond_10

    .line 222
    .line 223
    if-ge v5, v9, :cond_10

    .line 224
    .line 225
    iget-object v3, v13, Li5/p;->i:Li5/g;

    .line 226
    .line 227
    iget v3, v3, Li5/g;->f:I

    .line 228
    .line 229
    neg-int v3, v3

    .line 230
    add-int/2addr v15, v3

    .line 231
    :cond_10
    :goto_a
    add-int/lit8 v5, v5, 0x1

    .line 232
    .line 233
    move/from16 v3, v22

    .line 234
    .line 235
    move/from16 v12, v24

    .line 236
    .line 237
    const/16 v10, 0x8

    .line 238
    .line 239
    goto/16 :goto_4

    .line 240
    .line 241
    :cond_11
    move/from16 v22, v3

    .line 242
    .line 243
    move/from16 v24, v12

    .line 244
    .line 245
    if-lt v15, v4, :cond_13

    .line 246
    .line 247
    if-nez v17, :cond_12

    .line 248
    .line 249
    goto :goto_b

    .line 250
    :cond_12
    add-int/lit8 v12, v24, 0x1

    .line 251
    .line 252
    move/from16 v3, v22

    .line 253
    .line 254
    const/16 v10, 0x8

    .line 255
    .line 256
    goto/16 :goto_3

    .line 257
    .line 258
    :cond_13
    :goto_b
    move/from16 v3, v17

    .line 259
    .line 260
    move/from16 v5, v18

    .line 261
    .line 262
    goto :goto_c

    .line 263
    :cond_14
    move/from16 v22, v3

    .line 264
    .line 265
    move/from16 v19, p1

    .line 266
    .line 267
    const/4 v3, 0x0

    .line 268
    const/4 v5, 0x0

    .line 269
    const/4 v15, 0x0

    .line 270
    :goto_c
    iget v1, v1, Li5/g;->g:I

    .line 271
    .line 272
    if-eqz v22, :cond_15

    .line 273
    .line 274
    iget v1, v2, Li5/g;->g:I

    .line 275
    .line 276
    :cond_15
    const/high16 v2, 0x3f000000    # 0.5f

    .line 277
    .line 278
    if-le v15, v4, :cond_17

    .line 279
    .line 280
    const/high16 v10, 0x40000000    # 2.0f

    .line 281
    .line 282
    if-eqz v22, :cond_16

    .line 283
    .line 284
    sub-int v12, v15, v4

    .line 285
    .line 286
    int-to-float v12, v12

    .line 287
    div-float/2addr v12, v10

    .line 288
    add-float/2addr v12, v2

    .line 289
    float-to-int v10, v12

    .line 290
    add-int/2addr v1, v10

    .line 291
    goto :goto_d

    .line 292
    :cond_16
    sub-int v12, v15, v4

    .line 293
    .line 294
    int-to-float v12, v12

    .line 295
    div-float/2addr v12, v10

    .line 296
    add-float/2addr v12, v2

    .line 297
    float-to-int v10, v12

    .line 298
    sub-int/2addr v1, v10

    .line 299
    :cond_17
    :goto_d
    if-lez v3, :cond_26

    .line 300
    .line 301
    sub-int v10, v4, v15

    .line 302
    .line 303
    int-to-float v10, v10

    .line 304
    int-to-float v12, v3

    .line 305
    div-float v12, v10, v12

    .line 306
    .line 307
    add-float/2addr v12, v2

    .line 308
    float-to-int v12, v12

    .line 309
    const/4 v13, 0x0

    .line 310
    const/4 v14, 0x0

    .line 311
    :goto_e
    if-ge v13, v7, :cond_1f

    .line 312
    .line 313
    invoke-virtual {v6, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v17

    .line 317
    move/from16 v18, v2

    .line 318
    .line 319
    move-object/from16 v2, v17

    .line 320
    .line 321
    check-cast v2, Li5/p;

    .line 322
    .line 323
    move/from16 v17, v1

    .line 324
    .line 325
    iget-object v1, v2, Li5/p;->b:Lh5/d;

    .line 326
    .line 327
    move/from16 v23, v3

    .line 328
    .line 329
    iget-object v3, v2, Li5/p;->e:Li5/h;

    .line 330
    .line 331
    move/from16 v24, v10

    .line 332
    .line 333
    iget v10, v1, Lh5/d;->h0:I

    .line 334
    .line 335
    move/from16 v25, v12

    .line 336
    .line 337
    const/16 v12, 0x8

    .line 338
    .line 339
    if-ne v10, v12, :cond_19

    .line 340
    .line 341
    :cond_18
    move/from16 v26, v13

    .line 342
    .line 343
    goto :goto_12

    .line 344
    :cond_19
    iget v10, v2, Li5/p;->d:I

    .line 345
    .line 346
    const/4 v12, 0x3

    .line 347
    if-ne v10, v12, :cond_18

    .line 348
    .line 349
    iget-boolean v10, v3, Li5/g;->j:Z

    .line 350
    .line 351
    if-nez v10, :cond_18

    .line 352
    .line 353
    cmpl-float v10, v19, p1

    .line 354
    .line 355
    if-lez v10, :cond_1a

    .line 356
    .line 357
    iget-object v10, v1, Lh5/d;->l0:[F

    .line 358
    .line 359
    iget v12, v0, Li5/p;->f:I

    .line 360
    .line 361
    aget v10, v10, v12

    .line 362
    .line 363
    mul-float v10, v10, v24

    .line 364
    .line 365
    div-float v10, v10, v19

    .line 366
    .line 367
    add-float v10, v10, v18

    .line 368
    .line 369
    float-to-int v10, v10

    .line 370
    goto :goto_f

    .line 371
    :cond_1a
    move/from16 v10, v25

    .line 372
    .line 373
    :goto_f
    iget v12, v0, Li5/p;->f:I

    .line 374
    .line 375
    if-nez v12, :cond_1b

    .line 376
    .line 377
    iget v12, v1, Lh5/d;->w:I

    .line 378
    .line 379
    iget v1, v1, Lh5/d;->v:I

    .line 380
    .line 381
    goto :goto_10

    .line 382
    :cond_1b
    iget v12, v1, Lh5/d;->z:I

    .line 383
    .line 384
    iget v1, v1, Lh5/d;->y:I

    .line 385
    .line 386
    :goto_10
    iget v2, v2, Li5/p;->a:I

    .line 387
    .line 388
    move/from16 v26, v13

    .line 389
    .line 390
    const/4 v13, 0x1

    .line 391
    if-ne v2, v13, :cond_1c

    .line 392
    .line 393
    iget v2, v3, Li5/h;->m:I

    .line 394
    .line 395
    invoke-static {v10, v2}, Ljava/lang/Math;->min(II)I

    .line 396
    .line 397
    .line 398
    move-result v2

    .line 399
    goto :goto_11

    .line 400
    :cond_1c
    move v2, v10

    .line 401
    :goto_11
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 402
    .line 403
    .line 404
    move-result v1

    .line 405
    if-lez v12, :cond_1d

    .line 406
    .line 407
    invoke-static {v12, v1}, Ljava/lang/Math;->min(II)I

    .line 408
    .line 409
    .line 410
    move-result v1

    .line 411
    :cond_1d
    if-eq v1, v10, :cond_1e

    .line 412
    .line 413
    add-int/lit8 v14, v14, 0x1

    .line 414
    .line 415
    move v10, v1

    .line 416
    :cond_1e
    invoke-virtual {v3, v10}, Li5/h;->d(I)V

    .line 417
    .line 418
    .line 419
    :goto_12
    add-int/lit8 v13, v26, 0x1

    .line 420
    .line 421
    move/from16 v1, v17

    .line 422
    .line 423
    move/from16 v2, v18

    .line 424
    .line 425
    move/from16 v3, v23

    .line 426
    .line 427
    move/from16 v10, v24

    .line 428
    .line 429
    move/from16 v12, v25

    .line 430
    .line 431
    goto :goto_e

    .line 432
    :cond_1f
    move/from16 v17, v1

    .line 433
    .line 434
    move/from16 v18, v2

    .line 435
    .line 436
    move/from16 v23, v3

    .line 437
    .line 438
    if-lez v14, :cond_23

    .line 439
    .line 440
    sub-int v3, v23, v14

    .line 441
    .line 442
    const/4 v1, 0x0

    .line 443
    const/4 v15, 0x0

    .line 444
    :goto_13
    if-ge v1, v7, :cond_24

    .line 445
    .line 446
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v2

    .line 450
    check-cast v2, Li5/p;

    .line 451
    .line 452
    iget-object v10, v2, Li5/p;->b:Lh5/d;

    .line 453
    .line 454
    iget v10, v10, Lh5/d;->h0:I

    .line 455
    .line 456
    const/16 v12, 0x8

    .line 457
    .line 458
    if-ne v10, v12, :cond_20

    .line 459
    .line 460
    goto :goto_14

    .line 461
    :cond_20
    if-lez v1, :cond_21

    .line 462
    .line 463
    if-lt v1, v8, :cond_21

    .line 464
    .line 465
    iget-object v10, v2, Li5/p;->h:Li5/g;

    .line 466
    .line 467
    iget v10, v10, Li5/g;->f:I

    .line 468
    .line 469
    add-int/2addr v15, v10

    .line 470
    :cond_21
    iget-object v10, v2, Li5/p;->e:Li5/h;

    .line 471
    .line 472
    iget v10, v10, Li5/g;->g:I

    .line 473
    .line 474
    add-int/2addr v15, v10

    .line 475
    if-ge v1, v11, :cond_22

    .line 476
    .line 477
    if-ge v1, v9, :cond_22

    .line 478
    .line 479
    iget-object v2, v2, Li5/p;->i:Li5/g;

    .line 480
    .line 481
    iget v2, v2, Li5/g;->f:I

    .line 482
    .line 483
    neg-int v2, v2

    .line 484
    add-int/2addr v15, v2

    .line 485
    :cond_22
    :goto_14
    add-int/lit8 v1, v1, 0x1

    .line 486
    .line 487
    goto :goto_13

    .line 488
    :cond_23
    move/from16 v3, v23

    .line 489
    .line 490
    :cond_24
    iget v1, v0, Li5/d;->l:I

    .line 491
    .line 492
    const/4 v2, 0x2

    .line 493
    if-ne v1, v2, :cond_25

    .line 494
    .line 495
    if-nez v14, :cond_25

    .line 496
    .line 497
    const/4 v1, 0x0

    .line 498
    iput v1, v0, Li5/d;->l:I

    .line 499
    .line 500
    goto :goto_15

    .line 501
    :cond_25
    const/4 v1, 0x0

    .line 502
    goto :goto_15

    .line 503
    :cond_26
    move/from16 v17, v1

    .line 504
    .line 505
    move/from16 v18, v2

    .line 506
    .line 507
    move/from16 v23, v3

    .line 508
    .line 509
    const/4 v1, 0x0

    .line 510
    const/4 v2, 0x2

    .line 511
    :goto_15
    if-le v15, v4, :cond_27

    .line 512
    .line 513
    iput v2, v0, Li5/d;->l:I

    .line 514
    .line 515
    :cond_27
    if-lez v5, :cond_28

    .line 516
    .line 517
    if-nez v3, :cond_28

    .line 518
    .line 519
    if-ne v8, v9, :cond_28

    .line 520
    .line 521
    iput v2, v0, Li5/d;->l:I

    .line 522
    .line 523
    :cond_28
    iget v2, v0, Li5/d;->l:I

    .line 524
    .line 525
    const/4 v12, 0x1

    .line 526
    if-ne v2, v12, :cond_38

    .line 527
    .line 528
    if-le v5, v12, :cond_29

    .line 529
    .line 530
    sub-int/2addr v4, v15

    .line 531
    sub-int/2addr v5, v12

    .line 532
    div-int/2addr v4, v5

    .line 533
    goto :goto_16

    .line 534
    :cond_29
    if-ne v5, v12, :cond_2a

    .line 535
    .line 536
    sub-int/2addr v4, v15

    .line 537
    const/16 v16, 0x2

    .line 538
    .line 539
    div-int/lit8 v4, v4, 0x2

    .line 540
    .line 541
    goto :goto_16

    .line 542
    :cond_2a
    move v4, v1

    .line 543
    :goto_16
    if-lez v3, :cond_2b

    .line 544
    .line 545
    move v4, v1

    .line 546
    :cond_2b
    move v5, v1

    .line 547
    move/from16 v1, v17

    .line 548
    .line 549
    :goto_17
    if-ge v5, v7, :cond_56

    .line 550
    .line 551
    if-eqz v22, :cond_2c

    .line 552
    .line 553
    add-int/lit8 v0, v5, 0x1

    .line 554
    .line 555
    sub-int v0, v7, v0

    .line 556
    .line 557
    goto :goto_18

    .line 558
    :cond_2c
    move v0, v5

    .line 559
    :goto_18
    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 560
    .line 561
    .line 562
    move-result-object v0

    .line 563
    check-cast v0, Li5/p;

    .line 564
    .line 565
    iget-object v2, v0, Li5/p;->b:Lh5/d;

    .line 566
    .line 567
    iget-object v3, v0, Li5/p;->i:Li5/g;

    .line 568
    .line 569
    iget-object v10, v0, Li5/p;->h:Li5/g;

    .line 570
    .line 571
    iget v2, v2, Lh5/d;->h0:I

    .line 572
    .line 573
    const/16 v12, 0x8

    .line 574
    .line 575
    if-ne v2, v12, :cond_2d

    .line 576
    .line 577
    invoke-virtual {v10, v1}, Li5/g;->d(I)V

    .line 578
    .line 579
    .line 580
    invoke-virtual {v3, v1}, Li5/g;->d(I)V

    .line 581
    .line 582
    .line 583
    goto :goto_1f

    .line 584
    :cond_2d
    if-lez v5, :cond_2f

    .line 585
    .line 586
    if-eqz v22, :cond_2e

    .line 587
    .line 588
    sub-int/2addr v1, v4

    .line 589
    goto :goto_19

    .line 590
    :cond_2e
    add-int/2addr v1, v4

    .line 591
    :cond_2f
    :goto_19
    if-lez v5, :cond_31

    .line 592
    .line 593
    if-lt v5, v8, :cond_31

    .line 594
    .line 595
    if-eqz v22, :cond_30

    .line 596
    .line 597
    iget v2, v10, Li5/g;->f:I

    .line 598
    .line 599
    sub-int/2addr v1, v2

    .line 600
    goto :goto_1a

    .line 601
    :cond_30
    iget v2, v10, Li5/g;->f:I

    .line 602
    .line 603
    add-int/2addr v1, v2

    .line 604
    :cond_31
    :goto_1a
    if-eqz v22, :cond_32

    .line 605
    .line 606
    invoke-virtual {v3, v1}, Li5/g;->d(I)V

    .line 607
    .line 608
    .line 609
    goto :goto_1b

    .line 610
    :cond_32
    invoke-virtual {v10, v1}, Li5/g;->d(I)V

    .line 611
    .line 612
    .line 613
    :goto_1b
    iget-object v2, v0, Li5/p;->e:Li5/h;

    .line 614
    .line 615
    iget v12, v2, Li5/g;->g:I

    .line 616
    .line 617
    iget v13, v0, Li5/p;->d:I

    .line 618
    .line 619
    const/4 v14, 0x3

    .line 620
    if-ne v13, v14, :cond_33

    .line 621
    .line 622
    iget v13, v0, Li5/p;->a:I

    .line 623
    .line 624
    const/4 v14, 0x1

    .line 625
    if-ne v13, v14, :cond_33

    .line 626
    .line 627
    iget v12, v2, Li5/h;->m:I

    .line 628
    .line 629
    :cond_33
    if-eqz v22, :cond_34

    .line 630
    .line 631
    sub-int/2addr v1, v12

    .line 632
    goto :goto_1c

    .line 633
    :cond_34
    add-int/2addr v1, v12

    .line 634
    :goto_1c
    if-eqz v22, :cond_35

    .line 635
    .line 636
    invoke-virtual {v10, v1}, Li5/g;->d(I)V

    .line 637
    .line 638
    .line 639
    :goto_1d
    const/4 v12, 0x1

    .line 640
    goto :goto_1e

    .line 641
    :cond_35
    invoke-virtual {v3, v1}, Li5/g;->d(I)V

    .line 642
    .line 643
    .line 644
    goto :goto_1d

    .line 645
    :goto_1e
    iput-boolean v12, v0, Li5/p;->g:Z

    .line 646
    .line 647
    if-ge v5, v11, :cond_37

    .line 648
    .line 649
    if-ge v5, v9, :cond_37

    .line 650
    .line 651
    if-eqz v22, :cond_36

    .line 652
    .line 653
    iget v0, v3, Li5/g;->f:I

    .line 654
    .line 655
    neg-int v0, v0

    .line 656
    sub-int/2addr v1, v0

    .line 657
    goto :goto_1f

    .line 658
    :cond_36
    iget v0, v3, Li5/g;->f:I

    .line 659
    .line 660
    neg-int v0, v0

    .line 661
    add-int/2addr v1, v0

    .line 662
    :cond_37
    :goto_1f
    add-int/lit8 v5, v5, 0x1

    .line 663
    .line 664
    goto :goto_17

    .line 665
    :cond_38
    if-nez v2, :cond_45

    .line 666
    .line 667
    sub-int/2addr v4, v15

    .line 668
    const/16 v21, 0x1

    .line 669
    .line 670
    add-int/lit8 v5, v5, 0x1

    .line 671
    .line 672
    div-int/2addr v4, v5

    .line 673
    if-lez v3, :cond_39

    .line 674
    .line 675
    move v4, v1

    .line 676
    :cond_39
    move v5, v1

    .line 677
    move/from16 v1, v17

    .line 678
    .line 679
    :goto_20
    if-ge v5, v7, :cond_56

    .line 680
    .line 681
    if-eqz v22, :cond_3a

    .line 682
    .line 683
    add-int/lit8 v0, v5, 0x1

    .line 684
    .line 685
    sub-int v0, v7, v0

    .line 686
    .line 687
    goto :goto_21

    .line 688
    :cond_3a
    move v0, v5

    .line 689
    :goto_21
    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 690
    .line 691
    .line 692
    move-result-object v0

    .line 693
    check-cast v0, Li5/p;

    .line 694
    .line 695
    iget-object v2, v0, Li5/p;->b:Lh5/d;

    .line 696
    .line 697
    iget-object v3, v0, Li5/p;->i:Li5/g;

    .line 698
    .line 699
    iget-object v10, v0, Li5/p;->h:Li5/g;

    .line 700
    .line 701
    iget v2, v2, Lh5/d;->h0:I

    .line 702
    .line 703
    const/16 v12, 0x8

    .line 704
    .line 705
    if-ne v2, v12, :cond_3b

    .line 706
    .line 707
    invoke-virtual {v10, v1}, Li5/g;->d(I)V

    .line 708
    .line 709
    .line 710
    invoke-virtual {v3, v1}, Li5/g;->d(I)V

    .line 711
    .line 712
    .line 713
    goto :goto_27

    .line 714
    :cond_3b
    if-eqz v22, :cond_3c

    .line 715
    .line 716
    sub-int/2addr v1, v4

    .line 717
    goto :goto_22

    .line 718
    :cond_3c
    add-int/2addr v1, v4

    .line 719
    :goto_22
    if-lez v5, :cond_3e

    .line 720
    .line 721
    if-lt v5, v8, :cond_3e

    .line 722
    .line 723
    if-eqz v22, :cond_3d

    .line 724
    .line 725
    iget v2, v10, Li5/g;->f:I

    .line 726
    .line 727
    sub-int/2addr v1, v2

    .line 728
    goto :goto_23

    .line 729
    :cond_3d
    iget v2, v10, Li5/g;->f:I

    .line 730
    .line 731
    add-int/2addr v1, v2

    .line 732
    :cond_3e
    :goto_23
    if-eqz v22, :cond_3f

    .line 733
    .line 734
    invoke-virtual {v3, v1}, Li5/g;->d(I)V

    .line 735
    .line 736
    .line 737
    goto :goto_24

    .line 738
    :cond_3f
    invoke-virtual {v10, v1}, Li5/g;->d(I)V

    .line 739
    .line 740
    .line 741
    :goto_24
    iget-object v2, v0, Li5/p;->e:Li5/h;

    .line 742
    .line 743
    iget v12, v2, Li5/g;->g:I

    .line 744
    .line 745
    iget v13, v0, Li5/p;->d:I

    .line 746
    .line 747
    const/4 v14, 0x3

    .line 748
    if-ne v13, v14, :cond_40

    .line 749
    .line 750
    iget v0, v0, Li5/p;->a:I

    .line 751
    .line 752
    const/4 v14, 0x1

    .line 753
    if-ne v0, v14, :cond_40

    .line 754
    .line 755
    iget v0, v2, Li5/h;->m:I

    .line 756
    .line 757
    invoke-static {v12, v0}, Ljava/lang/Math;->min(II)I

    .line 758
    .line 759
    .line 760
    move-result v12

    .line 761
    :cond_40
    if-eqz v22, :cond_41

    .line 762
    .line 763
    sub-int/2addr v1, v12

    .line 764
    goto :goto_25

    .line 765
    :cond_41
    add-int/2addr v1, v12

    .line 766
    :goto_25
    if-eqz v22, :cond_42

    .line 767
    .line 768
    invoke-virtual {v10, v1}, Li5/g;->d(I)V

    .line 769
    .line 770
    .line 771
    goto :goto_26

    .line 772
    :cond_42
    invoke-virtual {v3, v1}, Li5/g;->d(I)V

    .line 773
    .line 774
    .line 775
    :goto_26
    if-ge v5, v11, :cond_44

    .line 776
    .line 777
    if-ge v5, v9, :cond_44

    .line 778
    .line 779
    if-eqz v22, :cond_43

    .line 780
    .line 781
    iget v0, v3, Li5/g;->f:I

    .line 782
    .line 783
    neg-int v0, v0

    .line 784
    sub-int/2addr v1, v0

    .line 785
    goto :goto_27

    .line 786
    :cond_43
    iget v0, v3, Li5/g;->f:I

    .line 787
    .line 788
    neg-int v0, v0

    .line 789
    add-int/2addr v1, v0

    .line 790
    :cond_44
    :goto_27
    add-int/lit8 v5, v5, 0x1

    .line 791
    .line 792
    goto :goto_20

    .line 793
    :cond_45
    const/4 v5, 0x2

    .line 794
    if-ne v2, v5, :cond_56

    .line 795
    .line 796
    iget v2, v0, Li5/p;->f:I

    .line 797
    .line 798
    if-nez v2, :cond_46

    .line 799
    .line 800
    iget-object v0, v0, Li5/p;->b:Lh5/d;

    .line 801
    .line 802
    iget v0, v0, Lh5/d;->e0:F

    .line 803
    .line 804
    goto :goto_28

    .line 805
    :cond_46
    iget-object v0, v0, Li5/p;->b:Lh5/d;

    .line 806
    .line 807
    iget v0, v0, Lh5/d;->f0:F

    .line 808
    .line 809
    :goto_28
    if-eqz v22, :cond_47

    .line 810
    .line 811
    const/high16 v2, 0x3f800000    # 1.0f

    .line 812
    .line 813
    sub-float v0, v2, v0

    .line 814
    .line 815
    :cond_47
    sub-int/2addr v4, v15

    .line 816
    int-to-float v2, v4

    .line 817
    mul-float/2addr v2, v0

    .line 818
    add-float v2, v2, v18

    .line 819
    .line 820
    float-to-int v0, v2

    .line 821
    if-ltz v0, :cond_48

    .line 822
    .line 823
    if-lez v3, :cond_49

    .line 824
    .line 825
    :cond_48
    move v0, v1

    .line 826
    :cond_49
    if-eqz v22, :cond_4a

    .line 827
    .line 828
    sub-int v0, v17, v0

    .line 829
    .line 830
    goto :goto_29

    .line 831
    :cond_4a
    add-int v0, v17, v0

    .line 832
    .line 833
    :goto_29
    move v5, v1

    .line 834
    :goto_2a
    if-ge v5, v7, :cond_56

    .line 835
    .line 836
    if-eqz v22, :cond_4b

    .line 837
    .line 838
    add-int/lit8 v1, v5, 0x1

    .line 839
    .line 840
    sub-int v1, v7, v1

    .line 841
    .line 842
    goto :goto_2b

    .line 843
    :cond_4b
    move v1, v5

    .line 844
    :goto_2b
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v1

    .line 848
    check-cast v1, Li5/p;

    .line 849
    .line 850
    iget-object v2, v1, Li5/p;->b:Lh5/d;

    .line 851
    .line 852
    iget-object v3, v1, Li5/p;->i:Li5/g;

    .line 853
    .line 854
    iget-object v4, v1, Li5/p;->h:Li5/g;

    .line 855
    .line 856
    iget v2, v2, Lh5/d;->h0:I

    .line 857
    .line 858
    const/16 v12, 0x8

    .line 859
    .line 860
    if-ne v2, v12, :cond_4c

    .line 861
    .line 862
    invoke-virtual {v4, v0}, Li5/g;->d(I)V

    .line 863
    .line 864
    .line 865
    invoke-virtual {v3, v0}, Li5/g;->d(I)V

    .line 866
    .line 867
    .line 868
    const/4 v13, 0x1

    .line 869
    const/4 v14, 0x3

    .line 870
    goto :goto_31

    .line 871
    :cond_4c
    if-lez v5, :cond_4e

    .line 872
    .line 873
    if-lt v5, v8, :cond_4e

    .line 874
    .line 875
    if-eqz v22, :cond_4d

    .line 876
    .line 877
    iget v2, v4, Li5/g;->f:I

    .line 878
    .line 879
    sub-int/2addr v0, v2

    .line 880
    goto :goto_2c

    .line 881
    :cond_4d
    iget v2, v4, Li5/g;->f:I

    .line 882
    .line 883
    add-int/2addr v0, v2

    .line 884
    :cond_4e
    :goto_2c
    if-eqz v22, :cond_4f

    .line 885
    .line 886
    invoke-virtual {v3, v0}, Li5/g;->d(I)V

    .line 887
    .line 888
    .line 889
    goto :goto_2d

    .line 890
    :cond_4f
    invoke-virtual {v4, v0}, Li5/g;->d(I)V

    .line 891
    .line 892
    .line 893
    :goto_2d
    iget-object v2, v1, Li5/p;->e:Li5/h;

    .line 894
    .line 895
    iget v10, v2, Li5/g;->g:I

    .line 896
    .line 897
    iget v13, v1, Li5/p;->d:I

    .line 898
    .line 899
    const/4 v14, 0x3

    .line 900
    if-ne v13, v14, :cond_50

    .line 901
    .line 902
    iget v1, v1, Li5/p;->a:I

    .line 903
    .line 904
    const/4 v13, 0x1

    .line 905
    if-ne v1, v13, :cond_51

    .line 906
    .line 907
    iget v10, v2, Li5/h;->m:I

    .line 908
    .line 909
    goto :goto_2e

    .line 910
    :cond_50
    const/4 v13, 0x1

    .line 911
    :cond_51
    :goto_2e
    if-eqz v22, :cond_52

    .line 912
    .line 913
    sub-int/2addr v0, v10

    .line 914
    goto :goto_2f

    .line 915
    :cond_52
    add-int/2addr v0, v10

    .line 916
    :goto_2f
    if-eqz v22, :cond_53

    .line 917
    .line 918
    invoke-virtual {v4, v0}, Li5/g;->d(I)V

    .line 919
    .line 920
    .line 921
    goto :goto_30

    .line 922
    :cond_53
    invoke-virtual {v3, v0}, Li5/g;->d(I)V

    .line 923
    .line 924
    .line 925
    :goto_30
    if-ge v5, v11, :cond_55

    .line 926
    .line 927
    if-ge v5, v9, :cond_55

    .line 928
    .line 929
    if-eqz v22, :cond_54

    .line 930
    .line 931
    iget v1, v3, Li5/g;->f:I

    .line 932
    .line 933
    neg-int v1, v1

    .line 934
    sub-int/2addr v0, v1

    .line 935
    goto :goto_31

    .line 936
    :cond_54
    iget v1, v3, Li5/g;->f:I

    .line 937
    .line 938
    neg-int v1, v1

    .line 939
    add-int/2addr v0, v1

    .line 940
    :cond_55
    :goto_31
    add-int/lit8 v5, v5, 0x1

    .line 941
    .line 942
    goto :goto_2a

    .line 943
    :cond_56
    :goto_32
    return-void
.end method

.method public final d()V
    .locals 7

    .line 1
    iget-object v0, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Li5/p;

    .line 18
    .line 19
    invoke-virtual {v2}, Li5/p;->d()V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    const/4 v2, 0x1

    .line 28
    if-ge v1, v2, :cond_1

    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    const/4 v3, 0x0

    .line 32
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Li5/p;

    .line 37
    .line 38
    iget-object v4, v4, Li5/p;->b:Lh5/d;

    .line 39
    .line 40
    sub-int/2addr v1, v2

    .line 41
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    check-cast v0, Li5/p;

    .line 46
    .line 47
    iget-object v0, v0, Li5/p;->b:Lh5/d;

    .line 48
    .line 49
    iget v1, p0, Li5/p;->f:I

    .line 50
    .line 51
    iget-object v5, p0, Li5/p;->i:Li5/g;

    .line 52
    .line 53
    iget-object v6, p0, Li5/p;->h:Li5/g;

    .line 54
    .line 55
    if-nez v1, :cond_5

    .line 56
    .line 57
    iget-object v1, v4, Lh5/d;->J:Lh5/c;

    .line 58
    .line 59
    iget-object v0, v0, Lh5/d;->L:Lh5/c;

    .line 60
    .line 61
    invoke-static {v1, v3}, Li5/p;->i(Lh5/c;I)Li5/g;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    invoke-virtual {p0}, Li5/d;->m()Lh5/d;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    if-eqz v4, :cond_2

    .line 74
    .line 75
    iget-object v1, v4, Lh5/d;->J:Lh5/c;

    .line 76
    .line 77
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    :cond_2
    if-eqz v2, :cond_3

    .line 82
    .line 83
    invoke-static {v6, v2, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 84
    .line 85
    .line 86
    :cond_3
    invoke-static {v0, v3}, Li5/p;->i(Lh5/c;I)Li5/g;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    invoke-virtual {p0}, Li5/d;->n()Lh5/d;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    if-eqz v2, :cond_4

    .line 99
    .line 100
    iget-object v0, v2, Lh5/d;->L:Lh5/c;

    .line 101
    .line 102
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    :cond_4
    if-eqz v1, :cond_9

    .line 107
    .line 108
    neg-int v0, v0

    .line 109
    invoke-static {v5, v1, v0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_5
    iget-object v1, v4, Lh5/d;->K:Lh5/c;

    .line 114
    .line 115
    iget-object v0, v0, Lh5/d;->M:Lh5/c;

    .line 116
    .line 117
    invoke-static {v1, v2}, Li5/p;->i(Lh5/c;I)Li5/g;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    invoke-virtual {p0}, Li5/d;->m()Lh5/d;

    .line 126
    .line 127
    .line 128
    move-result-object v4

    .line 129
    if-eqz v4, :cond_6

    .line 130
    .line 131
    iget-object v1, v4, Lh5/d;->K:Lh5/c;

    .line 132
    .line 133
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    :cond_6
    if-eqz v3, :cond_7

    .line 138
    .line 139
    invoke-static {v6, v3, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 140
    .line 141
    .line 142
    :cond_7
    invoke-static {v0, v2}, Li5/p;->i(Lh5/c;I)Li5/g;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    invoke-virtual {p0}, Li5/d;->n()Lh5/d;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    if-eqz v2, :cond_8

    .line 155
    .line 156
    iget-object v0, v2, Lh5/d;->M:Lh5/c;

    .line 157
    .line 158
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    :cond_8
    if-eqz v1, :cond_9

    .line 163
    .line 164
    neg-int v0, v0

    .line 165
    invoke-static {v5, v1, v0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 166
    .line 167
    .line 168
    :cond_9
    :goto_1
    iput-object p0, v6, Li5/g;->a:Li5/p;

    .line 169
    .line 170
    iput-object p0, v5, Li5/g;->a:Li5/p;

    .line 171
    .line 172
    return-void
.end method

.method public final e()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget-object v1, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 3
    .line 4
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 5
    .line 6
    .line 7
    move-result v2

    .line 8
    if-ge v0, v2, :cond_0

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    check-cast v1, Li5/p;

    .line 15
    .line 16
    invoke-virtual {v1}, Li5/p;->e()V

    .line 17
    .line 18
    .line 19
    add-int/lit8 v0, v0, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-void
.end method

.method public final f()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Li5/p;->c:Li5/m;

    .line 3
    .line 4
    iget-object p0, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Li5/p;

    .line 21
    .line 22
    invoke-virtual {v0}, Li5/p;->f()V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    return-void
.end method

.method public final j()J
    .locals 7

    .line 1
    iget-object p0, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-wide/16 v1, 0x0

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    :goto_0
    if-ge v3, v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    check-cast v4, Li5/p;

    .line 17
    .line 18
    iget-object v5, v4, Li5/p;->h:Li5/g;

    .line 19
    .line 20
    iget v5, v5, Li5/g;->f:I

    .line 21
    .line 22
    int-to-long v5, v5

    .line 23
    add-long/2addr v1, v5

    .line 24
    invoke-virtual {v4}, Li5/p;->j()J

    .line 25
    .line 26
    .line 27
    move-result-wide v5

    .line 28
    add-long/2addr v5, v1

    .line 29
    iget-object v1, v4, Li5/p;->i:Li5/g;

    .line 30
    .line 31
    iget v1, v1, Li5/g;->f:I

    .line 32
    .line 33
    int-to-long v1, v1

    .line 34
    add-long/2addr v1, v5

    .line 35
    add-int/lit8 v3, v3, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    return-wide v1
.end method

.method public final k()Z
    .locals 4

    .line 1
    iget-object p0, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    move v2, v1

    .line 9
    :goto_0
    if-ge v2, v0, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    check-cast v3, Li5/p;

    .line 16
    .line 17
    invoke-virtual {v3}, Li5/p;->k()Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-nez v3, :cond_0

    .line 22
    .line 23
    return v1

    .line 24
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 p0, 0x1

    .line 28
    return p0
.end method

.method public final m()Lh5/d;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget-object v1, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 3
    .line 4
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 5
    .line 6
    .line 7
    move-result v2

    .line 8
    if-ge v0, v2, :cond_1

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    check-cast v1, Li5/p;

    .line 15
    .line 16
    iget-object v1, v1, Li5/p;->b:Lh5/d;

    .line 17
    .line 18
    iget v2, v1, Lh5/d;->h0:I

    .line 19
    .line 20
    const/16 v3, 0x8

    .line 21
    .line 22
    if-eq v2, v3, :cond_0

    .line 23
    .line 24
    return-object v1

    .line 25
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const/4 p0, 0x0

    .line 29
    return-object p0
.end method

.method public final n()Lh5/d;
    .locals 4

    .line 1
    iget-object p0, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    add-int/lit8 v0, v0, -0x1

    .line 8
    .line 9
    :goto_0
    if-ltz v0, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Li5/p;

    .line 16
    .line 17
    iget-object v1, v1, Li5/p;->b:Lh5/d;

    .line 18
    .line 19
    iget v2, v1, Lh5/d;->h0:I

    .line 20
    .line 21
    const/16 v3, 0x8

    .line 22
    .line 23
    if-eq v2, v3, :cond_0

    .line 24
    .line 25
    return-object v1

    .line 26
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 p0, 0x0

    .line 30
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ChainRun "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Li5/p;->f:I

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    const-string v1, "horizontal : "

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-string v1, "vertical : "

    .line 16
    .line 17
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Li5/d;->k:Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Li5/p;

    .line 37
    .line 38
    const-string v2, "<"

    .line 39
    .line 40
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, "> "

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
