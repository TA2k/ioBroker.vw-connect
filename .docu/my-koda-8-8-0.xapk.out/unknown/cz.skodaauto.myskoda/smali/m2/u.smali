.class public final Lm2/u;
.super Lm2/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lm2/u;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lm2/u;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x2

    .line 5
    const/4 v3, 0x1

    .line 6
    invoke-direct {v0, v3, v1, v2}, Lm2/j0;-><init>(III)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lm2/u;->c:Lm2/u;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Landroidx/collection/h;Ll2/c;Ll2/i2;Ljp/uf;Lm2/k0;)V
    .locals 17

    .line 1
    move-object/from16 v0, p3

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    move-object/from16 v2, p1

    .line 5
    .line 6
    invoke-virtual {v2, v1}, Landroidx/collection/h;->f(I)I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    iget v3, v0, Ll2/i2;->n:I

    .line 11
    .line 12
    if-nez v3, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-string v3, "Cannot move a group while inserting"

    .line 16
    .line 17
    invoke-static {v3}, Ll2/v;->c(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    :goto_0
    const-string v3, "Parameter offset is out of bounds"

    .line 21
    .line 22
    if-ltz v2, :cond_1

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    invoke-static {v3}, Ll2/v;->c(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :goto_1
    if-nez v2, :cond_2

    .line 29
    .line 30
    goto/16 :goto_9

    .line 31
    .line 32
    :cond_2
    iget v4, v0, Ll2/i2;->t:I

    .line 33
    .line 34
    iget v5, v0, Ll2/i2;->v:I

    .line 35
    .line 36
    iget v6, v0, Ll2/i2;->u:I

    .line 37
    .line 38
    move v7, v4

    .line 39
    :goto_2
    if-lez v2, :cond_4

    .line 40
    .line 41
    iget-object v8, v0, Ll2/i2;->b:[I

    .line 42
    .line 43
    invoke-virtual {v0, v7}, Ll2/i2;->r(I)I

    .line 44
    .line 45
    .line 46
    move-result v9

    .line 47
    mul-int/lit8 v9, v9, 0x5

    .line 48
    .line 49
    add-int/lit8 v9, v9, 0x3

    .line 50
    .line 51
    aget v8, v8, v9

    .line 52
    .line 53
    add-int/2addr v7, v8

    .line 54
    if-gt v7, v6, :cond_3

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    invoke-static {v3}, Ll2/v;->c(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    :goto_3
    add-int/lit8 v2, v2, -0x1

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_4
    iget-object v2, v0, Ll2/i2;->b:[I

    .line 64
    .line 65
    invoke-virtual {v0, v7}, Ll2/i2;->r(I)I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    mul-int/lit8 v3, v3, 0x5

    .line 70
    .line 71
    add-int/lit8 v3, v3, 0x3

    .line 72
    .line 73
    aget v2, v2, v3

    .line 74
    .line 75
    iget-object v3, v0, Ll2/i2;->b:[I

    .line 76
    .line 77
    iget v6, v0, Ll2/i2;->t:I

    .line 78
    .line 79
    invoke-virtual {v0, v6}, Ll2/i2;->r(I)I

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    invoke-virtual {v0, v6, v3}, Ll2/i2;->g(I[I)I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    iget-object v6, v0, Ll2/i2;->b:[I

    .line 88
    .line 89
    invoke-virtual {v0, v7}, Ll2/i2;->r(I)I

    .line 90
    .line 91
    .line 92
    move-result v8

    .line 93
    invoke-virtual {v0, v8, v6}, Ll2/i2;->g(I[I)I

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    iget-object v8, v0, Ll2/i2;->b:[I

    .line 98
    .line 99
    add-int/2addr v7, v2

    .line 100
    invoke-virtual {v0, v7}, Ll2/i2;->r(I)I

    .line 101
    .line 102
    .line 103
    move-result v9

    .line 104
    invoke-virtual {v0, v9, v8}, Ll2/i2;->g(I[I)I

    .line 105
    .line 106
    .line 107
    move-result v8

    .line 108
    sub-int v9, v8, v6

    .line 109
    .line 110
    iget v10, v0, Ll2/i2;->t:I

    .line 111
    .line 112
    add-int/lit8 v10, v10, -0x1

    .line 113
    .line 114
    invoke-static {v10, v1}, Ljava/lang/Math;->max(II)I

    .line 115
    .line 116
    .line 117
    move-result v10

    .line 118
    invoke-virtual {v0, v9, v10}, Ll2/i2;->w(II)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, v2}, Ll2/i2;->v(I)V

    .line 122
    .line 123
    .line 124
    iget-object v10, v0, Ll2/i2;->b:[I

    .line 125
    .line 126
    invoke-virtual {v0, v7}, Ll2/i2;->r(I)I

    .line 127
    .line 128
    .line 129
    move-result v11

    .line 130
    mul-int/lit8 v11, v11, 0x5

    .line 131
    .line 132
    invoke-virtual {v0, v4}, Ll2/i2;->r(I)I

    .line 133
    .line 134
    .line 135
    move-result v12

    .line 136
    mul-int/lit8 v12, v12, 0x5

    .line 137
    .line 138
    mul-int/lit8 v13, v2, 0x5

    .line 139
    .line 140
    add-int/2addr v13, v11

    .line 141
    invoke-static {v12, v11, v13, v10, v10}, Lmx0/n;->h(III[I[I)V

    .line 142
    .line 143
    .line 144
    if-lez v9, :cond_5

    .line 145
    .line 146
    iget-object v11, v0, Ll2/i2;->c:[Ljava/lang/Object;

    .line 147
    .line 148
    add-int v12, v6, v9

    .line 149
    .line 150
    invoke-virtual {v0, v12}, Ll2/i2;->h(I)I

    .line 151
    .line 152
    .line 153
    move-result v12

    .line 154
    add-int/2addr v8, v9

    .line 155
    invoke-virtual {v0, v8}, Ll2/i2;->h(I)I

    .line 156
    .line 157
    .line 158
    move-result v8

    .line 159
    sub-int/2addr v8, v12

    .line 160
    invoke-static {v11, v12, v11, v3, v8}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 161
    .line 162
    .line 163
    :cond_5
    add-int/2addr v6, v9

    .line 164
    sub-int v3, v6, v3

    .line 165
    .line 166
    iget v8, v0, Ll2/i2;->k:I

    .line 167
    .line 168
    iget v11, v0, Ll2/i2;->l:I

    .line 169
    .line 170
    iget-object v12, v0, Ll2/i2;->c:[Ljava/lang/Object;

    .line 171
    .line 172
    array-length v12, v12

    .line 173
    iget v13, v0, Ll2/i2;->m:I

    .line 174
    .line 175
    add-int v14, v4, v2

    .line 176
    .line 177
    move v15, v4

    .line 178
    :goto_4
    if-ge v15, v14, :cond_7

    .line 179
    .line 180
    invoke-virtual {v0, v15}, Ll2/i2;->r(I)I

    .line 181
    .line 182
    .line 183
    move-result v1

    .line 184
    invoke-virtual {v0, v1, v10}, Ll2/i2;->g(I[I)I

    .line 185
    .line 186
    .line 187
    move-result v16

    .line 188
    move/from16 p1, v3

    .line 189
    .line 190
    sub-int v3, v16, p1

    .line 191
    .line 192
    move/from16 p2, v1

    .line 193
    .line 194
    if-ge v13, v1, :cond_6

    .line 195
    .line 196
    const/4 v1, 0x0

    .line 197
    goto :goto_5

    .line 198
    :cond_6
    move v1, v8

    .line 199
    :goto_5
    invoke-static {v3, v1, v11, v12}, Ll2/i2;->i(IIII)I

    .line 200
    .line 201
    .line 202
    move-result v1

    .line 203
    iget v3, v0, Ll2/i2;->k:I

    .line 204
    .line 205
    move/from16 v16, v8

    .line 206
    .line 207
    iget v8, v0, Ll2/i2;->l:I

    .line 208
    .line 209
    move-object/from16 p4, v10

    .line 210
    .line 211
    iget-object v10, v0, Ll2/i2;->c:[Ljava/lang/Object;

    .line 212
    .line 213
    array-length v10, v10

    .line 214
    invoke-static {v1, v3, v8, v10}, Ll2/i2;->i(IIII)I

    .line 215
    .line 216
    .line 217
    move-result v1

    .line 218
    mul-int/lit8 v3, p2, 0x5

    .line 219
    .line 220
    add-int/lit8 v3, v3, 0x4

    .line 221
    .line 222
    aput v1, p4, v3

    .line 223
    .line 224
    add-int/lit8 v15, v15, 0x1

    .line 225
    .line 226
    move/from16 v3, p1

    .line 227
    .line 228
    move-object/from16 v10, p4

    .line 229
    .line 230
    move/from16 v8, v16

    .line 231
    .line 232
    const/4 v1, 0x0

    .line 233
    goto :goto_4

    .line 234
    :cond_7
    add-int v1, v7, v2

    .line 235
    .line 236
    invoke-virtual {v0}, Ll2/i2;->p()I

    .line 237
    .line 238
    .line 239
    move-result v3

    .line 240
    iget-object v8, v0, Ll2/i2;->d:Ljava/util/ArrayList;

    .line 241
    .line 242
    invoke-static {v8, v7, v3}, Ll2/h2;->b(Ljava/util/ArrayList;II)I

    .line 243
    .line 244
    .line 245
    move-result v8

    .line 246
    new-instance v10, Ljava/util/ArrayList;

    .line 247
    .line 248
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 249
    .line 250
    .line 251
    if-ltz v8, :cond_8

    .line 252
    .line 253
    :goto_6
    iget-object v11, v0, Ll2/i2;->d:Ljava/util/ArrayList;

    .line 254
    .line 255
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 256
    .line 257
    .line 258
    move-result v11

    .line 259
    if-ge v8, v11, :cond_8

    .line 260
    .line 261
    iget-object v11, v0, Ll2/i2;->d:Ljava/util/ArrayList;

    .line 262
    .line 263
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v11

    .line 267
    check-cast v11, Ll2/a;

    .line 268
    .line 269
    invoke-virtual {v0, v11}, Ll2/i2;->c(Ll2/a;)I

    .line 270
    .line 271
    .line 272
    move-result v12

    .line 273
    if-lt v12, v7, :cond_8

    .line 274
    .line 275
    if-ge v12, v1, :cond_8

    .line 276
    .line 277
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 278
    .line 279
    .line 280
    iget-object v11, v0, Ll2/i2;->d:Ljava/util/ArrayList;

    .line 281
    .line 282
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v11

    .line 286
    check-cast v11, Ll2/a;

    .line 287
    .line 288
    goto :goto_6

    .line 289
    :cond_8
    sub-int v1, v4, v7

    .line 290
    .line 291
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 292
    .line 293
    .line 294
    move-result v8

    .line 295
    const/4 v11, 0x0

    .line 296
    :goto_7
    if-ge v11, v8, :cond_a

    .line 297
    .line 298
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v12

    .line 302
    check-cast v12, Ll2/a;

    .line 303
    .line 304
    invoke-virtual {v0, v12}, Ll2/i2;->c(Ll2/a;)I

    .line 305
    .line 306
    .line 307
    move-result v13

    .line 308
    add-int/2addr v13, v1

    .line 309
    iget v14, v0, Ll2/i2;->g:I

    .line 310
    .line 311
    if-lt v13, v14, :cond_9

    .line 312
    .line 313
    sub-int v14, v3, v13

    .line 314
    .line 315
    neg-int v14, v14

    .line 316
    iput v14, v12, Ll2/a;->a:I

    .line 317
    .line 318
    goto :goto_8

    .line 319
    :cond_9
    iput v13, v12, Ll2/a;->a:I

    .line 320
    .line 321
    :goto_8
    iget-object v14, v0, Ll2/i2;->d:Ljava/util/ArrayList;

    .line 322
    .line 323
    invoke-static {v14, v13, v3}, Ll2/h2;->b(Ljava/util/ArrayList;II)I

    .line 324
    .line 325
    .line 326
    move-result v13

    .line 327
    iget-object v14, v0, Ll2/i2;->d:Ljava/util/ArrayList;

    .line 328
    .line 329
    invoke-virtual {v14, v13, v12}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    add-int/lit8 v11, v11, 0x1

    .line 333
    .line 334
    goto :goto_7

    .line 335
    :cond_a
    invoke-virtual {v0, v7, v2}, Ll2/i2;->H(II)Z

    .line 336
    .line 337
    .line 338
    move-result v1

    .line 339
    if-eqz v1, :cond_b

    .line 340
    .line 341
    const-string v1, "Unexpectedly removed anchors"

    .line 342
    .line 343
    invoke-static {v1}, Ll2/v;->c(Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    :cond_b
    iget v1, v0, Ll2/i2;->u:I

    .line 347
    .line 348
    invoke-virtual {v0, v5, v1, v4}, Ll2/i2;->m(III)V

    .line 349
    .line 350
    .line 351
    if-lez v9, :cond_c

    .line 352
    .line 353
    add-int/lit8 v7, v7, -0x1

    .line 354
    .line 355
    invoke-virtual {v0, v6, v9, v7}, Ll2/i2;->I(III)V

    .line 356
    .line 357
    .line 358
    :cond_c
    :goto_9
    return-void
.end method
