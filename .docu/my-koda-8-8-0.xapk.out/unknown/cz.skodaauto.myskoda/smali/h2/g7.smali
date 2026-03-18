.class public final synthetic Lh2/g7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Ll2/t2;

.field public final synthetic g:J

.field public final synthetic h:Ll2/t2;

.field public final synthetic i:J

.field public final synthetic j:Ll2/t2;

.field public final synthetic k:Ll2/t2;


# direct methods
.method public synthetic constructor <init>(IFLc1/g0;JLc1/g0;JLc1/g0;Lc1/g0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh2/g7;->d:I

    .line 5
    .line 6
    iput p2, p0, Lh2/g7;->e:F

    .line 7
    .line 8
    iput-object p3, p0, Lh2/g7;->f:Ll2/t2;

    .line 9
    .line 10
    iput-wide p4, p0, Lh2/g7;->g:J

    .line 11
    .line 12
    iput-object p6, p0, Lh2/g7;->h:Ll2/t2;

    .line 13
    .line 14
    iput-wide p7, p0, Lh2/g7;->i:J

    .line 15
    .line 16
    iput-object p9, p0, Lh2/g7;->j:Ll2/t2;

    .line 17
    .line 18
    iput-object p10, p0, Lh2/g7;->k:Ll2/t2;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    invoke-interface {v1}, Lg3/d;->e()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    const-wide v4, 0xffffffffL

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    and-long/2addr v2, v4

    .line 17
    long-to-int v2, v2

    .line 18
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 19
    .line 20
    .line 21
    move-result v6

    .line 22
    iget v7, v0, Lh2/g7;->d:I

    .line 23
    .line 24
    iget v2, v0, Lh2/g7;->e:F

    .line 25
    .line 26
    const/16 v3, 0x20

    .line 27
    .line 28
    if-nez v7, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-interface {v1}, Lg3/d;->e()J

    .line 32
    .line 33
    .line 34
    move-result-wide v8

    .line 35
    and-long/2addr v4, v8

    .line 36
    long-to-int v4, v4

    .line 37
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    invoke-interface {v1}, Lg3/d;->e()J

    .line 42
    .line 43
    .line 44
    move-result-wide v8

    .line 45
    shr-long/2addr v8, v3

    .line 46
    long-to-int v5, v8

    .line 47
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    cmpl-float v4, v4, v5

    .line 52
    .line 53
    if-lez v4, :cond_1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    invoke-interface {v1, v6}, Lt4/c;->o0(F)F

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    add-float/2addr v2, v4

    .line 61
    :goto_0
    invoke-interface {v1}, Lg3/d;->e()J

    .line 62
    .line 63
    .line 64
    move-result-wide v4

    .line 65
    shr-long v3, v4, v3

    .line 66
    .line 67
    long-to-int v3, v3

    .line 68
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    invoke-interface {v1, v3}, Lt4/c;->o0(F)F

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    div-float v8, v2, v3

    .line 77
    .line 78
    iget-object v9, v0, Lh2/g7;->f:Ll2/t2;

    .line 79
    .line 80
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Ljava/lang/Number;

    .line 85
    .line 86
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    const/high16 v10, 0x3f800000    # 1.0f

    .line 91
    .line 92
    sub-float v3, v10, v8

    .line 93
    .line 94
    cmpg-float v2, v2, v3

    .line 95
    .line 96
    iget-wide v4, v0, Lh2/g7;->g:J

    .line 97
    .line 98
    const/4 v11, 0x0

    .line 99
    if-gez v2, :cond_3

    .line 100
    .line 101
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    check-cast v2, Ljava/lang/Number;

    .line 106
    .line 107
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    cmpl-float v2, v2, v11

    .line 112
    .line 113
    if-lez v2, :cond_2

    .line 114
    .line 115
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    check-cast v2, Ljava/lang/Number;

    .line 120
    .line 121
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    add-float/2addr v2, v8

    .line 126
    goto :goto_1

    .line 127
    :cond_2
    move v2, v11

    .line 128
    :goto_1
    const/high16 v3, 0x3f800000    # 1.0f

    .line 129
    .line 130
    invoke-static/range {v1 .. v7}, Lh2/n7;->f(Lg3/d;FFJFI)V

    .line 131
    .line 132
    .line 133
    :cond_3
    move-wide v12, v4

    .line 134
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    check-cast v2, Ljava/lang/Number;

    .line 139
    .line 140
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    iget-object v14, v0, Lh2/g7;->h:Ll2/t2;

    .line 145
    .line 146
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    check-cast v3, Ljava/lang/Number;

    .line 151
    .line 152
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 153
    .line 154
    .line 155
    move-result v3

    .line 156
    sub-float/2addr v2, v3

    .line 157
    cmpl-float v2, v2, v11

    .line 158
    .line 159
    iget-wide v3, v0, Lh2/g7;->i:J

    .line 160
    .line 161
    if-lez v2, :cond_4

    .line 162
    .line 163
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v2

    .line 167
    check-cast v2, Ljava/lang/Number;

    .line 168
    .line 169
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 170
    .line 171
    .line 172
    move-result v2

    .line 173
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v5

    .line 177
    check-cast v5, Ljava/lang/Number;

    .line 178
    .line 179
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 180
    .line 181
    .line 182
    move-result v5

    .line 183
    move-wide/from16 v17, v3

    .line 184
    .line 185
    move v3, v5

    .line 186
    move-wide/from16 v4, v17

    .line 187
    .line 188
    invoke-static/range {v1 .. v7}, Lh2/n7;->f(Lg3/d;FFJFI)V

    .line 189
    .line 190
    .line 191
    move-wide v15, v4

    .line 192
    goto :goto_2

    .line 193
    :cond_4
    move-wide v15, v3

    .line 194
    :goto_2
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    check-cast v2, Ljava/lang/Number;

    .line 199
    .line 200
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 201
    .line 202
    .line 203
    move-result v2

    .line 204
    cmpl-float v2, v2, v8

    .line 205
    .line 206
    iget-object v9, v0, Lh2/g7;->j:Ll2/t2;

    .line 207
    .line 208
    if-lez v2, :cond_7

    .line 209
    .line 210
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v2

    .line 214
    check-cast v2, Ljava/lang/Number;

    .line 215
    .line 216
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 217
    .line 218
    .line 219
    move-result v2

    .line 220
    cmpl-float v2, v2, v11

    .line 221
    .line 222
    if-lez v2, :cond_5

    .line 223
    .line 224
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v2

    .line 228
    check-cast v2, Ljava/lang/Number;

    .line 229
    .line 230
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 231
    .line 232
    .line 233
    move-result v2

    .line 234
    add-float/2addr v2, v8

    .line 235
    goto :goto_3

    .line 236
    :cond_5
    move v2, v11

    .line 237
    :goto_3
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    check-cast v3, Ljava/lang/Number;

    .line 242
    .line 243
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 244
    .line 245
    .line 246
    move-result v3

    .line 247
    cmpg-float v3, v3, v10

    .line 248
    .line 249
    if-gez v3, :cond_6

    .line 250
    .line 251
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v3

    .line 255
    check-cast v3, Ljava/lang/Number;

    .line 256
    .line 257
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 258
    .line 259
    .line 260
    move-result v3

    .line 261
    sub-float/2addr v3, v8

    .line 262
    :goto_4
    move-wide v4, v12

    .line 263
    goto :goto_5

    .line 264
    :cond_6
    move v3, v10

    .line 265
    goto :goto_4

    .line 266
    :goto_5
    invoke-static/range {v1 .. v7}, Lh2/n7;->f(Lg3/d;FFJFI)V

    .line 267
    .line 268
    .line 269
    move-wide v12, v4

    .line 270
    :cond_7
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v2

    .line 274
    check-cast v2, Ljava/lang/Number;

    .line 275
    .line 276
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 277
    .line 278
    .line 279
    move-result v2

    .line 280
    iget-object v14, v0, Lh2/g7;->k:Ll2/t2;

    .line 281
    .line 282
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    check-cast v0, Ljava/lang/Number;

    .line 287
    .line 288
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 289
    .line 290
    .line 291
    move-result v0

    .line 292
    sub-float/2addr v2, v0

    .line 293
    cmpl-float v0, v2, v11

    .line 294
    .line 295
    if-lez v0, :cond_8

    .line 296
    .line 297
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v0

    .line 301
    check-cast v0, Ljava/lang/Number;

    .line 302
    .line 303
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 304
    .line 305
    .line 306
    move-result v0

    .line 307
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v2

    .line 311
    check-cast v2, Ljava/lang/Number;

    .line 312
    .line 313
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 314
    .line 315
    .line 316
    move-result v2

    .line 317
    move-object v3, v1

    .line 318
    move v1, v0

    .line 319
    move-object v0, v3

    .line 320
    move v5, v6

    .line 321
    move v6, v7

    .line 322
    move-wide v3, v15

    .line 323
    invoke-static/range {v0 .. v6}, Lh2/n7;->f(Lg3/d;FFJFI)V

    .line 324
    .line 325
    .line 326
    move-object v1, v0

    .line 327
    move v6, v5

    .line 328
    :cond_8
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    check-cast v0, Ljava/lang/Number;

    .line 333
    .line 334
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 335
    .line 336
    .line 337
    move-result v0

    .line 338
    cmpl-float v0, v0, v8

    .line 339
    .line 340
    if-lez v0, :cond_a

    .line 341
    .line 342
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    check-cast v0, Ljava/lang/Number;

    .line 347
    .line 348
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 349
    .line 350
    .line 351
    move-result v0

    .line 352
    cmpg-float v0, v0, v10

    .line 353
    .line 354
    if-gez v0, :cond_9

    .line 355
    .line 356
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    check-cast v0, Ljava/lang/Number;

    .line 361
    .line 362
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 363
    .line 364
    .line 365
    move-result v0

    .line 366
    sub-float v10, v0, v8

    .line 367
    .line 368
    :cond_9
    move-object v0, v1

    .line 369
    move v2, v10

    .line 370
    const/4 v1, 0x0

    .line 371
    move v5, v6

    .line 372
    move v6, v7

    .line 373
    move-wide v3, v12

    .line 374
    invoke-static/range {v0 .. v6}, Lh2/n7;->f(Lg3/d;FFJFI)V

    .line 375
    .line 376
    .line 377
    :cond_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 378
    .line 379
    return-object v0
.end method
