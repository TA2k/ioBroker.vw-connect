.class public final synthetic Lxf0/x2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:J

.field public final synthetic h:Ljava/lang/Float;

.field public final synthetic i:J

.field public final synthetic j:I

.field public final synthetic k:Ljava/util/ArrayList;


# direct methods
.method public synthetic constructor <init>(JIIJLjava/lang/Float;JILjava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lxf0/x2;->d:J

    .line 5
    .line 6
    iput p3, p0, Lxf0/x2;->e:I

    .line 7
    .line 8
    iput p4, p0, Lxf0/x2;->f:I

    .line 9
    .line 10
    iput-wide p5, p0, Lxf0/x2;->g:J

    .line 11
    .line 12
    iput-object p7, p0, Lxf0/x2;->h:Ljava/lang/Float;

    .line 13
    .line 14
    iput-wide p8, p0, Lxf0/x2;->i:J

    .line 15
    .line 16
    iput p10, p0, Lxf0/x2;->j:I

    .line 17
    .line 18
    iput-object p11, p0, Lxf0/x2;->k:Ljava/util/ArrayList;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

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
    const-string v2, "$this$Canvas"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const/4 v8, 0x2

    .line 13
    int-to-float v9, v8

    .line 14
    invoke-interface {v1, v9}, Lt4/c;->w0(F)F

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    invoke-interface {v1, v9}, Lt4/c;->w0(F)F

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    int-to-long v4, v2

    .line 27
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    int-to-long v2, v2

    .line 32
    const/16 v12, 0x20

    .line 33
    .line 34
    shl-long/2addr v4, v12

    .line 35
    const-wide v13, 0xffffffffL

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    and-long/2addr v2, v13

    .line 41
    or-long v16, v4, v2

    .line 42
    .line 43
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    new-instance v15, Ld3/c;

    .line 48
    .line 49
    invoke-interface {v1}, Lg3/d;->e()J

    .line 50
    .line 51
    .line 52
    move-result-wide v3

    .line 53
    and-long/2addr v3, v13

    .line 54
    long-to-int v3, v3

    .line 55
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    iget v4, v0, Lxf0/x2;->j:I

    .line 60
    .line 61
    int-to-float v10, v4

    .line 62
    iget v11, v0, Lxf0/x2;->e:I

    .line 63
    .line 64
    iget-object v4, v0, Lxf0/x2;->k:Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-static {v11, v4}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    check-cast v4, Ljava/lang/Float;

    .line 71
    .line 72
    const/4 v5, 0x0

    .line 73
    if-eqz v4, :cond_0

    .line 74
    .line 75
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    goto :goto_0

    .line 80
    :cond_0
    move v4, v5

    .line 81
    :goto_0
    mul-float/2addr v4, v10

    .line 82
    sub-float/2addr v3, v4

    .line 83
    invoke-interface {v1}, Lg3/d;->e()J

    .line 84
    .line 85
    .line 86
    move-result-wide v6

    .line 87
    shr-long/2addr v6, v12

    .line 88
    long-to-int v4, v6

    .line 89
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    invoke-interface {v1}, Lg3/d;->e()J

    .line 94
    .line 95
    .line 96
    move-result-wide v6

    .line 97
    and-long/2addr v6, v13

    .line 98
    long-to-int v6, v6

    .line 99
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    invoke-direct {v15, v5, v3, v4, v6}, Ld3/c;-><init>(FFFF)V

    .line 104
    .line 105
    .line 106
    const-wide/16 v20, 0x0

    .line 107
    .line 108
    const/16 v22, 0x18

    .line 109
    .line 110
    move-wide/from16 v18, v16

    .line 111
    .line 112
    invoke-static/range {v15 .. v22}, Ljp/df;->b(Ld3/c;JJJI)Ld3/d;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    invoke-static {v2, v3}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 117
    .line 118
    .line 119
    const/4 v6, 0x0

    .line 120
    const/16 v7, 0x3c

    .line 121
    .line 122
    iget-wide v3, v0, Lxf0/x2;->d:J

    .line 123
    .line 124
    move v15, v5

    .line 125
    const/4 v5, 0x0

    .line 126
    invoke-static/range {v1 .. v7}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 127
    .line 128
    .line 129
    iget v2, v0, Lxf0/x2;->f:I

    .line 130
    .line 131
    if-ne v11, v2, :cond_1

    .line 132
    .line 133
    invoke-interface {v1}, Lg3/d;->e()J

    .line 134
    .line 135
    .line 136
    move-result-wide v3

    .line 137
    shr-long/2addr v3, v12

    .line 138
    long-to-int v3, v3

    .line 139
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 140
    .line 141
    .line 142
    move-result v3

    .line 143
    const/high16 v4, 0x40000000    # 2.0f

    .line 144
    .line 145
    div-float/2addr v3, v4

    .line 146
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    int-to-long v5, v3

    .line 151
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 152
    .line 153
    .line 154
    move-result v3

    .line 155
    move/from16 p1, v4

    .line 156
    .line 157
    move-wide/from16 v18, v5

    .line 158
    .line 159
    int-to-long v4, v3

    .line 160
    shl-long v6, v18, v12

    .line 161
    .line 162
    and-long v3, v4, v13

    .line 163
    .line 164
    or-long v4, v6, v3

    .line 165
    .line 166
    invoke-interface {v1}, Lg3/d;->e()J

    .line 167
    .line 168
    .line 169
    move-result-wide v6

    .line 170
    shr-long/2addr v6, v12

    .line 171
    long-to-int v3, v6

    .line 172
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 173
    .line 174
    .line 175
    move-result v3

    .line 176
    div-float v3, v3, p1

    .line 177
    .line 178
    invoke-interface {v1}, Lg3/d;->e()J

    .line 179
    .line 180
    .line 181
    move-result-wide v6

    .line 182
    and-long/2addr v6, v13

    .line 183
    long-to-int v6, v6

    .line 184
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 185
    .line 186
    .line 187
    move-result v6

    .line 188
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 189
    .line 190
    .line 191
    move-result v3

    .line 192
    move/from16 p1, v12

    .line 193
    .line 194
    move-wide/from16 v18, v13

    .line 195
    .line 196
    int-to-long v12, v3

    .line 197
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    int-to-long v6, v3

    .line 202
    shl-long v12, v12, p1

    .line 203
    .line 204
    and-long v6, v6, v18

    .line 205
    .line 206
    or-long/2addr v6, v12

    .line 207
    invoke-interface {v1, v9}, Lt4/c;->w0(F)F

    .line 208
    .line 209
    .line 210
    move-result v3

    .line 211
    invoke-interface {v1, v9}, Lt4/c;->w0(F)F

    .line 212
    .line 213
    .line 214
    move-result v9

    .line 215
    new-array v8, v8, [F

    .line 216
    .line 217
    const/4 v12, 0x0

    .line 218
    aput v3, v8, v12

    .line 219
    .line 220
    const/4 v3, 0x1

    .line 221
    aput v9, v8, v3

    .line 222
    .line 223
    move v3, v10

    .line 224
    new-instance v10, Le3/j;

    .line 225
    .line 226
    new-instance v9, Landroid/graphics/DashPathEffect;

    .line 227
    .line 228
    invoke-direct {v9, v8, v15}, Landroid/graphics/DashPathEffect;-><init>([FF)V

    .line 229
    .line 230
    .line 231
    invoke-direct {v10, v9}, Le3/j;-><init>(Landroid/graphics/DashPathEffect;)V

    .line 232
    .line 233
    .line 234
    move v8, v11

    .line 235
    const/16 v11, 0x1d8

    .line 236
    .line 237
    move v12, v2

    .line 238
    move v9, v3

    .line 239
    iget-wide v2, v0, Lxf0/x2;->g:J

    .line 240
    .line 241
    move v13, v8

    .line 242
    const/4 v8, 0x0

    .line 243
    move v14, v9

    .line 244
    const/4 v9, 0x0

    .line 245
    invoke-static/range {v1 .. v11}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 246
    .line 247
    .line 248
    goto :goto_1

    .line 249
    :cond_1
    move/from16 p1, v12

    .line 250
    .line 251
    move-wide/from16 v18, v13

    .line 252
    .line 253
    move v12, v2

    .line 254
    move v14, v10

    .line 255
    move v13, v11

    .line 256
    :goto_1
    if-ne v13, v12, :cond_2

    .line 257
    .line 258
    iget-object v2, v0, Lxf0/x2;->h:Ljava/lang/Float;

    .line 259
    .line 260
    if-eqz v2, :cond_2

    .line 261
    .line 262
    move-object v3, v1

    .line 263
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 264
    .line 265
    .line 266
    move-result-object v1

    .line 267
    new-instance v4, Ld3/c;

    .line 268
    .line 269
    invoke-interface {v3}, Lg3/d;->e()J

    .line 270
    .line 271
    .line 272
    move-result-wide v5

    .line 273
    and-long v5, v5, v18

    .line 274
    .line 275
    long-to-int v5, v5

    .line 276
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 277
    .line 278
    .line 279
    move-result v5

    .line 280
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 281
    .line 282
    .line 283
    move-result v2

    .line 284
    mul-float/2addr v2, v14

    .line 285
    sub-float/2addr v5, v2

    .line 286
    invoke-interface {v3}, Lg3/d;->e()J

    .line 287
    .line 288
    .line 289
    move-result-wide v6

    .line 290
    shr-long v6, v6, p1

    .line 291
    .line 292
    long-to-int v2, v6

    .line 293
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 294
    .line 295
    .line 296
    move-result v2

    .line 297
    invoke-interface {v3}, Lg3/d;->e()J

    .line 298
    .line 299
    .line 300
    move-result-wide v6

    .line 301
    and-long v6, v6, v18

    .line 302
    .line 303
    long-to-int v6, v6

    .line 304
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 305
    .line 306
    .line 307
    move-result v6

    .line 308
    invoke-direct {v4, v15, v5, v2, v6}, Ld3/c;-><init>(FFFF)V

    .line 309
    .line 310
    .line 311
    const-wide/16 v20, 0x0

    .line 312
    .line 313
    const/16 v22, 0x18

    .line 314
    .line 315
    move-wide/from16 v18, v16

    .line 316
    .line 317
    move-object v15, v4

    .line 318
    invoke-static/range {v15 .. v22}, Ljp/df;->b(Ld3/c;JJJI)Ld3/d;

    .line 319
    .line 320
    .line 321
    move-result-object v2

    .line 322
    invoke-static {v1, v2}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 323
    .line 324
    .line 325
    const/4 v5, 0x0

    .line 326
    const/16 v6, 0x3c

    .line 327
    .line 328
    iget-wide v7, v0, Lxf0/x2;->i:J

    .line 329
    .line 330
    const/4 v4, 0x0

    .line 331
    move-object v0, v3

    .line 332
    move-wide v2, v7

    .line 333
    invoke-static/range {v0 .. v6}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 334
    .line 335
    .line 336
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 337
    .line 338
    return-object v0
.end method
