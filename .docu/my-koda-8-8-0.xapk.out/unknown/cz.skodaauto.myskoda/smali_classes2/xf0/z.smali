.class public final Lxf0/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:J

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lvf0/a;JF)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lxf0/z;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxf0/z;->g:Ljava/lang/Object;

    iput-wide p2, p0, Lxf0/z;->f:J

    iput p4, p0, Lxf0/z;->e:F

    return-void
.end method

.method public constructor <init>(Lvf0/j;FJ)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lxf0/z;->d:I

    sget v0, Lxf0/e3;->a:F

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxf0/z;->g:Ljava/lang/Object;

    iput p2, p0, Lxf0/z;->e:F

    iput-wide p3, p0, Lxf0/z;->f:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lxf0/z;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    const-wide v4, 0xffffffffL

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    const/16 v6, 0x20

    .line 14
    .line 15
    const/4 v7, 0x0

    .line 16
    iget v8, v0, Lxf0/z;->e:F

    .line 17
    .line 18
    iget-object v9, v0, Lxf0/z;->g:Ljava/lang/Object;

    .line 19
    .line 20
    packed-switch v1, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    move-object/from16 v10, p1

    .line 24
    .line 25
    check-cast v10, Lg3/d;

    .line 26
    .line 27
    const-string v1, "$this$drawBackground"

    .line 28
    .line 29
    invoke-static {v10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    check-cast v9, Lvf0/j;

    .line 33
    .line 34
    iget-boolean v1, v9, Lvf0/j;->g:Z

    .line 35
    .line 36
    if-eqz v1, :cond_2

    .line 37
    .line 38
    iget-boolean v1, v9, Lvf0/j;->h:Z

    .line 39
    .line 40
    if-nez v1, :cond_2

    .line 41
    .line 42
    iget-object v1, v9, Lvf0/j;->c:Lvf0/m;

    .line 43
    .line 44
    iget-object v1, v1, Lvf0/m;->a:Ljava/lang/Integer;

    .line 45
    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    sget v9, Lxf0/e3;->c:F

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    invoke-interface {v10, v9}, Lt4/c;->w0(F)F

    .line 55
    .line 56
    .line 57
    move-result v12

    .line 58
    const/4 v9, 0x0

    .line 59
    const/16 v11, 0x64

    .line 60
    .line 61
    invoke-static {v1, v9, v11}, Lkp/r9;->e(III)I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-ge v1, v11, :cond_0

    .line 66
    .line 67
    const/high16 v7, 0x40a00000    # 5.0f

    .line 68
    .line 69
    :cond_0
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 70
    .line 71
    .line 72
    move-result v9

    .line 73
    int-to-long v13, v9

    .line 74
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 75
    .line 76
    .line 77
    move-result v8

    .line 78
    int-to-long v8, v8

    .line 79
    shl-long/2addr v13, v6

    .line 80
    and-long/2addr v4, v8

    .line 81
    or-long/2addr v4, v13

    .line 82
    if-ge v1, v3, :cond_1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_1
    move v3, v1

    .line 86
    :goto_0
    int-to-float v1, v3

    .line 87
    const/high16 v3, 0x42c80000    # 100.0f

    .line 88
    .line 89
    div-float/2addr v1, v3

    .line 90
    const/high16 v3, 0x43960000    # 300.0f

    .line 91
    .line 92
    mul-float/2addr v1, v3

    .line 93
    sub-float/2addr v1, v7

    .line 94
    new-instance v20, Lg3/h;

    .line 95
    .line 96
    const/16 v16, 0x0

    .line 97
    .line 98
    const/16 v17, 0x1a

    .line 99
    .line 100
    const/4 v13, 0x0

    .line 101
    const/4 v14, 0x1

    .line 102
    const/4 v15, 0x0

    .line 103
    move-object/from16 v11, v20

    .line 104
    .line 105
    invoke-direct/range {v11 .. v17}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 106
    .line 107
    .line 108
    const/16 v19, 0x0

    .line 109
    .line 110
    const/16 v21, 0x350

    .line 111
    .line 112
    iget-wide v11, v0, Lxf0/z;->f:J

    .line 113
    .line 114
    const/high16 v13, 0x42f00000    # 120.0f

    .line 115
    .line 116
    const-wide/16 v15, 0x0

    .line 117
    .line 118
    move v14, v1

    .line 119
    move-wide/from16 v17, v4

    .line 120
    .line 121
    invoke-static/range {v10 .. v21}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 122
    .line 123
    .line 124
    :cond_2
    return-object v2

    .line 125
    :pswitch_0
    move-object/from16 v1, p1

    .line 126
    .line 127
    check-cast v1, Lg3/d;

    .line 128
    .line 129
    const-string v10, "$this$drawBehind"

    .line 130
    .line 131
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    check-cast v9, Lvf0/a;

    .line 135
    .line 136
    iget-object v10, v9, Lvf0/a;->b:Ljava/util/List;

    .line 137
    .line 138
    invoke-interface {v10}, Ljava/util/List;->size()I

    .line 139
    .line 140
    .line 141
    move-result v10

    .line 142
    sub-int/2addr v10, v3

    .line 143
    iget-object v9, v9, Lvf0/a;->a:Ljava/util/List;

    .line 144
    .line 145
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 146
    .line 147
    .line 148
    move-result v9

    .line 149
    invoke-interface {v1, v8}, Lt4/c;->w0(F)F

    .line 150
    .line 151
    .line 152
    move-result v8

    .line 153
    sget v11, Lxf0/b0;->a:F

    .line 154
    .line 155
    new-instance v30, Lg3/h;

    .line 156
    .line 157
    const/16 v17, 0x0

    .line 158
    .line 159
    const/16 v18, 0x1e

    .line 160
    .line 161
    const/high16 v13, 0x40800000    # 4.0f

    .line 162
    .line 163
    const/4 v14, 0x0

    .line 164
    const/4 v15, 0x0

    .line 165
    const/16 v16, 0x0

    .line 166
    .line 167
    move-object/from16 v12, v30

    .line 168
    .line 169
    invoke-direct/range {v12 .. v18}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 170
    .line 171
    .line 172
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 173
    .line 174
    .line 175
    move-result v11

    .line 176
    int-to-long v11, v11

    .line 177
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 178
    .line 179
    .line 180
    move-result v14

    .line 181
    int-to-long v14, v14

    .line 182
    shl-long/2addr v11, v6

    .line 183
    and-long/2addr v14, v4

    .line 184
    or-long v25, v11, v14

    .line 185
    .line 186
    invoke-interface {v1}, Lg3/d;->e()J

    .line 187
    .line 188
    .line 189
    move-result-wide v11

    .line 190
    shr-long/2addr v11, v6

    .line 191
    long-to-int v11, v11

    .line 192
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 193
    .line 194
    .line 195
    move-result v11

    .line 196
    invoke-interface {v1}, Lg3/d;->e()J

    .line 197
    .line 198
    .line 199
    move-result-wide v14

    .line 200
    and-long/2addr v14, v4

    .line 201
    long-to-int v12, v14

    .line 202
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 203
    .line 204
    .line 205
    move-result v12

    .line 206
    const/4 v14, 0x2

    .line 207
    int-to-float v15, v14

    .line 208
    mul-float/2addr v15, v8

    .line 209
    sub-float/2addr v12, v15

    .line 210
    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 211
    .line 212
    .line 213
    move-result v11

    .line 214
    move-wide/from16 v16, v4

    .line 215
    .line 216
    int-to-long v4, v11

    .line 217
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 218
    .line 219
    .line 220
    move-result v11

    .line 221
    int-to-long v11, v11

    .line 222
    shl-long/2addr v4, v6

    .line 223
    and-long v11, v11, v16

    .line 224
    .line 225
    or-long v27, v4, v11

    .line 226
    .line 227
    const/16 v31, 0x0

    .line 228
    .line 229
    const/16 v32, 0x68

    .line 230
    .line 231
    iget-wide v4, v0, Lxf0/z;->f:J

    .line 232
    .line 233
    const/16 v29, 0x0

    .line 234
    .line 235
    move-object/from16 v22, v1

    .line 236
    .line 237
    move-wide/from16 v23, v4

    .line 238
    .line 239
    invoke-static/range {v22 .. v32}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 240
    .line 241
    .line 242
    if-le v10, v3, :cond_3

    .line 243
    .line 244
    invoke-interface/range {v22 .. v22}, Lg3/d;->e()J

    .line 245
    .line 246
    .line 247
    move-result-wide v0

    .line 248
    and-long v0, v0, v16

    .line 249
    .line 250
    long-to-int v0, v0

    .line 251
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 252
    .line 253
    .line 254
    move-result v0

    .line 255
    sub-float/2addr v0, v15

    .line 256
    int-to-float v1, v10

    .line 257
    div-float/2addr v0, v1

    .line 258
    :goto_1
    if-ge v3, v10, :cond_3

    .line 259
    .line 260
    int-to-float v1, v3

    .line 261
    mul-float/2addr v1, v0

    .line 262
    add-float/2addr v1, v8

    .line 263
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 264
    .line 265
    .line 266
    move-result v4

    .line 267
    int-to-long v4, v4

    .line 268
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 269
    .line 270
    .line 271
    move-result v11

    .line 272
    int-to-long v11, v11

    .line 273
    shl-long/2addr v4, v6

    .line 274
    and-long v11, v11, v16

    .line 275
    .line 276
    or-long v25, v4, v11

    .line 277
    .line 278
    invoke-interface/range {v22 .. v22}, Lg3/d;->e()J

    .line 279
    .line 280
    .line 281
    move-result-wide v4

    .line 282
    shr-long/2addr v4, v6

    .line 283
    long-to-int v4, v4

    .line 284
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 285
    .line 286
    .line 287
    move-result v4

    .line 288
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 289
    .line 290
    .line 291
    move-result v4

    .line 292
    int-to-long v4, v4

    .line 293
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 294
    .line 295
    .line 296
    move-result v1

    .line 297
    int-to-long v11, v1

    .line 298
    shl-long/2addr v4, v6

    .line 299
    and-long v11, v11, v16

    .line 300
    .line 301
    or-long v27, v4, v11

    .line 302
    .line 303
    new-array v1, v14, [F

    .line 304
    .line 305
    fill-array-data v1, :array_0

    .line 306
    .line 307
    .line 308
    new-instance v4, Le3/j;

    .line 309
    .line 310
    new-instance v5, Landroid/graphics/DashPathEffect;

    .line 311
    .line 312
    invoke-direct {v5, v1, v7}, Landroid/graphics/DashPathEffect;-><init>([FF)V

    .line 313
    .line 314
    .line 315
    invoke-direct {v4, v5}, Le3/j;-><init>(Landroid/graphics/DashPathEffect;)V

    .line 316
    .line 317
    .line 318
    const/16 v30, 0x0

    .line 319
    .line 320
    const/16 v32, 0x1d0

    .line 321
    .line 322
    move-object/from16 v31, v4

    .line 323
    .line 324
    move/from16 v29, v13

    .line 325
    .line 326
    invoke-static/range {v22 .. v32}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 327
    .line 328
    .line 329
    move-object/from16 v1, v22

    .line 330
    .line 331
    move-wide/from16 v4, v23

    .line 332
    .line 333
    add-int/lit8 v3, v3, 0x1

    .line 334
    .line 335
    goto :goto_1

    .line 336
    :cond_3
    move-object/from16 v1, v22

    .line 337
    .line 338
    move-wide/from16 v4, v23

    .line 339
    .line 340
    invoke-static {v8, v9, v4, v5, v1}, Lxf0/b0;->c(FIJLg3/d;)V

    .line 341
    .line 342
    .line 343
    return-object v2

    .line 344
    nop

    .line 345
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch

    .line 346
    .line 347
    .line 348
    .line 349
    .line 350
    .line 351
    :array_0
    .array-data 4
        0x41000000    # 8.0f
        0x41000000    # 8.0f
    .end array-data
.end method
