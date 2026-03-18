.class public final synthetic Lr61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:F


# direct methods
.method public synthetic constructor <init>(FF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lr61/a;->d:F

    .line 5
    .line 6
    iput p2, p0, Lr61/a;->e:F

    .line 7
    .line 8
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
    iget v11, v0, Lr61/a;->d:F

    .line 13
    .line 14
    invoke-interface {v1, v11}, Lt4/c;->w0(F)F

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/16 v3, 0x1f

    .line 19
    .line 20
    int-to-float v3, v3

    .line 21
    div-float/2addr v2, v3

    .line 22
    const/4 v4, 0x6

    .line 23
    int-to-float v4, v4

    .line 24
    mul-float v12, v2, v4

    .line 25
    .line 26
    invoke-interface {v1, v11}, Lt4/c;->w0(F)F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    div-float/2addr v2, v3

    .line 31
    mul-float/2addr v2, v4

    .line 32
    invoke-interface {v1, v12}, Lt4/c;->o0(F)F

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    sub-float v13, v11, v3

    .line 37
    .line 38
    invoke-interface {v1, v2}, Lt4/c;->o0(F)F

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    sub-float v3, v13, v3

    .line 43
    .line 44
    sget-wide v4, Ln61/a;->h:J

    .line 45
    .line 46
    invoke-interface {v1, v3}, Lt4/c;->w0(F)F

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    const/4 v14, 0x0

    .line 51
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 52
    .line 53
    .line 54
    move-result v6

    .line 55
    int-to-long v6, v6

    .line 56
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    int-to-long v8, v3

    .line 61
    const/16 v15, 0x20

    .line 62
    .line 63
    shl-long/2addr v6, v15

    .line 64
    const-wide v16, 0xffffffffL

    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    and-long v8, v8, v16

    .line 70
    .line 71
    or-long/2addr v6, v8

    .line 72
    iget v0, v0, Lr61/a;->e:F

    .line 73
    .line 74
    invoke-interface {v1, v0}, Lt4/c;->w0(F)F

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    int-to-long v8, v3

    .line 83
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    int-to-long v2, v2

    .line 88
    shl-long/2addr v8, v15

    .line 89
    and-long v2, v2, v16

    .line 90
    .line 91
    or-long/2addr v2, v8

    .line 92
    const/4 v9, 0x0

    .line 93
    const/16 v10, 0x78

    .line 94
    .line 95
    move v8, v0

    .line 96
    move-object v0, v1

    .line 97
    move-wide/from16 v19, v4

    .line 98
    .line 99
    move-wide/from16 v21, v6

    .line 100
    .line 101
    move-wide v5, v2

    .line 102
    move-wide/from16 v1, v19

    .line 103
    .line 104
    move-wide/from16 v3, v21

    .line 105
    .line 106
    const/4 v7, 0x0

    .line 107
    move/from16 v18, v8

    .line 108
    .line 109
    const/4 v8, 0x0

    .line 110
    move/from16 p1, v14

    .line 111
    .line 112
    move/from16 v14, v18

    .line 113
    .line 114
    invoke-static/range {v0 .. v10}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 115
    .line 116
    .line 117
    sget-wide v1, Ln61/a;->g:J

    .line 118
    .line 119
    invoke-interface {v0, v13}, Lt4/c;->w0(F)F

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    invoke-static/range {p1 .. p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 124
    .line 125
    .line 126
    move-result v4

    .line 127
    int-to-long v4, v4

    .line 128
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    int-to-long v6, v3

    .line 133
    shl-long v3, v4, v15

    .line 134
    .line 135
    and-long v5, v6, v16

    .line 136
    .line 137
    or-long/2addr v3, v5

    .line 138
    invoke-interface {v0, v14}, Lt4/c;->w0(F)F

    .line 139
    .line 140
    .line 141
    move-result v5

    .line 142
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    int-to-long v5, v5

    .line 147
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 148
    .line 149
    .line 150
    move-result v7

    .line 151
    int-to-long v7, v7

    .line 152
    shl-long/2addr v5, v15

    .line 153
    and-long v7, v7, v16

    .line 154
    .line 155
    or-long/2addr v5, v7

    .line 156
    const/4 v7, 0x0

    .line 157
    const/4 v8, 0x0

    .line 158
    invoke-static/range {v0 .. v10}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 159
    .line 160
    .line 161
    new-instance v1, Lin/t1;

    .line 162
    .line 163
    invoke-interface {v0, v14}, Lt4/c;->w0(F)F

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    invoke-interface {v0, v11}, Lt4/c;->w0(F)F

    .line 168
    .line 169
    .line 170
    move-result v3

    .line 171
    invoke-direct {v1, v2, v3}, Lin/t1;-><init>(FF)V

    .line 172
    .line 173
    .line 174
    iget-object v1, v1, Lin/t1;->c:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v1, Ljava/util/ArrayList;

    .line 177
    .line 178
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 179
    .line 180
    .line 181
    move-result-object v11

    .line 182
    :goto_0
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 183
    .line 184
    .line 185
    move-result v1

    .line 186
    if-eqz v1, :cond_0

    .line 187
    .line 188
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    move-object v12, v1

    .line 193
    check-cast v12, Lu71/b;

    .line 194
    .line 195
    sget-wide v1, Ln61/a;->g:J

    .line 196
    .line 197
    new-instance v3, Lg3/h;

    .line 198
    .line 199
    const/4 v8, 0x0

    .line 200
    const/16 v9, 0x1e

    .line 201
    .line 202
    const/high16 v4, 0x3f800000    # 1.0f

    .line 203
    .line 204
    const/4 v5, 0x0

    .line 205
    const/4 v6, 0x0

    .line 206
    const/4 v7, 0x0

    .line 207
    invoke-direct/range {v3 .. v9}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 208
    .line 209
    .line 210
    iget-object v4, v12, Lu71/b;->c:Lu71/a;

    .line 211
    .line 212
    iget v13, v12, Lu71/b;->e:F

    .line 213
    .line 214
    iget v14, v12, Lu71/b;->d:F

    .line 215
    .line 216
    iget v5, v4, Lu71/a;->a:F

    .line 217
    .line 218
    iget v4, v4, Lu71/a;->b:F

    .line 219
    .line 220
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    int-to-long v5, v5

    .line 225
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 226
    .line 227
    .line 228
    move-result v4

    .line 229
    int-to-long v7, v4

    .line 230
    shl-long v4, v5, v15

    .line 231
    .line 232
    and-long v6, v7, v16

    .line 233
    .line 234
    or-long/2addr v4, v6

    .line 235
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 236
    .line 237
    .line 238
    move-result v6

    .line 239
    int-to-long v6, v6

    .line 240
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 241
    .line 242
    .line 243
    move-result v8

    .line 244
    int-to-long v8, v8

    .line 245
    shl-long/2addr v6, v15

    .line 246
    and-long v8, v8, v16

    .line 247
    .line 248
    or-long/2addr v6, v8

    .line 249
    const/4 v9, 0x0

    .line 250
    const/16 v10, 0x68

    .line 251
    .line 252
    move-object v8, v3

    .line 253
    move-wide v3, v4

    .line 254
    move-wide v5, v6

    .line 255
    const/4 v7, 0x0

    .line 256
    invoke-static/range {v0 .. v10}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 257
    .line 258
    .line 259
    invoke-interface {v0}, Lg3/d;->x0()Lgw0/c;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 264
    .line 265
    .line 266
    move-result-object v1

    .line 267
    invoke-static {v1}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 268
    .line 269
    .line 270
    move-result-object v1

    .line 271
    iget v2, v12, Lu71/b;->a:I

    .line 272
    .line 273
    iget v3, v12, Lu71/b;->b:I

    .line 274
    .line 275
    const-string v4, ","

    .line 276
    .line 277
    const-string v5, ")"

    .line 278
    .line 279
    const-string v6, "("

    .line 280
    .line 281
    invoke-static {v2, v3, v6, v4, v5}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v2

    .line 285
    iget-object v3, v12, Lu71/b;->c:Lu71/a;

    .line 286
    .line 287
    iget v4, v3, Lu71/a;->a:F

    .line 288
    .line 289
    const/4 v5, 0x2

    .line 290
    int-to-float v5, v5

    .line 291
    div-float/2addr v14, v5

    .line 292
    add-float/2addr v14, v4

    .line 293
    iget v3, v3, Lu71/a;->b:F

    .line 294
    .line 295
    div-float/2addr v13, v5

    .line 296
    add-float/2addr v13, v3

    .line 297
    new-instance v3, Landroid/graphics/Paint;

    .line 298
    .line 299
    invoke-direct {v3}, Landroid/graphics/Paint;-><init>()V

    .line 300
    .line 301
    .line 302
    sget-object v4, Landroid/graphics/Paint$Align;->CENTER:Landroid/graphics/Paint$Align;

    .line 303
    .line 304
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setTextAlign(Landroid/graphics/Paint$Align;)V

    .line 305
    .line 306
    .line 307
    const/high16 v4, 0x42000000    # 32.0f

    .line 308
    .line 309
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 310
    .line 311
    .line 312
    sget-wide v4, Ln61/a;->f:J

    .line 313
    .line 314
    invoke-static {v4, v5}, Le3/j0;->z(J)I

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setColor(I)V

    .line 319
    .line 320
    .line 321
    invoke-virtual {v1, v2, v14, v13, v3}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V

    .line 322
    .line 323
    .line 324
    goto/16 :goto_0

    .line 325
    .line 326
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 327
    .line 328
    return-object v0
.end method
