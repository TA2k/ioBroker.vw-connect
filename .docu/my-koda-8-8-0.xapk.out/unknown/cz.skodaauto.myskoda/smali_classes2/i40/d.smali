.class public final Li40/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le3/n0;


# instance fields
.field public final a:F


# direct methods
.method public constructor <init>(F)V
    .locals 1

    .line 1
    sget v0, Li40/o3;->a:F

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput p1, p0, Li40/d;->a:F

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(JLt4/m;Lt4/c;)Le3/g0;
    .locals 16

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    const-string v1, "layoutDirection"

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v1, "density"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sget v2, Li40/o3;->a:F

    .line 20
    .line 21
    invoke-interface {v0, v2}, Lt4/c;->w0(F)F

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    move-object/from16 v3, p0

    .line 26
    .line 27
    iget v3, v3, Li40/d;->a:F

    .line 28
    .line 29
    invoke-interface {v0, v3}, Lt4/c;->w0(F)F

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    const-wide v3, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long v3, p1, v3

    .line 39
    .line 40
    long-to-int v3, v3

    .line 41
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    const/high16 v5, 0x3f000000    # 0.5f

    .line 46
    .line 47
    mul-float/2addr v4, v5

    .line 48
    iget-object v5, v1, Le3/i;->a:Landroid/graphics/Path;

    .line 49
    .line 50
    const/4 v6, 0x0

    .line 51
    invoke-virtual {v1, v2, v6}, Le3/i;->h(FF)V

    .line 52
    .line 53
    .line 54
    const/16 v7, 0x20

    .line 55
    .line 56
    shr-long v7, p1, v7

    .line 57
    .line 58
    long-to-int v7, v7

    .line 59
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    sub-float/2addr v8, v2

    .line 64
    invoke-virtual {v1, v8, v6}, Le3/i;->g(FF)V

    .line 65
    .line 66
    .line 67
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 68
    .line 69
    .line 70
    move-result v8

    .line 71
    const/4 v9, 0x2

    .line 72
    int-to-float v9, v9

    .line 73
    mul-float/2addr v9, v2

    .line 74
    sub-float/2addr v8, v9

    .line 75
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    iget-object v11, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 80
    .line 81
    if-nez v11, :cond_0

    .line 82
    .line 83
    new-instance v11, Landroid/graphics/RectF;

    .line 84
    .line 85
    invoke-direct {v11}, Landroid/graphics/RectF;-><init>()V

    .line 86
    .line 87
    .line 88
    iput-object v11, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 89
    .line 90
    :cond_0
    iget-object v11, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 91
    .line 92
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v11, v8, v6, v10, v9}, Landroid/graphics/RectF;->set(FFFF)V

    .line 96
    .line 97
    .line 98
    iget-object v8, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 99
    .line 100
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    const/high16 v10, -0x3d4c0000    # -90.0f

    .line 104
    .line 105
    const/high16 v11, 0x42b40000    # 90.0f

    .line 106
    .line 107
    const/4 v12, 0x0

    .line 108
    invoke-virtual {v5, v8, v10, v11, v12}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 109
    .line 110
    .line 111
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 112
    .line 113
    .line 114
    move-result v8

    .line 115
    sub-float v13, v4, v0

    .line 116
    .line 117
    invoke-virtual {v1, v8, v13}, Le3/i;->g(FF)V

    .line 118
    .line 119
    .line 120
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 121
    .line 122
    .line 123
    move-result v8

    .line 124
    sub-float/2addr v8, v0

    .line 125
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 126
    .line 127
    .line 128
    move-result v14

    .line 129
    add-float/2addr v14, v0

    .line 130
    add-float/2addr v4, v0

    .line 131
    iget-object v15, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 132
    .line 133
    if-nez v15, :cond_1

    .line 134
    .line 135
    new-instance v15, Landroid/graphics/RectF;

    .line 136
    .line 137
    invoke-direct {v15}, Landroid/graphics/RectF;-><init>()V

    .line 138
    .line 139
    .line 140
    iput-object v15, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 141
    .line 142
    :cond_1
    iget-object v15, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 143
    .line 144
    invoke-static {v15}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v15, v8, v13, v14, v4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 148
    .line 149
    .line 150
    iget-object v8, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 151
    .line 152
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    const/high16 v14, -0x3ccc0000    # -180.0f

    .line 156
    .line 157
    invoke-virtual {v5, v8, v10, v14, v12}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 158
    .line 159
    .line 160
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 165
    .line 166
    .line 167
    move-result v10

    .line 168
    sub-float/2addr v10, v2

    .line 169
    invoke-virtual {v1, v8, v10}, Le3/i;->g(FF)V

    .line 170
    .line 171
    .line 172
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 173
    .line 174
    .line 175
    move-result v8

    .line 176
    sub-float/2addr v8, v9

    .line 177
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 178
    .line 179
    .line 180
    move-result v10

    .line 181
    sub-float/2addr v10, v9

    .line 182
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 183
    .line 184
    .line 185
    move-result v7

    .line 186
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 187
    .line 188
    .line 189
    move-result v15

    .line 190
    iget-object v14, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 191
    .line 192
    if-nez v14, :cond_2

    .line 193
    .line 194
    new-instance v14, Landroid/graphics/RectF;

    .line 195
    .line 196
    invoke-direct {v14}, Landroid/graphics/RectF;-><init>()V

    .line 197
    .line 198
    .line 199
    iput-object v14, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 200
    .line 201
    :cond_2
    iget-object v14, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 202
    .line 203
    invoke-static {v14}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v14, v8, v10, v7, v15}, Landroid/graphics/RectF;->set(FFFF)V

    .line 207
    .line 208
    .line 209
    iget-object v7, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 210
    .line 211
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v5, v7, v6, v11, v12}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 215
    .line 216
    .line 217
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 218
    .line 219
    .line 220
    move-result v7

    .line 221
    invoke-virtual {v1, v2, v7}, Le3/i;->g(FF)V

    .line 222
    .line 223
    .line 224
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 225
    .line 226
    .line 227
    move-result v7

    .line 228
    sub-float/2addr v7, v9

    .line 229
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 230
    .line 231
    .line 232
    move-result v3

    .line 233
    iget-object v8, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 234
    .line 235
    if-nez v8, :cond_3

    .line 236
    .line 237
    new-instance v8, Landroid/graphics/RectF;

    .line 238
    .line 239
    invoke-direct {v8}, Landroid/graphics/RectF;-><init>()V

    .line 240
    .line 241
    .line 242
    iput-object v8, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 243
    .line 244
    :cond_3
    iget-object v8, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 245
    .line 246
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v8, v6, v7, v9, v3}, Landroid/graphics/RectF;->set(FFFF)V

    .line 250
    .line 251
    .line 252
    iget-object v3, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 253
    .line 254
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v5, v3, v11, v11, v12}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v1, v6, v4}, Le3/i;->g(FF)V

    .line 261
    .line 262
    .line 263
    neg-float v3, v0

    .line 264
    iget-object v7, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 265
    .line 266
    if-nez v7, :cond_4

    .line 267
    .line 268
    new-instance v7, Landroid/graphics/RectF;

    .line 269
    .line 270
    invoke-direct {v7}, Landroid/graphics/RectF;-><init>()V

    .line 271
    .line 272
    .line 273
    iput-object v7, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 274
    .line 275
    :cond_4
    iget-object v7, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 276
    .line 277
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v7, v3, v13, v0, v4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 281
    .line 282
    .line 283
    iget-object v0, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 284
    .line 285
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 286
    .line 287
    .line 288
    const/high16 v3, -0x3ccc0000    # -180.0f

    .line 289
    .line 290
    invoke-virtual {v5, v0, v11, v3, v12}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v1, v6, v2}, Le3/i;->g(FF)V

    .line 294
    .line 295
    .line 296
    iget-object v0, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 297
    .line 298
    if-nez v0, :cond_5

    .line 299
    .line 300
    new-instance v0, Landroid/graphics/RectF;

    .line 301
    .line 302
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 303
    .line 304
    .line 305
    iput-object v0, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 306
    .line 307
    :cond_5
    iget-object v0, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 308
    .line 309
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    invoke-virtual {v0, v6, v6, v9, v9}, Landroid/graphics/RectF;->set(FFFF)V

    .line 313
    .line 314
    .line 315
    iget-object v0, v1, Le3/i;->b:Landroid/graphics/RectF;

    .line 316
    .line 317
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 318
    .line 319
    .line 320
    const/high16 v2, 0x43340000    # 180.0f

    .line 321
    .line 322
    invoke-virtual {v5, v0, v2, v11, v12}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v1}, Le3/i;->e()V

    .line 326
    .line 327
    .line 328
    new-instance v0, Le3/d0;

    .line 329
    .line 330
    invoke-direct {v0, v1}, Le3/d0;-><init>(Le3/i;)V

    .line 331
    .line 332
    .line 333
    return-object v0
.end method
