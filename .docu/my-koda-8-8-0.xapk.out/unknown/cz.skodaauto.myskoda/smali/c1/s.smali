.class public final Lc1/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/w;


# instance fields
.field public final d:F

.field public final e:F

.field public final f:F

.field public final g:F

.field public final h:F

.field public final i:F


# direct methods
.method public constructor <init>(FFFF)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p3

    .line 8
    .line 9
    move/from16 v4, p4

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput v1, v0, Lc1/s;->d:F

    .line 15
    .line 16
    iput v2, v0, Lc1/s;->e:F

    .line 17
    .line 18
    iput v3, v0, Lc1/s;->f:F

    .line 19
    .line 20
    iput v4, v0, Lc1/s;->g:F

    .line 21
    .line 22
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    const/4 v6, 0x0

    .line 27
    const/4 v7, 0x1

    .line 28
    if-nez v5, :cond_0

    .line 29
    .line 30
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-nez v5, :cond_0

    .line 35
    .line 36
    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-nez v5, :cond_0

    .line 41
    .line 42
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-nez v5, :cond_0

    .line 47
    .line 48
    move v5, v7

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    move v5, v6

    .line 51
    :goto_0
    if-nez v5, :cond_1

    .line 52
    .line 53
    new-instance v5, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    const-string v8, "Parameters to CubicBezierEasing cannot be NaN. Actual parameters are: "

    .line 56
    .line 57
    invoke-direct {v5, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", "

    .line 64
    .line 65
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const/16 v1, 0x2e

    .line 84
    .line 85
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    invoke-static {v1}, Lc1/s0;->a(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    :cond_1
    const/4 v1, 0x5

    .line 96
    new-array v1, v1, [F

    .line 97
    .line 98
    const/4 v3, 0x0

    .line 99
    sub-float v5, v2, v3

    .line 100
    .line 101
    const/high16 v8, 0x40400000    # 3.0f

    .line 102
    .line 103
    mul-float/2addr v5, v8

    .line 104
    sub-float v9, v4, v2

    .line 105
    .line 106
    mul-float/2addr v9, v8

    .line 107
    const/high16 v10, 0x3f800000    # 1.0f

    .line 108
    .line 109
    sub-float v11, v10, v4

    .line 110
    .line 111
    mul-float/2addr v11, v8

    .line 112
    float-to-double v12, v5

    .line 113
    float-to-double v14, v9

    .line 114
    move/from16 p1, v8

    .line 115
    .line 116
    move/from16 p3, v9

    .line 117
    .line 118
    float-to-double v8, v11

    .line 119
    const-wide/high16 v16, 0x4000000000000000L    # 2.0

    .line 120
    .line 121
    mul-double v18, v14, v16

    .line 122
    .line 123
    sub-double v20, v12, v18

    .line 124
    .line 125
    add-double v20, v20, v8

    .line 126
    .line 127
    const-wide/16 v22, 0x0

    .line 128
    .line 129
    cmpg-double v22, v20, v22

    .line 130
    .line 131
    if-nez v22, :cond_3

    .line 132
    .line 133
    cmpg-double v7, v14, v8

    .line 134
    .line 135
    if-nez v7, :cond_2

    .line 136
    .line 137
    move v7, v6

    .line 138
    goto :goto_1

    .line 139
    :cond_2
    sub-double v12, v18, v8

    .line 140
    .line 141
    mul-double v8, v8, v16

    .line 142
    .line 143
    sub-double v18, v18, v8

    .line 144
    .line 145
    div-double v12, v12, v18

    .line 146
    .line 147
    double-to-float v7, v12

    .line 148
    invoke-static {v7, v1, v6}, Le3/j0;->E(F[FI)I

    .line 149
    .line 150
    .line 151
    move-result v7

    .line 152
    goto :goto_1

    .line 153
    :cond_3
    mul-double v16, v14, v14

    .line 154
    .line 155
    mul-double/2addr v8, v12

    .line 156
    sub-double v16, v16, v8

    .line 157
    .line 158
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->sqrt(D)D

    .line 159
    .line 160
    .line 161
    move-result-wide v8

    .line 162
    neg-double v8, v8

    .line 163
    neg-double v12, v12

    .line 164
    add-double/2addr v12, v14

    .line 165
    add-double v14, v8, v12

    .line 166
    .line 167
    neg-double v14, v14

    .line 168
    div-double v14, v14, v20

    .line 169
    .line 170
    double-to-float v14, v14

    .line 171
    invoke-static {v14, v1, v6}, Le3/j0;->E(F[FI)I

    .line 172
    .line 173
    .line 174
    move-result v14

    .line 175
    sub-double/2addr v8, v12

    .line 176
    div-double v8, v8, v20

    .line 177
    .line 178
    double-to-float v8, v8

    .line 179
    invoke-static {v8, v1, v14}, Le3/j0;->E(F[FI)I

    .line 180
    .line 181
    .line 182
    move-result v8

    .line 183
    add-int/2addr v8, v14

    .line 184
    if-le v8, v7, :cond_4

    .line 185
    .line 186
    aget v9, v1, v6

    .line 187
    .line 188
    aget v12, v1, v7

    .line 189
    .line 190
    cmpl-float v13, v9, v12

    .line 191
    .line 192
    if-lez v13, :cond_5

    .line 193
    .line 194
    aput v12, v1, v6

    .line 195
    .line 196
    aput v9, v1, v7

    .line 197
    .line 198
    :cond_4
    move v7, v8

    .line 199
    goto :goto_1

    .line 200
    :cond_5
    cmpg-float v7, v9, v12

    .line 201
    .line 202
    if-nez v7, :cond_4

    .line 203
    .line 204
    add-int/lit8 v7, v8, -0x1

    .line 205
    .line 206
    :goto_1
    sub-float v9, p3, v5

    .line 207
    .line 208
    const/high16 v8, 0x40000000    # 2.0f

    .line 209
    .line 210
    mul-float/2addr v9, v8

    .line 211
    sub-float v11, v11, p3

    .line 212
    .line 213
    mul-float/2addr v11, v8

    .line 214
    neg-float v12, v9

    .line 215
    sub-float/2addr v11, v9

    .line 216
    div-float/2addr v12, v11

    .line 217
    invoke-static {v12, v1, v7}, Le3/j0;->E(F[FI)I

    .line 218
    .line 219
    .line 220
    move-result v9

    .line 221
    add-int/2addr v9, v7

    .line 222
    invoke-static {v3, v10}, Ljava/lang/Math;->min(FF)F

    .line 223
    .line 224
    .line 225
    move-result v7

    .line 226
    invoke-static {v3, v10}, Ljava/lang/Math;->max(FF)F

    .line 227
    .line 228
    .line 229
    move-result v11

    .line 230
    :goto_2
    if-ge v6, v9, :cond_6

    .line 231
    .line 232
    aget v12, v1, v6

    .line 233
    .line 234
    sub-float v13, v2, v4

    .line 235
    .line 236
    mul-float v13, v13, p1

    .line 237
    .line 238
    add-float/2addr v13, v10

    .line 239
    sub-float/2addr v13, v3

    .line 240
    mul-float v14, v2, v8

    .line 241
    .line 242
    sub-float v14, v4, v14

    .line 243
    .line 244
    add-float/2addr v14, v3

    .line 245
    mul-float v14, v14, p1

    .line 246
    .line 247
    mul-float/2addr v13, v12

    .line 248
    add-float/2addr v13, v14

    .line 249
    mul-float/2addr v13, v12

    .line 250
    add-float/2addr v13, v5

    .line 251
    mul-float/2addr v13, v12

    .line 252
    add-float/2addr v13, v3

    .line 253
    invoke-static {v7, v13}, Ljava/lang/Math;->min(FF)F

    .line 254
    .line 255
    .line 256
    move-result v7

    .line 257
    invoke-static {v11, v13}, Ljava/lang/Math;->max(FF)F

    .line 258
    .line 259
    .line 260
    move-result v11

    .line 261
    add-int/lit8 v6, v6, 0x1

    .line 262
    .line 263
    goto :goto_2

    .line 264
    :cond_6
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 265
    .line 266
    .line 267
    move-result v1

    .line 268
    int-to-long v1, v1

    .line 269
    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 270
    .line 271
    .line 272
    move-result v3

    .line 273
    int-to-long v3, v3

    .line 274
    const/16 v5, 0x20

    .line 275
    .line 276
    shl-long/2addr v1, v5

    .line 277
    const-wide v6, 0xffffffffL

    .line 278
    .line 279
    .line 280
    .line 281
    .line 282
    and-long/2addr v3, v6

    .line 283
    or-long/2addr v1, v3

    .line 284
    shr-long v3, v1, v5

    .line 285
    .line 286
    long-to-int v3, v3

    .line 287
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 288
    .line 289
    .line 290
    move-result v3

    .line 291
    iput v3, v0, Lc1/s;->h:F

    .line 292
    .line 293
    and-long/2addr v1, v6

    .line 294
    long-to-int v1, v1

    .line 295
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 296
    .line 297
    .line 298
    move-result v1

    .line 299
    iput v1, v0, Lc1/s;->i:F

    .line 300
    .line 301
    return-void
.end method


# virtual methods
.method public final b(F)F
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    cmpl-float v3, v1, v2

    .line 7
    .line 8
    if-lez v3, :cond_25

    .line 9
    .line 10
    const/high16 v3, 0x3f800000    # 1.0f

    .line 11
    .line 12
    cmpg-float v4, v1, v3

    .line 13
    .line 14
    if-gez v4, :cond_25

    .line 15
    .line 16
    const/high16 v4, 0x34000000

    .line 17
    .line 18
    invoke-static {v1, v4}, Ljava/lang/Math;->max(FF)F

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    sub-float v5, v2, v4

    .line 23
    .line 24
    iget v6, v0, Lc1/s;->d:F

    .line 25
    .line 26
    sub-float v7, v6, v4

    .line 27
    .line 28
    iget v8, v0, Lc1/s;->f:F

    .line 29
    .line 30
    sub-float v9, v8, v4

    .line 31
    .line 32
    sub-float v4, v3, v4

    .line 33
    .line 34
    float-to-double v10, v5

    .line 35
    float-to-double v12, v7

    .line 36
    const-wide/high16 v14, 0x4000000000000000L    # 2.0

    .line 37
    .line 38
    mul-double/2addr v12, v14

    .line 39
    sub-double v12, v10, v12

    .line 40
    .line 41
    move/from16 v16, v2

    .line 42
    .line 43
    move/from16 v17, v3

    .line 44
    .line 45
    float-to-double v2, v9

    .line 46
    add-double/2addr v12, v2

    .line 47
    const-wide/high16 v2, 0x4008000000000000L    # 3.0

    .line 48
    .line 49
    mul-double/2addr v12, v2

    .line 50
    move-wide/from16 v18, v2

    .line 51
    .line 52
    sub-float v2, v7, v5

    .line 53
    .line 54
    float-to-double v2, v2

    .line 55
    mul-double v2, v2, v18

    .line 56
    .line 57
    neg-float v5, v5

    .line 58
    move-wide/from16 v20, v14

    .line 59
    .line 60
    float-to-double v14, v5

    .line 61
    sub-float/2addr v7, v9

    .line 62
    move-wide/from16 v22, v12

    .line 63
    .line 64
    float-to-double v12, v7

    .line 65
    mul-double v12, v12, v18

    .line 66
    .line 67
    add-double/2addr v12, v14

    .line 68
    float-to-double v4, v4

    .line 69
    add-double/2addr v12, v4

    .line 70
    const-wide/16 v4, 0x0

    .line 71
    .line 72
    sub-double v14, v12, v4

    .line 73
    .line 74
    invoke-static {v14, v15}, Ljava/lang/Math;->abs(D)D

    .line 75
    .line 76
    .line 77
    move-result-wide v14

    .line 78
    const-wide v24, 0x3e7ad7f29abcaf48L    # 1.0E-7

    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    cmpg-double v7, v14, v24

    .line 84
    .line 85
    const/high16 v9, 0x40000000    # 2.0f

    .line 86
    .line 87
    const v14, 0x358cedba    # 1.05E-6f

    .line 88
    .line 89
    .line 90
    const/high16 v15, 0x7fc00000    # Float.NaN

    .line 91
    .line 92
    if-gez v7, :cond_b

    .line 93
    .line 94
    sub-double v12, v22, v4

    .line 95
    .line 96
    invoke-static {v12, v13}, Ljava/lang/Math;->abs(D)D

    .line 97
    .line 98
    .line 99
    move-result-wide v12

    .line 100
    cmpg-double v7, v12, v24

    .line 101
    .line 102
    if-gez v7, :cond_4

    .line 103
    .line 104
    sub-double v4, v2, v4

    .line 105
    .line 106
    invoke-static {v4, v5}, Ljava/lang/Math;->abs(D)D

    .line 107
    .line 108
    .line 109
    move-result-wide v4

    .line 110
    cmpg-double v4, v4, v24

    .line 111
    .line 112
    if-gez v4, :cond_0

    .line 113
    .line 114
    goto/16 :goto_f

    .line 115
    .line 116
    :cond_0
    neg-double v4, v10

    .line 117
    div-double/2addr v4, v2

    .line 118
    double-to-float v2, v4

    .line 119
    cmpg-float v3, v2, v16

    .line 120
    .line 121
    if-gez v3, :cond_1

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_1
    move/from16 v16, v2

    .line 125
    .line 126
    :goto_0
    cmpl-float v3, v16, v17

    .line 127
    .line 128
    if-lez v3, :cond_2

    .line 129
    .line 130
    move/from16 v3, v17

    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_2
    move/from16 v3, v16

    .line 134
    .line 135
    :goto_1
    sub-float v2, v3, v2

    .line 136
    .line 137
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    cmpl-float v2, v2, v14

    .line 142
    .line 143
    if-lez v2, :cond_3

    .line 144
    .line 145
    goto/16 :goto_f

    .line 146
    .line 147
    :cond_3
    move v15, v3

    .line 148
    goto/16 :goto_f

    .line 149
    .line 150
    :cond_4
    mul-double v4, v2, v2

    .line 151
    .line 152
    const-wide/high16 v12, 0x4010000000000000L    # 4.0

    .line 153
    .line 154
    mul-double v12, v12, v22

    .line 155
    .line 156
    mul-double/2addr v12, v10

    .line 157
    sub-double/2addr v4, v12

    .line 158
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 159
    .line 160
    .line 161
    move-result-wide v4

    .line 162
    mul-double v12, v22, v20

    .line 163
    .line 164
    sub-double v10, v4, v2

    .line 165
    .line 166
    div-double/2addr v10, v12

    .line 167
    double-to-float v7, v10

    .line 168
    cmpg-float v10, v7, v16

    .line 169
    .line 170
    if-gez v10, :cond_5

    .line 171
    .line 172
    move/from16 v10, v16

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_5
    move v10, v7

    .line 176
    :goto_2
    cmpl-float v11, v10, v17

    .line 177
    .line 178
    if-lez v11, :cond_6

    .line 179
    .line 180
    move/from16 v10, v17

    .line 181
    .line 182
    :cond_6
    sub-float v7, v10, v7

    .line 183
    .line 184
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 185
    .line 186
    .line 187
    move-result v7

    .line 188
    cmpl-float v7, v7, v14

    .line 189
    .line 190
    if-lez v7, :cond_7

    .line 191
    .line 192
    move v10, v15

    .line 193
    :cond_7
    invoke-static {v10}, Ljava/lang/Float;->isNaN(F)Z

    .line 194
    .line 195
    .line 196
    move-result v7

    .line 197
    if-nez v7, :cond_8

    .line 198
    .line 199
    move v15, v10

    .line 200
    goto/16 :goto_f

    .line 201
    .line 202
    :cond_8
    neg-double v2, v2

    .line 203
    sub-double/2addr v2, v4

    .line 204
    div-double/2addr v2, v12

    .line 205
    double-to-float v2, v2

    .line 206
    cmpg-float v3, v2, v16

    .line 207
    .line 208
    if-gez v3, :cond_9

    .line 209
    .line 210
    goto :goto_3

    .line 211
    :cond_9
    move/from16 v16, v2

    .line 212
    .line 213
    :goto_3
    cmpl-float v3, v16, v17

    .line 214
    .line 215
    if-lez v3, :cond_a

    .line 216
    .line 217
    move/from16 v3, v17

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_a
    move/from16 v3, v16

    .line 221
    .line 222
    :goto_4
    sub-float v2, v3, v2

    .line 223
    .line 224
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 225
    .line 226
    .line 227
    move-result v2

    .line 228
    cmpl-float v2, v2, v14

    .line 229
    .line 230
    if-lez v2, :cond_3

    .line 231
    .line 232
    goto/16 :goto_f

    .line 233
    .line 234
    :cond_b
    div-double v22, v22, v12

    .line 235
    .line 236
    div-double/2addr v2, v12

    .line 237
    div-double/2addr v10, v12

    .line 238
    mul-double v12, v2, v18

    .line 239
    .line 240
    mul-double v24, v22, v22

    .line 241
    .line 242
    sub-double v12, v12, v24

    .line 243
    .line 244
    const-wide/high16 v24, 0x4022000000000000L    # 9.0

    .line 245
    .line 246
    div-double v12, v12, v24

    .line 247
    .line 248
    mul-double v20, v20, v22

    .line 249
    .line 250
    mul-double v20, v20, v22

    .line 251
    .line 252
    mul-double v20, v20, v22

    .line 253
    .line 254
    mul-double v24, v24, v22

    .line 255
    .line 256
    mul-double v24, v24, v2

    .line 257
    .line 258
    sub-double v20, v20, v24

    .line 259
    .line 260
    const-wide/high16 v2, 0x403b000000000000L    # 27.0

    .line 261
    .line 262
    mul-double/2addr v10, v2

    .line 263
    add-double v10, v10, v20

    .line 264
    .line 265
    const-wide/high16 v2, 0x404b000000000000L    # 54.0

    .line 266
    .line 267
    div-double/2addr v10, v2

    .line 268
    mul-double v2, v10, v10

    .line 269
    .line 270
    mul-double v20, v12, v12

    .line 271
    .line 272
    mul-double v12, v12, v20

    .line 273
    .line 274
    add-double/2addr v2, v12

    .line 275
    move-wide/from16 v20, v4

    .line 276
    .line 277
    div-double v4, v22, v18

    .line 278
    .line 279
    cmpg-double v7, v2, v20

    .line 280
    .line 281
    if-gez v7, :cond_18

    .line 282
    .line 283
    neg-double v2, v12

    .line 284
    invoke-static {v2, v3}, Ljava/lang/Math;->sqrt(D)D

    .line 285
    .line 286
    .line 287
    move-result-wide v2

    .line 288
    neg-double v10, v10

    .line 289
    div-double/2addr v10, v2

    .line 290
    const-wide/high16 v12, -0x4010000000000000L    # -1.0

    .line 291
    .line 292
    cmpg-double v7, v10, v12

    .line 293
    .line 294
    if-gez v7, :cond_c

    .line 295
    .line 296
    move-wide v10, v12

    .line 297
    :cond_c
    const-wide/high16 v12, 0x3ff0000000000000L    # 1.0

    .line 298
    .line 299
    cmpl-double v7, v10, v12

    .line 300
    .line 301
    if-lez v7, :cond_d

    .line 302
    .line 303
    move-wide v10, v12

    .line 304
    :cond_d
    invoke-static {v10, v11}, Ljava/lang/Math;->acos(D)D

    .line 305
    .line 306
    .line 307
    move-result-wide v10

    .line 308
    double-to-float v2, v2

    .line 309
    invoke-static {v2}, Llp/wa;->a(F)F

    .line 310
    .line 311
    .line 312
    move-result v2

    .line 313
    mul-float/2addr v2, v9

    .line 314
    float-to-double v2, v2

    .line 315
    div-double v12, v10, v18

    .line 316
    .line 317
    invoke-static {v12, v13}, Ljava/lang/Math;->cos(D)D

    .line 318
    .line 319
    .line 320
    move-result-wide v12

    .line 321
    mul-double/2addr v12, v2

    .line 322
    sub-double/2addr v12, v4

    .line 323
    double-to-float v7, v12

    .line 324
    cmpg-float v12, v7, v16

    .line 325
    .line 326
    if-gez v12, :cond_e

    .line 327
    .line 328
    move/from16 v12, v16

    .line 329
    .line 330
    goto :goto_5

    .line 331
    :cond_e
    move v12, v7

    .line 332
    :goto_5
    cmpl-float v13, v12, v17

    .line 333
    .line 334
    if-lez v13, :cond_f

    .line 335
    .line 336
    move/from16 v12, v17

    .line 337
    .line 338
    :cond_f
    sub-float v7, v12, v7

    .line 339
    .line 340
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 341
    .line 342
    .line 343
    move-result v7

    .line 344
    cmpl-float v7, v7, v14

    .line 345
    .line 346
    if-lez v7, :cond_10

    .line 347
    .line 348
    move v12, v15

    .line 349
    :cond_10
    invoke-static {v12}, Ljava/lang/Float;->isNaN(F)Z

    .line 350
    .line 351
    .line 352
    move-result v7

    .line 353
    if-nez v7, :cond_11

    .line 354
    .line 355
    :goto_6
    move v15, v12

    .line 356
    goto/16 :goto_f

    .line 357
    .line 358
    :cond_11
    const-wide v12, 0x401921fb54442d18L    # 6.283185307179586

    .line 359
    .line 360
    .line 361
    .line 362
    .line 363
    add-double/2addr v12, v10

    .line 364
    div-double v12, v12, v18

    .line 365
    .line 366
    invoke-static {v12, v13}, Ljava/lang/Math;->cos(D)D

    .line 367
    .line 368
    .line 369
    move-result-wide v12

    .line 370
    mul-double/2addr v12, v2

    .line 371
    sub-double/2addr v12, v4

    .line 372
    double-to-float v7, v12

    .line 373
    cmpg-float v12, v7, v16

    .line 374
    .line 375
    if-gez v12, :cond_12

    .line 376
    .line 377
    move/from16 v12, v16

    .line 378
    .line 379
    goto :goto_7

    .line 380
    :cond_12
    move v12, v7

    .line 381
    :goto_7
    cmpl-float v13, v12, v17

    .line 382
    .line 383
    if-lez v13, :cond_13

    .line 384
    .line 385
    move/from16 v12, v17

    .line 386
    .line 387
    :cond_13
    sub-float v7, v12, v7

    .line 388
    .line 389
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 390
    .line 391
    .line 392
    move-result v7

    .line 393
    cmpl-float v7, v7, v14

    .line 394
    .line 395
    if-lez v7, :cond_14

    .line 396
    .line 397
    move v12, v15

    .line 398
    :cond_14
    invoke-static {v12}, Ljava/lang/Float;->isNaN(F)Z

    .line 399
    .line 400
    .line 401
    move-result v7

    .line 402
    if-nez v7, :cond_15

    .line 403
    .line 404
    goto :goto_6

    .line 405
    :cond_15
    const-wide v12, 0x402921fb54442d18L    # 12.566370614359172

    .line 406
    .line 407
    .line 408
    .line 409
    .line 410
    add-double/2addr v10, v12

    .line 411
    div-double v10, v10, v18

    .line 412
    .line 413
    invoke-static {v10, v11}, Ljava/lang/Math;->cos(D)D

    .line 414
    .line 415
    .line 416
    move-result-wide v10

    .line 417
    mul-double/2addr v10, v2

    .line 418
    sub-double/2addr v10, v4

    .line 419
    double-to-float v2, v10

    .line 420
    cmpg-float v3, v2, v16

    .line 421
    .line 422
    if-gez v3, :cond_16

    .line 423
    .line 424
    goto :goto_8

    .line 425
    :cond_16
    move/from16 v16, v2

    .line 426
    .line 427
    :goto_8
    cmpl-float v3, v16, v17

    .line 428
    .line 429
    if-lez v3, :cond_17

    .line 430
    .line 431
    move/from16 v3, v17

    .line 432
    .line 433
    goto :goto_9

    .line 434
    :cond_17
    move/from16 v3, v16

    .line 435
    .line 436
    :goto_9
    sub-float v2, v3, v2

    .line 437
    .line 438
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 439
    .line 440
    .line 441
    move-result v2

    .line 442
    cmpl-float v2, v2, v14

    .line 443
    .line 444
    if-lez v2, :cond_3

    .line 445
    .line 446
    goto/16 :goto_f

    .line 447
    .line 448
    :cond_18
    if-nez v7, :cond_1f

    .line 449
    .line 450
    double-to-float v2, v10

    .line 451
    invoke-static {v2}, Llp/wa;->a(F)F

    .line 452
    .line 453
    .line 454
    move-result v2

    .line 455
    neg-float v2, v2

    .line 456
    mul-float v3, v2, v9

    .line 457
    .line 458
    double-to-float v4, v4

    .line 459
    sub-float/2addr v3, v4

    .line 460
    cmpg-float v5, v3, v16

    .line 461
    .line 462
    if-gez v5, :cond_19

    .line 463
    .line 464
    move/from16 v5, v16

    .line 465
    .line 466
    goto :goto_a

    .line 467
    :cond_19
    move v5, v3

    .line 468
    :goto_a
    cmpl-float v7, v5, v17

    .line 469
    .line 470
    if-lez v7, :cond_1a

    .line 471
    .line 472
    move/from16 v5, v17

    .line 473
    .line 474
    :cond_1a
    sub-float v3, v5, v3

    .line 475
    .line 476
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 477
    .line 478
    .line 479
    move-result v3

    .line 480
    cmpl-float v3, v3, v14

    .line 481
    .line 482
    if-lez v3, :cond_1b

    .line 483
    .line 484
    move v5, v15

    .line 485
    :cond_1b
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 486
    .line 487
    .line 488
    move-result v3

    .line 489
    if-nez v3, :cond_1c

    .line 490
    .line 491
    move v15, v5

    .line 492
    goto :goto_f

    .line 493
    :cond_1c
    neg-float v2, v2

    .line 494
    sub-float/2addr v2, v4

    .line 495
    cmpg-float v3, v2, v16

    .line 496
    .line 497
    if-gez v3, :cond_1d

    .line 498
    .line 499
    goto :goto_b

    .line 500
    :cond_1d
    move/from16 v16, v2

    .line 501
    .line 502
    :goto_b
    cmpl-float v3, v16, v17

    .line 503
    .line 504
    if-lez v3, :cond_1e

    .line 505
    .line 506
    move/from16 v3, v17

    .line 507
    .line 508
    goto :goto_c

    .line 509
    :cond_1e
    move/from16 v3, v16

    .line 510
    .line 511
    :goto_c
    sub-float v2, v3, v2

    .line 512
    .line 513
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 514
    .line 515
    .line 516
    move-result v2

    .line 517
    cmpl-float v2, v2, v14

    .line 518
    .line 519
    if-lez v2, :cond_3

    .line 520
    .line 521
    goto :goto_f

    .line 522
    :cond_1f
    invoke-static {v2, v3}, Ljava/lang/Math;->sqrt(D)D

    .line 523
    .line 524
    .line 525
    move-result-wide v2

    .line 526
    neg-double v12, v10

    .line 527
    add-double/2addr v12, v2

    .line 528
    double-to-float v7, v12

    .line 529
    invoke-static {v7}, Llp/wa;->a(F)F

    .line 530
    .line 531
    .line 532
    move-result v7

    .line 533
    add-double/2addr v10, v2

    .line 534
    double-to-float v2, v10

    .line 535
    invoke-static {v2}, Llp/wa;->a(F)F

    .line 536
    .line 537
    .line 538
    move-result v2

    .line 539
    sub-float/2addr v7, v2

    .line 540
    float-to-double v2, v7

    .line 541
    sub-double/2addr v2, v4

    .line 542
    double-to-float v2, v2

    .line 543
    cmpg-float v3, v2, v16

    .line 544
    .line 545
    if-gez v3, :cond_20

    .line 546
    .line 547
    goto :goto_d

    .line 548
    :cond_20
    move/from16 v16, v2

    .line 549
    .line 550
    :goto_d
    cmpl-float v3, v16, v17

    .line 551
    .line 552
    if-lez v3, :cond_21

    .line 553
    .line 554
    move/from16 v3, v17

    .line 555
    .line 556
    goto :goto_e

    .line 557
    :cond_21
    move/from16 v3, v16

    .line 558
    .line 559
    :goto_e
    sub-float v2, v3, v2

    .line 560
    .line 561
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 562
    .line 563
    .line 564
    move-result v2

    .line 565
    cmpl-float v2, v2, v14

    .line 566
    .line 567
    if-lez v2, :cond_3

    .line 568
    .line 569
    :goto_f
    invoke-static {v15}, Ljava/lang/Float;->isNaN(F)Z

    .line 570
    .line 571
    .line 572
    move-result v2

    .line 573
    iget v3, v0, Lc1/s;->g:F

    .line 574
    .line 575
    iget v4, v0, Lc1/s;->e:F

    .line 576
    .line 577
    if-nez v2, :cond_24

    .line 578
    .line 579
    const v1, 0x3eaaaaab

    .line 580
    .line 581
    .line 582
    sub-float v2, v4, v3

    .line 583
    .line 584
    add-float/2addr v2, v1

    .line 585
    mul-float/2addr v9, v4

    .line 586
    sub-float/2addr v3, v9

    .line 587
    mul-float/2addr v2, v15

    .line 588
    add-float/2addr v2, v3

    .line 589
    mul-float/2addr v2, v15

    .line 590
    add-float/2addr v2, v4

    .line 591
    const/high16 v1, 0x40400000    # 3.0f

    .line 592
    .line 593
    mul-float/2addr v2, v1

    .line 594
    mul-float/2addr v2, v15

    .line 595
    iget v1, v0, Lc1/s;->h:F

    .line 596
    .line 597
    cmpg-float v3, v2, v1

    .line 598
    .line 599
    if-gez v3, :cond_22

    .line 600
    .line 601
    move v2, v1

    .line 602
    :cond_22
    iget v0, v0, Lc1/s;->i:F

    .line 603
    .line 604
    cmpl-float v1, v2, v0

    .line 605
    .line 606
    if-lez v1, :cond_23

    .line 607
    .line 608
    return v0

    .line 609
    :cond_23
    return v2

    .line 610
    :cond_24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 611
    .line 612
    new-instance v2, Ljava/lang/StringBuilder;

    .line 613
    .line 614
    const-string v5, "The cubic curve with parameters ("

    .line 615
    .line 616
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 617
    .line 618
    .line 619
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 620
    .line 621
    .line 622
    const-string v5, ", "

    .line 623
    .line 624
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 625
    .line 626
    .line 627
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 628
    .line 629
    .line 630
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 631
    .line 632
    .line 633
    invoke-virtual {v2, v8}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 634
    .line 635
    .line 636
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 637
    .line 638
    .line 639
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 640
    .line 641
    .line 642
    const-string v3, ") has no solution at "

    .line 643
    .line 644
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 645
    .line 646
    .line 647
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 648
    .line 649
    .line 650
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 651
    .line 652
    .line 653
    move-result-object v1

    .line 654
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 655
    .line 656
    .line 657
    throw v0

    .line 658
    :cond_25
    return v1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lc1/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lc1/s;

    .line 6
    .line 7
    iget v0, p1, Lc1/s;->d:F

    .line 8
    .line 9
    iget v1, p0, Lc1/s;->d:F

    .line 10
    .line 11
    cmpg-float v0, v1, v0

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    iget v0, p0, Lc1/s;->e:F

    .line 16
    .line 17
    iget v1, p1, Lc1/s;->e:F

    .line 18
    .line 19
    cmpg-float v0, v0, v1

    .line 20
    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    iget v0, p0, Lc1/s;->f:F

    .line 24
    .line 25
    iget v1, p1, Lc1/s;->f:F

    .line 26
    .line 27
    cmpg-float v0, v0, v1

    .line 28
    .line 29
    if-nez v0, :cond_0

    .line 30
    .line 31
    iget p0, p0, Lc1/s;->g:F

    .line 32
    .line 33
    iget p1, p1, Lc1/s;->g:F

    .line 34
    .line 35
    cmpg-float p0, p0, p1

    .line 36
    .line 37
    if-nez p0, :cond_0

    .line 38
    .line 39
    const/4 p0, 0x1

    .line 40
    return p0

    .line 41
    :cond_0
    const/4 p0, 0x0

    .line 42
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lc1/s;->d:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget v2, p0, Lc1/s;->e:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lc1/s;->f:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget p0, p0, Lc1/s;->g:F

    .line 23
    .line 24
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "CubicBezierEasing(a="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lc1/s;->d:F

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", b="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lc1/s;->e:F

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", c="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lc1/s;->f:F

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", d="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget p0, p0, Lc1/s;->g:F

    .line 39
    .line 40
    const/16 v1, 0x29

    .line 41
    .line 42
    invoke-static {v0, p0, v1}, La7/g0;->i(Ljava/lang/StringBuilder;FC)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method
