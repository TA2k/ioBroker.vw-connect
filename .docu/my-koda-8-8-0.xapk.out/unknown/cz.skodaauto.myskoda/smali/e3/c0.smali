.class public final Le3/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:[F


# direct methods
.method public synthetic constructor <init>([F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le3/c0;->a:[F

    .line 5
    .line 6
    return-void
.end method

.method public static a()[F
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    new-array v0, v0, [F

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    return-object v0

    .line 9
    :array_0
    .array-data 4
        0x3f800000    # 1.0f
        0x0
        0x0
        0x0
        0x0
        0x3f800000    # 1.0f
        0x0
        0x0
        0x0
        0x0
        0x3f800000    # 1.0f
        0x0
        0x0
        0x0
        0x0
        0x3f800000    # 1.0f
    .end array-data
.end method

.method public static final b(J[F)J
    .locals 13

    .line 1
    array-length v0, p2

    .line 2
    const/16 v1, 0x10

    .line 3
    .line 4
    if-ge v0, v1, :cond_0

    .line 5
    .line 6
    return-wide p0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    aget v0, p2, v0

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    aget v2, p2, v1

    .line 12
    .line 13
    const/4 v3, 0x3

    .line 14
    aget v3, p2, v3

    .line 15
    .line 16
    const/4 v4, 0x4

    .line 17
    aget v4, p2, v4

    .line 18
    .line 19
    const/4 v5, 0x5

    .line 20
    aget v5, p2, v5

    .line 21
    .line 22
    const/4 v6, 0x7

    .line 23
    aget v6, p2, v6

    .line 24
    .line 25
    const/16 v7, 0xc

    .line 26
    .line 27
    aget v7, p2, v7

    .line 28
    .line 29
    const/16 v8, 0xd

    .line 30
    .line 31
    aget v8, p2, v8

    .line 32
    .line 33
    const/16 v9, 0xf

    .line 34
    .line 35
    aget p2, p2, v9

    .line 36
    .line 37
    const/16 v9, 0x20

    .line 38
    .line 39
    shr-long v10, p0, v9

    .line 40
    .line 41
    long-to-int v10, v10

    .line 42
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 43
    .line 44
    .line 45
    move-result v10

    .line 46
    const-wide v11, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    and-long/2addr p0, v11

    .line 52
    long-to-int p0, p0

    .line 53
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    mul-float/2addr v3, v10

    .line 58
    mul-float/2addr v6, p0

    .line 59
    add-float/2addr v6, v3

    .line 60
    add-float/2addr v6, p2

    .line 61
    int-to-float p1, v1

    .line 62
    div-float/2addr p1, v6

    .line 63
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 64
    .line 65
    .line 66
    move-result p2

    .line 67
    const v1, 0x7fffffff

    .line 68
    .line 69
    .line 70
    and-int/2addr p2, v1

    .line 71
    const/high16 v1, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 72
    .line 73
    if-ge p2, v1, :cond_1

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_1
    const/4 p1, 0x0

    .line 77
    :goto_0
    mul-float/2addr v0, v10

    .line 78
    mul-float/2addr v4, p0

    .line 79
    add-float/2addr v4, v0

    .line 80
    add-float/2addr v4, v7

    .line 81
    mul-float/2addr v4, p1

    .line 82
    mul-float/2addr v2, v10

    .line 83
    mul-float/2addr v5, p0

    .line 84
    add-float/2addr v5, v2

    .line 85
    add-float/2addr v5, v8

    .line 86
    mul-float/2addr v5, p1

    .line 87
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    int-to-long p0, p0

    .line 92
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    int-to-long v0, p2

    .line 97
    shl-long/2addr p0, v9

    .line 98
    and-long/2addr v0, v11

    .line 99
    or-long/2addr p0, v0

    .line 100
    return-wide p0
.end method

.method public static final c([FLd3/a;)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    array-length v2, v0

    .line 6
    const/16 v3, 0x10

    .line 7
    .line 8
    if-ge v2, v3, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    const/4 v2, 0x0

    .line 12
    aget v2, v0, v2

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    aget v3, v0, v3

    .line 16
    .line 17
    const/4 v4, 0x3

    .line 18
    aget v4, v0, v4

    .line 19
    .line 20
    const/4 v5, 0x4

    .line 21
    aget v5, v0, v5

    .line 22
    .line 23
    const/4 v6, 0x5

    .line 24
    aget v6, v0, v6

    .line 25
    .line 26
    const/4 v7, 0x7

    .line 27
    aget v7, v0, v7

    .line 28
    .line 29
    const/16 v8, 0xc

    .line 30
    .line 31
    aget v8, v0, v8

    .line 32
    .line 33
    const/16 v9, 0xd

    .line 34
    .line 35
    aget v9, v0, v9

    .line 36
    .line 37
    const/16 v10, 0xf

    .line 38
    .line 39
    aget v0, v0, v10

    .line 40
    .line 41
    iget v10, v1, Ld3/a;->b:F

    .line 42
    .line 43
    iget v11, v1, Ld3/a;->c:F

    .line 44
    .line 45
    iget v12, v1, Ld3/a;->d:F

    .line 46
    .line 47
    iget v13, v1, Ld3/a;->e:F

    .line 48
    .line 49
    mul-float v14, v4, v10

    .line 50
    .line 51
    mul-float v15, v7, v11

    .line 52
    .line 53
    add-float v16, v14, v15

    .line 54
    .line 55
    add-float v16, v16, v0

    .line 56
    .line 57
    const/high16 v17, 0x3f800000    # 1.0f

    .line 58
    .line 59
    div-float v16, v17, v16

    .line 60
    .line 61
    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 62
    .line 63
    .line 64
    move-result v18

    .line 65
    const v19, 0x7fffffff

    .line 66
    .line 67
    .line 68
    move/from16 p0, v0

    .line 69
    .line 70
    and-int v0, v18, v19

    .line 71
    .line 72
    const/16 v18, 0x0

    .line 73
    .line 74
    move/from16 v20, v2

    .line 75
    .line 76
    const/high16 v2, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 77
    .line 78
    if-ge v0, v2, :cond_1

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_1
    move/from16 v16, v18

    .line 82
    .line 83
    :goto_0
    mul-float v0, v20, v10

    .line 84
    .line 85
    mul-float v21, v5, v11

    .line 86
    .line 87
    add-float v22, v0, v21

    .line 88
    .line 89
    add-float v22, v22, v8

    .line 90
    .line 91
    mul-float v2, v22, v16

    .line 92
    .line 93
    mul-float/2addr v10, v3

    .line 94
    mul-float/2addr v11, v6

    .line 95
    add-float v22, v10, v11

    .line 96
    .line 97
    add-float v22, v22, v9

    .line 98
    .line 99
    move/from16 v23, v0

    .line 100
    .line 101
    mul-float v0, v22, v16

    .line 102
    .line 103
    mul-float/2addr v7, v13

    .line 104
    add-float/2addr v14, v7

    .line 105
    add-float v14, v14, p0

    .line 106
    .line 107
    div-float v14, v17, v14

    .line 108
    .line 109
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 110
    .line 111
    .line 112
    move-result v16

    .line 113
    move/from16 v22, v3

    .line 114
    .line 115
    and-int v3, v16, v19

    .line 116
    .line 117
    move/from16 v16, v4

    .line 118
    .line 119
    const/high16 v4, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 120
    .line 121
    if-ge v3, v4, :cond_2

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_2
    move/from16 v14, v18

    .line 125
    .line 126
    :goto_1
    mul-float/2addr v5, v13

    .line 127
    add-float v3, v23, v5

    .line 128
    .line 129
    add-float/2addr v3, v8

    .line 130
    mul-float/2addr v3, v14

    .line 131
    mul-float/2addr v6, v13

    .line 132
    add-float/2addr v10, v6

    .line 133
    add-float/2addr v10, v9

    .line 134
    mul-float/2addr v10, v14

    .line 135
    mul-float v4, v16, v12

    .line 136
    .line 137
    add-float/2addr v15, v4

    .line 138
    add-float v15, v15, p0

    .line 139
    .line 140
    div-float v13, v17, v15

    .line 141
    .line 142
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 143
    .line 144
    .line 145
    move-result v14

    .line 146
    and-int v14, v14, v19

    .line 147
    .line 148
    const/high16 v15, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 149
    .line 150
    if-ge v14, v15, :cond_3

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_3
    move/from16 v13, v18

    .line 154
    .line 155
    :goto_2
    mul-float v14, v20, v12

    .line 156
    .line 157
    add-float v21, v14, v21

    .line 158
    .line 159
    add-float v21, v21, v8

    .line 160
    .line 161
    mul-float v15, v21, v13

    .line 162
    .line 163
    mul-float v12, v12, v22

    .line 164
    .line 165
    add-float/2addr v11, v12

    .line 166
    add-float/2addr v11, v9

    .line 167
    mul-float/2addr v11, v13

    .line 168
    add-float/2addr v4, v7

    .line 169
    add-float v4, v4, p0

    .line 170
    .line 171
    div-float v17, v17, v4

    .line 172
    .line 173
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 174
    .line 175
    .line 176
    move-result v4

    .line 177
    and-int v4, v4, v19

    .line 178
    .line 179
    const/high16 v7, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 180
    .line 181
    if-ge v4, v7, :cond_4

    .line 182
    .line 183
    move/from16 v18, v17

    .line 184
    .line 185
    :cond_4
    add-float/2addr v14, v5

    .line 186
    add-float/2addr v14, v8

    .line 187
    mul-float v14, v14, v18

    .line 188
    .line 189
    add-float/2addr v12, v6

    .line 190
    add-float/2addr v12, v9

    .line 191
    mul-float v12, v12, v18

    .line 192
    .line 193
    invoke-static {v15, v14}, Ljava/lang/Math;->min(FF)F

    .line 194
    .line 195
    .line 196
    move-result v4

    .line 197
    invoke-static {v3, v4}, Ljava/lang/Math;->min(FF)F

    .line 198
    .line 199
    .line 200
    move-result v4

    .line 201
    invoke-static {v2, v4}, Ljava/lang/Math;->min(FF)F

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    iput v4, v1, Ld3/a;->b:F

    .line 206
    .line 207
    invoke-static {v11, v12}, Ljava/lang/Math;->min(FF)F

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    invoke-static {v10, v4}, Ljava/lang/Math;->min(FF)F

    .line 212
    .line 213
    .line 214
    move-result v4

    .line 215
    invoke-static {v0, v4}, Ljava/lang/Math;->min(FF)F

    .line 216
    .line 217
    .line 218
    move-result v4

    .line 219
    iput v4, v1, Ld3/a;->c:F

    .line 220
    .line 221
    invoke-static {v15, v14}, Ljava/lang/Math;->max(FF)F

    .line 222
    .line 223
    .line 224
    move-result v4

    .line 225
    invoke-static {v3, v4}, Ljava/lang/Math;->max(FF)F

    .line 226
    .line 227
    .line 228
    move-result v3

    .line 229
    invoke-static {v2, v3}, Ljava/lang/Math;->max(FF)F

    .line 230
    .line 231
    .line 232
    move-result v2

    .line 233
    iput v2, v1, Ld3/a;->d:F

    .line 234
    .line 235
    invoke-static {v11, v12}, Ljava/lang/Math;->max(FF)F

    .line 236
    .line 237
    .line 238
    move-result v2

    .line 239
    invoke-static {v10, v2}, Ljava/lang/Math;->max(FF)F

    .line 240
    .line 241
    .line 242
    move-result v2

    .line 243
    invoke-static {v0, v2}, Ljava/lang/Math;->max(FF)F

    .line 244
    .line 245
    .line 246
    move-result v0

    .line 247
    iput v0, v1, Ld3/a;->e:F

    .line 248
    .line 249
    return-void
.end method

.method public static final d([F)V
    .locals 3

    .line 1
    array-length v0, p0

    .line 2
    const/16 v1, 0x10

    .line 3
    .line 4
    if-ge v0, v1, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    const/high16 v1, 0x3f800000    # 1.0f

    .line 9
    .line 10
    aput v1, p0, v0

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    const/4 v2, 0x0

    .line 14
    aput v2, p0, v0

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    aput v2, p0, v0

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    aput v2, p0, v0

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    aput v2, p0, v0

    .line 24
    .line 25
    const/4 v0, 0x5

    .line 26
    aput v1, p0, v0

    .line 27
    .line 28
    const/4 v0, 0x6

    .line 29
    aput v2, p0, v0

    .line 30
    .line 31
    const/4 v0, 0x7

    .line 32
    aput v2, p0, v0

    .line 33
    .line 34
    const/16 v0, 0x8

    .line 35
    .line 36
    aput v2, p0, v0

    .line 37
    .line 38
    const/16 v0, 0x9

    .line 39
    .line 40
    aput v2, p0, v0

    .line 41
    .line 42
    const/16 v0, 0xa

    .line 43
    .line 44
    aput v1, p0, v0

    .line 45
    .line 46
    const/16 v0, 0xb

    .line 47
    .line 48
    aput v2, p0, v0

    .line 49
    .line 50
    const/16 v0, 0xc

    .line 51
    .line 52
    aput v2, p0, v0

    .line 53
    .line 54
    const/16 v0, 0xd

    .line 55
    .line 56
    aput v2, p0, v0

    .line 57
    .line 58
    const/16 v0, 0xe

    .line 59
    .line 60
    aput v2, p0, v0

    .line 61
    .line 62
    const/16 v0, 0xf

    .line 63
    .line 64
    aput v1, p0, v0

    .line 65
    .line 66
    return-void
.end method

.method public static final e([F[F)V
    .locals 49

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    array-length v2, v0

    .line 6
    const/16 v3, 0x10

    .line 7
    .line 8
    if-ge v2, v3, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    array-length v2, v1

    .line 12
    if-ge v2, v3, :cond_1

    .line 13
    .line 14
    :goto_0
    return-void

    .line 15
    :cond_1
    const/4 v2, 0x0

    .line 16
    aget v3, v0, v2

    .line 17
    .line 18
    aget v4, v1, v2

    .line 19
    .line 20
    mul-float v5, v3, v4

    .line 21
    .line 22
    const/4 v6, 0x1

    .line 23
    aget v7, v0, v6

    .line 24
    .line 25
    const/4 v8, 0x4

    .line 26
    aget v9, v1, v8

    .line 27
    .line 28
    mul-float v10, v7, v9

    .line 29
    .line 30
    add-float/2addr v10, v5

    .line 31
    const/4 v5, 0x2

    .line 32
    aget v11, v0, v5

    .line 33
    .line 34
    const/16 v12, 0x8

    .line 35
    .line 36
    aget v13, v1, v12

    .line 37
    .line 38
    mul-float v14, v11, v13

    .line 39
    .line 40
    add-float/2addr v14, v10

    .line 41
    const/4 v10, 0x3

    .line 42
    aget v15, v0, v10

    .line 43
    .line 44
    const/16 v16, 0xc

    .line 45
    .line 46
    aget v17, v1, v16

    .line 47
    .line 48
    mul-float v18, v15, v17

    .line 49
    .line 50
    add-float v18, v18, v14

    .line 51
    .line 52
    aget v14, v1, v6

    .line 53
    .line 54
    mul-float v19, v3, v14

    .line 55
    .line 56
    const/16 v20, 0x5

    .line 57
    .line 58
    aget v21, v1, v20

    .line 59
    .line 60
    mul-float v22, v7, v21

    .line 61
    .line 62
    add-float v22, v22, v19

    .line 63
    .line 64
    const/16 v19, 0x9

    .line 65
    .line 66
    aget v23, v1, v19

    .line 67
    .line 68
    mul-float v24, v11, v23

    .line 69
    .line 70
    add-float v24, v24, v22

    .line 71
    .line 72
    const/16 v22, 0xd

    .line 73
    .line 74
    aget v25, v1, v22

    .line 75
    .line 76
    mul-float v26, v15, v25

    .line 77
    .line 78
    add-float v26, v26, v24

    .line 79
    .line 80
    aget v24, v1, v5

    .line 81
    .line 82
    mul-float v27, v3, v24

    .line 83
    .line 84
    const/16 v28, 0x6

    .line 85
    .line 86
    aget v29, v1, v28

    .line 87
    .line 88
    mul-float v30, v7, v29

    .line 89
    .line 90
    add-float v30, v30, v27

    .line 91
    .line 92
    const/16 v27, 0xa

    .line 93
    .line 94
    aget v31, v1, v27

    .line 95
    .line 96
    mul-float v32, v11, v31

    .line 97
    .line 98
    add-float v32, v32, v30

    .line 99
    .line 100
    const/16 v30, 0xe

    .line 101
    .line 102
    aget v33, v1, v30

    .line 103
    .line 104
    mul-float v34, v15, v33

    .line 105
    .line 106
    add-float v34, v34, v32

    .line 107
    .line 108
    aget v32, v1, v10

    .line 109
    .line 110
    mul-float v3, v3, v32

    .line 111
    .line 112
    const/16 v35, 0x7

    .line 113
    .line 114
    aget v36, v1, v35

    .line 115
    .line 116
    mul-float v7, v7, v36

    .line 117
    .line 118
    add-float/2addr v7, v3

    .line 119
    const/16 v3, 0xb

    .line 120
    .line 121
    aget v37, v1, v3

    .line 122
    .line 123
    mul-float v11, v11, v37

    .line 124
    .line 125
    add-float/2addr v11, v7

    .line 126
    const/16 v7, 0xf

    .line 127
    .line 128
    aget v1, v1, v7

    .line 129
    .line 130
    mul-float/2addr v15, v1

    .line 131
    add-float/2addr v15, v11

    .line 132
    aget v11, v0, v8

    .line 133
    .line 134
    mul-float v38, v11, v4

    .line 135
    .line 136
    aget v39, v0, v20

    .line 137
    .line 138
    mul-float v40, v39, v9

    .line 139
    .line 140
    add-float v40, v40, v38

    .line 141
    .line 142
    aget v38, v0, v28

    .line 143
    .line 144
    mul-float v41, v38, v13

    .line 145
    .line 146
    add-float v41, v41, v40

    .line 147
    .line 148
    aget v40, v0, v35

    .line 149
    .line 150
    mul-float v42, v40, v17

    .line 151
    .line 152
    add-float v42, v42, v41

    .line 153
    .line 154
    mul-float v41, v11, v14

    .line 155
    .line 156
    mul-float v43, v39, v21

    .line 157
    .line 158
    add-float v43, v43, v41

    .line 159
    .line 160
    mul-float v41, v38, v23

    .line 161
    .line 162
    add-float v41, v41, v43

    .line 163
    .line 164
    mul-float v43, v40, v25

    .line 165
    .line 166
    add-float v43, v43, v41

    .line 167
    .line 168
    mul-float v41, v11, v24

    .line 169
    .line 170
    mul-float v44, v39, v29

    .line 171
    .line 172
    add-float v44, v44, v41

    .line 173
    .line 174
    mul-float v41, v38, v31

    .line 175
    .line 176
    add-float v41, v41, v44

    .line 177
    .line 178
    mul-float v44, v40, v33

    .line 179
    .line 180
    add-float v44, v44, v41

    .line 181
    .line 182
    mul-float v11, v11, v32

    .line 183
    .line 184
    mul-float v39, v39, v36

    .line 185
    .line 186
    add-float v39, v39, v11

    .line 187
    .line 188
    mul-float v38, v38, v37

    .line 189
    .line 190
    add-float v38, v38, v39

    .line 191
    .line 192
    mul-float v40, v40, v1

    .line 193
    .line 194
    add-float v40, v40, v38

    .line 195
    .line 196
    aget v11, v0, v12

    .line 197
    .line 198
    mul-float v38, v11, v4

    .line 199
    .line 200
    aget v39, v0, v19

    .line 201
    .line 202
    mul-float v41, v39, v9

    .line 203
    .line 204
    add-float v41, v41, v38

    .line 205
    .line 206
    aget v38, v0, v27

    .line 207
    .line 208
    mul-float v45, v38, v13

    .line 209
    .line 210
    add-float v45, v45, v41

    .line 211
    .line 212
    aget v41, v0, v3

    .line 213
    .line 214
    mul-float v46, v41, v17

    .line 215
    .line 216
    add-float v46, v46, v45

    .line 217
    .line 218
    mul-float v45, v11, v14

    .line 219
    .line 220
    mul-float v47, v39, v21

    .line 221
    .line 222
    add-float v47, v47, v45

    .line 223
    .line 224
    mul-float v45, v38, v23

    .line 225
    .line 226
    add-float v45, v45, v47

    .line 227
    .line 228
    mul-float v47, v41, v25

    .line 229
    .line 230
    add-float v47, v47, v45

    .line 231
    .line 232
    mul-float v45, v11, v24

    .line 233
    .line 234
    mul-float v48, v39, v29

    .line 235
    .line 236
    add-float v48, v48, v45

    .line 237
    .line 238
    mul-float v45, v38, v31

    .line 239
    .line 240
    add-float v45, v45, v48

    .line 241
    .line 242
    mul-float v48, v41, v33

    .line 243
    .line 244
    add-float v48, v48, v45

    .line 245
    .line 246
    mul-float v11, v11, v32

    .line 247
    .line 248
    mul-float v39, v39, v36

    .line 249
    .line 250
    add-float v39, v39, v11

    .line 251
    .line 252
    mul-float v38, v38, v37

    .line 253
    .line 254
    add-float v38, v38, v39

    .line 255
    .line 256
    mul-float v41, v41, v1

    .line 257
    .line 258
    add-float v41, v41, v38

    .line 259
    .line 260
    aget v11, v0, v16

    .line 261
    .line 262
    mul-float/2addr v4, v11

    .line 263
    aget v38, v0, v22

    .line 264
    .line 265
    mul-float v9, v9, v38

    .line 266
    .line 267
    add-float/2addr v9, v4

    .line 268
    aget v4, v0, v30

    .line 269
    .line 270
    mul-float/2addr v13, v4

    .line 271
    add-float/2addr v13, v9

    .line 272
    aget v9, v0, v7

    .line 273
    .line 274
    mul-float v17, v17, v9

    .line 275
    .line 276
    add-float v17, v17, v13

    .line 277
    .line 278
    mul-float/2addr v14, v11

    .line 279
    mul-float v21, v21, v38

    .line 280
    .line 281
    add-float v21, v21, v14

    .line 282
    .line 283
    mul-float v23, v23, v4

    .line 284
    .line 285
    add-float v23, v23, v21

    .line 286
    .line 287
    mul-float v25, v25, v9

    .line 288
    .line 289
    add-float v25, v25, v23

    .line 290
    .line 291
    mul-float v24, v24, v11

    .line 292
    .line 293
    mul-float v29, v29, v38

    .line 294
    .line 295
    add-float v29, v29, v24

    .line 296
    .line 297
    mul-float v31, v31, v4

    .line 298
    .line 299
    add-float v31, v31, v29

    .line 300
    .line 301
    mul-float v33, v33, v9

    .line 302
    .line 303
    add-float v33, v33, v31

    .line 304
    .line 305
    mul-float v11, v11, v32

    .line 306
    .line 307
    mul-float v38, v38, v36

    .line 308
    .line 309
    add-float v38, v38, v11

    .line 310
    .line 311
    mul-float v4, v4, v37

    .line 312
    .line 313
    add-float v4, v4, v38

    .line 314
    .line 315
    mul-float/2addr v9, v1

    .line 316
    add-float/2addr v9, v4

    .line 317
    aput v18, v0, v2

    .line 318
    .line 319
    aput v26, v0, v6

    .line 320
    .line 321
    aput v34, v0, v5

    .line 322
    .line 323
    aput v15, v0, v10

    .line 324
    .line 325
    aput v42, v0, v8

    .line 326
    .line 327
    aput v43, v0, v20

    .line 328
    .line 329
    aput v44, v0, v28

    .line 330
    .line 331
    aput v40, v0, v35

    .line 332
    .line 333
    aput v46, v0, v12

    .line 334
    .line 335
    aput v47, v0, v19

    .line 336
    .line 337
    aput v48, v0, v27

    .line 338
    .line 339
    aput v41, v0, v3

    .line 340
    .line 341
    aput v17, v0, v16

    .line 342
    .line 343
    aput v25, v0, v22

    .line 344
    .line 345
    aput v33, v0, v30

    .line 346
    .line 347
    aput v9, v0, v7

    .line 348
    .line 349
    return-void
.end method

.method public static final f([FFF)V
    .locals 8

    .line 1
    array-length v0, p0

    .line 2
    const/16 v1, 0x10

    .line 3
    .line 4
    if-ge v0, v1, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    aget v0, p0, v0

    .line 9
    .line 10
    mul-float/2addr v0, p1

    .line 11
    const/4 v1, 0x4

    .line 12
    aget v1, p0, v1

    .line 13
    .line 14
    mul-float/2addr v1, p2

    .line 15
    add-float/2addr v1, v0

    .line 16
    const/16 v0, 0x8

    .line 17
    .line 18
    aget v0, p0, v0

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    mul-float/2addr v0, v2

    .line 22
    add-float/2addr v0, v1

    .line 23
    const/16 v1, 0xc

    .line 24
    .line 25
    aget v3, p0, v1

    .line 26
    .line 27
    add-float/2addr v0, v3

    .line 28
    const/4 v3, 0x1

    .line 29
    aget v3, p0, v3

    .line 30
    .line 31
    mul-float/2addr v3, p1

    .line 32
    const/4 v4, 0x5

    .line 33
    aget v4, p0, v4

    .line 34
    .line 35
    mul-float/2addr v4, p2

    .line 36
    add-float/2addr v4, v3

    .line 37
    const/16 v3, 0x9

    .line 38
    .line 39
    aget v3, p0, v3

    .line 40
    .line 41
    mul-float/2addr v3, v2

    .line 42
    add-float/2addr v3, v4

    .line 43
    const/16 v4, 0xd

    .line 44
    .line 45
    aget v5, p0, v4

    .line 46
    .line 47
    add-float/2addr v3, v5

    .line 48
    const/4 v5, 0x2

    .line 49
    aget v5, p0, v5

    .line 50
    .line 51
    mul-float/2addr v5, p1

    .line 52
    const/4 v6, 0x6

    .line 53
    aget v6, p0, v6

    .line 54
    .line 55
    mul-float/2addr v6, p2

    .line 56
    add-float/2addr v6, v5

    .line 57
    const/16 v5, 0xa

    .line 58
    .line 59
    aget v5, p0, v5

    .line 60
    .line 61
    mul-float/2addr v5, v2

    .line 62
    add-float/2addr v5, v6

    .line 63
    const/16 v6, 0xe

    .line 64
    .line 65
    aget v7, p0, v6

    .line 66
    .line 67
    add-float/2addr v5, v7

    .line 68
    const/4 v7, 0x3

    .line 69
    aget v7, p0, v7

    .line 70
    .line 71
    mul-float/2addr v7, p1

    .line 72
    const/4 p1, 0x7

    .line 73
    aget p1, p0, p1

    .line 74
    .line 75
    mul-float/2addr p1, p2

    .line 76
    add-float/2addr p1, v7

    .line 77
    const/16 p2, 0xb

    .line 78
    .line 79
    aget p2, p0, p2

    .line 80
    .line 81
    mul-float/2addr p2, v2

    .line 82
    add-float/2addr p2, p1

    .line 83
    const/16 p1, 0xf

    .line 84
    .line 85
    aget v2, p0, p1

    .line 86
    .line 87
    add-float/2addr p2, v2

    .line 88
    aput v0, p0, v1

    .line 89
    .line 90
    aput v3, p0, v4

    .line 91
    .line 92
    aput v5, p0, v6

    .line 93
    .line 94
    aput p2, p0, p1

    .line 95
    .line 96
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Le3/c0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    check-cast p1, Le3/c0;

    .line 7
    .line 8
    iget-object p1, p1, Le3/c0;->a:[F

    .line 9
    .line 10
    iget-object p0, p0, Le3/c0;->a:[F

    .line 11
    .line 12
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    :goto_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Le3/c0;->a:[F

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([F)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "\n            |"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iget-object p0, p0, Le3/c0;->a:[F

    .line 10
    .line 11
    aget v1, p0, v1

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const/16 v1, 0x20

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    aget v2, p0, v2

    .line 23
    .line 24
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const/4 v2, 0x2

    .line 31
    aget v2, p0, v2

    .line 32
    .line 33
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const/4 v2, 0x3

    .line 40
    aget v2, p0, v2

    .line 41
    .line 42
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v2, "|\n            |"

    .line 46
    .line 47
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const/4 v3, 0x4

    .line 51
    aget v3, p0, v3

    .line 52
    .line 53
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const/4 v3, 0x5

    .line 60
    aget v3, p0, v3

    .line 61
    .line 62
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const/4 v3, 0x6

    .line 69
    aget v3, p0, v3

    .line 70
    .line 71
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const/4 v3, 0x7

    .line 78
    aget v3, p0, v3

    .line 79
    .line 80
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const/16 v3, 0x8

    .line 87
    .line 88
    aget v3, p0, v3

    .line 89
    .line 90
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const/16 v3, 0x9

    .line 97
    .line 98
    aget v3, p0, v3

    .line 99
    .line 100
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const/16 v3, 0xa

    .line 107
    .line 108
    aget v3, p0, v3

    .line 109
    .line 110
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const/16 v3, 0xb

    .line 117
    .line 118
    aget v3, p0, v3

    .line 119
    .line 120
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const/16 v2, 0xc

    .line 127
    .line 128
    aget v2, p0, v2

    .line 129
    .line 130
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const/16 v2, 0xd

    .line 137
    .line 138
    aget v2, p0, v2

    .line 139
    .line 140
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    const/16 v2, 0xe

    .line 147
    .line 148
    aget v2, p0, v2

    .line 149
    .line 150
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    const/16 v1, 0xf

    .line 157
    .line 158
    aget p0, p0, v1

    .line 159
    .line 160
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    const-string p0, "|\n        "

    .line 164
    .line 165
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    invoke-static {p0}, Lly0/q;->g(Ljava/lang/String;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0
.end method
