.class public final Lu7/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:I

.field public final c:F

.field public final d:F

.field public final e:F

.field public final f:I

.field public final g:I

.field public final h:I

.field public final i:[S

.field public j:[S

.field public k:I

.field public l:[S

.field public m:I

.field public n:[S

.field public o:I

.field public p:I

.field public q:I

.field public r:I

.field public s:I

.field public t:I

.field public u:I

.field public v:I

.field public w:D


# direct methods
.method public constructor <init>(IIFFI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lu7/h;->a:I

    .line 5
    .line 6
    iput p2, p0, Lu7/h;->b:I

    .line 7
    .line 8
    iput p3, p0, Lu7/h;->c:F

    .line 9
    .line 10
    iput p4, p0, Lu7/h;->d:F

    .line 11
    .line 12
    int-to-float p3, p1

    .line 13
    int-to-float p4, p5

    .line 14
    div-float/2addr p3, p4

    .line 15
    iput p3, p0, Lu7/h;->e:F

    .line 16
    .line 17
    div-int/lit16 p3, p1, 0x190

    .line 18
    .line 19
    iput p3, p0, Lu7/h;->f:I

    .line 20
    .line 21
    div-int/lit8 p1, p1, 0x41

    .line 22
    .line 23
    iput p1, p0, Lu7/h;->g:I

    .line 24
    .line 25
    mul-int/lit8 p1, p1, 0x2

    .line 26
    .line 27
    iput p1, p0, Lu7/h;->h:I

    .line 28
    .line 29
    new-array p3, p1, [S

    .line 30
    .line 31
    iput-object p3, p0, Lu7/h;->i:[S

    .line 32
    .line 33
    mul-int p3, p1, p2

    .line 34
    .line 35
    new-array p3, p3, [S

    .line 36
    .line 37
    iput-object p3, p0, Lu7/h;->j:[S

    .line 38
    .line 39
    mul-int p3, p1, p2

    .line 40
    .line 41
    new-array p3, p3, [S

    .line 42
    .line 43
    iput-object p3, p0, Lu7/h;->l:[S

    .line 44
    .line 45
    mul-int/2addr p1, p2

    .line 46
    new-array p1, p1, [S

    .line 47
    .line 48
    iput-object p1, p0, Lu7/h;->n:[S

    .line 49
    .line 50
    return-void
.end method

.method public static e(II[SI[SI[SI)V
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    if-ge v1, p1, :cond_1

    .line 4
    .line 5
    mul-int v2, p3, p1

    .line 6
    .line 7
    add-int/2addr v2, v1

    .line 8
    mul-int v3, p7, p1

    .line 9
    .line 10
    add-int/2addr v3, v1

    .line 11
    mul-int v4, p5, p1

    .line 12
    .line 13
    add-int/2addr v4, v1

    .line 14
    move v5, v0

    .line 15
    :goto_1
    if-ge v5, p0, :cond_0

    .line 16
    .line 17
    aget-short v6, p4, v4

    .line 18
    .line 19
    sub-int v7, p0, v5

    .line 20
    .line 21
    mul-int/2addr v7, v6

    .line 22
    aget-short v6, p6, v3

    .line 23
    .line 24
    mul-int/2addr v6, v5

    .line 25
    add-int/2addr v6, v7

    .line 26
    div-int/2addr v6, p0

    .line 27
    int-to-short v6, v6

    .line 28
    aput-short v6, p2, v2

    .line 29
    .line 30
    add-int/2addr v2, p1

    .line 31
    add-int/2addr v4, p1

    .line 32
    add-int/2addr v3, p1

    .line 33
    add-int/lit8 v5, v5, 0x1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    return-void
.end method


# virtual methods
.method public final a([SII)V
    .locals 3

    .line 1
    iget-object v0, p0, Lu7/h;->l:[S

    .line 2
    .line 3
    iget v1, p0, Lu7/h;->m:I

    .line 4
    .line 5
    invoke-virtual {p0, v0, v1, p3}, Lu7/h;->c([SII)[S

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lu7/h;->l:[S

    .line 10
    .line 11
    iget v1, p0, Lu7/h;->b:I

    .line 12
    .line 13
    mul-int/2addr p2, v1

    .line 14
    iget v2, p0, Lu7/h;->m:I

    .line 15
    .line 16
    mul-int/2addr v2, v1

    .line 17
    mul-int/2addr v1, p3

    .line 18
    invoke-static {p1, p2, v0, v2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 19
    .line 20
    .line 21
    iget p1, p0, Lu7/h;->m:I

    .line 22
    .line 23
    add-int/2addr p1, p3

    .line 24
    iput p1, p0, Lu7/h;->m:I

    .line 25
    .line 26
    return-void
.end method

.method public final b([SII)V
    .locals 6

    .line 1
    iget v0, p0, Lu7/h;->h:I

    .line 2
    .line 3
    div-int/2addr v0, p3

    .line 4
    iget v1, p0, Lu7/h;->b:I

    .line 5
    .line 6
    mul-int/2addr p3, v1

    .line 7
    mul-int/2addr p2, v1

    .line 8
    const/4 v1, 0x0

    .line 9
    move v2, v1

    .line 10
    :goto_0
    if-ge v2, v0, :cond_1

    .line 11
    .line 12
    move v3, v1

    .line 13
    move v4, v3

    .line 14
    :goto_1
    if-ge v3, p3, :cond_0

    .line 15
    .line 16
    mul-int v5, v2, p3

    .line 17
    .line 18
    add-int/2addr v5, p2

    .line 19
    add-int/2addr v5, v3

    .line 20
    aget-short v5, p1, v5

    .line 21
    .line 22
    add-int/2addr v4, v5

    .line 23
    add-int/lit8 v3, v3, 0x1

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    div-int/2addr v4, p3

    .line 27
    iget-object v3, p0, Lu7/h;->i:[S

    .line 28
    .line 29
    int-to-short v4, v4

    .line 30
    aput-short v4, v3, v2

    .line 31
    .line 32
    add-int/lit8 v2, v2, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    return-void
.end method

.method public final c([SII)[S
    .locals 1

    .line 1
    array-length v0, p1

    .line 2
    iget p0, p0, Lu7/h;->b:I

    .line 3
    .line 4
    div-int/2addr v0, p0

    .line 5
    add-int/2addr p2, p3

    .line 6
    if-gt p2, v0, :cond_0

    .line 7
    .line 8
    return-object p1

    .line 9
    :cond_0
    mul-int/lit8 v0, v0, 0x3

    .line 10
    .line 11
    div-int/lit8 v0, v0, 0x2

    .line 12
    .line 13
    add-int/2addr v0, p3

    .line 14
    mul-int/2addr v0, p0

    .line 15
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([SI)[S

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public final d([SIII)I
    .locals 9

    .line 1
    iget v0, p0, Lu7/h;->b:I

    .line 2
    .line 3
    mul-int/2addr p2, v0

    .line 4
    const/4 v0, 0x0

    .line 5
    const/16 v1, 0xff

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    move v3, v0

    .line 9
    move v4, v3

    .line 10
    :goto_0
    if-gt p3, p4, :cond_3

    .line 11
    .line 12
    move v5, v0

    .line 13
    move v6, v5

    .line 14
    :goto_1
    if-ge v5, p3, :cond_0

    .line 15
    .line 16
    add-int v7, p2, v5

    .line 17
    .line 18
    aget-short v7, p1, v7

    .line 19
    .line 20
    add-int v8, p2, p3

    .line 21
    .line 22
    add-int/2addr v8, v5

    .line 23
    aget-short v8, p1, v8

    .line 24
    .line 25
    sub-int/2addr v7, v8

    .line 26
    invoke-static {v7}, Ljava/lang/Math;->abs(I)I

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    add-int/2addr v6, v7

    .line 31
    add-int/lit8 v5, v5, 0x1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_0
    mul-int v5, v6, v3

    .line 35
    .line 36
    mul-int v7, v2, p3

    .line 37
    .line 38
    if-ge v5, v7, :cond_1

    .line 39
    .line 40
    move v3, p3

    .line 41
    move v2, v6

    .line 42
    :cond_1
    mul-int v5, v6, v1

    .line 43
    .line 44
    mul-int v7, v4, p3

    .line 45
    .line 46
    if-le v5, v7, :cond_2

    .line 47
    .line 48
    move v1, p3

    .line 49
    move v4, v6

    .line 50
    :cond_2
    add-int/lit8 p3, p3, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    div-int/2addr v2, v3

    .line 54
    iput v2, p0, Lu7/h;->u:I

    .line 55
    .line 56
    div-int/2addr v4, v1

    .line 57
    iput v4, p0, Lu7/h;->v:I

    .line 58
    .line 59
    return v3
.end method

.method public final f()V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lu7/h;->m:I

    .line 4
    .line 5
    iget v2, v0, Lu7/h;->c:F

    .line 6
    .line 7
    iget v3, v0, Lu7/h;->d:F

    .line 8
    .line 9
    div-float/2addr v2, v3

    .line 10
    float-to-double v4, v2

    .line 11
    iget v2, v0, Lu7/h;->e:F

    .line 12
    .line 13
    mul-float/2addr v2, v3

    .line 14
    const-wide v6, 0x3ff0000a80000000L    # 1.0000100135803223

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    cmpl-double v3, v4, v6

    .line 20
    .line 21
    iget v6, v0, Lu7/h;->a:I

    .line 22
    .line 23
    const/4 v7, 0x1

    .line 24
    iget v8, v0, Lu7/h;->b:I

    .line 25
    .line 26
    const/4 v9, 0x0

    .line 27
    if-gtz v3, :cond_1

    .line 28
    .line 29
    const-wide v10, 0x3fefffeb00000000L    # 0.9999899864196777

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    cmpg-double v3, v4, v10

    .line 35
    .line 36
    if-gez v3, :cond_0

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    iget-object v3, v0, Lu7/h;->j:[S

    .line 40
    .line 41
    iget v4, v0, Lu7/h;->k:I

    .line 42
    .line 43
    invoke-virtual {v0, v3, v9, v4}, Lu7/h;->a([SII)V

    .line 44
    .line 45
    .line 46
    iput v9, v0, Lu7/h;->k:I

    .line 47
    .line 48
    :goto_0
    move/from16 v20, v2

    .line 49
    .line 50
    goto/16 :goto_c

    .line 51
    .line 52
    :cond_1
    :goto_1
    iget v3, v0, Lu7/h;->k:I

    .line 53
    .line 54
    iget v10, v0, Lu7/h;->h:I

    .line 55
    .line 56
    if-ge v3, v10, :cond_2

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_2
    move v11, v9

    .line 60
    :goto_2
    iget v12, v0, Lu7/h;->r:I

    .line 61
    .line 62
    if-lez v12, :cond_3

    .line 63
    .line 64
    invoke-static {v10, v12}, Ljava/lang/Math;->min(II)I

    .line 65
    .line 66
    .line 67
    move-result v12

    .line 68
    iget-object v13, v0, Lu7/h;->j:[S

    .line 69
    .line 70
    invoke-virtual {v0, v13, v11, v12}, Lu7/h;->a([SII)V

    .line 71
    .line 72
    .line 73
    iget v13, v0, Lu7/h;->r:I

    .line 74
    .line 75
    sub-int/2addr v13, v12

    .line 76
    iput v13, v0, Lu7/h;->r:I

    .line 77
    .line 78
    add-int/2addr v11, v12

    .line 79
    move/from16 v20, v2

    .line 80
    .line 81
    move-wide/from16 v21, v4

    .line 82
    .line 83
    move v4, v10

    .line 84
    goto/16 :goto_b

    .line 85
    .line 86
    :cond_3
    iget-object v12, v0, Lu7/h;->j:[S

    .line 87
    .line 88
    const/16 v13, 0xfa0

    .line 89
    .line 90
    if-le v6, v13, :cond_4

    .line 91
    .line 92
    div-int/lit16 v13, v6, 0xfa0

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_4
    move v13, v7

    .line 96
    :goto_3
    iget v14, v0, Lu7/h;->g:I

    .line 97
    .line 98
    iget v15, v0, Lu7/h;->f:I

    .line 99
    .line 100
    if-ne v8, v7, :cond_5

    .line 101
    .line 102
    if-ne v13, v7, :cond_5

    .line 103
    .line 104
    invoke-virtual {v0, v12, v11, v15, v14}, Lu7/h;->d([SIII)I

    .line 105
    .line 106
    .line 107
    move-result v12

    .line 108
    move/from16 v20, v2

    .line 109
    .line 110
    move-wide/from16 v21, v4

    .line 111
    .line 112
    goto :goto_7

    .line 113
    :cond_5
    invoke-virtual {v0, v12, v11, v13}, Lu7/h;->b([SII)V

    .line 114
    .line 115
    .line 116
    div-int v7, v15, v13

    .line 117
    .line 118
    move/from16 v20, v2

    .line 119
    .line 120
    div-int v2, v14, v13

    .line 121
    .line 122
    move-wide/from16 v21, v4

    .line 123
    .line 124
    iget-object v4, v0, Lu7/h;->i:[S

    .line 125
    .line 126
    invoke-virtual {v0, v4, v9, v7, v2}, Lu7/h;->d([SIII)I

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    const/4 v5, 0x1

    .line 131
    if-eq v13, v5, :cond_9

    .line 132
    .line 133
    mul-int/2addr v2, v13

    .line 134
    mul-int/lit8 v13, v13, 0x4

    .line 135
    .line 136
    sub-int v5, v2, v13

    .line 137
    .line 138
    add-int/2addr v2, v13

    .line 139
    if-ge v5, v15, :cond_6

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_6
    move v15, v5

    .line 143
    :goto_4
    if-le v2, v14, :cond_7

    .line 144
    .line 145
    :goto_5
    const/4 v5, 0x1

    .line 146
    goto :goto_6

    .line 147
    :cond_7
    move v14, v2

    .line 148
    goto :goto_5

    .line 149
    :goto_6
    if-ne v8, v5, :cond_8

    .line 150
    .line 151
    invoke-virtual {v0, v12, v11, v15, v14}, Lu7/h;->d([SIII)I

    .line 152
    .line 153
    .line 154
    move-result v12

    .line 155
    goto :goto_7

    .line 156
    :cond_8
    invoke-virtual {v0, v12, v11, v5}, Lu7/h;->b([SII)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0, v4, v9, v15, v14}, Lu7/h;->d([SIII)I

    .line 160
    .line 161
    .line 162
    move-result v12

    .line 163
    goto :goto_7

    .line 164
    :cond_9
    move v12, v2

    .line 165
    :goto_7
    iget v2, v0, Lu7/h;->u:I

    .line 166
    .line 167
    iget v4, v0, Lu7/h;->v:I

    .line 168
    .line 169
    if-eqz v2, :cond_c

    .line 170
    .line 171
    iget v5, v0, Lu7/h;->s:I

    .line 172
    .line 173
    if-nez v5, :cond_a

    .line 174
    .line 175
    goto :goto_8

    .line 176
    :cond_a
    mul-int/lit8 v7, v2, 0x3

    .line 177
    .line 178
    if-le v4, v7, :cond_b

    .line 179
    .line 180
    goto :goto_8

    .line 181
    :cond_b
    mul-int/lit8 v4, v2, 0x2

    .line 182
    .line 183
    iget v7, v0, Lu7/h;->t:I

    .line 184
    .line 185
    mul-int/lit8 v7, v7, 0x3

    .line 186
    .line 187
    if-gt v4, v7, :cond_d

    .line 188
    .line 189
    :cond_c
    :goto_8
    move v5, v12

    .line 190
    :cond_d
    iput v2, v0, Lu7/h;->t:I

    .line 191
    .line 192
    iput v12, v0, Lu7/h;->s:I

    .line 193
    .line 194
    const-wide/high16 v12, 0x3ff0000000000000L    # 1.0

    .line 195
    .line 196
    cmpl-double v2, v21, v12

    .line 197
    .line 198
    const-wide/high16 v14, 0x4000000000000000L    # 2.0

    .line 199
    .line 200
    if-lez v2, :cond_f

    .line 201
    .line 202
    move-wide/from16 v16, v14

    .line 203
    .line 204
    iget-object v15, v0, Lu7/h;->j:[S

    .line 205
    .line 206
    cmpl-double v2, v21, v16

    .line 207
    .line 208
    if-ltz v2, :cond_e

    .line 209
    .line 210
    move-wide/from16 v23, v12

    .line 211
    .line 212
    int-to-double v12, v5

    .line 213
    sub-double v16, v21, v23

    .line 214
    .line 215
    div-double v12, v12, v16

    .line 216
    .line 217
    move v4, v10

    .line 218
    iget-wide v9, v0, Lu7/h;->w:D

    .line 219
    .line 220
    add-double/2addr v12, v9

    .line 221
    invoke-static {v12, v13}, Ljava/lang/Math;->round(D)J

    .line 222
    .line 223
    .line 224
    move-result-wide v9

    .line 225
    long-to-int v7, v9

    .line 226
    int-to-double v9, v7

    .line 227
    sub-double/2addr v12, v9

    .line 228
    iput-wide v12, v0, Lu7/h;->w:D

    .line 229
    .line 230
    goto :goto_9

    .line 231
    :cond_e
    move v4, v10

    .line 232
    move-wide/from16 v23, v12

    .line 233
    .line 234
    int-to-double v9, v5

    .line 235
    sub-double v12, v16, v21

    .line 236
    .line 237
    mul-double/2addr v12, v9

    .line 238
    sub-double v9, v21, v23

    .line 239
    .line 240
    div-double/2addr v12, v9

    .line 241
    iget-wide v9, v0, Lu7/h;->w:D

    .line 242
    .line 243
    add-double/2addr v12, v9

    .line 244
    invoke-static {v12, v13}, Ljava/lang/Math;->round(D)J

    .line 245
    .line 246
    .line 247
    move-result-wide v9

    .line 248
    long-to-int v7, v9

    .line 249
    iput v7, v0, Lu7/h;->r:I

    .line 250
    .line 251
    int-to-double v9, v7

    .line 252
    sub-double/2addr v12, v9

    .line 253
    iput-wide v12, v0, Lu7/h;->w:D

    .line 254
    .line 255
    move v7, v5

    .line 256
    :goto_9
    iget-object v9, v0, Lu7/h;->l:[S

    .line 257
    .line 258
    iget v10, v0, Lu7/h;->m:I

    .line 259
    .line 260
    invoke-virtual {v0, v9, v10, v7}, Lu7/h;->c([SII)[S

    .line 261
    .line 262
    .line 263
    move-result-object v13

    .line 264
    iput-object v13, v0, Lu7/h;->l:[S

    .line 265
    .line 266
    iget v14, v0, Lu7/h;->m:I

    .line 267
    .line 268
    add-int v18, v11, v5

    .line 269
    .line 270
    iget v12, v0, Lu7/h;->b:I

    .line 271
    .line 272
    move-object/from16 v17, v15

    .line 273
    .line 274
    move/from16 v16, v11

    .line 275
    .line 276
    move v11, v7

    .line 277
    invoke-static/range {v11 .. v18}, Lu7/h;->e(II[SI[SI[SI)V

    .line 278
    .line 279
    .line 280
    move/from16 v18, v16

    .line 281
    .line 282
    iget v7, v0, Lu7/h;->m:I

    .line 283
    .line 284
    add-int/2addr v7, v11

    .line 285
    iput v7, v0, Lu7/h;->m:I

    .line 286
    .line 287
    add-int/2addr v5, v11

    .line 288
    add-int v5, v5, v18

    .line 289
    .line 290
    move v11, v5

    .line 291
    goto :goto_b

    .line 292
    :cond_f
    move v4, v10

    .line 293
    move/from16 v18, v11

    .line 294
    .line 295
    move-wide/from16 v23, v12

    .line 296
    .line 297
    move-wide/from16 v16, v14

    .line 298
    .line 299
    iget-object v15, v0, Lu7/h;->j:[S

    .line 300
    .line 301
    const-wide/high16 v9, 0x3fe0000000000000L    # 0.5

    .line 302
    .line 303
    cmpg-double v7, v21, v9

    .line 304
    .line 305
    if-gez v7, :cond_10

    .line 306
    .line 307
    int-to-double v9, v5

    .line 308
    mul-double v9, v9, v21

    .line 309
    .line 310
    sub-double v12, v23, v21

    .line 311
    .line 312
    div-double/2addr v9, v12

    .line 313
    iget-wide v11, v0, Lu7/h;->w:D

    .line 314
    .line 315
    add-double/2addr v9, v11

    .line 316
    invoke-static {v9, v10}, Ljava/lang/Math;->round(D)J

    .line 317
    .line 318
    .line 319
    move-result-wide v11

    .line 320
    long-to-int v7, v11

    .line 321
    int-to-double v11, v7

    .line 322
    sub-double/2addr v9, v11

    .line 323
    iput-wide v9, v0, Lu7/h;->w:D

    .line 324
    .line 325
    move v11, v7

    .line 326
    goto :goto_a

    .line 327
    :cond_10
    int-to-double v9, v5

    .line 328
    mul-double v11, v21, v16

    .line 329
    .line 330
    sub-double v11, v11, v23

    .line 331
    .line 332
    mul-double/2addr v11, v9

    .line 333
    sub-double v9, v23, v21

    .line 334
    .line 335
    div-double/2addr v11, v9

    .line 336
    iget-wide v9, v0, Lu7/h;->w:D

    .line 337
    .line 338
    add-double/2addr v11, v9

    .line 339
    invoke-static {v11, v12}, Ljava/lang/Math;->round(D)J

    .line 340
    .line 341
    .line 342
    move-result-wide v9

    .line 343
    long-to-int v7, v9

    .line 344
    iput v7, v0, Lu7/h;->r:I

    .line 345
    .line 346
    int-to-double v9, v7

    .line 347
    sub-double/2addr v11, v9

    .line 348
    iput-wide v11, v0, Lu7/h;->w:D

    .line 349
    .line 350
    move v11, v5

    .line 351
    :goto_a
    iget-object v7, v0, Lu7/h;->l:[S

    .line 352
    .line 353
    iget v9, v0, Lu7/h;->m:I

    .line 354
    .line 355
    add-int v10, v5, v11

    .line 356
    .line 357
    invoke-virtual {v0, v7, v9, v10}, Lu7/h;->c([SII)[S

    .line 358
    .line 359
    .line 360
    move-result-object v7

    .line 361
    iput-object v7, v0, Lu7/h;->l:[S

    .line 362
    .line 363
    mul-int v9, v18, v8

    .line 364
    .line 365
    iget v12, v0, Lu7/h;->m:I

    .line 366
    .line 367
    mul-int/2addr v12, v8

    .line 368
    mul-int v13, v5, v8

    .line 369
    .line 370
    invoke-static {v15, v9, v7, v12, v13}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 371
    .line 372
    .line 373
    iget-object v13, v0, Lu7/h;->l:[S

    .line 374
    .line 375
    iget v7, v0, Lu7/h;->m:I

    .line 376
    .line 377
    add-int v14, v7, v5

    .line 378
    .line 379
    add-int v16, v18, v5

    .line 380
    .line 381
    iget v12, v0, Lu7/h;->b:I

    .line 382
    .line 383
    move-object/from16 v17, v15

    .line 384
    .line 385
    invoke-static/range {v11 .. v18}, Lu7/h;->e(II[SI[SI[SI)V

    .line 386
    .line 387
    .line 388
    iget v5, v0, Lu7/h;->m:I

    .line 389
    .line 390
    add-int/2addr v5, v10

    .line 391
    iput v5, v0, Lu7/h;->m:I

    .line 392
    .line 393
    add-int v11, v18, v11

    .line 394
    .line 395
    :goto_b
    add-int v10, v11, v4

    .line 396
    .line 397
    if-le v10, v3, :cond_1a

    .line 398
    .line 399
    iget v3, v0, Lu7/h;->k:I

    .line 400
    .line 401
    sub-int/2addr v3, v11

    .line 402
    iget-object v4, v0, Lu7/h;->j:[S

    .line 403
    .line 404
    mul-int/2addr v11, v8

    .line 405
    mul-int v5, v3, v8

    .line 406
    .line 407
    const/4 v2, 0x0

    .line 408
    invoke-static {v4, v11, v4, v2, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 409
    .line 410
    .line 411
    iput v3, v0, Lu7/h;->k:I

    .line 412
    .line 413
    :goto_c
    const/high16 v3, 0x3f800000    # 1.0f

    .line 414
    .line 415
    cmpl-float v3, v20, v3

    .line 416
    .line 417
    if-eqz v3, :cond_19

    .line 418
    .line 419
    iget v3, v0, Lu7/h;->m:I

    .line 420
    .line 421
    if-ne v3, v1, :cond_11

    .line 422
    .line 423
    goto/16 :goto_12

    .line 424
    .line 425
    :cond_11
    int-to-float v3, v6

    .line 426
    div-float v3, v3, v20

    .line 427
    .line 428
    float-to-long v3, v3

    .line 429
    int-to-long v5, v6

    .line 430
    :goto_d
    const-wide/16 v9, 0x0

    .line 431
    .line 432
    cmp-long v7, v3, v9

    .line 433
    .line 434
    if-eqz v7, :cond_12

    .line 435
    .line 436
    cmp-long v7, v5, v9

    .line 437
    .line 438
    if-eqz v7, :cond_12

    .line 439
    .line 440
    const-wide/16 v11, 0x2

    .line 441
    .line 442
    rem-long v13, v3, v11

    .line 443
    .line 444
    cmp-long v7, v13, v9

    .line 445
    .line 446
    if-nez v7, :cond_12

    .line 447
    .line 448
    rem-long v13, v5, v11

    .line 449
    .line 450
    cmp-long v7, v13, v9

    .line 451
    .line 452
    if-nez v7, :cond_12

    .line 453
    .line 454
    div-long/2addr v3, v11

    .line 455
    div-long/2addr v5, v11

    .line 456
    goto :goto_d

    .line 457
    :cond_12
    iget v7, v0, Lu7/h;->m:I

    .line 458
    .line 459
    sub-int/2addr v7, v1

    .line 460
    iget-object v9, v0, Lu7/h;->n:[S

    .line 461
    .line 462
    iget v10, v0, Lu7/h;->o:I

    .line 463
    .line 464
    invoke-virtual {v0, v9, v10, v7}, Lu7/h;->c([SII)[S

    .line 465
    .line 466
    .line 467
    move-result-object v9

    .line 468
    iput-object v9, v0, Lu7/h;->n:[S

    .line 469
    .line 470
    iget-object v10, v0, Lu7/h;->l:[S

    .line 471
    .line 472
    mul-int v11, v1, v8

    .line 473
    .line 474
    iget v12, v0, Lu7/h;->o:I

    .line 475
    .line 476
    mul-int/2addr v12, v8

    .line 477
    mul-int v13, v7, v8

    .line 478
    .line 479
    invoke-static {v10, v11, v9, v12, v13}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 480
    .line 481
    .line 482
    iput v1, v0, Lu7/h;->m:I

    .line 483
    .line 484
    iget v1, v0, Lu7/h;->o:I

    .line 485
    .line 486
    add-int/2addr v1, v7

    .line 487
    iput v1, v0, Lu7/h;->o:I

    .line 488
    .line 489
    const/4 v1, 0x0

    .line 490
    :goto_e
    iget v7, v0, Lu7/h;->o:I

    .line 491
    .line 492
    add-int/lit8 v9, v7, -0x1

    .line 493
    .line 494
    if-ge v1, v9, :cond_17

    .line 495
    .line 496
    :goto_f
    iget v7, v0, Lu7/h;->p:I

    .line 497
    .line 498
    const/4 v9, 0x1

    .line 499
    add-int/2addr v7, v9

    .line 500
    int-to-long v10, v7

    .line 501
    mul-long v12, v10, v3

    .line 502
    .line 503
    iget v14, v0, Lu7/h;->q:I

    .line 504
    .line 505
    int-to-long v14, v14

    .line 506
    mul-long v16, v14, v5

    .line 507
    .line 508
    cmp-long v12, v12, v16

    .line 509
    .line 510
    if-lez v12, :cond_14

    .line 511
    .line 512
    iget-object v7, v0, Lu7/h;->l:[S

    .line 513
    .line 514
    iget v10, v0, Lu7/h;->m:I

    .line 515
    .line 516
    invoke-virtual {v0, v7, v10, v9}, Lu7/h;->c([SII)[S

    .line 517
    .line 518
    .line 519
    move-result-object v7

    .line 520
    iput-object v7, v0, Lu7/h;->l:[S

    .line 521
    .line 522
    const/4 v7, 0x0

    .line 523
    :goto_10
    if-ge v7, v8, :cond_13

    .line 524
    .line 525
    iget-object v9, v0, Lu7/h;->l:[S

    .line 526
    .line 527
    iget v10, v0, Lu7/h;->m:I

    .line 528
    .line 529
    mul-int/2addr v10, v8

    .line 530
    add-int/2addr v10, v7

    .line 531
    iget-object v11, v0, Lu7/h;->n:[S

    .line 532
    .line 533
    mul-int v12, v1, v8

    .line 534
    .line 535
    add-int/2addr v12, v7

    .line 536
    aget-short v13, v11, v12

    .line 537
    .line 538
    add-int/2addr v12, v8

    .line 539
    aget-short v11, v11, v12

    .line 540
    .line 541
    iget v12, v0, Lu7/h;->q:I

    .line 542
    .line 543
    int-to-long v14, v12

    .line 544
    mul-long/2addr v14, v5

    .line 545
    iget v12, v0, Lu7/h;->p:I

    .line 546
    .line 547
    move-wide/from16 v17, v3

    .line 548
    .line 549
    int-to-long v2, v12

    .line 550
    mul-long v2, v2, v17

    .line 551
    .line 552
    const/16 v19, 0x1

    .line 553
    .line 554
    add-int/lit8 v12, v12, 0x1

    .line 555
    .line 556
    move v4, v1

    .line 557
    move-wide/from16 v20, v2

    .line 558
    .line 559
    int-to-long v1, v12

    .line 560
    mul-long v1, v1, v17

    .line 561
    .line 562
    sub-long v14, v1, v14

    .line 563
    .line 564
    sub-long v1, v1, v20

    .line 565
    .line 566
    int-to-long v12, v13

    .line 567
    mul-long/2addr v12, v14

    .line 568
    sub-long v14, v1, v14

    .line 569
    .line 570
    move-wide/from16 v20, v1

    .line 571
    .line 572
    int-to-long v1, v11

    .line 573
    mul-long/2addr v14, v1

    .line 574
    add-long/2addr v14, v12

    .line 575
    div-long v14, v14, v20

    .line 576
    .line 577
    long-to-int v1, v14

    .line 578
    int-to-short v1, v1

    .line 579
    aput-short v1, v9, v10

    .line 580
    .line 581
    add-int/lit8 v7, v7, 0x1

    .line 582
    .line 583
    move v1, v4

    .line 584
    move-wide/from16 v3, v17

    .line 585
    .line 586
    goto :goto_10

    .line 587
    :cond_13
    move-wide/from16 v17, v3

    .line 588
    .line 589
    move v4, v1

    .line 590
    iget v1, v0, Lu7/h;->q:I

    .line 591
    .line 592
    const/16 v19, 0x1

    .line 593
    .line 594
    add-int/lit8 v1, v1, 0x1

    .line 595
    .line 596
    iput v1, v0, Lu7/h;->q:I

    .line 597
    .line 598
    iget v1, v0, Lu7/h;->m:I

    .line 599
    .line 600
    add-int/lit8 v1, v1, 0x1

    .line 601
    .line 602
    iput v1, v0, Lu7/h;->m:I

    .line 603
    .line 604
    move v1, v4

    .line 605
    move-wide/from16 v3, v17

    .line 606
    .line 607
    goto :goto_f

    .line 608
    :cond_14
    move-wide/from16 v17, v3

    .line 609
    .line 610
    move/from16 v19, v9

    .line 611
    .line 612
    move v4, v1

    .line 613
    iput v7, v0, Lu7/h;->p:I

    .line 614
    .line 615
    cmp-long v1, v10, v5

    .line 616
    .line 617
    if-nez v1, :cond_16

    .line 618
    .line 619
    const/4 v2, 0x0

    .line 620
    iput v2, v0, Lu7/h;->p:I

    .line 621
    .line 622
    cmp-long v1, v14, v17

    .line 623
    .line 624
    if-nez v1, :cond_15

    .line 625
    .line 626
    move/from16 v1, v19

    .line 627
    .line 628
    goto :goto_11

    .line 629
    :cond_15
    move v1, v2

    .line 630
    :goto_11
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 631
    .line 632
    .line 633
    iput v2, v0, Lu7/h;->q:I

    .line 634
    .line 635
    :cond_16
    add-int/lit8 v1, v4, 0x1

    .line 636
    .line 637
    move-wide/from16 v3, v17

    .line 638
    .line 639
    goto/16 :goto_e

    .line 640
    .line 641
    :cond_17
    if-nez v9, :cond_18

    .line 642
    .line 643
    goto :goto_12

    .line 644
    :cond_18
    iget-object v1, v0, Lu7/h;->n:[S

    .line 645
    .line 646
    mul-int v3, v9, v8

    .line 647
    .line 648
    sub-int/2addr v7, v9

    .line 649
    mul-int/2addr v7, v8

    .line 650
    const/4 v2, 0x0

    .line 651
    invoke-static {v1, v3, v1, v2, v7}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 652
    .line 653
    .line 654
    iget v1, v0, Lu7/h;->o:I

    .line 655
    .line 656
    sub-int/2addr v1, v9

    .line 657
    iput v1, v0, Lu7/h;->o:I

    .line 658
    .line 659
    :cond_19
    :goto_12
    return-void

    .line 660
    :cond_1a
    const/4 v2, 0x0

    .line 661
    const/16 v19, 0x1

    .line 662
    .line 663
    move v9, v2

    .line 664
    move v10, v4

    .line 665
    move/from16 v7, v19

    .line 666
    .line 667
    move/from16 v2, v20

    .line 668
    .line 669
    move-wide/from16 v4, v21

    .line 670
    .line 671
    goto/16 :goto_2
.end method
