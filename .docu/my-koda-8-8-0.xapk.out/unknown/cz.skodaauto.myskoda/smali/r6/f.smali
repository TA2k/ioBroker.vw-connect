.class public final Lr6/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:D

.field public b:D

.field public c:Z

.field public d:D

.field public e:D

.field public f:D

.field public g:D

.field public h:D

.field public i:D

.field public final j:Lb1/x0;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide v0, 0x4097700000000000L    # 1500.0

    .line 2
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v0

    iput-wide v0, p0, Lr6/f;->a:D

    const-wide/high16 v0, 0x3fe0000000000000L    # 0.5

    .line 3
    iput-wide v0, p0, Lr6/f;->b:D

    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, Lr6/f;->c:Z

    const-wide v0, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 5
    iput-wide v0, p0, Lr6/f;->i:D

    .line 6
    new-instance v0, Lb1/x0;

    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object v0, p0, Lr6/f;->j:Lb1/x0;

    return-void
.end method

.method public constructor <init>(F)V
    .locals 2

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide v0, 0x4097700000000000L    # 1500.0

    .line 10
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v0

    iput-wide v0, p0, Lr6/f;->a:D

    const-wide/high16 v0, 0x3fe0000000000000L    # 0.5

    .line 11
    iput-wide v0, p0, Lr6/f;->b:D

    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p0, Lr6/f;->c:Z

    .line 13
    new-instance v0, Lb1/x0;

    .line 14
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 15
    iput-object v0, p0, Lr6/f;->j:Lb1/x0;

    float-to-double v0, p1

    .line 16
    iput-wide v0, p0, Lr6/f;->i:D

    return-void
.end method


# virtual methods
.method public final a(F)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v0, p1, v0

    .line 3
    .line 4
    if-ltz v0, :cond_0

    .line 5
    .line 6
    float-to-double v0, p1

    .line 7
    iput-wide v0, p0, Lr6/f;->b:D

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    iput-boolean p1, p0, Lr6/f;->c:Z

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "Damping ratio must be non-negative"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public final b(F)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v0, p1, v0

    .line 3
    .line 4
    if-lez v0, :cond_0

    .line 5
    .line 6
    float-to-double v0, p1

    .line 7
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lr6/f;->a:D

    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    iput-boolean p1, p0, Lr6/f;->c:Z

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    const-string p1, "Spring stiffness constant must be positive."

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0
.end method

.method public final c(JDD)Lb1/x0;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Lr6/f;->c:Z

    .line 4
    .line 5
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    :goto_0
    move-wide/from16 v4, p1

    .line 10
    .line 11
    goto :goto_2

    .line 12
    :cond_0
    iget-wide v4, v0, Lr6/f;->i:D

    .line 13
    .line 14
    const-wide v6, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    cmpl-double v1, v4, v6

    .line 20
    .line 21
    if-eqz v1, :cond_5

    .line 22
    .line 23
    iget-wide v4, v0, Lr6/f;->b:D

    .line 24
    .line 25
    cmpl-double v1, v4, v2

    .line 26
    .line 27
    if-lez v1, :cond_1

    .line 28
    .line 29
    neg-double v6, v4

    .line 30
    iget-wide v8, v0, Lr6/f;->a:D

    .line 31
    .line 32
    mul-double/2addr v6, v8

    .line 33
    mul-double/2addr v4, v4

    .line 34
    sub-double/2addr v4, v2

    .line 35
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 36
    .line 37
    .line 38
    move-result-wide v4

    .line 39
    mul-double/2addr v4, v8

    .line 40
    add-double/2addr v4, v6

    .line 41
    iput-wide v4, v0, Lr6/f;->f:D

    .line 42
    .line 43
    iget-wide v4, v0, Lr6/f;->b:D

    .line 44
    .line 45
    neg-double v6, v4

    .line 46
    iget-wide v8, v0, Lr6/f;->a:D

    .line 47
    .line 48
    mul-double/2addr v6, v8

    .line 49
    mul-double/2addr v4, v4

    .line 50
    sub-double/2addr v4, v2

    .line 51
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 52
    .line 53
    .line 54
    move-result-wide v4

    .line 55
    mul-double/2addr v4, v8

    .line 56
    sub-double/2addr v6, v4

    .line 57
    iput-wide v6, v0, Lr6/f;->g:D

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    const-wide/16 v6, 0x0

    .line 61
    .line 62
    cmpl-double v1, v4, v6

    .line 63
    .line 64
    if-ltz v1, :cond_2

    .line 65
    .line 66
    cmpg-double v1, v4, v2

    .line 67
    .line 68
    if-gez v1, :cond_2

    .line 69
    .line 70
    iget-wide v6, v0, Lr6/f;->a:D

    .line 71
    .line 72
    mul-double/2addr v4, v4

    .line 73
    sub-double v4, v2, v4

    .line 74
    .line 75
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 76
    .line 77
    .line 78
    move-result-wide v4

    .line 79
    mul-double/2addr v4, v6

    .line 80
    iput-wide v4, v0, Lr6/f;->h:D

    .line 81
    .line 82
    :cond_2
    :goto_1
    const/4 v1, 0x1

    .line 83
    iput-boolean v1, v0, Lr6/f;->c:Z

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :goto_2
    long-to-double v4, v4

    .line 87
    const-wide v6, 0x408f400000000000L    # 1000.0

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    div-double/2addr v4, v6

    .line 93
    iget-wide v6, v0, Lr6/f;->i:D

    .line 94
    .line 95
    sub-double v6, p3, v6

    .line 96
    .line 97
    iget-wide v8, v0, Lr6/f;->b:D

    .line 98
    .line 99
    cmpl-double v1, v8, v2

    .line 100
    .line 101
    const-wide v10, 0x4005bf0a8b145769L    # Math.E

    .line 102
    .line 103
    .line 104
    .line 105
    .line 106
    if-lez v1, :cond_3

    .line 107
    .line 108
    iget-wide v1, v0, Lr6/f;->g:D

    .line 109
    .line 110
    mul-double v8, v1, v6

    .line 111
    .line 112
    sub-double v8, v8, p5

    .line 113
    .line 114
    iget-wide v12, v0, Lr6/f;->f:D

    .line 115
    .line 116
    sub-double v12, v1, v12

    .line 117
    .line 118
    div-double/2addr v8, v12

    .line 119
    sub-double/2addr v6, v8

    .line 120
    mul-double/2addr v1, v4

    .line 121
    invoke-static {v10, v11, v1, v2}, Ljava/lang/Math;->pow(DD)D

    .line 122
    .line 123
    .line 124
    move-result-wide v1

    .line 125
    mul-double/2addr v1, v6

    .line 126
    iget-wide v12, v0, Lr6/f;->f:D

    .line 127
    .line 128
    mul-double/2addr v12, v4

    .line 129
    invoke-static {v10, v11, v12, v13}, Ljava/lang/Math;->pow(DD)D

    .line 130
    .line 131
    .line 132
    move-result-wide v12

    .line 133
    mul-double/2addr v12, v8

    .line 134
    add-double/2addr v12, v1

    .line 135
    iget-wide v1, v0, Lr6/f;->g:D

    .line 136
    .line 137
    mul-double/2addr v6, v1

    .line 138
    mul-double/2addr v1, v4

    .line 139
    invoke-static {v10, v11, v1, v2}, Ljava/lang/Math;->pow(DD)D

    .line 140
    .line 141
    .line 142
    move-result-wide v1

    .line 143
    mul-double/2addr v1, v6

    .line 144
    iget-wide v6, v0, Lr6/f;->f:D

    .line 145
    .line 146
    mul-double/2addr v8, v6

    .line 147
    mul-double/2addr v6, v4

    .line 148
    invoke-static {v10, v11, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 149
    .line 150
    .line 151
    move-result-wide v3

    .line 152
    mul-double/2addr v3, v8

    .line 153
    add-double/2addr v3, v1

    .line 154
    goto/16 :goto_3

    .line 155
    .line 156
    :cond_3
    if-nez v1, :cond_4

    .line 157
    .line 158
    iget-wide v1, v0, Lr6/f;->a:D

    .line 159
    .line 160
    mul-double v8, v1, v6

    .line 161
    .line 162
    add-double v8, v8, p5

    .line 163
    .line 164
    mul-double v12, v8, v4

    .line 165
    .line 166
    add-double/2addr v12, v6

    .line 167
    neg-double v1, v1

    .line 168
    mul-double/2addr v1, v4

    .line 169
    invoke-static {v10, v11, v1, v2}, Ljava/lang/Math;->pow(DD)D

    .line 170
    .line 171
    .line 172
    move-result-wide v1

    .line 173
    mul-double/2addr v1, v12

    .line 174
    iget-wide v6, v0, Lr6/f;->a:D

    .line 175
    .line 176
    neg-double v6, v6

    .line 177
    mul-double/2addr v6, v4

    .line 178
    invoke-static {v10, v11, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 179
    .line 180
    .line 181
    move-result-wide v6

    .line 182
    mul-double/2addr v6, v12

    .line 183
    iget-wide v12, v0, Lr6/f;->a:D

    .line 184
    .line 185
    neg-double v12, v12

    .line 186
    mul-double/2addr v6, v12

    .line 187
    mul-double/2addr v12, v4

    .line 188
    invoke-static {v10, v11, v12, v13}, Ljava/lang/Math;->pow(DD)D

    .line 189
    .line 190
    .line 191
    move-result-wide v3

    .line 192
    mul-double/2addr v3, v8

    .line 193
    add-double/2addr v3, v6

    .line 194
    move-wide v12, v1

    .line 195
    goto :goto_3

    .line 196
    :cond_4
    iget-wide v12, v0, Lr6/f;->h:D

    .line 197
    .line 198
    div-double/2addr v2, v12

    .line 199
    iget-wide v12, v0, Lr6/f;->a:D

    .line 200
    .line 201
    mul-double v14, v8, v12

    .line 202
    .line 203
    mul-double/2addr v14, v6

    .line 204
    add-double v14, v14, p5

    .line 205
    .line 206
    mul-double/2addr v14, v2

    .line 207
    neg-double v1, v8

    .line 208
    mul-double/2addr v1, v12

    .line 209
    mul-double/2addr v1, v4

    .line 210
    invoke-static {v10, v11, v1, v2}, Ljava/lang/Math;->pow(DD)D

    .line 211
    .line 212
    .line 213
    move-result-wide v1

    .line 214
    iget-wide v8, v0, Lr6/f;->h:D

    .line 215
    .line 216
    mul-double/2addr v8, v4

    .line 217
    invoke-static {v8, v9}, Ljava/lang/Math;->cos(D)D

    .line 218
    .line 219
    .line 220
    move-result-wide v8

    .line 221
    mul-double/2addr v8, v6

    .line 222
    iget-wide v12, v0, Lr6/f;->h:D

    .line 223
    .line 224
    mul-double/2addr v12, v4

    .line 225
    invoke-static {v12, v13}, Ljava/lang/Math;->sin(D)D

    .line 226
    .line 227
    .line 228
    move-result-wide v12

    .line 229
    mul-double/2addr v12, v14

    .line 230
    add-double/2addr v12, v8

    .line 231
    mul-double/2addr v12, v1

    .line 232
    iget-wide v1, v0, Lr6/f;->a:D

    .line 233
    .line 234
    neg-double v8, v1

    .line 235
    mul-double/2addr v8, v12

    .line 236
    iget-wide v10, v0, Lr6/f;->b:D

    .line 237
    .line 238
    mul-double/2addr v8, v10

    .line 239
    neg-double v10, v10

    .line 240
    mul-double/2addr v10, v1

    .line 241
    mul-double/2addr v10, v4

    .line 242
    const-wide v1, 0x4005bf0a8b145769L    # Math.E

    .line 243
    .line 244
    .line 245
    .line 246
    .line 247
    invoke-static {v1, v2, v10, v11}, Ljava/lang/Math;->pow(DD)D

    .line 248
    .line 249
    .line 250
    move-result-wide v1

    .line 251
    iget-wide v10, v0, Lr6/f;->h:D

    .line 252
    .line 253
    move-wide/from16 p1, v1

    .line 254
    .line 255
    neg-double v1, v10

    .line 256
    mul-double/2addr v1, v6

    .line 257
    mul-double/2addr v10, v4

    .line 258
    invoke-static {v10, v11}, Ljava/lang/Math;->sin(D)D

    .line 259
    .line 260
    .line 261
    move-result-wide v6

    .line 262
    mul-double/2addr v6, v1

    .line 263
    iget-wide v1, v0, Lr6/f;->h:D

    .line 264
    .line 265
    mul-double/2addr v14, v1

    .line 266
    mul-double/2addr v1, v4

    .line 267
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    .line 268
    .line 269
    .line 270
    move-result-wide v1

    .line 271
    mul-double/2addr v1, v14

    .line 272
    add-double/2addr v1, v6

    .line 273
    mul-double v1, v1, p1

    .line 274
    .line 275
    add-double v3, v1, v8

    .line 276
    .line 277
    :goto_3
    iget-wide v1, v0, Lr6/f;->i:D

    .line 278
    .line 279
    add-double/2addr v12, v1

    .line 280
    double-to-float v1, v12

    .line 281
    iget-object v0, v0, Lr6/f;->j:Lb1/x0;

    .line 282
    .line 283
    iput v1, v0, Lb1/x0;->d:F

    .line 284
    .line 285
    double-to-float v1, v3

    .line 286
    iput v1, v0, Lb1/x0;->e:F

    .line 287
    .line 288
    return-object v0

    .line 289
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 290
    .line 291
    const-string v1, "Error: Final position of the spring must be set before the animation starts"

    .line 292
    .line 293
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    throw v0
.end method
