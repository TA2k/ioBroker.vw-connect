.class public final La5/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public final b:La5/b;

.field public final c:Lgw0/c;

.field public d:I

.field public e:[I

.field public f:[I

.field public g:[F

.field public h:I

.field public i:I

.field public j:Z


# direct methods
.method public constructor <init>(La5/b;Lgw0/c;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, La5/a;->a:I

    .line 6
    .line 7
    const/16 v1, 0x8

    .line 8
    .line 9
    iput v1, p0, La5/a;->d:I

    .line 10
    .line 11
    new-array v2, v1, [I

    .line 12
    .line 13
    iput-object v2, p0, La5/a;->e:[I

    .line 14
    .line 15
    new-array v2, v1, [I

    .line 16
    .line 17
    iput-object v2, p0, La5/a;->f:[I

    .line 18
    .line 19
    new-array v1, v1, [F

    .line 20
    .line 21
    iput-object v1, p0, La5/a;->g:[F

    .line 22
    .line 23
    const/4 v1, -0x1

    .line 24
    iput v1, p0, La5/a;->h:I

    .line 25
    .line 26
    iput v1, p0, La5/a;->i:I

    .line 27
    .line 28
    iput-boolean v0, p0, La5/a;->j:Z

    .line 29
    .line 30
    iput-object p1, p0, La5/a;->b:La5/b;

    .line 31
    .line 32
    iput-object p2, p0, La5/a;->c:Lgw0/c;

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final a(La5/h;FZ)V
    .locals 11

    .line 1
    const v0, -0x457ced91    # -0.001f

    .line 2
    .line 3
    .line 4
    cmpl-float v1, p2, v0

    .line 5
    .line 6
    const v2, 0x3a83126f    # 0.001f

    .line 7
    .line 8
    .line 9
    if-lez v1, :cond_0

    .line 10
    .line 11
    cmpg-float v1, p2, v2

    .line 12
    .line 13
    if-gez v1, :cond_0

    .line 14
    .line 15
    goto/16 :goto_6

    .line 16
    .line 17
    :cond_0
    iget v1, p0, La5/a;->h:I

    .line 18
    .line 19
    iget-object v3, p0, La5/a;->b:La5/b;

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, -0x1

    .line 23
    const/4 v6, 0x1

    .line 24
    if-ne v1, v5, :cond_1

    .line 25
    .line 26
    iput v4, p0, La5/a;->h:I

    .line 27
    .line 28
    iget-object p3, p0, La5/a;->g:[F

    .line 29
    .line 30
    aput p2, p3, v4

    .line 31
    .line 32
    iget-object p2, p0, La5/a;->e:[I

    .line 33
    .line 34
    iget p3, p1, La5/h;->e:I

    .line 35
    .line 36
    aput p3, p2, v4

    .line 37
    .line 38
    iget-object p2, p0, La5/a;->f:[I

    .line 39
    .line 40
    aput v5, p2, v4

    .line 41
    .line 42
    iget p2, p1, La5/h;->n:I

    .line 43
    .line 44
    add-int/2addr p2, v6

    .line 45
    iput p2, p1, La5/h;->n:I

    .line 46
    .line 47
    invoke-virtual {p1, v3}, La5/h;->a(La5/b;)V

    .line 48
    .line 49
    .line 50
    iget p1, p0, La5/a;->a:I

    .line 51
    .line 52
    add-int/2addr p1, v6

    .line 53
    iput p1, p0, La5/a;->a:I

    .line 54
    .line 55
    iget-boolean p1, p0, La5/a;->j:Z

    .line 56
    .line 57
    if-nez p1, :cond_10

    .line 58
    .line 59
    iget p1, p0, La5/a;->i:I

    .line 60
    .line 61
    add-int/2addr p1, v6

    .line 62
    iput p1, p0, La5/a;->i:I

    .line 63
    .line 64
    iget-object p2, p0, La5/a;->e:[I

    .line 65
    .line 66
    array-length p3, p2

    .line 67
    if-lt p1, p3, :cond_10

    .line 68
    .line 69
    iput-boolean v6, p0, La5/a;->j:Z

    .line 70
    .line 71
    array-length p1, p2

    .line 72
    sub-int/2addr p1, v6

    .line 73
    iput p1, p0, La5/a;->i:I

    .line 74
    .line 75
    return-void

    .line 76
    :cond_1
    move v7, v4

    .line 77
    move v8, v5

    .line 78
    :goto_0
    if-eq v1, v5, :cond_8

    .line 79
    .line 80
    iget v9, p0, La5/a;->a:I

    .line 81
    .line 82
    if-ge v7, v9, :cond_8

    .line 83
    .line 84
    iget-object v9, p0, La5/a;->e:[I

    .line 85
    .line 86
    aget v9, v9, v1

    .line 87
    .line 88
    iget v10, p1, La5/h;->e:I

    .line 89
    .line 90
    if-ne v9, v10, :cond_6

    .line 91
    .line 92
    iget-object v4, p0, La5/a;->g:[F

    .line 93
    .line 94
    aget v5, v4, v1

    .line 95
    .line 96
    add-float/2addr v5, p2

    .line 97
    cmpl-float p2, v5, v0

    .line 98
    .line 99
    const/4 v0, 0x0

    .line 100
    if-lez p2, :cond_2

    .line 101
    .line 102
    cmpg-float p2, v5, v2

    .line 103
    .line 104
    if-gez p2, :cond_2

    .line 105
    .line 106
    move v5, v0

    .line 107
    :cond_2
    aput v5, v4, v1

    .line 108
    .line 109
    cmpl-float p2, v5, v0

    .line 110
    .line 111
    if-nez p2, :cond_10

    .line 112
    .line 113
    iget p2, p0, La5/a;->h:I

    .line 114
    .line 115
    if-ne v1, p2, :cond_3

    .line 116
    .line 117
    iget-object p2, p0, La5/a;->f:[I

    .line 118
    .line 119
    aget p2, p2, v1

    .line 120
    .line 121
    iput p2, p0, La5/a;->h:I

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_3
    iget-object p2, p0, La5/a;->f:[I

    .line 125
    .line 126
    aget v0, p2, v1

    .line 127
    .line 128
    aput v0, p2, v8

    .line 129
    .line 130
    :goto_1
    if-eqz p3, :cond_4

    .line 131
    .line 132
    invoke-virtual {p1, v3}, La5/h;->b(La5/b;)V

    .line 133
    .line 134
    .line 135
    :cond_4
    iget-boolean p2, p0, La5/a;->j:Z

    .line 136
    .line 137
    if-eqz p2, :cond_5

    .line 138
    .line 139
    iput v1, p0, La5/a;->i:I

    .line 140
    .line 141
    :cond_5
    iget p2, p1, La5/h;->n:I

    .line 142
    .line 143
    sub-int/2addr p2, v6

    .line 144
    iput p2, p1, La5/h;->n:I

    .line 145
    .line 146
    iget p1, p0, La5/a;->a:I

    .line 147
    .line 148
    sub-int/2addr p1, v6

    .line 149
    iput p1, p0, La5/a;->a:I

    .line 150
    .line 151
    return-void

    .line 152
    :cond_6
    if-ge v9, v10, :cond_7

    .line 153
    .line 154
    move v8, v1

    .line 155
    :cond_7
    iget-object v9, p0, La5/a;->f:[I

    .line 156
    .line 157
    aget v1, v9, v1

    .line 158
    .line 159
    add-int/lit8 v7, v7, 0x1

    .line 160
    .line 161
    goto :goto_0

    .line 162
    :cond_8
    iget p3, p0, La5/a;->i:I

    .line 163
    .line 164
    add-int/lit8 v0, p3, 0x1

    .line 165
    .line 166
    iget-boolean v1, p0, La5/a;->j:Z

    .line 167
    .line 168
    if-eqz v1, :cond_a

    .line 169
    .line 170
    iget-object v0, p0, La5/a;->e:[I

    .line 171
    .line 172
    aget v1, v0, p3

    .line 173
    .line 174
    if-ne v1, v5, :cond_9

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_9
    array-length p3, v0

    .line 178
    goto :goto_2

    .line 179
    :cond_a
    move p3, v0

    .line 180
    :goto_2
    iget-object v0, p0, La5/a;->e:[I

    .line 181
    .line 182
    array-length v1, v0

    .line 183
    if-lt p3, v1, :cond_c

    .line 184
    .line 185
    iget v1, p0, La5/a;->a:I

    .line 186
    .line 187
    array-length v0, v0

    .line 188
    if-ge v1, v0, :cond_c

    .line 189
    .line 190
    move v0, v4

    .line 191
    :goto_3
    iget-object v1, p0, La5/a;->e:[I

    .line 192
    .line 193
    array-length v2, v1

    .line 194
    if-ge v0, v2, :cond_c

    .line 195
    .line 196
    aget v1, v1, v0

    .line 197
    .line 198
    if-ne v1, v5, :cond_b

    .line 199
    .line 200
    move p3, v0

    .line 201
    goto :goto_4

    .line 202
    :cond_b
    add-int/lit8 v0, v0, 0x1

    .line 203
    .line 204
    goto :goto_3

    .line 205
    :cond_c
    :goto_4
    iget-object v0, p0, La5/a;->e:[I

    .line 206
    .line 207
    array-length v1, v0

    .line 208
    if-lt p3, v1, :cond_d

    .line 209
    .line 210
    array-length p3, v0

    .line 211
    iget v0, p0, La5/a;->d:I

    .line 212
    .line 213
    mul-int/lit8 v0, v0, 0x2

    .line 214
    .line 215
    iput v0, p0, La5/a;->d:I

    .line 216
    .line 217
    iput-boolean v4, p0, La5/a;->j:Z

    .line 218
    .line 219
    add-int/lit8 v1, p3, -0x1

    .line 220
    .line 221
    iput v1, p0, La5/a;->i:I

    .line 222
    .line 223
    iget-object v1, p0, La5/a;->g:[F

    .line 224
    .line 225
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([FI)[F

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    iput-object v0, p0, La5/a;->g:[F

    .line 230
    .line 231
    iget-object v0, p0, La5/a;->e:[I

    .line 232
    .line 233
    iget v1, p0, La5/a;->d:I

    .line 234
    .line 235
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    iput-object v0, p0, La5/a;->e:[I

    .line 240
    .line 241
    iget-object v0, p0, La5/a;->f:[I

    .line 242
    .line 243
    iget v1, p0, La5/a;->d:I

    .line 244
    .line 245
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    iput-object v0, p0, La5/a;->f:[I

    .line 250
    .line 251
    :cond_d
    iget-object v0, p0, La5/a;->e:[I

    .line 252
    .line 253
    iget v1, p1, La5/h;->e:I

    .line 254
    .line 255
    aput v1, v0, p3

    .line 256
    .line 257
    iget-object v0, p0, La5/a;->g:[F

    .line 258
    .line 259
    aput p2, v0, p3

    .line 260
    .line 261
    if-eq v8, v5, :cond_e

    .line 262
    .line 263
    iget-object p2, p0, La5/a;->f:[I

    .line 264
    .line 265
    aget v0, p2, v8

    .line 266
    .line 267
    aput v0, p2, p3

    .line 268
    .line 269
    aput p3, p2, v8

    .line 270
    .line 271
    goto :goto_5

    .line 272
    :cond_e
    iget-object p2, p0, La5/a;->f:[I

    .line 273
    .line 274
    iget v0, p0, La5/a;->h:I

    .line 275
    .line 276
    aput v0, p2, p3

    .line 277
    .line 278
    iput p3, p0, La5/a;->h:I

    .line 279
    .line 280
    :goto_5
    iget p2, p1, La5/h;->n:I

    .line 281
    .line 282
    add-int/2addr p2, v6

    .line 283
    iput p2, p1, La5/h;->n:I

    .line 284
    .line 285
    invoke-virtual {p1, v3}, La5/h;->a(La5/b;)V

    .line 286
    .line 287
    .line 288
    iget p1, p0, La5/a;->a:I

    .line 289
    .line 290
    add-int/2addr p1, v6

    .line 291
    iput p1, p0, La5/a;->a:I

    .line 292
    .line 293
    iget-boolean p1, p0, La5/a;->j:Z

    .line 294
    .line 295
    if-nez p1, :cond_f

    .line 296
    .line 297
    iget p1, p0, La5/a;->i:I

    .line 298
    .line 299
    add-int/2addr p1, v6

    .line 300
    iput p1, p0, La5/a;->i:I

    .line 301
    .line 302
    :cond_f
    iget p1, p0, La5/a;->i:I

    .line 303
    .line 304
    iget-object p2, p0, La5/a;->e:[I

    .line 305
    .line 306
    array-length p3, p2

    .line 307
    if-lt p1, p3, :cond_10

    .line 308
    .line 309
    iput-boolean v6, p0, La5/a;->j:Z

    .line 310
    .line 311
    array-length p1, p2

    .line 312
    sub-int/2addr p1, v6

    .line 313
    iput p1, p0, La5/a;->i:I

    .line 314
    .line 315
    :cond_10
    :goto_6
    return-void
.end method

.method public final b()V
    .locals 5

    .line 1
    iget v0, p0, La5/a;->h:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    move v2, v1

    .line 5
    :goto_0
    const/4 v3, -0x1

    .line 6
    if-eq v0, v3, :cond_1

    .line 7
    .line 8
    iget v4, p0, La5/a;->a:I

    .line 9
    .line 10
    if-ge v2, v4, :cond_1

    .line 11
    .line 12
    iget-object v3, p0, La5/a;->c:Lgw0/c;

    .line 13
    .line 14
    iget-object v3, v3, Lgw0/c;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v3, [La5/h;

    .line 17
    .line 18
    iget-object v4, p0, La5/a;->e:[I

    .line 19
    .line 20
    aget v4, v4, v0

    .line 21
    .line 22
    aget-object v3, v3, v4

    .line 23
    .line 24
    if-eqz v3, :cond_0

    .line 25
    .line 26
    iget-object v4, p0, La5/a;->b:La5/b;

    .line 27
    .line 28
    invoke-virtual {v3, v4}, La5/h;->b(La5/b;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    iget-object v3, p0, La5/a;->f:[I

    .line 32
    .line 33
    aget v0, v3, v0

    .line 34
    .line 35
    add-int/lit8 v2, v2, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    iput v3, p0, La5/a;->h:I

    .line 39
    .line 40
    iput v3, p0, La5/a;->i:I

    .line 41
    .line 42
    iput-boolean v1, p0, La5/a;->j:Z

    .line 43
    .line 44
    iput v1, p0, La5/a;->a:I

    .line 45
    .line 46
    return-void
.end method

.method public final c(La5/h;)F
    .locals 4

    .line 1
    iget v0, p0, La5/a;->h:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :goto_0
    const/4 v2, -0x1

    .line 5
    if-eq v0, v2, :cond_1

    .line 6
    .line 7
    iget v2, p0, La5/a;->a:I

    .line 8
    .line 9
    if-ge v1, v2, :cond_1

    .line 10
    .line 11
    iget-object v2, p0, La5/a;->e:[I

    .line 12
    .line 13
    aget v2, v2, v0

    .line 14
    .line 15
    iget v3, p1, La5/h;->e:I

    .line 16
    .line 17
    if-ne v2, v3, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, La5/a;->g:[F

    .line 20
    .line 21
    aget p0, p0, v0

    .line 22
    .line 23
    return p0

    .line 24
    :cond_0
    iget-object v2, p0, La5/a;->f:[I

    .line 25
    .line 26
    aget v0, v2, v0

    .line 27
    .line 28
    add-int/lit8 v1, v1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const/4 p0, 0x0

    .line 32
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget p0, p0, La5/a;->a:I

    .line 2
    .line 3
    return p0
.end method

.method public final e(I)La5/h;
    .locals 3

    .line 1
    iget v0, p0, La5/a;->h:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :goto_0
    const/4 v2, -0x1

    .line 5
    if-eq v0, v2, :cond_1

    .line 6
    .line 7
    iget v2, p0, La5/a;->a:I

    .line 8
    .line 9
    if-ge v1, v2, :cond_1

    .line 10
    .line 11
    if-ne v1, p1, :cond_0

    .line 12
    .line 13
    iget-object p1, p0, La5/a;->c:Lgw0/c;

    .line 14
    .line 15
    iget-object p1, p1, Lgw0/c;->g:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p1, [La5/h;

    .line 18
    .line 19
    iget-object p0, p0, La5/a;->e:[I

    .line 20
    .line 21
    aget p0, p0, v0

    .line 22
    .line 23
    aget-object p0, p1, p0

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_0
    iget-object v2, p0, La5/a;->f:[I

    .line 27
    .line 28
    aget v0, v2, v0

    .line 29
    .line 30
    add-int/lit8 v1, v1, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return-object p0
.end method

.method public final f(I)F
    .locals 3

    .line 1
    iget v0, p0, La5/a;->h:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :goto_0
    const/4 v2, -0x1

    .line 5
    if-eq v0, v2, :cond_1

    .line 6
    .line 7
    iget v2, p0, La5/a;->a:I

    .line 8
    .line 9
    if-ge v1, v2, :cond_1

    .line 10
    .line 11
    if-ne v1, p1, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, La5/a;->g:[F

    .line 14
    .line 15
    aget p0, p0, v0

    .line 16
    .line 17
    return p0

    .line 18
    :cond_0
    iget-object v2, p0, La5/a;->f:[I

    .line 19
    .line 20
    aget v0, v2, v0

    .line 21
    .line 22
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    return p0
.end method

.method public final g(La5/h;F)V
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpl-float v0, p2, v0

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1, v1}, La5/a;->h(La5/h;Z)F

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget v0, p0, La5/a;->h:I

    .line 12
    .line 13
    iget-object v2, p0, La5/a;->b:La5/b;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    const/4 v4, -0x1

    .line 17
    if-ne v0, v4, :cond_1

    .line 18
    .line 19
    iput v3, p0, La5/a;->h:I

    .line 20
    .line 21
    iget-object v0, p0, La5/a;->g:[F

    .line 22
    .line 23
    aput p2, v0, v3

    .line 24
    .line 25
    iget-object p2, p0, La5/a;->e:[I

    .line 26
    .line 27
    iget v0, p1, La5/h;->e:I

    .line 28
    .line 29
    aput v0, p2, v3

    .line 30
    .line 31
    iget-object p2, p0, La5/a;->f:[I

    .line 32
    .line 33
    aput v4, p2, v3

    .line 34
    .line 35
    iget p2, p1, La5/h;->n:I

    .line 36
    .line 37
    add-int/2addr p2, v1

    .line 38
    iput p2, p1, La5/h;->n:I

    .line 39
    .line 40
    invoke-virtual {p1, v2}, La5/h;->a(La5/b;)V

    .line 41
    .line 42
    .line 43
    iget p1, p0, La5/a;->a:I

    .line 44
    .line 45
    add-int/2addr p1, v1

    .line 46
    iput p1, p0, La5/a;->a:I

    .line 47
    .line 48
    iget-boolean p1, p0, La5/a;->j:Z

    .line 49
    .line 50
    if-nez p1, :cond_d

    .line 51
    .line 52
    iget p1, p0, La5/a;->i:I

    .line 53
    .line 54
    add-int/2addr p1, v1

    .line 55
    iput p1, p0, La5/a;->i:I

    .line 56
    .line 57
    iget-object p2, p0, La5/a;->e:[I

    .line 58
    .line 59
    array-length v0, p2

    .line 60
    if-lt p1, v0, :cond_d

    .line 61
    .line 62
    iput-boolean v1, p0, La5/a;->j:Z

    .line 63
    .line 64
    array-length p1, p2

    .line 65
    sub-int/2addr p1, v1

    .line 66
    iput p1, p0, La5/a;->i:I

    .line 67
    .line 68
    return-void

    .line 69
    :cond_1
    move v5, v3

    .line 70
    move v6, v4

    .line 71
    :goto_0
    if-eq v0, v4, :cond_4

    .line 72
    .line 73
    iget v7, p0, La5/a;->a:I

    .line 74
    .line 75
    if-ge v5, v7, :cond_4

    .line 76
    .line 77
    iget-object v7, p0, La5/a;->e:[I

    .line 78
    .line 79
    aget v7, v7, v0

    .line 80
    .line 81
    iget v8, p1, La5/h;->e:I

    .line 82
    .line 83
    if-ne v7, v8, :cond_2

    .line 84
    .line 85
    iget-object p0, p0, La5/a;->g:[F

    .line 86
    .line 87
    aput p2, p0, v0

    .line 88
    .line 89
    return-void

    .line 90
    :cond_2
    if-ge v7, v8, :cond_3

    .line 91
    .line 92
    move v6, v0

    .line 93
    :cond_3
    iget-object v7, p0, La5/a;->f:[I

    .line 94
    .line 95
    aget v0, v7, v0

    .line 96
    .line 97
    add-int/lit8 v5, v5, 0x1

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_4
    iget v0, p0, La5/a;->i:I

    .line 101
    .line 102
    add-int/lit8 v5, v0, 0x1

    .line 103
    .line 104
    iget-boolean v7, p0, La5/a;->j:Z

    .line 105
    .line 106
    if-eqz v7, :cond_6

    .line 107
    .line 108
    iget-object v5, p0, La5/a;->e:[I

    .line 109
    .line 110
    aget v7, v5, v0

    .line 111
    .line 112
    if-ne v7, v4, :cond_5

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_5
    array-length v0, v5

    .line 116
    goto :goto_1

    .line 117
    :cond_6
    move v0, v5

    .line 118
    :goto_1
    iget-object v5, p0, La5/a;->e:[I

    .line 119
    .line 120
    array-length v7, v5

    .line 121
    if-lt v0, v7, :cond_8

    .line 122
    .line 123
    iget v7, p0, La5/a;->a:I

    .line 124
    .line 125
    array-length v5, v5

    .line 126
    if-ge v7, v5, :cond_8

    .line 127
    .line 128
    move v5, v3

    .line 129
    :goto_2
    iget-object v7, p0, La5/a;->e:[I

    .line 130
    .line 131
    array-length v8, v7

    .line 132
    if-ge v5, v8, :cond_8

    .line 133
    .line 134
    aget v7, v7, v5

    .line 135
    .line 136
    if-ne v7, v4, :cond_7

    .line 137
    .line 138
    move v0, v5

    .line 139
    goto :goto_3

    .line 140
    :cond_7
    add-int/lit8 v5, v5, 0x1

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_8
    :goto_3
    iget-object v5, p0, La5/a;->e:[I

    .line 144
    .line 145
    array-length v7, v5

    .line 146
    if-lt v0, v7, :cond_9

    .line 147
    .line 148
    array-length v0, v5

    .line 149
    iget v5, p0, La5/a;->d:I

    .line 150
    .line 151
    mul-int/lit8 v5, v5, 0x2

    .line 152
    .line 153
    iput v5, p0, La5/a;->d:I

    .line 154
    .line 155
    iput-boolean v3, p0, La5/a;->j:Z

    .line 156
    .line 157
    add-int/lit8 v3, v0, -0x1

    .line 158
    .line 159
    iput v3, p0, La5/a;->i:I

    .line 160
    .line 161
    iget-object v3, p0, La5/a;->g:[F

    .line 162
    .line 163
    invoke-static {v3, v5}, Ljava/util/Arrays;->copyOf([FI)[F

    .line 164
    .line 165
    .line 166
    move-result-object v3

    .line 167
    iput-object v3, p0, La5/a;->g:[F

    .line 168
    .line 169
    iget-object v3, p0, La5/a;->e:[I

    .line 170
    .line 171
    iget v5, p0, La5/a;->d:I

    .line 172
    .line 173
    invoke-static {v3, v5}, Ljava/util/Arrays;->copyOf([II)[I

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    iput-object v3, p0, La5/a;->e:[I

    .line 178
    .line 179
    iget-object v3, p0, La5/a;->f:[I

    .line 180
    .line 181
    iget v5, p0, La5/a;->d:I

    .line 182
    .line 183
    invoke-static {v3, v5}, Ljava/util/Arrays;->copyOf([II)[I

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    iput-object v3, p0, La5/a;->f:[I

    .line 188
    .line 189
    :cond_9
    iget-object v3, p0, La5/a;->e:[I

    .line 190
    .line 191
    iget v5, p1, La5/h;->e:I

    .line 192
    .line 193
    aput v5, v3, v0

    .line 194
    .line 195
    iget-object v3, p0, La5/a;->g:[F

    .line 196
    .line 197
    aput p2, v3, v0

    .line 198
    .line 199
    if-eq v6, v4, :cond_a

    .line 200
    .line 201
    iget-object p2, p0, La5/a;->f:[I

    .line 202
    .line 203
    aget v3, p2, v6

    .line 204
    .line 205
    aput v3, p2, v0

    .line 206
    .line 207
    aput v0, p2, v6

    .line 208
    .line 209
    goto :goto_4

    .line 210
    :cond_a
    iget-object p2, p0, La5/a;->f:[I

    .line 211
    .line 212
    iget v3, p0, La5/a;->h:I

    .line 213
    .line 214
    aput v3, p2, v0

    .line 215
    .line 216
    iput v0, p0, La5/a;->h:I

    .line 217
    .line 218
    :goto_4
    iget p2, p1, La5/h;->n:I

    .line 219
    .line 220
    add-int/2addr p2, v1

    .line 221
    iput p2, p1, La5/h;->n:I

    .line 222
    .line 223
    invoke-virtual {p1, v2}, La5/h;->a(La5/b;)V

    .line 224
    .line 225
    .line 226
    iget p1, p0, La5/a;->a:I

    .line 227
    .line 228
    add-int/2addr p1, v1

    .line 229
    iput p1, p0, La5/a;->a:I

    .line 230
    .line 231
    iget-boolean p2, p0, La5/a;->j:Z

    .line 232
    .line 233
    if-nez p2, :cond_b

    .line 234
    .line 235
    iget p2, p0, La5/a;->i:I

    .line 236
    .line 237
    add-int/2addr p2, v1

    .line 238
    iput p2, p0, La5/a;->i:I

    .line 239
    .line 240
    :cond_b
    iget-object p2, p0, La5/a;->e:[I

    .line 241
    .line 242
    array-length v0, p2

    .line 243
    if-lt p1, v0, :cond_c

    .line 244
    .line 245
    iput-boolean v1, p0, La5/a;->j:Z

    .line 246
    .line 247
    :cond_c
    iget p1, p0, La5/a;->i:I

    .line 248
    .line 249
    array-length v0, p2

    .line 250
    if-lt p1, v0, :cond_d

    .line 251
    .line 252
    iput-boolean v1, p0, La5/a;->j:Z

    .line 253
    .line 254
    array-length p1, p2

    .line 255
    sub-int/2addr p1, v1

    .line 256
    iput p1, p0, La5/a;->i:I

    .line 257
    .line 258
    :cond_d
    return-void
.end method

.method public final h(La5/h;Z)F
    .locals 7

    .line 1
    iget v0, p0, La5/a;->h:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    goto :goto_2

    .line 7
    :cond_0
    const/4 v2, 0x0

    .line 8
    move v3, v1

    .line 9
    :goto_0
    if-eq v0, v1, :cond_5

    .line 10
    .line 11
    iget v4, p0, La5/a;->a:I

    .line 12
    .line 13
    if-ge v2, v4, :cond_5

    .line 14
    .line 15
    iget-object v4, p0, La5/a;->e:[I

    .line 16
    .line 17
    aget v4, v4, v0

    .line 18
    .line 19
    iget v5, p1, La5/h;->e:I

    .line 20
    .line 21
    if-ne v4, v5, :cond_4

    .line 22
    .line 23
    iget v2, p0, La5/a;->h:I

    .line 24
    .line 25
    if-ne v0, v2, :cond_1

    .line 26
    .line 27
    iget-object v2, p0, La5/a;->f:[I

    .line 28
    .line 29
    aget v2, v2, v0

    .line 30
    .line 31
    iput v2, p0, La5/a;->h:I

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    iget-object v2, p0, La5/a;->f:[I

    .line 35
    .line 36
    aget v4, v2, v0

    .line 37
    .line 38
    aput v4, v2, v3

    .line 39
    .line 40
    :goto_1
    if-eqz p2, :cond_2

    .line 41
    .line 42
    iget-object p2, p0, La5/a;->b:La5/b;

    .line 43
    .line 44
    invoke-virtual {p1, p2}, La5/h;->b(La5/b;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    iget p2, p1, La5/h;->n:I

    .line 48
    .line 49
    add-int/lit8 p2, p2, -0x1

    .line 50
    .line 51
    iput p2, p1, La5/h;->n:I

    .line 52
    .line 53
    iget p1, p0, La5/a;->a:I

    .line 54
    .line 55
    add-int/lit8 p1, p1, -0x1

    .line 56
    .line 57
    iput p1, p0, La5/a;->a:I

    .line 58
    .line 59
    iget-object p1, p0, La5/a;->e:[I

    .line 60
    .line 61
    aput v1, p1, v0

    .line 62
    .line 63
    iget-boolean p1, p0, La5/a;->j:Z

    .line 64
    .line 65
    if-eqz p1, :cond_3

    .line 66
    .line 67
    iput v0, p0, La5/a;->i:I

    .line 68
    .line 69
    :cond_3
    iget-object p0, p0, La5/a;->g:[F

    .line 70
    .line 71
    aget p0, p0, v0

    .line 72
    .line 73
    return p0

    .line 74
    :cond_4
    iget-object v3, p0, La5/a;->f:[I

    .line 75
    .line 76
    aget v3, v3, v0

    .line 77
    .line 78
    add-int/lit8 v2, v2, 0x1

    .line 79
    .line 80
    move v6, v3

    .line 81
    move v3, v0

    .line 82
    move v0, v6

    .line 83
    goto :goto_0

    .line 84
    :cond_5
    :goto_2
    const/4 p0, 0x0

    .line 85
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, La5/a;->h:I

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    :goto_0
    const/4 v3, -0x1

    .line 7
    if-eq v0, v3, :cond_0

    .line 8
    .line 9
    iget v3, p0, La5/a;->a:I

    .line 10
    .line 11
    if-ge v2, v3, :cond_0

    .line 12
    .line 13
    const-string v3, " -> "

    .line 14
    .line 15
    invoke-static {v1, v3}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-static {v1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iget-object v3, p0, La5/a;->g:[F

    .line 24
    .line 25
    aget v3, v3, v0

    .line 26
    .line 27
    const-string v4, " : "

    .line 28
    .line 29
    invoke-static {v3, v4, v1}, Lkx/a;->g(FLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-static {v1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    iget-object v3, p0, La5/a;->c:Lgw0/c;

    .line 38
    .line 39
    iget-object v3, v3, Lgw0/c;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v3, [La5/h;

    .line 42
    .line 43
    iget-object v4, p0, La5/a;->e:[I

    .line 44
    .line 45
    aget v4, v4, v0

    .line 46
    .line 47
    aget-object v3, v3, v4

    .line 48
    .line 49
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    iget-object v3, p0, La5/a;->f:[I

    .line 57
    .line 58
    aget v0, v3, v0

    .line 59
    .line 60
    add-int/lit8 v2, v2, 0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    return-object v1
.end method
