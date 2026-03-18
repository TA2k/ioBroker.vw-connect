.class public final Lr11/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Z

.field public final g:I

.field public final h:I


# direct methods
.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/n;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p3, p0, Lr11/n;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-boolean p4, p0, Lr11/n;->f:Z

    .line 9
    .line 10
    const/4 p1, 0x2

    .line 11
    if-lt p2, p1, :cond_0

    .line 12
    .line 13
    iput p1, p0, Lr11/n;->g:I

    .line 14
    .line 15
    iput p2, p0, Lr11/n;->h:I

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public static f(Ljava/lang/CharSequence;II)I
    .locals 3

    .line 1
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sub-int/2addr v0, p1

    .line 6
    invoke-static {v0, p2}, Ljava/lang/Math;->min(II)I

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    const/4 v0, 0x0

    .line 11
    :goto_0
    if-lez p2, :cond_1

    .line 12
    .line 13
    add-int v1, p1, v0

    .line 14
    .line 15
    invoke-interface {p0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/16 v2, 0x30

    .line 20
    .line 21
    if-lt v1, v2, :cond_1

    .line 22
    .line 23
    const/16 v2, 0x39

    .line 24
    .line 25
    if-le v1, v2, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 29
    .line 30
    add-int/lit8 p2, p2, -0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    :goto_1
    return v0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lr11/n;->e()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 1

    .line 1
    if-nez p6, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    if-nez p5, :cond_1

    .line 5
    .line 6
    iget-object p2, p0, Lr11/n;->d:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p2, :cond_1

    .line 9
    .line 10
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_1
    if-ltz p5, :cond_2

    .line 15
    .line 16
    const/16 p2, 0x2b

    .line 17
    .line 18
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    const/16 p2, 0x2d

    .line 23
    .line 24
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 25
    .line 26
    .line 27
    neg-int p5, p5

    .line 28
    :goto_0
    const p2, 0x36ee80

    .line 29
    .line 30
    .line 31
    div-int p3, p5, p2

    .line 32
    .line 33
    const/4 p4, 0x2

    .line 34
    invoke-static {p1, p3, p4}, Lr11/u;->a(Ljava/lang/Appendable;II)V

    .line 35
    .line 36
    .line 37
    const/4 p6, 0x1

    .line 38
    iget p7, p0, Lr11/n;->h:I

    .line 39
    .line 40
    if-ne p7, p6, :cond_3

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_3
    mul-int/2addr p3, p2

    .line 44
    sub-int/2addr p5, p3

    .line 45
    iget p2, p0, Lr11/n;->g:I

    .line 46
    .line 47
    if-nez p5, :cond_4

    .line 48
    .line 49
    if-gt p2, p6, :cond_4

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_4
    const p3, 0xea60

    .line 53
    .line 54
    .line 55
    div-int p6, p5, p3

    .line 56
    .line 57
    const/16 v0, 0x3a

    .line 58
    .line 59
    iget-boolean p0, p0, Lr11/n;->f:Z

    .line 60
    .line 61
    if-eqz p0, :cond_5

    .line 62
    .line 63
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 64
    .line 65
    .line 66
    :cond_5
    invoke-static {p1, p6, p4}, Lr11/u;->a(Ljava/lang/Appendable;II)V

    .line 67
    .line 68
    .line 69
    if-ne p7, p4, :cond_6

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_6
    mul-int/2addr p6, p3

    .line 73
    sub-int/2addr p5, p6

    .line 74
    if-nez p5, :cond_7

    .line 75
    .line 76
    if-gt p2, p4, :cond_7

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_7
    div-int/lit16 p3, p5, 0x3e8

    .line 80
    .line 81
    if-eqz p0, :cond_8

    .line 82
    .line 83
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 84
    .line 85
    .line 86
    :cond_8
    invoke-static {p1, p3, p4}, Lr11/u;->a(Ljava/lang/Appendable;II)V

    .line 87
    .line 88
    .line 89
    const/4 p4, 0x3

    .line 90
    if-ne p7, p4, :cond_9

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_9
    mul-int/lit16 p3, p3, 0x3e8

    .line 94
    .line 95
    sub-int/2addr p5, p3

    .line 96
    if-nez p5, :cond_a

    .line 97
    .line 98
    if-gt p2, p4, :cond_a

    .line 99
    .line 100
    :goto_1
    return-void

    .line 101
    :cond_a
    if-eqz p0, :cond_b

    .line 102
    .line 103
    const/16 p0, 0x2e

    .line 104
    .line 105
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 106
    .line 107
    .line 108
    :cond_b
    invoke-static {p1, p5, p4}, Lr11/u;->a(Ljava/lang/Appendable;II)V

    .line 109
    .line 110
    .line 111
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 11

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    sub-int/2addr v2, p3

    .line 11
    const/4 v3, 0x0

    .line 12
    const/16 v4, 0x2b

    .line 13
    .line 14
    const/16 v5, 0x2d

    .line 15
    .line 16
    iget-object p0, p0, Lr11/n;->e:Ljava/lang/String;

    .line 17
    .line 18
    if-eqz p0, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 21
    .line 22
    .line 23
    move-result v6

    .line 24
    if-nez v6, :cond_1

    .line 25
    .line 26
    if-lez v2, :cond_0

    .line 27
    .line 28
    invoke-interface {p2, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eq p0, v5, :cond_2

    .line 33
    .line 34
    if-ne p0, v4, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iput-object v3, p1, Lr11/s;->i:Lr11/r;

    .line 38
    .line 39
    iput-object v1, p1, Lr11/s;->e:Ljava/lang/Integer;

    .line 40
    .line 41
    return p3

    .line 42
    :cond_1
    invoke-static {p3, p2, p0}, Lvp/y1;->O(ILjava/lang/CharSequence;Ljava/lang/String;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    iput-object v3, p1, Lr11/s;->i:Lr11/r;

    .line 49
    .line 50
    iput-object v1, p1, Lr11/s;->e:Ljava/lang/Integer;

    .line 51
    .line 52
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    add-int/2addr p0, p3

    .line 57
    return p0

    .line 58
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 59
    if-gt v2, p0, :cond_3

    .line 60
    .line 61
    not-int p0, p3

    .line 62
    return p0

    .line 63
    :cond_3
    invoke-interface {p2, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-ne v1, v5, :cond_4

    .line 68
    .line 69
    move v1, p0

    .line 70
    goto :goto_1

    .line 71
    :cond_4
    if-ne v1, v4, :cond_1b

    .line 72
    .line 73
    move v1, v0

    .line 74
    :goto_1
    add-int/lit8 v4, p3, 0x1

    .line 75
    .line 76
    const/4 v5, 0x2

    .line 77
    invoke-static {p2, v4, v5}, Lr11/n;->f(Ljava/lang/CharSequence;II)I

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    if-ge v6, v5, :cond_5

    .line 82
    .line 83
    not-int p0, v4

    .line 84
    return p0

    .line 85
    :cond_5
    invoke-static {v4, p2}, Lr11/u;->d(ILjava/lang/CharSequence;)I

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    const/16 v7, 0x17

    .line 90
    .line 91
    if-le v6, v7, :cond_6

    .line 92
    .line 93
    not-int p0, v4

    .line 94
    return p0

    .line 95
    :cond_6
    const v4, 0x36ee80

    .line 96
    .line 97
    .line 98
    mul-int/2addr v6, v4

    .line 99
    add-int/lit8 v4, v2, -0x3

    .line 100
    .line 101
    add-int/lit8 v7, p3, 0x3

    .line 102
    .line 103
    if-gtz v4, :cond_7

    .line 104
    .line 105
    goto/16 :goto_7

    .line 106
    .line 107
    :cond_7
    invoke-interface {p2, v7}, Ljava/lang/CharSequence;->charAt(I)C

    .line 108
    .line 109
    .line 110
    move-result v8

    .line 111
    const/16 v9, 0x3a

    .line 112
    .line 113
    const/16 v10, 0x30

    .line 114
    .line 115
    if-ne v8, v9, :cond_8

    .line 116
    .line 117
    add-int/lit8 v4, v2, -0x4

    .line 118
    .line 119
    add-int/lit8 v7, p3, 0x4

    .line 120
    .line 121
    move v0, p0

    .line 122
    goto :goto_2

    .line 123
    :cond_8
    if-lt v8, v10, :cond_19

    .line 124
    .line 125
    const/16 p3, 0x39

    .line 126
    .line 127
    if-gt v8, p3, :cond_19

    .line 128
    .line 129
    :goto_2
    invoke-static {p2, v7, v5}, Lr11/n;->f(Ljava/lang/CharSequence;II)I

    .line 130
    .line 131
    .line 132
    move-result p3

    .line 133
    if-nez p3, :cond_9

    .line 134
    .line 135
    if-nez v0, :cond_9

    .line 136
    .line 137
    goto/16 :goto_7

    .line 138
    .line 139
    :cond_9
    if-ge p3, v5, :cond_a

    .line 140
    .line 141
    not-int p0, v7

    .line 142
    return p0

    .line 143
    :cond_a
    invoke-static {v7, p2}, Lr11/u;->d(ILjava/lang/CharSequence;)I

    .line 144
    .line 145
    .line 146
    move-result p3

    .line 147
    const/16 v2, 0x3b

    .line 148
    .line 149
    if-le p3, v2, :cond_b

    .line 150
    .line 151
    not-int p0, v7

    .line 152
    return p0

    .line 153
    :cond_b
    const v8, 0xea60

    .line 154
    .line 155
    .line 156
    mul-int/2addr p3, v8

    .line 157
    add-int/2addr v6, p3

    .line 158
    add-int/lit8 p3, v4, -0x2

    .line 159
    .line 160
    add-int/lit8 v8, v7, 0x2

    .line 161
    .line 162
    if-gtz p3, :cond_c

    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_c
    if-eqz v0, :cond_e

    .line 166
    .line 167
    invoke-interface {p2, v8}, Ljava/lang/CharSequence;->charAt(I)C

    .line 168
    .line 169
    .line 170
    move-result p3

    .line 171
    if-eq p3, v9, :cond_d

    .line 172
    .line 173
    :goto_3
    move v7, v8

    .line 174
    goto/16 :goto_7

    .line 175
    .line 176
    :cond_d
    add-int/lit8 p3, v4, -0x3

    .line 177
    .line 178
    add-int/lit8 v7, v7, 0x3

    .line 179
    .line 180
    goto :goto_4

    .line 181
    :cond_e
    move v7, v8

    .line 182
    :goto_4
    invoke-static {p2, v7, v5}, Lr11/n;->f(Ljava/lang/CharSequence;II)I

    .line 183
    .line 184
    .line 185
    move-result v4

    .line 186
    if-nez v4, :cond_f

    .line 187
    .line 188
    if-nez v0, :cond_f

    .line 189
    .line 190
    goto/16 :goto_7

    .line 191
    .line 192
    :cond_f
    if-ge v4, v5, :cond_10

    .line 193
    .line 194
    not-int p0, v7

    .line 195
    return p0

    .line 196
    :cond_10
    invoke-static {v7, p2}, Lr11/u;->d(ILjava/lang/CharSequence;)I

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    if-le v4, v2, :cond_11

    .line 201
    .line 202
    not-int p0, v7

    .line 203
    return p0

    .line 204
    :cond_11
    mul-int/lit16 v4, v4, 0x3e8

    .line 205
    .line 206
    add-int/2addr v6, v4

    .line 207
    add-int/lit8 p3, p3, -0x2

    .line 208
    .line 209
    add-int/lit8 v2, v7, 0x2

    .line 210
    .line 211
    if-gtz p3, :cond_12

    .line 212
    .line 213
    goto :goto_5

    .line 214
    :cond_12
    if-eqz v0, :cond_14

    .line 215
    .line 216
    invoke-interface {p2, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 217
    .line 218
    .line 219
    move-result p3

    .line 220
    const/16 v4, 0x2e

    .line 221
    .line 222
    if-eq p3, v4, :cond_13

    .line 223
    .line 224
    invoke-interface {p2, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 225
    .line 226
    .line 227
    move-result p3

    .line 228
    const/16 v4, 0x2c

    .line 229
    .line 230
    if-eq p3, v4, :cond_13

    .line 231
    .line 232
    :goto_5
    move v7, v2

    .line 233
    goto :goto_7

    .line 234
    :cond_13
    add-int/lit8 v7, v7, 0x3

    .line 235
    .line 236
    goto :goto_6

    .line 237
    :cond_14
    move v7, v2

    .line 238
    :goto_6
    const/4 p3, 0x3

    .line 239
    invoke-static {p2, v7, p3}, Lr11/n;->f(Ljava/lang/CharSequence;II)I

    .line 240
    .line 241
    .line 242
    move-result p3

    .line 243
    if-nez p3, :cond_15

    .line 244
    .line 245
    if-nez v0, :cond_15

    .line 246
    .line 247
    goto :goto_7

    .line 248
    :cond_15
    if-ge p3, p0, :cond_16

    .line 249
    .line 250
    not-int p0, v7

    .line 251
    return p0

    .line 252
    :cond_16
    add-int/lit8 v0, v7, 0x1

    .line 253
    .line 254
    invoke-interface {p2, v7}, Ljava/lang/CharSequence;->charAt(I)C

    .line 255
    .line 256
    .line 257
    move-result v2

    .line 258
    sub-int/2addr v2, v10

    .line 259
    mul-int/lit8 v2, v2, 0x64

    .line 260
    .line 261
    add-int/2addr v6, v2

    .line 262
    if-le p3, p0, :cond_18

    .line 263
    .line 264
    add-int/lit8 p0, v7, 0x2

    .line 265
    .line 266
    invoke-interface {p2, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 267
    .line 268
    .line 269
    move-result v0

    .line 270
    sub-int/2addr v0, v10

    .line 271
    mul-int/lit8 v0, v0, 0xa

    .line 272
    .line 273
    add-int/2addr v6, v0

    .line 274
    if-le p3, v5, :cond_17

    .line 275
    .line 276
    add-int/lit8 v7, v7, 0x3

    .line 277
    .line 278
    invoke-interface {p2, p0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 279
    .line 280
    .line 281
    move-result p0

    .line 282
    sub-int/2addr p0, v10

    .line 283
    add-int/2addr v6, p0

    .line 284
    goto :goto_7

    .line 285
    :cond_17
    move v7, p0

    .line 286
    goto :goto_7

    .line 287
    :cond_18
    move v7, v0

    .line 288
    :cond_19
    :goto_7
    if-eqz v1, :cond_1a

    .line 289
    .line 290
    neg-int v6, v6

    .line 291
    :cond_1a
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 292
    .line 293
    .line 294
    move-result-object p0

    .line 295
    iput-object v3, p1, Lr11/s;->i:Lr11/r;

    .line 296
    .line 297
    iput-object p0, p1, Lr11/s;->e:Ljava/lang/Integer;

    .line 298
    .line 299
    return v7

    .line 300
    :cond_1b
    not-int p0, p3

    .line 301
    return p0
.end method

.method public final e()I
    .locals 3

    .line 1
    iget v0, p0, Lr11/n;->g:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    shl-int/lit8 v1, v1, 0x1

    .line 6
    .line 7
    iget-boolean v2, p0, Lr11/n;->f:Z

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    add-int/lit8 v0, v0, -0x1

    .line 12
    .line 13
    add-int/2addr v1, v0

    .line 14
    :cond_0
    iget-object p0, p0, Lr11/n;->d:Ljava/lang/String;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-le v0, v1, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0

    .line 29
    :cond_1
    return v1
.end method
