.class public abstract Ls01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[C


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    new-array v0, v0, [C

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Ls01/a;->a:[C

    .line 9
    .line 10
    return-void

    .line 11
    :array_0
    .array-data 2
        0x30s
        0x31s
        0x32s
        0x33s
        0x34s
        0x35s
        0x36s
        0x37s
        0x38s
        0x39s
        0x41s
        0x42s
        0x43s
        0x44s
        0x45s
        0x46s
    .end array-data
.end method

.method public static a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;
    .locals 11

    .line 1
    and-int/lit8 v0, p2, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move v3, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v3, p0

    .line 9
    :goto_0
    and-int/lit8 p0, p2, 0x2

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    :cond_1
    move v4, p1

    .line 18
    and-int/lit8 p0, p2, 0x8

    .line 19
    .line 20
    if-eqz p0, :cond_2

    .line 21
    .line 22
    move v6, v1

    .line 23
    goto :goto_1

    .line 24
    :cond_2
    move/from16 v6, p5

    .line 25
    .line 26
    :goto_1
    and-int/lit8 p0, p2, 0x10

    .line 27
    .line 28
    const/4 p1, 0x1

    .line 29
    if-eqz p0, :cond_3

    .line 30
    .line 31
    move v7, v1

    .line 32
    goto :goto_2

    .line 33
    :cond_3
    move v7, p1

    .line 34
    :goto_2
    and-int/lit8 p0, p2, 0x20

    .line 35
    .line 36
    if-eqz p0, :cond_4

    .line 37
    .line 38
    move v8, v1

    .line 39
    goto :goto_3

    .line 40
    :cond_4
    move v8, p1

    .line 41
    :goto_3
    and-int/lit8 p0, p2, 0x40

    .line 42
    .line 43
    if-eqz p0, :cond_5

    .line 44
    .line 45
    move v9, v1

    .line 46
    goto :goto_4

    .line 47
    :cond_5
    move v9, p1

    .line 48
    :goto_4
    const-string p0, "<this>"

    .line 49
    .line 50
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const/16 v10, 0x80

    .line 54
    .line 55
    move-object v2, p3

    .line 56
    move-object v5, p4

    .line 57
    invoke-static/range {v2 .. v10}, Ls01/a;->b(Ljava/lang/String;IILjava/lang/String;ZZZZI)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0
.end method

.method public static b(Ljava/lang/String;IILjava/lang/String;ZZZZI)Ljava/lang/String;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    and-int/lit8 v2, p8, 0x1

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    move v2, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move/from16 v2, p1

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v4, p8, 0x2

    .line 15
    .line 16
    if-eqz v4, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move/from16 v4, p2

    .line 24
    .line 25
    :goto_1
    and-int/lit8 v5, p8, 0x8

    .line 26
    .line 27
    if-eqz v5, :cond_2

    .line 28
    .line 29
    move v5, v3

    .line 30
    goto :goto_2

    .line 31
    :cond_2
    move/from16 v5, p4

    .line 32
    .line 33
    :goto_2
    and-int/lit8 v6, p8, 0x10

    .line 34
    .line 35
    if-eqz v6, :cond_3

    .line 36
    .line 37
    move v6, v3

    .line 38
    goto :goto_3

    .line 39
    :cond_3
    move/from16 v6, p5

    .line 40
    .line 41
    :goto_3
    and-int/lit8 v7, p8, 0x40

    .line 42
    .line 43
    if-eqz v7, :cond_4

    .line 44
    .line 45
    goto :goto_4

    .line 46
    :cond_4
    move/from16 v3, p7

    .line 47
    .line 48
    :goto_4
    const-string v7, "<this>"

    .line 49
    .line 50
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    move v7, v2

    .line 54
    :goto_5
    if-ge v7, v4, :cond_13

    .line 55
    .line 56
    invoke-virtual {v0, v7}, Ljava/lang/String;->codePointAt(I)I

    .line 57
    .line 58
    .line 59
    move-result v8

    .line 60
    const/16 v9, 0x80

    .line 61
    .line 62
    const/16 v10, 0x20

    .line 63
    .line 64
    const/16 v11, 0x2b

    .line 65
    .line 66
    const/16 v12, 0x25

    .line 67
    .line 68
    const/16 v13, 0x7f

    .line 69
    .line 70
    if-lt v8, v10, :cond_8

    .line 71
    .line 72
    if-eq v8, v13, :cond_8

    .line 73
    .line 74
    if-lt v8, v9, :cond_5

    .line 75
    .line 76
    if-eqz v3, :cond_8

    .line 77
    .line 78
    :cond_5
    int-to-char v14, v8

    .line 79
    invoke-static {v1, v14}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 80
    .line 81
    .line 82
    move-result v14

    .line 83
    if-nez v14, :cond_8

    .line 84
    .line 85
    if-ne v8, v12, :cond_6

    .line 86
    .line 87
    if-eqz v5, :cond_8

    .line 88
    .line 89
    if-eqz v6, :cond_6

    .line 90
    .line 91
    invoke-static {v7, v4, v0}, Ls01/a;->c(IILjava/lang/String;)Z

    .line 92
    .line 93
    .line 94
    move-result v14

    .line 95
    if-eqz v14, :cond_8

    .line 96
    .line 97
    :cond_6
    if-ne v8, v11, :cond_7

    .line 98
    .line 99
    if-eqz p6, :cond_7

    .line 100
    .line 101
    goto :goto_6

    .line 102
    :cond_7
    invoke-static {v8}, Ljava/lang/Character;->charCount(I)I

    .line 103
    .line 104
    .line 105
    move-result v8

    .line 106
    add-int/2addr v7, v8

    .line 107
    goto :goto_5

    .line 108
    :cond_8
    :goto_6
    new-instance v8, Lu01/f;

    .line 109
    .line 110
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v8, v2, v7, v0}, Lu01/f;->r0(IILjava/lang/String;)V

    .line 114
    .line 115
    .line 116
    const/4 v2, 0x0

    .line 117
    :goto_7
    if-ge v7, v4, :cond_12

    .line 118
    .line 119
    invoke-virtual {v0, v7}, Ljava/lang/String;->codePointAt(I)I

    .line 120
    .line 121
    .line 122
    move-result v14

    .line 123
    if-eqz v5, :cond_9

    .line 124
    .line 125
    const/16 v15, 0x9

    .line 126
    .line 127
    if-eq v14, v15, :cond_f

    .line 128
    .line 129
    const/16 v15, 0xa

    .line 130
    .line 131
    if-eq v14, v15, :cond_f

    .line 132
    .line 133
    const/16 v15, 0xc

    .line 134
    .line 135
    if-eq v14, v15, :cond_f

    .line 136
    .line 137
    const/16 v15, 0xd

    .line 138
    .line 139
    if-ne v14, v15, :cond_9

    .line 140
    .line 141
    goto :goto_9

    .line 142
    :cond_9
    const-string v15, "+"

    .line 143
    .line 144
    if-ne v14, v10, :cond_a

    .line 145
    .line 146
    const-string v12, " !\"#$&\'()+,/:;<=>?@[\\]^`{|}~"

    .line 147
    .line 148
    if-ne v1, v12, :cond_a

    .line 149
    .line 150
    invoke-virtual {v8, v15}, Lu01/f;->x0(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    goto :goto_9

    .line 154
    :cond_a
    if-ne v14, v11, :cond_c

    .line 155
    .line 156
    if-eqz p6, :cond_c

    .line 157
    .line 158
    if-eqz v5, :cond_b

    .line 159
    .line 160
    goto :goto_8

    .line 161
    :cond_b
    const-string v15, "%2B"

    .line 162
    .line 163
    :goto_8
    invoke-virtual {v8, v15}, Lu01/f;->x0(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    goto :goto_9

    .line 167
    :cond_c
    if-lt v14, v10, :cond_10

    .line 168
    .line 169
    if-eq v14, v13, :cond_10

    .line 170
    .line 171
    if-lt v14, v9, :cond_d

    .line 172
    .line 173
    if-eqz v3, :cond_10

    .line 174
    .line 175
    :cond_d
    int-to-char v12, v14

    .line 176
    invoke-static {v1, v12}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 177
    .line 178
    .line 179
    move-result v12

    .line 180
    if-nez v12, :cond_10

    .line 181
    .line 182
    const/16 v12, 0x25

    .line 183
    .line 184
    if-ne v14, v12, :cond_e

    .line 185
    .line 186
    if-eqz v5, :cond_10

    .line 187
    .line 188
    if-eqz v6, :cond_e

    .line 189
    .line 190
    invoke-static {v7, v4, v0}, Ls01/a;->c(IILjava/lang/String;)Z

    .line 191
    .line 192
    .line 193
    move-result v12

    .line 194
    if-nez v12, :cond_e

    .line 195
    .line 196
    goto :goto_a

    .line 197
    :cond_e
    invoke-virtual {v8, v14}, Lu01/f;->y0(I)V

    .line 198
    .line 199
    .line 200
    :cond_f
    :goto_9
    const/16 v9, 0x25

    .line 201
    .line 202
    goto :goto_c

    .line 203
    :cond_10
    :goto_a
    if-nez v2, :cond_11

    .line 204
    .line 205
    new-instance v2, Lu01/f;

    .line 206
    .line 207
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 208
    .line 209
    .line 210
    :cond_11
    invoke-virtual {v2, v14}, Lu01/f;->y0(I)V

    .line 211
    .line 212
    .line 213
    :goto_b
    invoke-virtual {v2}, Lu01/f;->Z()Z

    .line 214
    .line 215
    .line 216
    move-result v12

    .line 217
    if-nez v12, :cond_f

    .line 218
    .line 219
    invoke-virtual {v2}, Lu01/f;->readByte()B

    .line 220
    .line 221
    .line 222
    move-result v12

    .line 223
    and-int/lit16 v15, v12, 0xff

    .line 224
    .line 225
    const/16 v9, 0x25

    .line 226
    .line 227
    invoke-virtual {v8, v9}, Lu01/f;->h0(I)V

    .line 228
    .line 229
    .line 230
    shr-int/lit8 v15, v15, 0x4

    .line 231
    .line 232
    and-int/lit8 v15, v15, 0xf

    .line 233
    .line 234
    sget-object v16, Ls01/a;->a:[C

    .line 235
    .line 236
    aget-char v15, v16, v15

    .line 237
    .line 238
    invoke-virtual {v8, v15}, Lu01/f;->h0(I)V

    .line 239
    .line 240
    .line 241
    and-int/lit8 v12, v12, 0xf

    .line 242
    .line 243
    aget-char v12, v16, v12

    .line 244
    .line 245
    invoke-virtual {v8, v12}, Lu01/f;->h0(I)V

    .line 246
    .line 247
    .line 248
    const/16 v9, 0x80

    .line 249
    .line 250
    goto :goto_b

    .line 251
    :goto_c
    invoke-static {v14}, Ljava/lang/Character;->charCount(I)I

    .line 252
    .line 253
    .line 254
    move-result v12

    .line 255
    add-int/2addr v7, v12

    .line 256
    move v12, v9

    .line 257
    const/16 v9, 0x80

    .line 258
    .line 259
    goto/16 :goto_7

    .line 260
    .line 261
    :cond_12
    invoke-virtual {v8}, Lu01/f;->T()Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    return-object v0

    .line 266
    :cond_13
    invoke-virtual {v0, v2, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    const-string v1, "substring(...)"

    .line 271
    .line 272
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    return-object v0
.end method

.method public static final c(IILjava/lang/String;)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    add-int/lit8 v0, p0, 0x2

    .line 7
    .line 8
    if-ge v0, p1, :cond_0

    .line 9
    .line 10
    invoke-virtual {p2, p0}, Ljava/lang/String;->charAt(I)C

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    const/16 v1, 0x25

    .line 15
    .line 16
    if-ne p1, v1, :cond_0

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    add-int/2addr p0, p1

    .line 20
    invoke-virtual {p2, p0}, Ljava/lang/String;->charAt(I)C

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    invoke-static {p0}, Le01/e;->n(C)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    const/4 v1, -0x1

    .line 29
    if-eq p0, v1, :cond_0

    .line 30
    .line 31
    invoke-virtual {p2, v0}, Ljava/lang/String;->charAt(I)C

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {p0}, Le01/e;->n(C)I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-eq p0, v1, :cond_0

    .line 40
    .line 41
    return p1

    .line 42
    :cond_0
    const/4 p0, 0x0

    .line 43
    return p0
.end method

.method public static d(IIILjava/lang/String;)Ljava/lang/String;
    .locals 8

    .line 1
    and-int/lit8 v0, p2, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p0, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p2, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    :cond_1
    and-int/lit8 p2, p2, 0x4

    .line 16
    .line 17
    if-eqz p2, :cond_2

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_2
    const/4 v1, 0x1

    .line 21
    :goto_0
    const-string p2, "<this>"

    .line 22
    .line 23
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    move p2, p0

    .line 27
    :goto_1
    if-ge p2, p1, :cond_8

    .line 28
    .line 29
    invoke-virtual {p3, p2}, Ljava/lang/String;->charAt(I)C

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    const/16 v2, 0x2b

    .line 34
    .line 35
    const/16 v3, 0x25

    .line 36
    .line 37
    if-eq v0, v3, :cond_4

    .line 38
    .line 39
    if-ne v0, v2, :cond_3

    .line 40
    .line 41
    if-eqz v1, :cond_3

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_3
    add-int/lit8 p2, p2, 0x1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_4
    :goto_2
    new-instance v0, Lu01/f;

    .line 48
    .line 49
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0, p0, p2, p3}, Lu01/f;->r0(IILjava/lang/String;)V

    .line 53
    .line 54
    .line 55
    :goto_3
    if-ge p2, p1, :cond_7

    .line 56
    .line 57
    invoke-virtual {p3, p2}, Ljava/lang/String;->codePointAt(I)I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-ne p0, v3, :cond_5

    .line 62
    .line 63
    add-int/lit8 v4, p2, 0x2

    .line 64
    .line 65
    if-ge v4, p1, :cond_5

    .line 66
    .line 67
    add-int/lit8 v5, p2, 0x1

    .line 68
    .line 69
    invoke-virtual {p3, v5}, Ljava/lang/String;->charAt(I)C

    .line 70
    .line 71
    .line 72
    move-result v5

    .line 73
    invoke-static {v5}, Le01/e;->n(C)I

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    invoke-virtual {p3, v4}, Ljava/lang/String;->charAt(I)C

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    invoke-static {v6}, Le01/e;->n(C)I

    .line 82
    .line 83
    .line 84
    move-result v6

    .line 85
    const/4 v7, -0x1

    .line 86
    if-eq v5, v7, :cond_6

    .line 87
    .line 88
    if-eq v6, v7, :cond_6

    .line 89
    .line 90
    shl-int/lit8 p2, v5, 0x4

    .line 91
    .line 92
    add-int/2addr p2, v6

    .line 93
    invoke-virtual {v0, p2}, Lu01/f;->h0(I)V

    .line 94
    .line 95
    .line 96
    invoke-static {p0}, Ljava/lang/Character;->charCount(I)I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    add-int p2, p0, v4

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_5
    if-ne p0, v2, :cond_6

    .line 104
    .line 105
    if-eqz v1, :cond_6

    .line 106
    .line 107
    const/16 p0, 0x20

    .line 108
    .line 109
    invoke-virtual {v0, p0}, Lu01/f;->h0(I)V

    .line 110
    .line 111
    .line 112
    add-int/lit8 p2, p2, 0x1

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_6
    invoke-virtual {v0, p0}, Lu01/f;->y0(I)V

    .line 116
    .line 117
    .line 118
    invoke-static {p0}, Ljava/lang/Character;->charCount(I)I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    add-int/2addr p2, p0

    .line 123
    goto :goto_3

    .line 124
    :cond_7
    invoke-virtual {v0}, Lu01/f;->T()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    return-object p0

    .line 129
    :cond_8
    invoke-virtual {p3, p0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    const-string p1, "substring(...)"

    .line 134
    .line 135
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    return-object p0
.end method
