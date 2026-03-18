.class public final Ln1/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:I

.field public final c:Ljava/lang/Object;

.field public final d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lb81/a;IILn1/k;Lca/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ln1/l;->d:Ljava/lang/Object;

    .line 3
    iput-object p1, p0, Ln1/l;->c:Ljava/lang/Object;

    .line 4
    iput p2, p0, Ln1/l;->a:I

    .line 5
    iput p3, p0, Ln1/l;->b:I

    .line 6
    iput-object p4, p0, Ln1/l;->e:Ljava/lang/Object;

    .line 7
    iput-object p5, p0, Ln1/l;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lxw/h;)V
    .locals 2

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iput-object v0, p0, Ln1/l;->d:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 10
    iput v0, p0, Ln1/l;->a:I

    const/4 v0, 0x1

    .line 11
    iput v0, p0, Ln1/l;->b:I

    .line 12
    new-instance v1, Lcom/google/android/gms/internal/measurement/i4;

    invoke-direct {v1, p1, v0}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Lxw/h;Z)V

    iput-object v1, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 13
    iget-object p1, p1, Lxw/h;->b:Lxw/i;

    .line 14
    new-instance v0, Lxw/i;

    invoke-direct {v0}, Lxw/i;-><init>()V

    .line 15
    iget-char v1, p1, Lxw/i;->a:C

    iput-char v1, v0, Lxw/i;->a:C

    .line 16
    iget-char v1, p1, Lxw/i;->c:C

    iput-char v1, v0, Lxw/i;->c:C

    .line 17
    iget-char v1, p1, Lxw/i;->b:C

    iput-char v1, v0, Lxw/i;->b:C

    .line 18
    iget-char p1, p1, Lxw/i;->d:C

    iput-char p1, v0, Lxw/i;->d:C

    .line 19
    iput-object v0, p0, Ln1/l;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(II)J
    .locals 2

    .line 1
    iget-object p0, p0, Ln1/l;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb81/a;

    .line 4
    .line 5
    iget-object v0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, [I

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-ne p2, v1, :cond_0

    .line 11
    .line 12
    aget p0, v0, p1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    add-int/2addr p2, p1

    .line 16
    sub-int/2addr p2, v1

    .line 17
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, [I

    .line 20
    .line 21
    aget v1, p0, p2

    .line 22
    .line 23
    aget p2, v0, p2

    .line 24
    .line 25
    add-int/2addr v1, p2

    .line 26
    aget p0, p0, p1

    .line 27
    .line 28
    sub-int p0, v1, p0

    .line 29
    .line 30
    :goto_0
    const/4 p1, 0x0

    .line 31
    if-gez p0, :cond_1

    .line 32
    .line 33
    move p0, p1

    .line 34
    :cond_1
    if-ltz p0, :cond_2

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_2
    const-string p2, "width must be >= 0"

    .line 38
    .line 39
    invoke-static {p2}, Lt4/i;->a(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :goto_1
    const p2, 0x7fffffff

    .line 43
    .line 44
    .line 45
    invoke-static {p0, p0, p1, p2}, Lt4/b;->h(IIII)J

    .line 46
    .line 47
    .line 48
    move-result-wide p0

    .line 49
    return-wide p0
.end method

.method public b(I)Ln1/p;
    .locals 13

    .line 1
    iget-object v0, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lca/m;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Lca/m;->h(I)Ln1/t;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget v1, v0, Ln1/t;->a:I

    .line 10
    .line 11
    iget-object v2, v0, Ln1/t;->b:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    const/4 v4, 0x0

    .line 18
    if-eqz v3, :cond_1

    .line 19
    .line 20
    add-int v5, v1, v3

    .line 21
    .line 22
    iget v6, p0, Ln1/l;->a:I

    .line 23
    .line 24
    if-ne v5, v6, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget v5, p0, Ln1/l;->b:I

    .line 28
    .line 29
    move v11, v5

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    :goto_0
    move v11, v4

    .line 32
    :goto_1
    new-array v5, v3, [Ln1/o;

    .line 33
    .line 34
    move v10, v4

    .line 35
    :goto_2
    if-ge v4, v3, :cond_2

    .line 36
    .line 37
    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    check-cast v6, Ln1/b;

    .line 42
    .line 43
    iget-wide v6, v6, Ln1/b;->a:J

    .line 44
    .line 45
    long-to-int v6, v6

    .line 46
    invoke-virtual {p0, v10, v6}, Ln1/l;->a(II)J

    .line 47
    .line 48
    .line 49
    move-result-wide v7

    .line 50
    iget-object v9, p0, Ln1/l;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v9, Ln1/k;

    .line 53
    .line 54
    move v12, v11

    .line 55
    move v11, v6

    .line 56
    move-object v6, v9

    .line 57
    add-int v9, v1, v4

    .line 58
    .line 59
    invoke-virtual/range {v6 .. v12}, Ln1/k;->b0(JIIII)Ln1/o;

    .line 60
    .line 61
    .line 62
    move-result-object v6

    .line 63
    add-int/2addr v10, v11

    .line 64
    aput-object v6, v5, v4

    .line 65
    .line 66
    add-int/lit8 v4, v4, 0x1

    .line 67
    .line 68
    move v11, v12

    .line 69
    goto :goto_2

    .line 70
    :cond_2
    move v12, v11

    .line 71
    iget-object v10, v0, Ln1/t;->b:Ljava/util/List;

    .line 72
    .line 73
    new-instance v6, Ln1/p;

    .line 74
    .line 75
    iget-object p0, p0, Ln1/l;->d:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v9, p0

    .line 78
    check-cast v9, Lb81/a;

    .line 79
    .line 80
    move v7, p1

    .line 81
    move-object v8, v5

    .line 82
    invoke-direct/range {v6 .. v11}, Ln1/p;-><init>(I[Ln1/o;Lb81/a;Ljava/util/List;I)V

    .line 83
    .line 84
    .line 85
    return-object v6
.end method

.method public c(C)V
    .locals 13

    .line 1
    iget-object v0, p0, Ln1/l;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lxw/i;

    .line 4
    .line 5
    iget-object v1, p0, Ln1/l;->d:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    iget v2, p0, Ln1/l;->a:I

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    const/4 v4, 0x0

    .line 13
    if-eqz v2, :cond_18

    .line 14
    .line 15
    const/4 v5, 0x3

    .line 16
    if-eq v2, v3, :cond_16

    .line 17
    .line 18
    const/16 v6, 0x21

    .line 19
    .line 20
    const/4 v7, 0x2

    .line 21
    if-eq v2, v7, :cond_5

    .line 22
    .line 23
    if-eq v2, v5, :cond_0

    .line 24
    .line 25
    goto/16 :goto_7

    .line 26
    .line 27
    :cond_0
    iget-char v2, v0, Lxw/i;->b:C

    .line 28
    .line 29
    if-ne p1, v2, :cond_1

    .line 30
    .line 31
    iput v7, p0, Ln1/l;->a:I

    .line 32
    .line 33
    iget-char p1, v0, Lxw/i;->d:C

    .line 34
    .line 35
    if-nez p1, :cond_19

    .line 36
    .line 37
    invoke-virtual {p0, v4}, Ln1/l;->c(C)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    iget-char v2, v0, Lxw/i;->a:C

    .line 42
    .line 43
    if-ne p1, v2, :cond_4

    .line 44
    .line 45
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->length()I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-lez v2, :cond_4

    .line 50
    .line 51
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->charAt(I)C

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-eq v2, v6, :cond_4

    .line 56
    .line 57
    iget-char p1, v0, Lxw/i;->a:C

    .line 58
    .line 59
    invoke-virtual {v1, v4, p1}, Ljava/lang/StringBuilder;->insert(IC)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    iget-char p1, v0, Lxw/i;->c:C

    .line 63
    .line 64
    if-eqz p1, :cond_2

    .line 65
    .line 66
    invoke-virtual {v1, v3, p1}, Ljava/lang/StringBuilder;->insert(IC)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    :cond_2
    iget-object p1, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p1, Lcom/google/android/gms/internal/measurement/i4;

    .line 72
    .line 73
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/i4;->i(Ljava/lang/StringBuilder;)V

    .line 74
    .line 75
    .line 76
    iget-char p1, v0, Lxw/i;->c:C

    .line 77
    .line 78
    if-nez p1, :cond_3

    .line 79
    .line 80
    iget-object p1, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast p1, Lcom/google/android/gms/internal/measurement/i4;

    .line 83
    .line 84
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/i4;->i(Ljava/lang/StringBuilder;)V

    .line 85
    .line 86
    .line 87
    iput v5, p0, Ln1/l;->a:I

    .line 88
    .line 89
    return-void

    .line 90
    :cond_3
    iput v3, p0, Ln1/l;->a:I

    .line 91
    .line 92
    return-void

    .line 93
    :cond_4
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :cond_5
    iget-char v2, v0, Lxw/i;->d:C

    .line 98
    .line 99
    if-ne p1, v2, :cond_15

    .line 100
    .line 101
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->charAt(I)C

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    const/16 v2, 0x3d

    .line 106
    .line 107
    if-ne p1, v2, :cond_b

    .line 108
    .line 109
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->length()I

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    sub-int/2addr p1, v3

    .line 114
    invoke-virtual {v1, v3, p1}, Ljava/lang/StringBuilder;->substring(II)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    const-string v2, " "

    .line 119
    .line 120
    invoke-virtual {p1, v2}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    array-length v5, v2

    .line 125
    if-ne v5, v7, :cond_a

    .line 126
    .line 127
    aget-object v5, v2, v4

    .line 128
    .line 129
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 130
    .line 131
    .line 132
    move-result v5

    .line 133
    if-eq v5, v3, :cond_7

    .line 134
    .line 135
    if-ne v5, v7, :cond_6

    .line 136
    .line 137
    aget-object v5, v2, v4

    .line 138
    .line 139
    invoke-virtual {v5, v4}, Ljava/lang/String;->charAt(I)C

    .line 140
    .line 141
    .line 142
    move-result v5

    .line 143
    iput-char v5, v0, Lxw/i;->a:C

    .line 144
    .line 145
    aget-object v5, v2, v4

    .line 146
    .line 147
    invoke-virtual {v5, v3}, Ljava/lang/String;->charAt(I)C

    .line 148
    .line 149
    .line 150
    move-result v5

    .line 151
    iput-char v5, v0, Lxw/i;->c:C

    .line 152
    .line 153
    goto :goto_0

    .line 154
    :cond_6
    new-instance p0, La8/r0;

    .line 155
    .line 156
    invoke-static {p1}, Lxw/i;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    throw p0

    .line 164
    :cond_7
    aget-object v5, v2, v4

    .line 165
    .line 166
    invoke-virtual {v5, v4}, Ljava/lang/String;->charAt(I)C

    .line 167
    .line 168
    .line 169
    move-result v5

    .line 170
    iput-char v5, v0, Lxw/i;->a:C

    .line 171
    .line 172
    iput-char v4, v0, Lxw/i;->c:C

    .line 173
    .line 174
    :goto_0
    aget-object v5, v2, v3

    .line 175
    .line 176
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 177
    .line 178
    .line 179
    move-result v5

    .line 180
    if-eq v5, v3, :cond_9

    .line 181
    .line 182
    if-ne v5, v7, :cond_8

    .line 183
    .line 184
    aget-object p1, v2, v3

    .line 185
    .line 186
    invoke-virtual {p1, v4}, Ljava/lang/String;->charAt(I)C

    .line 187
    .line 188
    .line 189
    move-result p1

    .line 190
    iput-char p1, v0, Lxw/i;->b:C

    .line 191
    .line 192
    aget-object p1, v2, v3

    .line 193
    .line 194
    invoke-virtual {p1, v3}, Ljava/lang/String;->charAt(I)C

    .line 195
    .line 196
    .line 197
    move-result p1

    .line 198
    iput-char p1, v0, Lxw/i;->d:C

    .line 199
    .line 200
    goto :goto_1

    .line 201
    :cond_8
    new-instance p0, La8/r0;

    .line 202
    .line 203
    invoke-static {p1}, Lxw/i;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    throw p0

    .line 211
    :cond_9
    aget-object p1, v2, v3

    .line 212
    .line 213
    invoke-virtual {p1, v4}, Ljava/lang/String;->charAt(I)C

    .line 214
    .line 215
    .line 216
    move-result p1

    .line 217
    iput-char p1, v0, Lxw/i;->b:C

    .line 218
    .line 219
    iput-char v4, v0, Lxw/i;->d:C

    .line 220
    .line 221
    :goto_1
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 222
    .line 223
    .line 224
    iget-object p1, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast p1, Lcom/google/android/gms/internal/measurement/i4;

    .line 227
    .line 228
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast p1, Ljava/util/ArrayList;

    .line 231
    .line 232
    new-instance v0, Lxw/k;

    .line 233
    .line 234
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 235
    .line 236
    .line 237
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    goto/16 :goto_6

    .line 241
    .line 242
    :cond_a
    new-instance p0, La8/r0;

    .line 243
    .line 244
    invoke-static {p1}, Lxw/i;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object p1

    .line 248
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    throw p0

    .line 252
    :cond_b
    iget-char p1, v0, Lxw/i;->a:C

    .line 253
    .line 254
    const/16 v2, 0x7b

    .line 255
    .line 256
    if-ne p1, v2, :cond_e

    .line 257
    .line 258
    iget-char p1, v0, Lxw/i;->c:C

    .line 259
    .line 260
    if-ne p1, v2, :cond_e

    .line 261
    .line 262
    iget-char p1, v0, Lxw/i;->b:C

    .line 263
    .line 264
    const/16 v2, 0x7d

    .line 265
    .line 266
    if-ne p1, v2, :cond_e

    .line 267
    .line 268
    iget-char p1, v0, Lxw/i;->d:C

    .line 269
    .line 270
    if-ne p1, v2, :cond_e

    .line 271
    .line 272
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->charAt(I)C

    .line 273
    .line 274
    .line 275
    move-result p1

    .line 276
    iget-char v0, v0, Lxw/i;->a:C

    .line 277
    .line 278
    if-ne p1, v0, :cond_e

    .line 279
    .line 280
    :try_start_0
    iget-object p1, p0, Ln1/l;->e:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast p1, Ljava/io/StringReader;

    .line 283
    .line 284
    invoke-virtual {p1}, Ljava/io/Reader;->read()I

    .line 285
    .line 286
    .line 287
    move-result p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 288
    if-eq p1, v2, :cond_d

    .line 289
    .line 290
    const/4 v0, -0x1

    .line 291
    if-ne p1, v0, :cond_c

    .line 292
    .line 293
    const-string p1, ""

    .line 294
    .line 295
    goto :goto_2

    .line 296
    :cond_c
    int-to-char p1, p1

    .line 297
    invoke-static {p1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object p1

    .line 301
    :goto_2
    new-instance v0, Lxw/r;

    .line 302
    .line 303
    new-instance v2, Ljava/lang/StringBuilder;

    .line 304
    .line 305
    const-string v3, "Invalid triple-mustache tag: {{"

    .line 306
    .line 307
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 311
    .line 312
    .line 313
    const-string v1, "}}"

    .line 314
    .line 315
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 316
    .line 317
    .line 318
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 319
    .line 320
    .line 321
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 322
    .line 323
    .line 324
    move-result-object p1

    .line 325
    iget p0, p0, Ln1/l;->b:I

    .line 326
    .line 327
    invoke-direct {v0, p1, p0}, Lxw/r;-><init>(Ljava/lang/String;I)V

    .line 328
    .line 329
    .line 330
    throw v0

    .line 331
    :cond_d
    const-string p1, "&"

    .line 332
    .line 333
    invoke-virtual {v1, v4, v3, p1}, Ljava/lang/StringBuilder;->replace(IILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    goto :goto_3

    .line 337
    :catch_0
    move-exception v0

    .line 338
    move-object p0, v0

    .line 339
    new-instance p1, La8/r0;

    .line 340
    .line 341
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 342
    .line 343
    .line 344
    throw p1

    .line 345
    :cond_e
    :goto_3
    iget-object p1, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 346
    .line 347
    move-object v11, p1

    .line 348
    check-cast v11, Lcom/google/android/gms/internal/measurement/i4;

    .line 349
    .line 350
    iget v10, p0, Ln1/l;->b:I

    .line 351
    .line 352
    iget-object p1, v11, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast p1, Lxw/h;

    .line 355
    .line 356
    iget-object v0, v11, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 357
    .line 358
    move-object v8, v0

    .line 359
    check-cast v8, Lxw/h;

    .line 360
    .line 361
    iget-object v0, v11, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast v0, Ljava/util/ArrayList;

    .line 364
    .line 365
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v2

    .line 369
    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object v2

    .line 373
    invoke-virtual {v2, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v3

    .line 377
    invoke-virtual {v3}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v9

    .line 381
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {v2, v4}, Ljava/lang/String;->charAt(I)C

    .line 385
    .line 386
    .line 387
    move-result v1

    .line 388
    if-eq v1, v6, :cond_14

    .line 389
    .line 390
    const/16 v3, 0x23

    .line 391
    .line 392
    if-eq v1, v3, :cond_13

    .line 393
    .line 394
    const/16 v3, 0x26

    .line 395
    .line 396
    if-eq v1, v3, :cond_12

    .line 397
    .line 398
    const/16 v3, 0x2f

    .line 399
    .line 400
    if-eq v1, v3, :cond_11

    .line 401
    .line 402
    const/16 v3, 0x3e

    .line 403
    .line 404
    if-eq v1, v3, :cond_10

    .line 405
    .line 406
    const/16 v3, 0x5e

    .line 407
    .line 408
    if-eq v1, v3, :cond_f

    .line 409
    .line 410
    invoke-static {v10, v2}, Lcom/google/android/gms/internal/measurement/i4;->u(ILjava/lang/String;)V

    .line 411
    .line 412
    .line 413
    new-instance v1, Lxw/q;

    .line 414
    .line 415
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 416
    .line 417
    .line 418
    sget-object p1, Lxw/f;->a:Lro/f;

    .line 419
    .line 420
    invoke-direct {v1, v2, v10, p1}, Lxw/q;-><init>(Ljava/lang/String;ILxw/j;)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 424
    .line 425
    .line 426
    goto :goto_5

    .line 427
    :cond_f
    invoke-static {v10, v2}, Lcom/google/android/gms/internal/measurement/i4;->u(ILjava/lang/String;)V

    .line 428
    .line 429
    .line 430
    new-instance v7, Lxw/g;

    .line 431
    .line 432
    const/4 v12, 0x1

    .line 433
    invoke-direct/range {v7 .. v12}, Lxw/g;-><init>(Lxw/h;Ljava/lang/String;ILcom/google/android/gms/internal/measurement/i4;I)V

    .line 434
    .line 435
    .line 436
    :goto_4
    move-object v11, v7

    .line 437
    goto :goto_5

    .line 438
    :cond_10
    new-instance v1, Lxw/l;

    .line 439
    .line 440
    invoke-direct {v1, p1, v9}, Lxw/l;-><init>(Lxw/h;Ljava/lang/String;)V

    .line 441
    .line 442
    .line 443
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 444
    .line 445
    .line 446
    goto :goto_5

    .line 447
    :cond_11
    invoke-static {v10, v2}, Lcom/google/android/gms/internal/measurement/i4;->u(ILjava/lang/String;)V

    .line 448
    .line 449
    .line 450
    invoke-virtual {v11, v10, v9}, Lcom/google/android/gms/internal/measurement/i4;->c(ILjava/lang/String;)Lcom/google/android/gms/internal/measurement/i4;

    .line 451
    .line 452
    .line 453
    move-result-object v11

    .line 454
    goto :goto_5

    .line 455
    :cond_12
    invoke-static {v10, v2}, Lcom/google/android/gms/internal/measurement/i4;->u(ILjava/lang/String;)V

    .line 456
    .line 457
    .line 458
    new-instance v1, Lxw/q;

    .line 459
    .line 460
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 461
    .line 462
    .line 463
    sget-object p1, Lxw/f;->b:Lxw/e;

    .line 464
    .line 465
    invoke-direct {v1, v9, v10, p1}, Lxw/q;-><init>(Ljava/lang/String;ILxw/j;)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 469
    .line 470
    .line 471
    goto :goto_5

    .line 472
    :cond_13
    invoke-static {v10, v2}, Lcom/google/android/gms/internal/measurement/i4;->u(ILjava/lang/String;)V

    .line 473
    .line 474
    .line 475
    new-instance v7, Lxw/g;

    .line 476
    .line 477
    const/4 v12, 0x0

    .line 478
    invoke-direct/range {v7 .. v12}, Lxw/g;-><init>(Lxw/h;Ljava/lang/String;ILcom/google/android/gms/internal/measurement/i4;I)V

    .line 479
    .line 480
    .line 481
    goto :goto_4

    .line 482
    :cond_14
    new-instance p1, Lxw/k;

    .line 483
    .line 484
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 485
    .line 486
    .line 487
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 488
    .line 489
    .line 490
    :goto_5
    iput-object v11, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 491
    .line 492
    :goto_6
    iput v4, p0, Ln1/l;->a:I

    .line 493
    .line 494
    return-void

    .line 495
    :cond_15
    iget-char v0, v0, Lxw/i;->b:C

    .line 496
    .line 497
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 498
    .line 499
    .line 500
    iput v5, p0, Ln1/l;->a:I

    .line 501
    .line 502
    invoke-virtual {p0, p1}, Ln1/l;->c(C)V

    .line 503
    .line 504
    .line 505
    return-void

    .line 506
    :cond_16
    iget-char v2, v0, Lxw/i;->c:C

    .line 507
    .line 508
    if-ne p1, v2, :cond_17

    .line 509
    .line 510
    iget-object p1, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 511
    .line 512
    check-cast p1, Lcom/google/android/gms/internal/measurement/i4;

    .line 513
    .line 514
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/i4;->i(Ljava/lang/StringBuilder;)V

    .line 515
    .line 516
    .line 517
    iput v5, p0, Ln1/l;->a:I

    .line 518
    .line 519
    return-void

    .line 520
    :cond_17
    iget-char v0, v0, Lxw/i;->a:C

    .line 521
    .line 522
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 523
    .line 524
    .line 525
    iput v4, p0, Ln1/l;->a:I

    .line 526
    .line 527
    invoke-virtual {p0, p1}, Ln1/l;->c(C)V

    .line 528
    .line 529
    .line 530
    return-void

    .line 531
    :cond_18
    iget-char v2, v0, Lxw/i;->a:C

    .line 532
    .line 533
    if-ne p1, v2, :cond_1a

    .line 534
    .line 535
    iput v3, p0, Ln1/l;->a:I

    .line 536
    .line 537
    iget-char p1, v0, Lxw/i;->c:C

    .line 538
    .line 539
    if-nez p1, :cond_19

    .line 540
    .line 541
    invoke-virtual {p0, v4}, Ln1/l;->c(C)V

    .line 542
    .line 543
    .line 544
    :cond_19
    :goto_7
    return-void

    .line 545
    :cond_1a
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 546
    .line 547
    .line 548
    return-void
.end method
