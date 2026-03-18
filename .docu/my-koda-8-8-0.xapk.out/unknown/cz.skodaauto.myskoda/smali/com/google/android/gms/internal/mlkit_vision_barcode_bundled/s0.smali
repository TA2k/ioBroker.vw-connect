.class public abstract Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Ljava/io/Serializable;


# static fields
.field public static final e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;


# instance fields
.field public d:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->b:[B

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;-><init>([B)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 9
    .line 10
    sget v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l0;->a:I

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->d:I

    .line 6
    .line 7
    return-void
.end method

.method public static g(Ljava/util/Iterator;I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;
    .locals 9

    .line 1
    if-lez p1, :cond_e

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p1, v0, :cond_0

    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    ushr-int/lit8 v1, p1, 0x1

    .line 14
    .line 15
    invoke-static {p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->g(Ljava/util/Iterator;I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    sub-int/2addr p1, v1

    .line 20
    invoke-static {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->g(Ljava/util/Iterator;I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const p1, 0x7fffffff

    .line 25
    .line 26
    .line 27
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    sub-int/2addr p1, v1

    .line 32
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-lt p1, v1, :cond_d

    .line 37
    .line 38
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    if-nez p1, :cond_1

    .line 43
    .line 44
    return-object v2

    .line 45
    :cond_1
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-nez p1, :cond_2

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_2
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    add-int/2addr v1, p1

    .line 61
    const/4 p1, 0x0

    .line 62
    const/16 v3, 0x80

    .line 63
    .line 64
    if-ge v1, v3, :cond_5

    .line 65
    .line 66
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    add-int v3, v0, v1

    .line 75
    .line 76
    new-array v4, v3, [B

    .line 77
    .line 78
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    invoke-static {p1, v0, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 83
    .line 84
    .line 85
    invoke-static {p1, v0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 86
    .line 87
    .line 88
    if-lez v0, :cond_3

    .line 89
    .line 90
    invoke-virtual {v2, p1, v4, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 91
    .line 92
    .line 93
    :cond_3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    invoke-static {p1, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 98
    .line 99
    .line 100
    invoke-static {v0, v3, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 101
    .line 102
    .line 103
    if-lez v1, :cond_4

    .line 104
    .line 105
    invoke-virtual {p0, p1, v4, v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 106
    .line 107
    .line 108
    :cond_4
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 109
    .line 110
    invoke-direct {p0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;-><init>([B)V

    .line 111
    .line 112
    .line 113
    return-object p0

    .line 114
    :cond_5
    instance-of v4, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 115
    .line 116
    if-eqz v4, :cond_a

    .line 117
    .line 118
    move-object v4, v2

    .line 119
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 120
    .line 121
    iget-object v5, v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 122
    .line 123
    iget-object v6, v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 124
    .line 125
    invoke-virtual {v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 130
    .line 131
    .line 132
    move-result v8

    .line 133
    add-int/2addr v8, v7

    .line 134
    if-ge v8, v3, :cond_8

    .line 135
    .line 136
    invoke-virtual {v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    add-int v2, v0, v1

    .line 145
    .line 146
    new-array v3, v2, [B

    .line 147
    .line 148
    invoke-virtual {v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 149
    .line 150
    .line 151
    move-result v4

    .line 152
    invoke-static {p1, v0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 153
    .line 154
    .line 155
    invoke-static {p1, v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 156
    .line 157
    .line 158
    if-lez v0, :cond_6

    .line 159
    .line 160
    invoke-virtual {v6, p1, v3, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 161
    .line 162
    .line 163
    :cond_6
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 164
    .line 165
    .line 166
    move-result v4

    .line 167
    invoke-static {p1, v1, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 168
    .line 169
    .line 170
    invoke-static {v0, v2, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 171
    .line 172
    .line 173
    if-lez v1, :cond_7

    .line 174
    .line 175
    invoke-virtual {p0, p1, v3, v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 176
    .line 177
    .line 178
    :cond_7
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 179
    .line 180
    invoke-direct {p0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;-><init>([B)V

    .line 181
    .line 182
    .line 183
    new-instance p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 184
    .line 185
    invoke-direct {p1, v5, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 186
    .line 187
    .line 188
    return-object p1

    .line 189
    :cond_8
    invoke-virtual {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->m()I

    .line 190
    .line 191
    .line 192
    move-result p1

    .line 193
    invoke-virtual {v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->m()I

    .line 194
    .line 195
    .line 196
    move-result v3

    .line 197
    if-le p1, v3, :cond_a

    .line 198
    .line 199
    iget p1, v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->j:I

    .line 200
    .line 201
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->m()I

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    if-gt p1, v3, :cond_9

    .line 206
    .line 207
    goto :goto_0

    .line 208
    :cond_9
    new-instance p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 209
    .line 210
    invoke-direct {p1, v6, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 211
    .line 212
    .line 213
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 214
    .line 215
    invoke-direct {p0, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 216
    .line 217
    .line 218
    return-object p0

    .line 219
    :cond_a
    :goto_0
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->m()I

    .line 220
    .line 221
    .line 222
    move-result p1

    .line 223
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->m()I

    .line 224
    .line 225
    .line 226
    move-result v3

    .line 227
    invoke-static {p1, v3}, Ljava/lang/Math;->max(II)I

    .line 228
    .line 229
    .line 230
    move-result p1

    .line 231
    add-int/2addr p1, v0

    .line 232
    invoke-static {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->A(I)I

    .line 233
    .line 234
    .line 235
    move-result p1

    .line 236
    if-lt v1, p1, :cond_b

    .line 237
    .line 238
    new-instance p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 239
    .line 240
    invoke-direct {p1, v2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 241
    .line 242
    .line 243
    return-object p1

    .line 244
    :cond_b
    new-instance p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;

    .line 245
    .line 246
    const/4 v0, 0x3

    .line 247
    invoke-direct {p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;-><init>(I)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->c(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->c(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 254
    .line 255
    .line 256
    iget-object p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast p0, Ljava/util/ArrayDeque;

    .line 259
    .line 260
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object p1

    .line 264
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 265
    .line 266
    :goto_1
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 267
    .line 268
    .line 269
    move-result v0

    .line 270
    if-nez v0, :cond_c

    .line 271
    .line 272
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 277
    .line 278
    new-instance v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 279
    .line 280
    invoke-direct {v1, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 281
    .line 282
    .line 283
    move-object p1, v1

    .line 284
    goto :goto_1

    .line 285
    :cond_c
    return-object p1

    .line 286
    :cond_d
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 287
    .line 288
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 289
    .line 290
    .line 291
    move-result v0

    .line 292
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 293
    .line 294
    .line 295
    move-result p0

    .line 296
    const-string v1, "ByteString would be too long: "

    .line 297
    .line 298
    const-string v2, "+"

    .line 299
    .line 300
    invoke-static {v1, v2, v0, p0}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object p0

    .line 304
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 305
    .line 306
    .line 307
    throw p1

    .line 308
    :cond_e
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 309
    .line 310
    const-string v0, "length ("

    .line 311
    .line 312
    const-string v1, ") must be >= 1"

    .line 313
    .line 314
    invoke-static {v0, p1, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object p1

    .line 318
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    throw p0
.end method

.method public static v(III)I
    .locals 3

    .line 1
    or-int v0, p0, p1

    .line 2
    .line 3
    sub-int v1, p1, p0

    .line 4
    .line 5
    or-int/2addr v0, v1

    .line 6
    sub-int v2, p2, p1

    .line 7
    .line 8
    or-int/2addr v0, v2

    .line 9
    if-gez v0, :cond_2

    .line 10
    .line 11
    if-ltz p0, :cond_1

    .line 12
    .line 13
    if-ge p1, p0, :cond_0

    .line 14
    .line 15
    new-instance p2, Ljava/lang/IndexOutOfBoundsException;

    .line 16
    .line 17
    const-string v0, "Beginning index larger than ending index: "

    .line 18
    .line 19
    const-string v1, ", "

    .line 20
    .line 21
    invoke-static {v0, v1, p0, p1}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-direct {p2, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p2

    .line 29
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 30
    .line 31
    const-string v0, "End index: "

    .line 32
    .line 33
    const-string v1, " >= "

    .line 34
    .line 35
    invoke-static {v0, v1, p1, p2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    .line 44
    .line 45
    const-string p2, "Beginning index: "

    .line 46
    .line 47
    const-string v0, " < 0"

    .line 48
    .line 49
    invoke-static {p2, p0, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-direct {p1, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p1

    .line 57
    :cond_2
    return v1
.end method

.method public static x([BII)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;
    .locals 3

    .line 1
    add-int v0, p1, p2

    .line 2
    .line 3
    array-length v1, p0

    .line 4
    invoke-static {p1, v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 5
    .line 6
    .line 7
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 8
    .line 9
    new-array v1, p2, [B

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-static {p0, p1, v1, v2, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;-><init>([B)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static y(Ljava/io/InputStream;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;
    .locals 7

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    const/16 v1, 0x100

    .line 7
    .line 8
    :goto_0
    new-array v2, v1, [B

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    move v4, v3

    .line 12
    :goto_1
    if-ge v4, v1, :cond_1

    .line 13
    .line 14
    sub-int v5, v1, v4

    .line 15
    .line 16
    invoke-virtual {p0, v2, v4, v5}, Ljava/io/InputStream;->read([BII)I

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    const/4 v6, -0x1

    .line 21
    if-ne v5, v6, :cond_0

    .line 22
    .line 23
    goto :goto_2

    .line 24
    :cond_0
    add-int/2addr v4, v5

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    :goto_2
    if-nez v4, :cond_2

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    goto :goto_3

    .line 30
    :cond_2
    invoke-static {v2, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->x([BII)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    :goto_3
    if-nez v2, :cond_4

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-nez p0, :cond_3

    .line 41
    .line 42
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_3
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-static {v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->g(Ljava/util/Iterator;I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_4
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    add-int/2addr v1, v1

    .line 58
    const/16 v2, 0x2000

    .line 59
    .line 60
    invoke-static {v1, v2}, Ljava/lang/Math;->min(II)I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    goto :goto_0
.end method

.method public static z(II)V
    .locals 3

    .line 1
    add-int/lit8 v0, p0, 0x1

    .line 2
    .line 3
    sub-int v0, p1, v0

    .line 4
    .line 5
    or-int/2addr v0, p0

    .line 6
    if-gez v0, :cond_1

    .line 7
    .line 8
    if-gez p0, :cond_0

    .line 9
    .line 10
    new-instance p1, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 11
    .line 12
    const-string v0, "Index < 0: "

    .line 13
    .line 14
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-direct {p1, p0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p1

    .line 22
    :cond_0
    new-instance v0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 23
    .line 24
    const-string v1, "Index > length: "

    .line 25
    .line 26
    const-string v2, ", "

    .line 27
    .line 28
    invoke-static {v1, v2, p0, p1}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-direct {v0, p0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw v0

    .line 36
    :cond_1
    return-void
.end method


# virtual methods
.method public abstract c(I)B
.end method

.method public abstract e(I)B
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->d:I

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {p0, v1, v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->o(III)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    :cond_0
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->d:I

    .line 18
    .line 19
    :cond_1
    return v0
.end method

.method public abstract i()I
.end method

.method public bridge synthetic iterator()Ljava/util/Iterator;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->w()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public abstract k(I[BII)V
.end method

.method public abstract m()I
.end method

.method public abstract n()Z
.end method

.method public abstract o(III)I
.end method

.method public abstract p(III)I
.end method

.method public abstract r(II)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;
.end method

.method public abstract s(Ljava/nio/charset/Charset;)Ljava/lang/String;
.end method

.method public abstract t(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;)V
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/16 v3, 0x32

    .line 20
    .line 21
    if-gt v2, v3, :cond_0

    .line 22
    .line 23
    invoke-static {p0}, Ljp/fe;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v2, 0x0

    .line 29
    const/16 v3, 0x2f

    .line 30
    .line 31
    invoke-virtual {p0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->r(II)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-static {p0}, Ljp/fe;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string v2, "..."

    .line 40
    .line 41
    invoke-virtual {p0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    :goto_0
    const-string v2, " size="

    .line 46
    .line 47
    const-string v3, " contents=\""

    .line 48
    .line 49
    const-string v4, "<ByteString@"

    .line 50
    .line 51
    invoke-static {v4, v1, v0, v2, v3}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    const-string v1, "\">"

    .line 56
    .line 57
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0
.end method

.method public abstract u()Z
.end method

.method public w()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
