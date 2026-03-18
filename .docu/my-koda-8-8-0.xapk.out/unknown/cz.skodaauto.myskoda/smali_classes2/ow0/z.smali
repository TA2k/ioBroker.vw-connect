.class public final Low0/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final k:Low0/f0;


# instance fields
.field public a:Ljava/lang/String;

.field public b:Z

.field public c:I

.field public d:Low0/b0;

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public g:Ljava/lang/String;

.field public h:Ljava/util/List;

.field public i:Low0/n;

.field public j:Lj1/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "http://localhost"

    .line 2
    .line 3
    invoke-static {v0}, Ljp/sc;->d(Ljava/lang/String;)Low0/f0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Low0/z;->k:Low0/f0;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Low0/x;->b:Low0/w;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    sget-object v1, Low0/w;->b:Low0/h;

    .line 9
    .line 10
    const-string v2, "parameters"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    const-string v2, ""

    .line 19
    .line 20
    iput-object v2, v0, Low0/z;->a:Ljava/lang/String;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    iput-boolean v2, v0, Low0/z;->b:Z

    .line 24
    .line 25
    iput v2, v0, Low0/z;->c:I

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    iput-object v3, v0, Low0/z;->d:Low0/b0;

    .line 29
    .line 30
    iput-object v3, v0, Low0/z;->e:Ljava/lang/String;

    .line 31
    .line 32
    iput-object v3, v0, Low0/z;->f:Ljava/lang/String;

    .line 33
    .line 34
    sget-object v3, Low0/a;->a:Ljava/util/Set;

    .line 35
    .line 36
    sget-object v3, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 37
    .line 38
    const-string v4, "charset"

    .line 39
    .line 40
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    new-instance v4, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/nio/charset/Charset;->newEncoder()Ljava/nio/charset/CharsetEncoder;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    const-string v5, "newEncoder(...)"

    .line 53
    .line 54
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    new-instance v3, Lnz0/a;

    .line 58
    .line 59
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    new-instance v6, Lla/p;

    .line 63
    .line 64
    const/16 v7, 0x1c

    .line 65
    .line 66
    invoke-direct {v6, v4, v7}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 67
    .line 68
    .line 69
    invoke-static {v3, v6}, Low0/a;->f(Lnz0/a;Lay0/k;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    iput-object v3, v0, Low0/z;->g:Ljava/lang/String;

    .line 77
    .line 78
    new-instance v3, Ljava/util/ArrayList;

    .line 79
    .line 80
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 81
    .line 82
    const/16 v6, 0xa

    .line 83
    .line 84
    invoke-static {v4, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 85
    .line 86
    .line 87
    move-result v7

    .line 88
    invoke-direct {v3, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 89
    .line 90
    .line 91
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v8

    .line 99
    const-string v9, "<this>"

    .line 100
    .line 101
    const/4 v10, 0x1

    .line 102
    if-eqz v8, :cond_9

    .line 103
    .line 104
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v8

    .line 108
    check-cast v8, Ljava/lang/String;

    .line 109
    .line 110
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    new-instance v9, Ljava/lang/StringBuilder;

    .line 114
    .line 115
    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    .line 116
    .line 117
    .line 118
    sget-object v11, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 119
    .line 120
    move v12, v2

    .line 121
    :goto_1
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 122
    .line 123
    .line 124
    move-result v13

    .line 125
    if-ge v12, v13, :cond_8

    .line 126
    .line 127
    invoke-virtual {v8, v12}, Ljava/lang/String;->charAt(I)C

    .line 128
    .line 129
    .line 130
    move-result v13

    .line 131
    sget-object v14, Low0/a;->b:Ljava/util/Set;

    .line 132
    .line 133
    invoke-static {v13}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 134
    .line 135
    .line 136
    move-result-object v15

    .line 137
    invoke-interface {v14, v15}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v14

    .line 141
    if-nez v14, :cond_7

    .line 142
    .line 143
    sget-object v14, Low0/a;->d:Ljava/util/Set;

    .line 144
    .line 145
    invoke-static {v13}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 146
    .line 147
    .line 148
    move-result-object v15

    .line 149
    invoke-interface {v14, v15}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v14

    .line 153
    if-eqz v14, :cond_0

    .line 154
    .line 155
    goto :goto_7

    .line 156
    :cond_0
    const v14, 0xd800

    .line 157
    .line 158
    .line 159
    if-gt v14, v13, :cond_1

    .line 160
    .line 161
    const v14, 0xe000

    .line 162
    .line 163
    .line 164
    if-ge v13, v14, :cond_1

    .line 165
    .line 166
    const/4 v13, 0x2

    .line 167
    goto :goto_2

    .line 168
    :cond_1
    move v13, v10

    .line 169
    :goto_2
    invoke-virtual {v11}, Ljava/nio/charset/Charset;->newEncoder()Ljava/nio/charset/CharsetEncoder;

    .line 170
    .line 171
    .line 172
    move-result-object v14

    .line 173
    invoke-static {v14, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    add-int/2addr v13, v12

    .line 177
    new-instance v15, Lnz0/a;

    .line 178
    .line 179
    invoke-direct {v15}, Ljava/lang/Object;-><init>()V

    .line 180
    .line 181
    .line 182
    if-lt v12, v13, :cond_2

    .line 183
    .line 184
    goto :goto_4

    .line 185
    :cond_2
    :goto_3
    invoke-static {v14, v8, v12, v13}, Ljp/q1;->b(Ljava/nio/charset/CharsetEncoder;Ljava/lang/CharSequence;II)[B

    .line 186
    .line 187
    .line 188
    move-result-object v6

    .line 189
    array-length v2, v6

    .line 190
    invoke-virtual {v15, v2, v6}, Lnz0/a;->k(I[B)V

    .line 191
    .line 192
    .line 193
    array-length v2, v6

    .line 194
    if-ltz v2, :cond_6

    .line 195
    .line 196
    add-int/2addr v12, v2

    .line 197
    if-lt v12, v13, :cond_5

    .line 198
    .line 199
    :cond_3
    :goto_4
    invoke-virtual {v15}, Lnz0/a;->Z()Z

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    if-nez v2, :cond_4

    .line 204
    .line 205
    :goto_5
    invoke-virtual {v15}, Lnz0/a;->Z()Z

    .line 206
    .line 207
    .line 208
    move-result v2

    .line 209
    if-nez v2, :cond_3

    .line 210
    .line 211
    invoke-virtual {v15}, Lnz0/a;->readByte()B

    .line 212
    .line 213
    .line 214
    move-result v2

    .line 215
    invoke-static {v2}, Low0/a;->g(B)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    invoke-virtual {v9, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    goto :goto_5

    .line 223
    :cond_4
    move v12, v13

    .line 224
    :goto_6
    const/4 v2, 0x0

    .line 225
    const/16 v6, 0xa

    .line 226
    .line 227
    goto :goto_1

    .line 228
    :cond_5
    const/4 v2, 0x0

    .line 229
    goto :goto_3

    .line 230
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 231
    .line 232
    const-string v1, "Check failed."

    .line 233
    .line 234
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    throw v0

    .line 238
    :cond_7
    :goto_7
    invoke-virtual {v9, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    add-int/lit8 v12, v12, 0x1

    .line 242
    .line 243
    goto :goto_6

    .line 244
    :cond_8
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object v2

    .line 248
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    const/4 v2, 0x0

    .line 252
    const/16 v6, 0xa

    .line 253
    .line 254
    goto/16 :goto_0

    .line 255
    .line 256
    :cond_9
    iput-object v3, v0, Low0/z;->h:Ljava/util/List;

    .line 257
    .line 258
    new-instance v2, Low0/n;

    .line 259
    .line 260
    invoke-direct {v2, v10}, Low0/n;-><init>(I)V

    .line 261
    .line 262
    .line 263
    :goto_8
    sget-object v3, Lmx0/r;->d:Lmx0/r;

    .line 264
    .line 265
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 266
    .line 267
    .line 268
    move-result v5

    .line 269
    if-eqz v5, :cond_b

    .line 270
    .line 271
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v3

    .line 275
    check-cast v3, Ljava/lang/String;

    .line 276
    .line 277
    invoke-virtual {v1, v3}, Low0/h;->d(Ljava/lang/String;)Ljava/util/List;

    .line 278
    .line 279
    .line 280
    const/4 v5, 0x0

    .line 281
    invoke-static {v3, v5}, Low0/a;->e(Ljava/lang/String;Z)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v3

    .line 285
    new-instance v6, Ljava/util/ArrayList;

    .line 286
    .line 287
    const/16 v7, 0xa

    .line 288
    .line 289
    invoke-static {v4, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 290
    .line 291
    .line 292
    move-result v8

    .line 293
    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 294
    .line 295
    .line 296
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 297
    .line 298
    .line 299
    move-result-object v8

    .line 300
    :goto_9
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 301
    .line 302
    .line 303
    move-result v11

    .line 304
    if-eqz v11, :cond_a

    .line 305
    .line 306
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v11

    .line 310
    check-cast v11, Ljava/lang/String;

    .line 311
    .line 312
    invoke-static {v11, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    invoke-static {v11, v10}, Low0/a;->e(Ljava/lang/String;Z)Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object v11

    .line 319
    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 320
    .line 321
    .line 322
    goto :goto_9

    .line 323
    :cond_a
    invoke-virtual {v2, v3, v6}, Lap0/o;->i(Ljava/lang/String;Ljava/lang/Iterable;)V

    .line 324
    .line 325
    .line 326
    goto :goto_8

    .line 327
    :cond_b
    iput-object v2, v0, Low0/z;->i:Low0/n;

    .line 328
    .line 329
    new-instance v1, Lj1/a;

    .line 330
    .line 331
    const/16 v3, 0x17

    .line 332
    .line 333
    invoke-direct {v1, v2, v3}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 334
    .line 335
    .line 336
    iput-object v1, v0, Low0/z;->j:Lj1/a;

    .line 337
    .line 338
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Low0/z;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    invoke-virtual {p0}, Low0/z;->d()Low0/b0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v0, v0, Low0/b0;->d:Ljava/lang/String;

    .line 15
    .line 16
    const-string v1, "file"

    .line 17
    .line 18
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    sget-object v0, Low0/z;->k:Low0/f0;

    .line 26
    .line 27
    iget-object v1, v0, Low0/f0;->d:Ljava/lang/String;

    .line 28
    .line 29
    iput-object v1, p0, Low0/z;->a:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v1, p0, Low0/z;->d:Low0/b0;

    .line 32
    .line 33
    if-nez v1, :cond_2

    .line 34
    .line 35
    iget-object v1, v0, Low0/f0;->i:Low0/b0;

    .line 36
    .line 37
    iput-object v1, p0, Low0/z;->d:Low0/b0;

    .line 38
    .line 39
    :cond_2
    iget v1, p0, Low0/z;->c:I

    .line 40
    .line 41
    if-nez v1, :cond_3

    .line 42
    .line 43
    iget v0, v0, Low0/f0;->e:I

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Low0/z;->e(I)V

    .line 46
    .line 47
    .line 48
    :cond_3
    :goto_0
    return-void
.end method

.method public final b()Low0/f0;
    .locals 10

    .line 1
    invoke-virtual {p0}, Low0/z;->a()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Low0/f0;

    .line 5
    .line 6
    iget-object v1, p0, Low0/z;->d:Low0/b0;

    .line 7
    .line 8
    iget-object v2, p0, Low0/z;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget v3, p0, Low0/z;->c:I

    .line 11
    .line 12
    iget-object v4, p0, Low0/z;->h:Ljava/util/List;

    .line 13
    .line 14
    check-cast v4, Ljava/lang/Iterable;

    .line 15
    .line 16
    move-object v5, v4

    .line 17
    new-instance v4, Ljava/util/ArrayList;

    .line 18
    .line 19
    const/16 v6, 0xa

    .line 20
    .line 21
    invoke-static {v5, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 22
    .line 23
    .line 24
    move-result v6

    .line 25
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    if-eqz v6, :cond_0

    .line 37
    .line 38
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    check-cast v6, Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {v6}, Low0/a;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    iget-object v5, p0, Low0/z;->j:Lj1/a;

    .line 53
    .line 54
    iget-object v5, v5, Lj1/a;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v5, Low0/n;

    .line 57
    .line 58
    invoke-static {v5}, Ljp/tc;->b(Low0/n;)Low0/x;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    iget-object v6, p0, Low0/z;->g:Ljava/lang/String;

    .line 63
    .line 64
    const/16 v7, 0xf

    .line 65
    .line 66
    const/4 v8, 0x0

    .line 67
    invoke-static {v8, v8, v7, v6}, Low0/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    iget-object v7, p0, Low0/z;->e:Ljava/lang/String;

    .line 72
    .line 73
    const/4 v8, 0x0

    .line 74
    if-eqz v7, :cond_1

    .line 75
    .line 76
    invoke-static {v7}, Low0/a;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    goto :goto_1

    .line 81
    :cond_1
    move-object v7, v8

    .line 82
    :goto_1
    iget-object v9, p0, Low0/z;->f:Ljava/lang/String;

    .line 83
    .line 84
    if-eqz v9, :cond_2

    .line 85
    .line 86
    invoke-static {v9}, Low0/a;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v8

    .line 90
    :cond_2
    invoke-virtual {p0}, Low0/z;->c()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v9

    .line 94
    invoke-direct/range {v0 .. v9}, Low0/f0;-><init>(Low0/b0;Ljava/lang/String;ILjava/util/ArrayList;Low0/x;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    return-object v0
.end method

.method public final c()Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Low0/z;->a()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    const/16 v1, 0x100

    .line 7
    .line 8
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, v0}, Ljp/rc;->c(Low0/z;Ljava/lang/StringBuilder;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string v0, "toString(...)"

    .line 19
    .line 20
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public final d()Low0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Low0/z;->d:Low0/b0;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Low0/b0;->f:Low0/b0;

    .line 6
    .line 7
    sget-object p0, Low0/b0;->f:Low0/b0;

    .line 8
    .line 9
    :cond_0
    return-object p0
.end method

.method public final e(I)V
    .locals 1

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    const/high16 v0, 0x10000

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    iput p1, p0, Low0/z;->c:I

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    const-string p0, "Port must be between 0 and 65535, or 0 if not set. Provided: "

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const/16 v1, 0x100

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Ljp/rc;->c(Low0/z;Ljava/lang/StringBuilder;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, "toString(...)"

    .line 16
    .line 17
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-object p0
.end method
