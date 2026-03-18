.class public final Landroidx/datastore/preferences/protobuf/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/datastore/preferences/protobuf/a1;


# static fields
.field public static final n:[I

.field public static final o:Lsun/misc/Unsafe;


# instance fields
.field public final a:[I

.field public final b:[Ljava/lang/Object;

.field public final c:I

.field public final d:I

.field public final e:Landroidx/datastore/preferences/protobuf/a;

.field public final f:Z

.field public final g:[I

.field public final h:I

.field public final i:I

.field public final j:Landroidx/datastore/preferences/protobuf/t0;

.field public final k:Landroidx/datastore/preferences/protobuf/f0;

.field public final l:Landroidx/datastore/preferences/protobuf/i1;

.field public final m:Landroidx/datastore/preferences/protobuf/n0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    sput-object v0, Landroidx/datastore/preferences/protobuf/r0;->n:[I

    .line 5
    .line 6
    invoke-static {}, Landroidx/datastore/preferences/protobuf/n1;->i()Lsun/misc/Unsafe;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>([I[Ljava/lang/Object;IILandroidx/datastore/preferences/protobuf/a;[IIILandroidx/datastore/preferences/protobuf/t0;Landroidx/datastore/preferences/protobuf/f0;Landroidx/datastore/preferences/protobuf/i1;Landroidx/datastore/preferences/protobuf/p;Landroidx/datastore/preferences/protobuf/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/datastore/preferences/protobuf/r0;->b:[Ljava/lang/Object;

    .line 7
    .line 8
    iput p3, p0, Landroidx/datastore/preferences/protobuf/r0;->c:I

    .line 9
    .line 10
    iput p4, p0, Landroidx/datastore/preferences/protobuf/r0;->d:I

    .line 11
    .line 12
    instance-of p1, p5, Landroidx/datastore/preferences/protobuf/x;

    .line 13
    .line 14
    iput-boolean p1, p0, Landroidx/datastore/preferences/protobuf/r0;->f:Z

    .line 15
    .line 16
    iput-object p6, p0, Landroidx/datastore/preferences/protobuf/r0;->g:[I

    .line 17
    .line 18
    iput p7, p0, Landroidx/datastore/preferences/protobuf/r0;->h:I

    .line 19
    .line 20
    iput p8, p0, Landroidx/datastore/preferences/protobuf/r0;->i:I

    .line 21
    .line 22
    iput-object p9, p0, Landroidx/datastore/preferences/protobuf/r0;->j:Landroidx/datastore/preferences/protobuf/t0;

    .line 23
    .line 24
    iput-object p10, p0, Landroidx/datastore/preferences/protobuf/r0;->k:Landroidx/datastore/preferences/protobuf/f0;

    .line 25
    .line 26
    iput-object p11, p0, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 27
    .line 28
    iput-object p5, p0, Landroidx/datastore/preferences/protobuf/r0;->e:Landroidx/datastore/preferences/protobuf/a;

    .line 29
    .line 30
    iput-object p13, p0, Landroidx/datastore/preferences/protobuf/r0;->m:Landroidx/datastore/preferences/protobuf/n0;

    .line 31
    .line 32
    return-void
.end method

.method public static F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;
    .locals 5

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NoSuchFieldException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    invoke-virtual {p0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v1, v0

    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, v1, :cond_1

    .line 13
    .line 14
    aget-object v3, v0, v2

    .line 15
    .line 16
    invoke-virtual {v3}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-virtual {p1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_0

    .line 25
    .line 26
    return-object v3

    .line 27
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    new-instance v1, Ljava/lang/RuntimeException;

    .line 31
    .line 32
    const-string v2, "Field "

    .line 33
    .line 34
    const-string v3, " for "

    .line 35
    .line 36
    invoke-static {v2, p1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p0, " not found. Known fields are "

    .line 48
    .line 49
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-static {v0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v1
.end method

.method public static K(I)I
    .locals 1

    .line 1
    const/high16 v0, 0xff00000

    .line 2
    .line 3
    and-int/2addr p0, v0

    .line 4
    ushr-int/lit8 p0, p0, 0x14

    .line 5
    .line 6
    return p0
.end method

.method public static p(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p0, Landroidx/datastore/preferences/protobuf/x;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p0, Landroidx/datastore/preferences/protobuf/x;

    .line 10
    .line 11
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/x;->g()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_1
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public static w(Landroidx/datastore/preferences/protobuf/z0;Landroidx/datastore/preferences/protobuf/t0;Landroidx/datastore/preferences/protobuf/f0;Landroidx/datastore/preferences/protobuf/i1;Landroidx/datastore/preferences/protobuf/p;Landroidx/datastore/preferences/protobuf/n0;)Landroidx/datastore/preferences/protobuf/r0;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/datastore/preferences/protobuf/z0;->b:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 11
    .line 12
    .line 13
    move-result v4

    .line 14
    const v6, 0xd800

    .line 15
    .line 16
    .line 17
    if-lt v4, v6, :cond_0

    .line 18
    .line 19
    const/4 v4, 0x1

    .line 20
    :goto_0
    add-int/lit8 v7, v4, 0x1

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-lt v4, v6, :cond_1

    .line 27
    .line 28
    move v4, v7

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v7, 0x1

    .line 31
    :cond_1
    add-int/lit8 v4, v7, 0x1

    .line 32
    .line 33
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    if-lt v7, v6, :cond_3

    .line 38
    .line 39
    and-int/lit16 v7, v7, 0x1fff

    .line 40
    .line 41
    const/16 v9, 0xd

    .line 42
    .line 43
    :goto_1
    add-int/lit8 v10, v4, 0x1

    .line 44
    .line 45
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-lt v4, v6, :cond_2

    .line 50
    .line 51
    and-int/lit16 v4, v4, 0x1fff

    .line 52
    .line 53
    shl-int/2addr v4, v9

    .line 54
    or-int/2addr v7, v4

    .line 55
    add-int/lit8 v9, v9, 0xd

    .line 56
    .line 57
    move v4, v10

    .line 58
    goto :goto_1

    .line 59
    :cond_2
    shl-int/2addr v4, v9

    .line 60
    or-int/2addr v7, v4

    .line 61
    move v4, v10

    .line 62
    :cond_3
    if-nez v7, :cond_4

    .line 63
    .line 64
    sget-object v7, Landroidx/datastore/preferences/protobuf/r0;->n:[I

    .line 65
    .line 66
    move v9, v3

    .line 67
    move v10, v9

    .line 68
    move v11, v10

    .line 69
    move v12, v11

    .line 70
    move v13, v12

    .line 71
    move/from16 v16, v13

    .line 72
    .line 73
    move-object v15, v7

    .line 74
    move/from16 v7, v16

    .line 75
    .line 76
    goto/16 :goto_a

    .line 77
    .line 78
    :cond_4
    add-int/lit8 v7, v4, 0x1

    .line 79
    .line 80
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    if-lt v4, v6, :cond_6

    .line 85
    .line 86
    and-int/lit16 v4, v4, 0x1fff

    .line 87
    .line 88
    const/16 v9, 0xd

    .line 89
    .line 90
    :goto_2
    add-int/lit8 v10, v7, 0x1

    .line 91
    .line 92
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 93
    .line 94
    .line 95
    move-result v7

    .line 96
    if-lt v7, v6, :cond_5

    .line 97
    .line 98
    and-int/lit16 v7, v7, 0x1fff

    .line 99
    .line 100
    shl-int/2addr v7, v9

    .line 101
    or-int/2addr v4, v7

    .line 102
    add-int/lit8 v9, v9, 0xd

    .line 103
    .line 104
    move v7, v10

    .line 105
    goto :goto_2

    .line 106
    :cond_5
    shl-int/2addr v7, v9

    .line 107
    or-int/2addr v4, v7

    .line 108
    move v7, v10

    .line 109
    :cond_6
    add-int/lit8 v9, v7, 0x1

    .line 110
    .line 111
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    if-lt v7, v6, :cond_8

    .line 116
    .line 117
    and-int/lit16 v7, v7, 0x1fff

    .line 118
    .line 119
    const/16 v10, 0xd

    .line 120
    .line 121
    :goto_3
    add-int/lit8 v11, v9, 0x1

    .line 122
    .line 123
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 124
    .line 125
    .line 126
    move-result v9

    .line 127
    if-lt v9, v6, :cond_7

    .line 128
    .line 129
    and-int/lit16 v9, v9, 0x1fff

    .line 130
    .line 131
    shl-int/2addr v9, v10

    .line 132
    or-int/2addr v7, v9

    .line 133
    add-int/lit8 v10, v10, 0xd

    .line 134
    .line 135
    move v9, v11

    .line 136
    goto :goto_3

    .line 137
    :cond_7
    shl-int/2addr v9, v10

    .line 138
    or-int/2addr v7, v9

    .line 139
    move v9, v11

    .line 140
    :cond_8
    add-int/lit8 v10, v9, 0x1

    .line 141
    .line 142
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 143
    .line 144
    .line 145
    move-result v9

    .line 146
    if-lt v9, v6, :cond_a

    .line 147
    .line 148
    and-int/lit16 v9, v9, 0x1fff

    .line 149
    .line 150
    const/16 v11, 0xd

    .line 151
    .line 152
    :goto_4
    add-int/lit8 v12, v10, 0x1

    .line 153
    .line 154
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 155
    .line 156
    .line 157
    move-result v10

    .line 158
    if-lt v10, v6, :cond_9

    .line 159
    .line 160
    and-int/lit16 v10, v10, 0x1fff

    .line 161
    .line 162
    shl-int/2addr v10, v11

    .line 163
    or-int/2addr v9, v10

    .line 164
    add-int/lit8 v11, v11, 0xd

    .line 165
    .line 166
    move v10, v12

    .line 167
    goto :goto_4

    .line 168
    :cond_9
    shl-int/2addr v10, v11

    .line 169
    or-int/2addr v9, v10

    .line 170
    move v10, v12

    .line 171
    :cond_a
    add-int/lit8 v11, v10, 0x1

    .line 172
    .line 173
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 174
    .line 175
    .line 176
    move-result v10

    .line 177
    if-lt v10, v6, :cond_c

    .line 178
    .line 179
    and-int/lit16 v10, v10, 0x1fff

    .line 180
    .line 181
    const/16 v12, 0xd

    .line 182
    .line 183
    :goto_5
    add-int/lit8 v13, v11, 0x1

    .line 184
    .line 185
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 186
    .line 187
    .line 188
    move-result v11

    .line 189
    if-lt v11, v6, :cond_b

    .line 190
    .line 191
    and-int/lit16 v11, v11, 0x1fff

    .line 192
    .line 193
    shl-int/2addr v11, v12

    .line 194
    or-int/2addr v10, v11

    .line 195
    add-int/lit8 v12, v12, 0xd

    .line 196
    .line 197
    move v11, v13

    .line 198
    goto :goto_5

    .line 199
    :cond_b
    shl-int/2addr v11, v12

    .line 200
    or-int/2addr v10, v11

    .line 201
    move v11, v13

    .line 202
    :cond_c
    add-int/lit8 v12, v11, 0x1

    .line 203
    .line 204
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 205
    .line 206
    .line 207
    move-result v11

    .line 208
    if-lt v11, v6, :cond_e

    .line 209
    .line 210
    and-int/lit16 v11, v11, 0x1fff

    .line 211
    .line 212
    const/16 v13, 0xd

    .line 213
    .line 214
    :goto_6
    add-int/lit8 v14, v12, 0x1

    .line 215
    .line 216
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 217
    .line 218
    .line 219
    move-result v12

    .line 220
    if-lt v12, v6, :cond_d

    .line 221
    .line 222
    and-int/lit16 v12, v12, 0x1fff

    .line 223
    .line 224
    shl-int/2addr v12, v13

    .line 225
    or-int/2addr v11, v12

    .line 226
    add-int/lit8 v13, v13, 0xd

    .line 227
    .line 228
    move v12, v14

    .line 229
    goto :goto_6

    .line 230
    :cond_d
    shl-int/2addr v12, v13

    .line 231
    or-int/2addr v11, v12

    .line 232
    move v12, v14

    .line 233
    :cond_e
    add-int/lit8 v13, v12, 0x1

    .line 234
    .line 235
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 236
    .line 237
    .line 238
    move-result v12

    .line 239
    if-lt v12, v6, :cond_10

    .line 240
    .line 241
    and-int/lit16 v12, v12, 0x1fff

    .line 242
    .line 243
    const/16 v14, 0xd

    .line 244
    .line 245
    :goto_7
    add-int/lit8 v15, v13, 0x1

    .line 246
    .line 247
    invoke-virtual {v1, v13}, Ljava/lang/String;->charAt(I)C

    .line 248
    .line 249
    .line 250
    move-result v13

    .line 251
    if-lt v13, v6, :cond_f

    .line 252
    .line 253
    and-int/lit16 v13, v13, 0x1fff

    .line 254
    .line 255
    shl-int/2addr v13, v14

    .line 256
    or-int/2addr v12, v13

    .line 257
    add-int/lit8 v14, v14, 0xd

    .line 258
    .line 259
    move v13, v15

    .line 260
    goto :goto_7

    .line 261
    :cond_f
    shl-int/2addr v13, v14

    .line 262
    or-int/2addr v12, v13

    .line 263
    move v13, v15

    .line 264
    :cond_10
    add-int/lit8 v14, v13, 0x1

    .line 265
    .line 266
    invoke-virtual {v1, v13}, Ljava/lang/String;->charAt(I)C

    .line 267
    .line 268
    .line 269
    move-result v13

    .line 270
    if-lt v13, v6, :cond_12

    .line 271
    .line 272
    and-int/lit16 v13, v13, 0x1fff

    .line 273
    .line 274
    const/16 v15, 0xd

    .line 275
    .line 276
    :goto_8
    add-int/lit8 v16, v14, 0x1

    .line 277
    .line 278
    invoke-virtual {v1, v14}, Ljava/lang/String;->charAt(I)C

    .line 279
    .line 280
    .line 281
    move-result v14

    .line 282
    if-lt v14, v6, :cond_11

    .line 283
    .line 284
    and-int/lit16 v14, v14, 0x1fff

    .line 285
    .line 286
    shl-int/2addr v14, v15

    .line 287
    or-int/2addr v13, v14

    .line 288
    add-int/lit8 v15, v15, 0xd

    .line 289
    .line 290
    move/from16 v14, v16

    .line 291
    .line 292
    goto :goto_8

    .line 293
    :cond_11
    shl-int/2addr v14, v15

    .line 294
    or-int/2addr v13, v14

    .line 295
    move/from16 v14, v16

    .line 296
    .line 297
    :cond_12
    add-int/lit8 v15, v14, 0x1

    .line 298
    .line 299
    invoke-virtual {v1, v14}, Ljava/lang/String;->charAt(I)C

    .line 300
    .line 301
    .line 302
    move-result v14

    .line 303
    if-lt v14, v6, :cond_14

    .line 304
    .line 305
    and-int/lit16 v14, v14, 0x1fff

    .line 306
    .line 307
    const/16 v16, 0xd

    .line 308
    .line 309
    :goto_9
    add-int/lit8 v17, v15, 0x1

    .line 310
    .line 311
    invoke-virtual {v1, v15}, Ljava/lang/String;->charAt(I)C

    .line 312
    .line 313
    .line 314
    move-result v15

    .line 315
    if-lt v15, v6, :cond_13

    .line 316
    .line 317
    and-int/lit16 v15, v15, 0x1fff

    .line 318
    .line 319
    shl-int v15, v15, v16

    .line 320
    .line 321
    or-int/2addr v14, v15

    .line 322
    add-int/lit8 v16, v16, 0xd

    .line 323
    .line 324
    move/from16 v15, v17

    .line 325
    .line 326
    goto :goto_9

    .line 327
    :cond_13
    shl-int v15, v15, v16

    .line 328
    .line 329
    or-int/2addr v14, v15

    .line 330
    move/from16 v15, v17

    .line 331
    .line 332
    :cond_14
    add-int v16, v14, v12

    .line 333
    .line 334
    add-int v13, v16, v13

    .line 335
    .line 336
    new-array v13, v13, [I

    .line 337
    .line 338
    mul-int/lit8 v16, v4, 0x2

    .line 339
    .line 340
    add-int v16, v16, v7

    .line 341
    .line 342
    move v7, v12

    .line 343
    move v12, v9

    .line 344
    move v9, v7

    .line 345
    move v7, v4

    .line 346
    move v4, v15

    .line 347
    move-object v15, v13

    .line 348
    move v13, v10

    .line 349
    move/from16 v10, v16

    .line 350
    .line 351
    move/from16 v16, v14

    .line 352
    .line 353
    :goto_a
    sget-object v14, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 354
    .line 355
    iget-object v3, v0, Landroidx/datastore/preferences/protobuf/z0;->c:[Ljava/lang/Object;

    .line 356
    .line 357
    iget-object v8, v0, Landroidx/datastore/preferences/protobuf/z0;->a:Landroidx/datastore/preferences/protobuf/a;

    .line 358
    .line 359
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 360
    .line 361
    .line 362
    move-result-object v8

    .line 363
    mul-int/lit8 v5, v11, 0x3

    .line 364
    .line 365
    new-array v5, v5, [I

    .line 366
    .line 367
    const/4 v6, 0x2

    .line 368
    mul-int/2addr v11, v6

    .line 369
    new-array v11, v11, [Ljava/lang/Object;

    .line 370
    .line 371
    add-int v9, v16, v9

    .line 372
    .line 373
    move/from16 v24, v9

    .line 374
    .line 375
    move/from16 v23, v16

    .line 376
    .line 377
    const/4 v6, 0x0

    .line 378
    const/16 v21, 0x0

    .line 379
    .line 380
    :goto_b
    if-ge v4, v2, :cond_36

    .line 381
    .line 382
    add-int/lit8 v25, v4, 0x1

    .line 383
    .line 384
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 385
    .line 386
    .line 387
    move-result v4

    .line 388
    move/from16 v26, v2

    .line 389
    .line 390
    const v2, 0xd800

    .line 391
    .line 392
    .line 393
    if-lt v4, v2, :cond_16

    .line 394
    .line 395
    and-int/lit16 v4, v4, 0x1fff

    .line 396
    .line 397
    move/from16 v2, v25

    .line 398
    .line 399
    const/16 v25, 0xd

    .line 400
    .line 401
    :goto_c
    add-int/lit8 v27, v2, 0x1

    .line 402
    .line 403
    invoke-virtual {v1, v2}, Ljava/lang/String;->charAt(I)C

    .line 404
    .line 405
    .line 406
    move-result v2

    .line 407
    move-object/from16 v28, v3

    .line 408
    .line 409
    const v3, 0xd800

    .line 410
    .line 411
    .line 412
    if-lt v2, v3, :cond_15

    .line 413
    .line 414
    and-int/lit16 v2, v2, 0x1fff

    .line 415
    .line 416
    shl-int v2, v2, v25

    .line 417
    .line 418
    or-int/2addr v4, v2

    .line 419
    add-int/lit8 v25, v25, 0xd

    .line 420
    .line 421
    move/from16 v2, v27

    .line 422
    .line 423
    move-object/from16 v3, v28

    .line 424
    .line 425
    goto :goto_c

    .line 426
    :cond_15
    shl-int v2, v2, v25

    .line 427
    .line 428
    or-int/2addr v4, v2

    .line 429
    move/from16 v2, v27

    .line 430
    .line 431
    goto :goto_d

    .line 432
    :cond_16
    move-object/from16 v28, v3

    .line 433
    .line 434
    move/from16 v2, v25

    .line 435
    .line 436
    :goto_d
    add-int/lit8 v3, v2, 0x1

    .line 437
    .line 438
    invoke-virtual {v1, v2}, Ljava/lang/String;->charAt(I)C

    .line 439
    .line 440
    .line 441
    move-result v2

    .line 442
    move/from16 v25, v3

    .line 443
    .line 444
    const v3, 0xd800

    .line 445
    .line 446
    .line 447
    if-lt v2, v3, :cond_18

    .line 448
    .line 449
    and-int/lit16 v2, v2, 0x1fff

    .line 450
    .line 451
    move/from16 v3, v25

    .line 452
    .line 453
    const/16 v25, 0xd

    .line 454
    .line 455
    :goto_e
    add-int/lit8 v27, v3, 0x1

    .line 456
    .line 457
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 458
    .line 459
    .line 460
    move-result v3

    .line 461
    move/from16 v29, v2

    .line 462
    .line 463
    const v2, 0xd800

    .line 464
    .line 465
    .line 466
    if-lt v3, v2, :cond_17

    .line 467
    .line 468
    and-int/lit16 v2, v3, 0x1fff

    .line 469
    .line 470
    shl-int v2, v2, v25

    .line 471
    .line 472
    or-int v2, v29, v2

    .line 473
    .line 474
    add-int/lit8 v25, v25, 0xd

    .line 475
    .line 476
    move/from16 v3, v27

    .line 477
    .line 478
    goto :goto_e

    .line 479
    :cond_17
    shl-int v2, v3, v25

    .line 480
    .line 481
    or-int v2, v29, v2

    .line 482
    .line 483
    move/from16 v3, v27

    .line 484
    .line 485
    goto :goto_f

    .line 486
    :cond_18
    move/from16 v3, v25

    .line 487
    .line 488
    :goto_f
    move/from16 v25, v4

    .line 489
    .line 490
    and-int/lit16 v4, v2, 0xff

    .line 491
    .line 492
    move-object/from16 v27, v5

    .line 493
    .line 494
    and-int/lit16 v5, v2, 0x400

    .line 495
    .line 496
    if-eqz v5, :cond_19

    .line 497
    .line 498
    add-int/lit8 v5, v21, 0x1

    .line 499
    .line 500
    aput v6, v15, v21

    .line 501
    .line 502
    move/from16 v21, v5

    .line 503
    .line 504
    :cond_19
    const/16 v5, 0x33

    .line 505
    .line 506
    move/from16 v31, v7

    .line 507
    .line 508
    if-lt v4, v5, :cond_23

    .line 509
    .line 510
    add-int/lit8 v5, v3, 0x1

    .line 511
    .line 512
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 513
    .line 514
    .line 515
    move-result v3

    .line 516
    const v7, 0xd800

    .line 517
    .line 518
    .line 519
    if-lt v3, v7, :cond_1b

    .line 520
    .line 521
    and-int/lit16 v3, v3, 0x1fff

    .line 522
    .line 523
    const/16 v34, 0xd

    .line 524
    .line 525
    :goto_10
    add-int/lit8 v35, v5, 0x1

    .line 526
    .line 527
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 528
    .line 529
    .line 530
    move-result v5

    .line 531
    if-lt v5, v7, :cond_1a

    .line 532
    .line 533
    and-int/lit16 v5, v5, 0x1fff

    .line 534
    .line 535
    shl-int v5, v5, v34

    .line 536
    .line 537
    or-int/2addr v3, v5

    .line 538
    add-int/lit8 v34, v34, 0xd

    .line 539
    .line 540
    move/from16 v5, v35

    .line 541
    .line 542
    const v7, 0xd800

    .line 543
    .line 544
    .line 545
    goto :goto_10

    .line 546
    :cond_1a
    shl-int v5, v5, v34

    .line 547
    .line 548
    or-int/2addr v3, v5

    .line 549
    move/from16 v5, v35

    .line 550
    .line 551
    :cond_1b
    add-int/lit8 v7, v4, -0x33

    .line 552
    .line 553
    move/from16 v34, v3

    .line 554
    .line 555
    const/16 v3, 0x9

    .line 556
    .line 557
    if-eq v7, v3, :cond_1c

    .line 558
    .line 559
    const/16 v3, 0x11

    .line 560
    .line 561
    if-ne v7, v3, :cond_1d

    .line 562
    .line 563
    :cond_1c
    move/from16 v29, v5

    .line 564
    .line 565
    const/4 v3, 0x3

    .line 566
    const/4 v5, 0x2

    .line 567
    const/4 v7, 0x1

    .line 568
    goto :goto_13

    .line 569
    :cond_1d
    const/16 v3, 0xc

    .line 570
    .line 571
    if-ne v7, v3, :cond_20

    .line 572
    .line 573
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/z0;->a()I

    .line 574
    .line 575
    .line 576
    move-result v3

    .line 577
    const/4 v7, 0x1

    .line 578
    invoke-static {v3, v7}, Lu/w;->a(II)Z

    .line 579
    .line 580
    .line 581
    move-result v3

    .line 582
    if-nez v3, :cond_1e

    .line 583
    .line 584
    and-int/lit16 v3, v2, 0x800

    .line 585
    .line 586
    if-eqz v3, :cond_1f

    .line 587
    .line 588
    :cond_1e
    move/from16 v29, v5

    .line 589
    .line 590
    const/4 v3, 0x3

    .line 591
    const/4 v5, 0x2

    .line 592
    goto :goto_12

    .line 593
    :cond_1f
    :goto_11
    move/from16 v29, v5

    .line 594
    .line 595
    const/4 v5, 0x2

    .line 596
    goto :goto_14

    .line 597
    :goto_12
    invoke-static {v6, v3, v5, v7}, La7/g0;->d(IIII)I

    .line 598
    .line 599
    .line 600
    move-result v3

    .line 601
    add-int/lit8 v19, v10, 0x1

    .line 602
    .line 603
    aget-object v10, v28, v10

    .line 604
    .line 605
    aput-object v10, v11, v3

    .line 606
    .line 607
    move/from16 v10, v19

    .line 608
    .line 609
    goto :goto_14

    .line 610
    :cond_20
    const/4 v7, 0x1

    .line 611
    goto :goto_11

    .line 612
    :goto_13
    invoke-static {v6, v3, v5, v7}, La7/g0;->d(IIII)I

    .line 613
    .line 614
    .line 615
    move-result v3

    .line 616
    add-int/lit8 v7, v10, 0x1

    .line 617
    .line 618
    aget-object v10, v28, v10

    .line 619
    .line 620
    aput-object v10, v11, v3

    .line 621
    .line 622
    move v10, v7

    .line 623
    :goto_14
    mul-int/lit8 v3, v34, 0x2

    .line 624
    .line 625
    aget-object v5, v28, v3

    .line 626
    .line 627
    instance-of v7, v5, Ljava/lang/reflect/Field;

    .line 628
    .line 629
    if-eqz v7, :cond_21

    .line 630
    .line 631
    check-cast v5, Ljava/lang/reflect/Field;

    .line 632
    .line 633
    :goto_15
    move v7, v9

    .line 634
    move/from16 v30, v10

    .line 635
    .line 636
    goto :goto_16

    .line 637
    :cond_21
    check-cast v5, Ljava/lang/String;

    .line 638
    .line 639
    invoke-static {v8, v5}, Landroidx/datastore/preferences/protobuf/r0;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 640
    .line 641
    .line 642
    move-result-object v5

    .line 643
    aput-object v5, v28, v3

    .line 644
    .line 645
    goto :goto_15

    .line 646
    :goto_16
    invoke-virtual {v14, v5}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 647
    .line 648
    .line 649
    move-result-wide v9

    .line 650
    long-to-int v5, v9

    .line 651
    add-int/lit8 v3, v3, 0x1

    .line 652
    .line 653
    aget-object v9, v28, v3

    .line 654
    .line 655
    instance-of v10, v9, Ljava/lang/reflect/Field;

    .line 656
    .line 657
    if-eqz v10, :cond_22

    .line 658
    .line 659
    check-cast v9, Ljava/lang/reflect/Field;

    .line 660
    .line 661
    goto :goto_17

    .line 662
    :cond_22
    check-cast v9, Ljava/lang/String;

    .line 663
    .line 664
    invoke-static {v8, v9}, Landroidx/datastore/preferences/protobuf/r0;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 665
    .line 666
    .line 667
    move-result-object v9

    .line 668
    aput-object v9, v28, v3

    .line 669
    .line 670
    :goto_17
    invoke-virtual {v14, v9}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 671
    .line 672
    .line 673
    move-result-wide v9

    .line 674
    long-to-int v3, v9

    .line 675
    move-object/from16 v32, v1

    .line 676
    .line 677
    move v9, v5

    .line 678
    move v1, v6

    .line 679
    move/from16 v10, v29

    .line 680
    .line 681
    const/16 v22, 0x2

    .line 682
    .line 683
    move v5, v3

    .line 684
    move/from16 v29, v7

    .line 685
    .line 686
    const/4 v3, 0x0

    .line 687
    goto/16 :goto_23

    .line 688
    .line 689
    :cond_23
    move v7, v9

    .line 690
    add-int/lit8 v5, v10, 0x1

    .line 691
    .line 692
    aget-object v9, v28, v10

    .line 693
    .line 694
    check-cast v9, Ljava/lang/String;

    .line 695
    .line 696
    invoke-static {v8, v9}, Landroidx/datastore/preferences/protobuf/r0;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 697
    .line 698
    .line 699
    move-result-object v9

    .line 700
    move/from16 v34, v5

    .line 701
    .line 702
    const/16 v5, 0x9

    .line 703
    .line 704
    if-eq v4, v5, :cond_24

    .line 705
    .line 706
    const/16 v5, 0x11

    .line 707
    .line 708
    if-ne v4, v5, :cond_25

    .line 709
    .line 710
    :cond_24
    move/from16 v29, v7

    .line 711
    .line 712
    const/4 v5, 0x3

    .line 713
    const/4 v7, 0x1

    .line 714
    const/4 v10, 0x2

    .line 715
    goto/16 :goto_1c

    .line 716
    .line 717
    :cond_25
    const/16 v5, 0x1b

    .line 718
    .line 719
    if-eq v4, v5, :cond_26

    .line 720
    .line 721
    const/16 v5, 0x31

    .line 722
    .line 723
    if-ne v4, v5, :cond_27

    .line 724
    .line 725
    :cond_26
    move/from16 v29, v7

    .line 726
    .line 727
    move/from16 v19, v10

    .line 728
    .line 729
    const/4 v5, 0x3

    .line 730
    const/4 v7, 0x1

    .line 731
    const/4 v10, 0x2

    .line 732
    goto :goto_1b

    .line 733
    :cond_27
    const/16 v5, 0xc

    .line 734
    .line 735
    if-eq v4, v5, :cond_2b

    .line 736
    .line 737
    const/16 v5, 0x1e

    .line 738
    .line 739
    if-eq v4, v5, :cond_2b

    .line 740
    .line 741
    const/16 v5, 0x2c

    .line 742
    .line 743
    if-ne v4, v5, :cond_28

    .line 744
    .line 745
    goto :goto_19

    .line 746
    :cond_28
    const/16 v5, 0x32

    .line 747
    .line 748
    if-ne v4, v5, :cond_2a

    .line 749
    .line 750
    add-int/lit8 v5, v23, 0x1

    .line 751
    .line 752
    aput v6, v15, v23

    .line 753
    .line 754
    div-int/lit8 v23, v6, 0x3

    .line 755
    .line 756
    const/16 v22, 0x2

    .line 757
    .line 758
    mul-int/lit8 v23, v23, 0x2

    .line 759
    .line 760
    add-int/lit8 v29, v10, 0x2

    .line 761
    .line 762
    aget-object v30, v28, v34

    .line 763
    .line 764
    aput-object v30, v11, v23

    .line 765
    .line 766
    move/from16 v30, v5

    .line 767
    .line 768
    and-int/lit16 v5, v2, 0x800

    .line 769
    .line 770
    if-eqz v5, :cond_29

    .line 771
    .line 772
    add-int/lit8 v23, v23, 0x1

    .line 773
    .line 774
    add-int/lit8 v5, v10, 0x3

    .line 775
    .line 776
    aget-object v10, v28, v29

    .line 777
    .line 778
    aput-object v10, v11, v23

    .line 779
    .line 780
    move/from16 v29, v7

    .line 781
    .line 782
    move/from16 v23, v30

    .line 783
    .line 784
    :goto_18
    const/4 v7, 0x1

    .line 785
    goto :goto_1e

    .line 786
    :cond_29
    move/from16 v5, v29

    .line 787
    .line 788
    move/from16 v23, v30

    .line 789
    .line 790
    move/from16 v29, v7

    .line 791
    .line 792
    goto :goto_18

    .line 793
    :cond_2a
    move/from16 v29, v7

    .line 794
    .line 795
    const/4 v7, 0x1

    .line 796
    goto :goto_1d

    .line 797
    :cond_2b
    :goto_19
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/z0;->a()I

    .line 798
    .line 799
    .line 800
    move-result v5

    .line 801
    move/from16 v29, v7

    .line 802
    .line 803
    const/4 v7, 0x1

    .line 804
    if-eq v5, v7, :cond_2c

    .line 805
    .line 806
    and-int/lit16 v5, v2, 0x800

    .line 807
    .line 808
    if-eqz v5, :cond_2d

    .line 809
    .line 810
    :cond_2c
    move/from16 v19, v10

    .line 811
    .line 812
    const/4 v5, 0x3

    .line 813
    const/4 v10, 0x2

    .line 814
    invoke-static {v6, v5, v10, v7}, La7/g0;->d(IIII)I

    .line 815
    .line 816
    .line 817
    move-result v5

    .line 818
    add-int/lit8 v19, v19, 0x2

    .line 819
    .line 820
    aget-object v22, v28, v34

    .line 821
    .line 822
    aput-object v22, v11, v5

    .line 823
    .line 824
    :goto_1a
    move/from16 v5, v19

    .line 825
    .line 826
    goto :goto_1e

    .line 827
    :goto_1b
    invoke-static {v6, v5, v10, v7}, La7/g0;->d(IIII)I

    .line 828
    .line 829
    .line 830
    move-result v5

    .line 831
    add-int/lit8 v19, v19, 0x2

    .line 832
    .line 833
    aget-object v22, v28, v34

    .line 834
    .line 835
    aput-object v22, v11, v5

    .line 836
    .line 837
    goto :goto_1a

    .line 838
    :goto_1c
    invoke-static {v6, v5, v10, v7}, La7/g0;->d(IIII)I

    .line 839
    .line 840
    .line 841
    move-result v5

    .line 842
    invoke-virtual {v9}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 843
    .line 844
    .line 845
    move-result-object v10

    .line 846
    aput-object v10, v11, v5

    .line 847
    .line 848
    :cond_2d
    :goto_1d
    move/from16 v5, v34

    .line 849
    .line 850
    :goto_1e
    invoke-virtual {v14, v9}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 851
    .line 852
    .line 853
    move-result-wide v9

    .line 854
    long-to-int v9, v9

    .line 855
    and-int/lit16 v10, v2, 0x1000

    .line 856
    .line 857
    if-eqz v10, :cond_31

    .line 858
    .line 859
    const/16 v10, 0x11

    .line 860
    .line 861
    if-gt v4, v10, :cond_31

    .line 862
    .line 863
    add-int/lit8 v10, v3, 0x1

    .line 864
    .line 865
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 866
    .line 867
    .line 868
    move-result v3

    .line 869
    const v7, 0xd800

    .line 870
    .line 871
    .line 872
    if-lt v3, v7, :cond_2f

    .line 873
    .line 874
    and-int/lit16 v3, v3, 0x1fff

    .line 875
    .line 876
    const/16 v20, 0xd

    .line 877
    .line 878
    :goto_1f
    add-int/lit8 v30, v10, 0x1

    .line 879
    .line 880
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 881
    .line 882
    .line 883
    move-result v10

    .line 884
    if-lt v10, v7, :cond_2e

    .line 885
    .line 886
    and-int/lit16 v10, v10, 0x1fff

    .line 887
    .line 888
    shl-int v10, v10, v20

    .line 889
    .line 890
    or-int/2addr v3, v10

    .line 891
    add-int/lit8 v20, v20, 0xd

    .line 892
    .line 893
    move/from16 v10, v30

    .line 894
    .line 895
    goto :goto_1f

    .line 896
    :cond_2e
    shl-int v10, v10, v20

    .line 897
    .line 898
    or-int/2addr v3, v10

    .line 899
    move/from16 v10, v30

    .line 900
    .line 901
    :cond_2f
    const/16 v22, 0x2

    .line 902
    .line 903
    mul-int/lit8 v20, v31, 0x2

    .line 904
    .line 905
    div-int/lit8 v30, v3, 0x20

    .line 906
    .line 907
    add-int v30, v30, v20

    .line 908
    .line 909
    aget-object v7, v28, v30

    .line 910
    .line 911
    move-object/from16 v32, v1

    .line 912
    .line 913
    instance-of v1, v7, Ljava/lang/reflect/Field;

    .line 914
    .line 915
    if-eqz v1, :cond_30

    .line 916
    .line 917
    check-cast v7, Ljava/lang/reflect/Field;

    .line 918
    .line 919
    :goto_20
    move/from16 v30, v5

    .line 920
    .line 921
    move v1, v6

    .line 922
    goto :goto_21

    .line 923
    :cond_30
    check-cast v7, Ljava/lang/String;

    .line 924
    .line 925
    invoke-static {v8, v7}, Landroidx/datastore/preferences/protobuf/r0;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 926
    .line 927
    .line 928
    move-result-object v7

    .line 929
    aput-object v7, v28, v30

    .line 930
    .line 931
    goto :goto_20

    .line 932
    :goto_21
    invoke-virtual {v14, v7}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 933
    .line 934
    .line 935
    move-result-wide v5

    .line 936
    long-to-int v5, v5

    .line 937
    rem-int/lit8 v3, v3, 0x20

    .line 938
    .line 939
    goto :goto_22

    .line 940
    :cond_31
    move-object/from16 v32, v1

    .line 941
    .line 942
    move/from16 v30, v5

    .line 943
    .line 944
    move v1, v6

    .line 945
    const/16 v22, 0x2

    .line 946
    .line 947
    const v5, 0xfffff

    .line 948
    .line 949
    .line 950
    move v10, v3

    .line 951
    const/4 v3, 0x0

    .line 952
    :goto_22
    const/16 v6, 0x12

    .line 953
    .line 954
    if-lt v4, v6, :cond_32

    .line 955
    .line 956
    const/16 v6, 0x31

    .line 957
    .line 958
    if-gt v4, v6, :cond_32

    .line 959
    .line 960
    add-int/lit8 v6, v24, 0x1

    .line 961
    .line 962
    aput v9, v15, v24

    .line 963
    .line 964
    move/from16 v24, v6

    .line 965
    .line 966
    :cond_32
    :goto_23
    add-int/lit8 v6, v1, 0x1

    .line 967
    .line 968
    aput v25, v27, v1

    .line 969
    .line 970
    add-int/lit8 v7, v1, 0x2

    .line 971
    .line 972
    move/from16 v25, v1

    .line 973
    .line 974
    and-int/lit16 v1, v2, 0x200

    .line 975
    .line 976
    if-eqz v1, :cond_33

    .line 977
    .line 978
    const/high16 v1, 0x20000000

    .line 979
    .line 980
    goto :goto_24

    .line 981
    :cond_33
    const/4 v1, 0x0

    .line 982
    :goto_24
    move/from16 v33, v1

    .line 983
    .line 984
    and-int/lit16 v1, v2, 0x100

    .line 985
    .line 986
    if-eqz v1, :cond_34

    .line 987
    .line 988
    const/high16 v1, 0x10000000

    .line 989
    .line 990
    goto :goto_25

    .line 991
    :cond_34
    const/4 v1, 0x0

    .line 992
    :goto_25
    or-int v1, v33, v1

    .line 993
    .line 994
    and-int/lit16 v2, v2, 0x800

    .line 995
    .line 996
    if-eqz v2, :cond_35

    .line 997
    .line 998
    const/high16 v2, -0x80000000

    .line 999
    .line 1000
    goto :goto_26

    .line 1001
    :cond_35
    const/4 v2, 0x0

    .line 1002
    :goto_26
    or-int/2addr v1, v2

    .line 1003
    shl-int/lit8 v2, v4, 0x14

    .line 1004
    .line 1005
    or-int/2addr v1, v2

    .line 1006
    or-int/2addr v1, v9

    .line 1007
    aput v1, v27, v6

    .line 1008
    .line 1009
    add-int/lit8 v6, v25, 0x3

    .line 1010
    .line 1011
    shl-int/lit8 v1, v3, 0x14

    .line 1012
    .line 1013
    or-int/2addr v1, v5

    .line 1014
    aput v1, v27, v7

    .line 1015
    .line 1016
    move v4, v10

    .line 1017
    move/from16 v2, v26

    .line 1018
    .line 1019
    move-object/from16 v5, v27

    .line 1020
    .line 1021
    move-object/from16 v3, v28

    .line 1022
    .line 1023
    move/from16 v9, v29

    .line 1024
    .line 1025
    move/from16 v10, v30

    .line 1026
    .line 1027
    move/from16 v7, v31

    .line 1028
    .line 1029
    move-object/from16 v1, v32

    .line 1030
    .line 1031
    goto/16 :goto_b

    .line 1032
    .line 1033
    :cond_36
    move-object/from16 v27, v5

    .line 1034
    .line 1035
    move/from16 v29, v9

    .line 1036
    .line 1037
    new-instance v9, Landroidx/datastore/preferences/protobuf/r0;

    .line 1038
    .line 1039
    iget-object v14, v0, Landroidx/datastore/preferences/protobuf/z0;->a:Landroidx/datastore/preferences/protobuf/a;

    .line 1040
    .line 1041
    move-object/from16 v18, p1

    .line 1042
    .line 1043
    move-object/from16 v19, p2

    .line 1044
    .line 1045
    move-object/from16 v20, p3

    .line 1046
    .line 1047
    move-object/from16 v21, p4

    .line 1048
    .line 1049
    move-object/from16 v22, p5

    .line 1050
    .line 1051
    move-object/from16 v10, v27

    .line 1052
    .line 1053
    move/from16 v17, v29

    .line 1054
    .line 1055
    invoke-direct/range {v9 .. v22}, Landroidx/datastore/preferences/protobuf/r0;-><init>([I[Ljava/lang/Object;IILandroidx/datastore/preferences/protobuf/a;[IIILandroidx/datastore/preferences/protobuf/t0;Landroidx/datastore/preferences/protobuf/f0;Landroidx/datastore/preferences/protobuf/i1;Landroidx/datastore/preferences/protobuf/p;Landroidx/datastore/preferences/protobuf/n0;)V

    .line 1056
    .line 1057
    .line 1058
    return-object v9
.end method

.method public static x(I)J
    .locals 2

    .line 1
    const v0, 0xfffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p0, v0

    .line 5
    int-to-long v0, p0

    .line 6
    return-wide v0
.end method

.method public static y(JLjava/lang/Object;)I
    .locals 1

    .line 1
    sget-object v0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static z(JLjava/lang/Object;)J
    .locals 1

    .line 1
    sget-object v0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Long;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    return-wide p0
.end method


# virtual methods
.method public final A(I)I
    .locals 6

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/r0;->c:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-lt p1, v0, :cond_2

    .line 5
    .line 6
    iget v0, p0, Landroidx/datastore/preferences/protobuf/r0;->d:I

    .line 7
    .line 8
    if-gt p1, v0, :cond_2

    .line 9
    .line 10
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 11
    .line 12
    array-length v0, p0

    .line 13
    div-int/lit8 v0, v0, 0x3

    .line 14
    .line 15
    add-int/lit8 v0, v0, -0x1

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    :goto_0
    if-gt v2, v0, :cond_2

    .line 19
    .line 20
    add-int v3, v0, v2

    .line 21
    .line 22
    ushr-int/lit8 v3, v3, 0x1

    .line 23
    .line 24
    mul-int/lit8 v4, v3, 0x3

    .line 25
    .line 26
    aget v5, p0, v4

    .line 27
    .line 28
    if-ne p1, v5, :cond_0

    .line 29
    .line 30
    return v4

    .line 31
    :cond_0
    if-ge p1, v5, :cond_1

    .line 32
    .line 33
    add-int/lit8 v3, v3, -0x1

    .line 34
    .line 35
    move v0, v3

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 38
    .line 39
    move v2, v3

    .line 40
    goto :goto_0

    .line 41
    :cond_2
    return v1
.end method

.method public final B(Ljava/lang/Object;JLandroidx/collection/h;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->k:Landroidx/datastore/preferences/protobuf/f0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p2, p3, p1}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget-object p1, p4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p1, Landroidx/datastore/preferences/protobuf/k;

    .line 13
    .line 14
    iget p2, p4, Landroidx/collection/h;->e:I

    .line 15
    .line 16
    and-int/lit8 p3, p2, 0x7

    .line 17
    .line 18
    const/4 v0, 0x3

    .line 19
    if-ne p3, v0, :cond_3

    .line 20
    .line 21
    :cond_0
    invoke-interface {p5}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 22
    .line 23
    .line 24
    move-result-object p3

    .line 25
    invoke-virtual {p4, p3, p5, p6}, Landroidx/collection/h;->i(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p5, p3}, Landroidx/datastore/preferences/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {p0, p3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 35
    .line 36
    .line 37
    move-result p3

    .line 38
    if-nez p3, :cond_2

    .line 39
    .line 40
    iget p3, p4, Landroidx/collection/h;->g:I

    .line 41
    .line 42
    if-eqz p3, :cond_1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 46
    .line 47
    .line 48
    move-result p3

    .line 49
    if-eq p3, p2, :cond_0

    .line 50
    .line 51
    iput p3, p4, Landroidx/collection/h;->g:I

    .line 52
    .line 53
    :cond_2
    :goto_0
    return-void

    .line 54
    :cond_3
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    throw p0
.end method

.method public final C(Ljava/lang/Object;ILandroidx/collection/h;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V
    .locals 2

    .line 1
    const v0, 0xfffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p2, v0

    .line 5
    int-to-long v0, p2

    .line 6
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->k:Landroidx/datastore/preferences/protobuf/f0;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-static {v0, v1, p1}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    iget-object p1, p3, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p1, Landroidx/datastore/preferences/protobuf/k;

    .line 18
    .line 19
    iget p2, p3, Landroidx/collection/h;->e:I

    .line 20
    .line 21
    and-int/lit8 v0, p2, 0x7

    .line 22
    .line 23
    const/4 v1, 0x2

    .line 24
    if-ne v0, v1, :cond_3

    .line 25
    .line 26
    :cond_0
    invoke-interface {p4}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {p3, v0, p4, p5}, Landroidx/collection/h;->k(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p4, v0}, Landroidx/datastore/preferences/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p0, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    iget v0, p3, Landroidx/collection/h;->g:I

    .line 46
    .line 47
    if-eqz v0, :cond_1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eq v0, p2, :cond_0

    .line 55
    .line 56
    iput v0, p3, Landroidx/collection/h;->g:I

    .line 57
    .line 58
    :cond_2
    :goto_0
    return-void

    .line 59
    :cond_3
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    throw p0
.end method

.method public final D(ILandroidx/collection/h;Ljava/lang/Object;)V
    .locals 3

    .line 1
    const/high16 v0, 0x20000000

    .line 2
    .line 3
    and-int/2addr v0, p1

    .line 4
    const/4 v1, 0x2

    .line 5
    const v2, 0xfffff

    .line 6
    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    and-int p0, p1, v2

    .line 11
    .line 12
    int-to-long p0, p0

    .line 13
    invoke-virtual {p2, v1}, Landroidx/collection/h;->J0(I)V

    .line 14
    .line 15
    .line 16
    iget-object p2, p2, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p2, Landroidx/datastore/preferences/protobuf/k;

    .line 19
    .line 20
    invoke-virtual {p2}, Landroidx/datastore/preferences/protobuf/k;->B()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    invoke-static {p3, p0, p1, p2}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    iget-boolean p0, p0, Landroidx/datastore/preferences/protobuf/r0;->f:Z

    .line 29
    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    and-int p0, p1, v2

    .line 33
    .line 34
    int-to-long p0, p0

    .line 35
    invoke-virtual {p2, v1}, Landroidx/collection/h;->J0(I)V

    .line 36
    .line 37
    .line 38
    iget-object p2, p2, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p2, Landroidx/datastore/preferences/protobuf/k;

    .line 41
    .line 42
    invoke-virtual {p2}, Landroidx/datastore/preferences/protobuf/k;->A()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    invoke-static {p3, p0, p1, p2}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    and-int p0, p1, v2

    .line 51
    .line 52
    int-to-long p0, p0

    .line 53
    invoke-virtual {p2}, Landroidx/collection/h;->q()Landroidx/datastore/preferences/protobuf/h;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-static {p3, p0, p1, p2}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public final E(ILandroidx/collection/h;Ljava/lang/Object;)V
    .locals 2

    .line 1
    const/high16 v0, 0x20000000

    .line 2
    .line 3
    and-int/2addr v0, p1

    .line 4
    const v1, 0xfffff

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->k:Landroidx/datastore/preferences/protobuf/f0;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    and-int/2addr p1, v1

    .line 12
    int-to-long v0, p1

    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1, p3}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 p1, 0x1

    .line 21
    invoke-virtual {p2, p0, p1}, Landroidx/collection/h;->v0(Landroidx/datastore/preferences/protobuf/z;Z)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    and-int/2addr p1, v1

    .line 26
    int-to-long v0, p1

    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    invoke-static {v0, v1, p3}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const/4 p1, 0x0

    .line 35
    invoke-virtual {p2, p0, p1}, Landroidx/collection/h;->v0(Landroidx/datastore/preferences/protobuf/z;Z)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final G(ILjava/lang/Object;)V
    .locals 4

    .line 1
    add-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p1

    .line 6
    .line 7
    const p1, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr p1, p0

    .line 11
    int-to-long v0, p1

    .line 12
    const-wide/32 v2, 0xfffff

    .line 13
    .line 14
    .line 15
    cmp-long p1, v0, v2

    .line 16
    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    ushr-int/lit8 p0, p0, 0x14

    .line 21
    .line 22
    const/4 p1, 0x1

    .line 23
    shl-int p0, p1, p0

    .line 24
    .line 25
    sget-object p1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 26
    .line 27
    invoke-virtual {p1, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    or-int/2addr p0, p1

    .line 32
    invoke-static {v0, v1, p2, p0}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final H(ILjava/lang/Object;I)V
    .locals 2

    .line 1
    add-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p3

    .line 6
    .line 7
    const p3, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr p0, p3

    .line 11
    int-to-long v0, p0

    .line 12
    invoke-static {v0, v1, p2, p1}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final I(Ljava/lang/Object;ILandroidx/datastore/preferences/protobuf/a;)V
    .locals 3

    .line 1
    sget-object v0, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const v2, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr v1, v2

    .line 11
    int-to-long v1, v1

    .line 12
    invoke-virtual {v0, p1, v1, v2, p3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, p2, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final J(Ljava/lang/Object;IILandroidx/datastore/preferences/protobuf/a;)V
    .locals 3

    .line 1
    sget-object v0, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 2
    .line 3
    invoke-virtual {p0, p3}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const v2, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr v1, v2

    .line 11
    int-to-long v1, v1

    .line 12
    invoke-virtual {v0, p1, v1, v2, p4}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, p2, p1, p3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final L(I)I
    .locals 0

    .line 1
    add-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p1

    .line 6
    .line 7
    return p0
.end method

.method public final M(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/j0;)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v6, p2

    .line 6
    .line 7
    iget-object v7, v0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 8
    .line 9
    array-length v8, v7

    .line 10
    sget-object v9, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 11
    .line 12
    const v10, 0xfffff

    .line 13
    .line 14
    .line 15
    move v3, v10

    .line 16
    const/4 v2, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    :goto_0
    if-ge v2, v8, :cond_13

    .line 19
    .line 20
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    aget v12, v7, v2

    .line 25
    .line 26
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 27
    .line 28
    .line 29
    move-result v13

    .line 30
    const/16 v14, 0x11

    .line 31
    .line 32
    const/4 v15, 0x1

    .line 33
    if-gt v13, v14, :cond_2

    .line 34
    .line 35
    add-int/lit8 v14, v2, 0x2

    .line 36
    .line 37
    aget v14, v7, v14

    .line 38
    .line 39
    and-int v11, v14, v10

    .line 40
    .line 41
    if-eq v11, v3, :cond_1

    .line 42
    .line 43
    if-ne v11, v10, :cond_0

    .line 44
    .line 45
    const/4 v4, 0x0

    .line 46
    goto :goto_1

    .line 47
    :cond_0
    int-to-long v3, v11

    .line 48
    invoke-virtual {v9, v1, v3, v4}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    move v4, v3

    .line 53
    :goto_1
    move v3, v11

    .line 54
    :cond_1
    ushr-int/lit8 v11, v14, 0x14

    .line 55
    .line 56
    shl-int v11, v15, v11

    .line 57
    .line 58
    move/from16 v32, v11

    .line 59
    .line 60
    move v11, v5

    .line 61
    move/from16 v5, v32

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_2
    move v11, v5

    .line 65
    const/4 v5, 0x0

    .line 66
    :goto_2
    and-int/2addr v11, v10

    .line 67
    int-to-long v10, v11

    .line 68
    const/16 v16, 0x3f

    .line 69
    .line 70
    packed-switch v13, :pswitch_data_0

    .line 71
    .line 72
    .line 73
    :cond_3
    :goto_3
    move-object v13, v6

    .line 74
    :goto_4
    const/4 v6, 0x0

    .line 75
    goto/16 :goto_1a

    .line 76
    .line 77
    :pswitch_0
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    if-eqz v5, :cond_3

    .line 82
    .line 83
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 88
    .line 89
    .line 90
    move-result-object v10

    .line 91
    invoke-virtual {v6, v12, v5, v10}, Landroidx/datastore/preferences/protobuf/j0;->a(ILjava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :pswitch_1
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-eqz v5, :cond_3

    .line 100
    .line 101
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 102
    .line 103
    .line 104
    move-result-wide v10

    .line 105
    iget-object v5, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 108
    .line 109
    shl-long v17, v10, v15

    .line 110
    .line 111
    shr-long v10, v10, v16

    .line 112
    .line 113
    xor-long v10, v17, v10

    .line 114
    .line 115
    invoke-virtual {v5, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->L(IJ)V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :pswitch_2
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 120
    .line 121
    .line 122
    move-result v5

    .line 123
    if-eqz v5, :cond_3

    .line 124
    .line 125
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 126
    .line 127
    .line 128
    move-result v5

    .line 129
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 132
    .line 133
    shl-int/lit8 v11, v5, 0x1

    .line 134
    .line 135
    shr-int/lit8 v5, v5, 0x1f

    .line 136
    .line 137
    xor-int/2addr v5, v11

    .line 138
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->J(II)V

    .line 139
    .line 140
    .line 141
    goto :goto_3

    .line 142
    :pswitch_3
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    if-eqz v5, :cond_3

    .line 147
    .line 148
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 149
    .line 150
    .line 151
    move-result-wide v10

    .line 152
    iget-object v5, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 155
    .line 156
    invoke-virtual {v5, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->B(IJ)V

    .line 157
    .line 158
    .line 159
    goto :goto_3

    .line 160
    :pswitch_4
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 161
    .line 162
    .line 163
    move-result v5

    .line 164
    if-eqz v5, :cond_3

    .line 165
    .line 166
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 167
    .line 168
    .line 169
    move-result v5

    .line 170
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 173
    .line 174
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->z(II)V

    .line 175
    .line 176
    .line 177
    goto :goto_3

    .line 178
    :pswitch_5
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 179
    .line 180
    .line 181
    move-result v5

    .line 182
    if-eqz v5, :cond_3

    .line 183
    .line 184
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 185
    .line 186
    .line 187
    move-result v5

    .line 188
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 191
    .line 192
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->D(II)V

    .line 193
    .line 194
    .line 195
    goto :goto_3

    .line 196
    :pswitch_6
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 197
    .line 198
    .line 199
    move-result v5

    .line 200
    if-eqz v5, :cond_3

    .line 201
    .line 202
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 203
    .line 204
    .line 205
    move-result v5

    .line 206
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 209
    .line 210
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->J(II)V

    .line 211
    .line 212
    .line 213
    goto/16 :goto_3

    .line 214
    .line 215
    :pswitch_7
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 216
    .line 217
    .line 218
    move-result v5

    .line 219
    if-eqz v5, :cond_3

    .line 220
    .line 221
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    check-cast v5, Landroidx/datastore/preferences/protobuf/h;

    .line 226
    .line 227
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 230
    .line 231
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->x(ILandroidx/datastore/preferences/protobuf/h;)V

    .line 232
    .line 233
    .line 234
    goto/16 :goto_3

    .line 235
    .line 236
    :pswitch_8
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 237
    .line 238
    .line 239
    move-result v5

    .line 240
    if-eqz v5, :cond_3

    .line 241
    .line 242
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v5

    .line 246
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 247
    .line 248
    .line 249
    move-result-object v10

    .line 250
    iget-object v11, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v11, Landroidx/datastore/preferences/protobuf/l;

    .line 253
    .line 254
    check-cast v5, Landroidx/datastore/preferences/protobuf/a;

    .line 255
    .line 256
    invoke-virtual {v11, v12, v5, v10}, Landroidx/datastore/preferences/protobuf/l;->F(ILandroidx/datastore/preferences/protobuf/a;Landroidx/datastore/preferences/protobuf/a1;)V

    .line 257
    .line 258
    .line 259
    goto/16 :goto_3

    .line 260
    .line 261
    :pswitch_9
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 262
    .line 263
    .line 264
    move-result v5

    .line 265
    if-eqz v5, :cond_3

    .line 266
    .line 267
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    instance-of v10, v5, Ljava/lang/String;

    .line 272
    .line 273
    if-eqz v10, :cond_4

    .line 274
    .line 275
    check-cast v5, Ljava/lang/String;

    .line 276
    .line 277
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 280
    .line 281
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->G(ILjava/lang/String;)V

    .line 282
    .line 283
    .line 284
    goto/16 :goto_3

    .line 285
    .line 286
    :cond_4
    check-cast v5, Landroidx/datastore/preferences/protobuf/h;

    .line 287
    .line 288
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 289
    .line 290
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 291
    .line 292
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->x(ILandroidx/datastore/preferences/protobuf/h;)V

    .line 293
    .line 294
    .line 295
    goto/16 :goto_3

    .line 296
    .line 297
    :pswitch_a
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 298
    .line 299
    .line 300
    move-result v5

    .line 301
    if-eqz v5, :cond_3

    .line 302
    .line 303
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 304
    .line 305
    invoke-virtual {v5, v1, v10, v11}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v5

    .line 309
    check-cast v5, Ljava/lang/Boolean;

    .line 310
    .line 311
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 312
    .line 313
    .line 314
    move-result v5

    .line 315
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 318
    .line 319
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->w(IZ)V

    .line 320
    .line 321
    .line 322
    goto/16 :goto_3

    .line 323
    .line 324
    :pswitch_b
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 325
    .line 326
    .line 327
    move-result v5

    .line 328
    if-eqz v5, :cond_3

    .line 329
    .line 330
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 331
    .line 332
    .line 333
    move-result v5

    .line 334
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 335
    .line 336
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 337
    .line 338
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->z(II)V

    .line 339
    .line 340
    .line 341
    goto/16 :goto_3

    .line 342
    .line 343
    :pswitch_c
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 344
    .line 345
    .line 346
    move-result v5

    .line 347
    if-eqz v5, :cond_3

    .line 348
    .line 349
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 350
    .line 351
    .line 352
    move-result-wide v10

    .line 353
    iget-object v5, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 354
    .line 355
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 356
    .line 357
    invoke-virtual {v5, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->B(IJ)V

    .line 358
    .line 359
    .line 360
    goto/16 :goto_3

    .line 361
    .line 362
    :pswitch_d
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 363
    .line 364
    .line 365
    move-result v5

    .line 366
    if-eqz v5, :cond_3

    .line 367
    .line 368
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 369
    .line 370
    .line 371
    move-result v5

    .line 372
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 373
    .line 374
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 375
    .line 376
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->D(II)V

    .line 377
    .line 378
    .line 379
    goto/16 :goto_3

    .line 380
    .line 381
    :pswitch_e
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 382
    .line 383
    .line 384
    move-result v5

    .line 385
    if-eqz v5, :cond_3

    .line 386
    .line 387
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 388
    .line 389
    .line 390
    move-result-wide v10

    .line 391
    iget-object v5, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 392
    .line 393
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 394
    .line 395
    invoke-virtual {v5, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->L(IJ)V

    .line 396
    .line 397
    .line 398
    goto/16 :goto_3

    .line 399
    .line 400
    :pswitch_f
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 401
    .line 402
    .line 403
    move-result v5

    .line 404
    if-eqz v5, :cond_3

    .line 405
    .line 406
    invoke-static {v10, v11, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 407
    .line 408
    .line 409
    move-result-wide v10

    .line 410
    iget-object v5, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 411
    .line 412
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 413
    .line 414
    invoke-virtual {v5, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->L(IJ)V

    .line 415
    .line 416
    .line 417
    goto/16 :goto_3

    .line 418
    .line 419
    :pswitch_10
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 420
    .line 421
    .line 422
    move-result v5

    .line 423
    if-eqz v5, :cond_3

    .line 424
    .line 425
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 426
    .line 427
    invoke-virtual {v5, v1, v10, v11}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object v5

    .line 431
    check-cast v5, Ljava/lang/Float;

    .line 432
    .line 433
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 434
    .line 435
    .line 436
    move-result v5

    .line 437
    iget-object v10, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 438
    .line 439
    check-cast v10, Landroidx/datastore/preferences/protobuf/l;

    .line 440
    .line 441
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 442
    .line 443
    .line 444
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 445
    .line 446
    .line 447
    move-result v5

    .line 448
    invoke-virtual {v10, v12, v5}, Landroidx/datastore/preferences/protobuf/l;->z(II)V

    .line 449
    .line 450
    .line 451
    goto/16 :goto_3

    .line 452
    .line 453
    :pswitch_11
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 454
    .line 455
    .line 456
    move-result v5

    .line 457
    if-eqz v5, :cond_3

    .line 458
    .line 459
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 460
    .line 461
    invoke-virtual {v5, v1, v10, v11}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    move-result-object v5

    .line 465
    check-cast v5, Ljava/lang/Double;

    .line 466
    .line 467
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 468
    .line 469
    .line 470
    move-result-wide v10

    .line 471
    iget-object v5, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 472
    .line 473
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 474
    .line 475
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 476
    .line 477
    .line 478
    invoke-static {v10, v11}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 479
    .line 480
    .line 481
    move-result-wide v10

    .line 482
    invoke-virtual {v5, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->B(IJ)V

    .line 483
    .line 484
    .line 485
    goto/16 :goto_3

    .line 486
    .line 487
    :pswitch_12
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    move-result-object v5

    .line 491
    if-eqz v5, :cond_b

    .line 492
    .line 493
    div-int/lit8 v10, v2, 0x3

    .line 494
    .line 495
    const/4 v11, 0x2

    .line 496
    mul-int/2addr v10, v11

    .line 497
    iget-object v13, v0, Landroidx/datastore/preferences/protobuf/r0;->b:[Ljava/lang/Object;

    .line 498
    .line 499
    aget-object v10, v13, v10

    .line 500
    .line 501
    iget-object v13, v0, Landroidx/datastore/preferences/protobuf/r0;->m:Landroidx/datastore/preferences/protobuf/n0;

    .line 502
    .line 503
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 504
    .line 505
    .line 506
    check-cast v10, Landroidx/datastore/preferences/protobuf/l0;

    .line 507
    .line 508
    iget-object v10, v10, Landroidx/datastore/preferences/protobuf/l0;->a:Landroidx/datastore/preferences/protobuf/k0;

    .line 509
    .line 510
    iget-object v13, v10, Landroidx/datastore/preferences/protobuf/k0;->b:Landroidx/datastore/preferences/protobuf/v1;

    .line 511
    .line 512
    iget-object v10, v10, Landroidx/datastore/preferences/protobuf/k0;->a:Landroidx/datastore/preferences/protobuf/v1;

    .line 513
    .line 514
    check-cast v5, Landroidx/datastore/preferences/protobuf/m0;

    .line 515
    .line 516
    iget-object v14, v6, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast v14, Landroidx/datastore/preferences/protobuf/l;

    .line 519
    .line 520
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 521
    .line 522
    .line 523
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/m0;->entrySet()Ljava/util/Set;

    .line 524
    .line 525
    .line 526
    move-result-object v5

    .line 527
    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 528
    .line 529
    .line 530
    move-result-object v5

    .line 531
    :goto_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 532
    .line 533
    .line 534
    move-result v18

    .line 535
    if-eqz v18, :cond_b

    .line 536
    .line 537
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 538
    .line 539
    .line 540
    move-result-object v18

    .line 541
    check-cast v18, Ljava/util/Map$Entry;

    .line 542
    .line 543
    invoke-virtual {v14, v12, v11}, Landroidx/datastore/preferences/protobuf/l;->I(II)V

    .line 544
    .line 545
    .line 546
    move/from16 v19, v11

    .line 547
    .line 548
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 549
    .line 550
    .line 551
    move-result-object v11

    .line 552
    move/from16 v20, v15

    .line 553
    .line 554
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    move-result-object v15

    .line 558
    sget v21, Landroidx/datastore/preferences/protobuf/r;->c:I

    .line 559
    .line 560
    invoke-static/range {v20 .. v20}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 561
    .line 562
    .line 563
    move-result v21

    .line 564
    move/from16 v22, v3

    .line 565
    .line 566
    sget-object v3, Landroidx/datastore/preferences/protobuf/v1;->g:Landroidx/datastore/preferences/protobuf/s1;

    .line 567
    .line 568
    if-ne v10, v3, :cond_5

    .line 569
    .line 570
    mul-int/lit8 v21, v21, 0x2

    .line 571
    .line 572
    :cond_5
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 573
    .line 574
    .line 575
    move-result v23

    .line 576
    move/from16 v24, v4

    .line 577
    .line 578
    const-string v4, "There is no way to get here, but the compiler thinks otherwise."

    .line 579
    .line 580
    const/16 v25, 0x8

    .line 581
    .line 582
    const/16 v26, 0x4

    .line 583
    .line 584
    move-object/from16 v27, v5

    .line 585
    .line 586
    packed-switch v23, :pswitch_data_1

    .line 587
    .line 588
    .line 589
    new-instance v0, Ljava/lang/RuntimeException;

    .line 590
    .line 591
    invoke-direct {v0, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    throw v0

    .line 595
    :pswitch_13
    check-cast v11, Ljava/lang/Long;

    .line 596
    .line 597
    invoke-virtual {v11}, Ljava/lang/Long;->longValue()J

    .line 598
    .line 599
    .line 600
    move-result-wide v28

    .line 601
    shl-long v30, v28, v20

    .line 602
    .line 603
    shr-long v28, v28, v16

    .line 604
    .line 605
    xor-long v28, v30, v28

    .line 606
    .line 607
    invoke-static/range {v28 .. v29}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 608
    .line 609
    .line 610
    move-result v11

    .line 611
    :goto_6
    move v5, v11

    .line 612
    goto/16 :goto_b

    .line 613
    .line 614
    :pswitch_14
    check-cast v11, Ljava/lang/Integer;

    .line 615
    .line 616
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 617
    .line 618
    .line 619
    move-result v11

    .line 620
    shl-int/lit8 v23, v11, 0x1

    .line 621
    .line 622
    shr-int/lit8 v11, v11, 0x1f

    .line 623
    .line 624
    xor-int v11, v23, v11

    .line 625
    .line 626
    invoke-static {v11}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 627
    .line 628
    .line 629
    move-result v11

    .line 630
    goto :goto_6

    .line 631
    :pswitch_15
    check-cast v11, Ljava/lang/Long;

    .line 632
    .line 633
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 634
    .line 635
    .line 636
    :goto_7
    move/from16 v5, v25

    .line 637
    .line 638
    goto/16 :goto_b

    .line 639
    .line 640
    :pswitch_16
    check-cast v11, Ljava/lang/Integer;

    .line 641
    .line 642
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 643
    .line 644
    .line 645
    :goto_8
    move/from16 v5, v26

    .line 646
    .line 647
    goto/16 :goto_b

    .line 648
    .line 649
    :pswitch_17
    check-cast v11, Ljava/lang/Integer;

    .line 650
    .line 651
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 652
    .line 653
    .line 654
    move-result v11

    .line 655
    int-to-long v5, v11

    .line 656
    invoke-static {v5, v6}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 657
    .line 658
    .line 659
    move-result v5

    .line 660
    goto/16 :goto_b

    .line 661
    .line 662
    :pswitch_18
    check-cast v11, Ljava/lang/Integer;

    .line 663
    .line 664
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 665
    .line 666
    .line 667
    move-result v5

    .line 668
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 669
    .line 670
    .line 671
    move-result v5

    .line 672
    goto/16 :goto_b

    .line 673
    .line 674
    :pswitch_19
    instance-of v5, v11, Landroidx/datastore/preferences/protobuf/h;

    .line 675
    .line 676
    if-eqz v5, :cond_6

    .line 677
    .line 678
    check-cast v11, Landroidx/datastore/preferences/protobuf/h;

    .line 679
    .line 680
    invoke-virtual {v11}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 681
    .line 682
    .line 683
    move-result v5

    .line 684
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 685
    .line 686
    .line 687
    move-result v6

    .line 688
    :goto_9
    add-int/2addr v5, v6

    .line 689
    goto/16 :goto_b

    .line 690
    .line 691
    :cond_6
    check-cast v11, [B

    .line 692
    .line 693
    array-length v5, v11

    .line 694
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 695
    .line 696
    .line 697
    move-result v6

    .line 698
    goto :goto_9

    .line 699
    :pswitch_1a
    check-cast v11, Landroidx/datastore/preferences/protobuf/a;

    .line 700
    .line 701
    check-cast v11, Landroidx/datastore/preferences/protobuf/x;

    .line 702
    .line 703
    const/4 v5, 0x0

    .line 704
    invoke-virtual {v11, v5}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 705
    .line 706
    .line 707
    move-result v6

    .line 708
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 709
    .line 710
    .line 711
    move-result v11

    .line 712
    add-int/2addr v6, v11

    .line 713
    :goto_a
    move v5, v6

    .line 714
    goto :goto_b

    .line 715
    :pswitch_1b
    const/4 v5, 0x0

    .line 716
    check-cast v11, Landroidx/datastore/preferences/protobuf/a;

    .line 717
    .line 718
    check-cast v11, Landroidx/datastore/preferences/protobuf/x;

    .line 719
    .line 720
    invoke-virtual {v11, v5}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 721
    .line 722
    .line 723
    move-result v6

    .line 724
    goto :goto_a

    .line 725
    :pswitch_1c
    instance-of v5, v11, Landroidx/datastore/preferences/protobuf/h;

    .line 726
    .line 727
    if-eqz v5, :cond_7

    .line 728
    .line 729
    check-cast v11, Landroidx/datastore/preferences/protobuf/h;

    .line 730
    .line 731
    invoke-virtual {v11}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 732
    .line 733
    .line 734
    move-result v5

    .line 735
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 736
    .line 737
    .line 738
    move-result v6

    .line 739
    goto :goto_9

    .line 740
    :cond_7
    check-cast v11, Ljava/lang/String;

    .line 741
    .line 742
    invoke-static {v11}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 743
    .line 744
    .line 745
    move-result v5

    .line 746
    goto :goto_b

    .line 747
    :pswitch_1d
    check-cast v11, Ljava/lang/Boolean;

    .line 748
    .line 749
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 750
    .line 751
    .line 752
    move/from16 v5, v20

    .line 753
    .line 754
    goto :goto_b

    .line 755
    :pswitch_1e
    check-cast v11, Ljava/lang/Integer;

    .line 756
    .line 757
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 758
    .line 759
    .line 760
    goto :goto_8

    .line 761
    :pswitch_1f
    check-cast v11, Ljava/lang/Long;

    .line 762
    .line 763
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 764
    .line 765
    .line 766
    goto/16 :goto_7

    .line 767
    .line 768
    :pswitch_20
    check-cast v11, Ljava/lang/Integer;

    .line 769
    .line 770
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 771
    .line 772
    .line 773
    move-result v5

    .line 774
    int-to-long v5, v5

    .line 775
    invoke-static {v5, v6}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 776
    .line 777
    .line 778
    move-result v5

    .line 779
    goto :goto_b

    .line 780
    :pswitch_21
    check-cast v11, Ljava/lang/Long;

    .line 781
    .line 782
    invoke-virtual {v11}, Ljava/lang/Long;->longValue()J

    .line 783
    .line 784
    .line 785
    move-result-wide v5

    .line 786
    invoke-static {v5, v6}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 787
    .line 788
    .line 789
    move-result v5

    .line 790
    goto :goto_b

    .line 791
    :pswitch_22
    check-cast v11, Ljava/lang/Long;

    .line 792
    .line 793
    invoke-virtual {v11}, Ljava/lang/Long;->longValue()J

    .line 794
    .line 795
    .line 796
    move-result-wide v5

    .line 797
    invoke-static {v5, v6}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 798
    .line 799
    .line 800
    move-result v5

    .line 801
    goto :goto_b

    .line 802
    :pswitch_23
    check-cast v11, Ljava/lang/Float;

    .line 803
    .line 804
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 805
    .line 806
    .line 807
    goto/16 :goto_8

    .line 808
    .line 809
    :pswitch_24
    check-cast v11, Ljava/lang/Double;

    .line 810
    .line 811
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 812
    .line 813
    .line 814
    goto/16 :goto_7

    .line 815
    .line 816
    :goto_b
    add-int v5, v5, v21

    .line 817
    .line 818
    invoke-static/range {v19 .. v19}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 819
    .line 820
    .line 821
    move-result v6

    .line 822
    if-ne v13, v3, :cond_8

    .line 823
    .line 824
    mul-int/lit8 v6, v6, 0x2

    .line 825
    .line 826
    :cond_8
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    .line 827
    .line 828
    .line 829
    move-result v3

    .line 830
    packed-switch v3, :pswitch_data_2

    .line 831
    .line 832
    .line 833
    new-instance v0, Ljava/lang/RuntimeException;

    .line 834
    .line 835
    invoke-direct {v0, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 836
    .line 837
    .line 838
    throw v0

    .line 839
    :pswitch_25
    check-cast v15, Ljava/lang/Long;

    .line 840
    .line 841
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 842
    .line 843
    .line 844
    move-result-wide v3

    .line 845
    shl-long v25, v3, v20

    .line 846
    .line 847
    shr-long v3, v3, v16

    .line 848
    .line 849
    xor-long v3, v25, v3

    .line 850
    .line 851
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 852
    .line 853
    .line 854
    move-result v3

    .line 855
    goto/16 :goto_f

    .line 856
    .line 857
    :pswitch_26
    check-cast v15, Ljava/lang/Integer;

    .line 858
    .line 859
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 860
    .line 861
    .line 862
    move-result v3

    .line 863
    shl-int/lit8 v4, v3, 0x1

    .line 864
    .line 865
    shr-int/lit8 v3, v3, 0x1f

    .line 866
    .line 867
    xor-int/2addr v3, v4

    .line 868
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 869
    .line 870
    .line 871
    move-result v3

    .line 872
    goto/16 :goto_f

    .line 873
    .line 874
    :pswitch_27
    check-cast v15, Ljava/lang/Long;

    .line 875
    .line 876
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 877
    .line 878
    .line 879
    :goto_c
    move/from16 v3, v25

    .line 880
    .line 881
    goto/16 :goto_f

    .line 882
    .line 883
    :pswitch_28
    check-cast v15, Ljava/lang/Integer;

    .line 884
    .line 885
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 886
    .line 887
    .line 888
    :goto_d
    move/from16 v3, v26

    .line 889
    .line 890
    goto/16 :goto_f

    .line 891
    .line 892
    :pswitch_29
    check-cast v15, Ljava/lang/Integer;

    .line 893
    .line 894
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 895
    .line 896
    .line 897
    move-result v3

    .line 898
    int-to-long v3, v3

    .line 899
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 900
    .line 901
    .line 902
    move-result v3

    .line 903
    goto/16 :goto_f

    .line 904
    .line 905
    :pswitch_2a
    check-cast v15, Ljava/lang/Integer;

    .line 906
    .line 907
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 908
    .line 909
    .line 910
    move-result v3

    .line 911
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 912
    .line 913
    .line 914
    move-result v3

    .line 915
    goto/16 :goto_f

    .line 916
    .line 917
    :pswitch_2b
    instance-of v3, v15, Landroidx/datastore/preferences/protobuf/h;

    .line 918
    .line 919
    if-eqz v3, :cond_9

    .line 920
    .line 921
    check-cast v15, Landroidx/datastore/preferences/protobuf/h;

    .line 922
    .line 923
    invoke-virtual {v15}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 924
    .line 925
    .line 926
    move-result v3

    .line 927
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 928
    .line 929
    .line 930
    move-result v4

    .line 931
    :goto_e
    add-int/2addr v3, v4

    .line 932
    goto/16 :goto_f

    .line 933
    .line 934
    :cond_9
    check-cast v15, [B

    .line 935
    .line 936
    array-length v3, v15

    .line 937
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 938
    .line 939
    .line 940
    move-result v4

    .line 941
    goto :goto_e

    .line 942
    :pswitch_2c
    check-cast v15, Landroidx/datastore/preferences/protobuf/a;

    .line 943
    .line 944
    check-cast v15, Landroidx/datastore/preferences/protobuf/x;

    .line 945
    .line 946
    const/4 v3, 0x0

    .line 947
    invoke-virtual {v15, v3}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 948
    .line 949
    .line 950
    move-result v3

    .line 951
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 952
    .line 953
    .line 954
    move-result v4

    .line 955
    goto :goto_e

    .line 956
    :pswitch_2d
    const/4 v3, 0x0

    .line 957
    check-cast v15, Landroidx/datastore/preferences/protobuf/a;

    .line 958
    .line 959
    check-cast v15, Landroidx/datastore/preferences/protobuf/x;

    .line 960
    .line 961
    invoke-virtual {v15, v3}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 962
    .line 963
    .line 964
    move-result v3

    .line 965
    goto :goto_f

    .line 966
    :pswitch_2e
    instance-of v3, v15, Landroidx/datastore/preferences/protobuf/h;

    .line 967
    .line 968
    if-eqz v3, :cond_a

    .line 969
    .line 970
    check-cast v15, Landroidx/datastore/preferences/protobuf/h;

    .line 971
    .line 972
    invoke-virtual {v15}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 973
    .line 974
    .line 975
    move-result v3

    .line 976
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 977
    .line 978
    .line 979
    move-result v4

    .line 980
    goto :goto_e

    .line 981
    :cond_a
    check-cast v15, Ljava/lang/String;

    .line 982
    .line 983
    invoke-static {v15}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 984
    .line 985
    .line 986
    move-result v3

    .line 987
    goto :goto_f

    .line 988
    :pswitch_2f
    check-cast v15, Ljava/lang/Boolean;

    .line 989
    .line 990
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 991
    .line 992
    .line 993
    move/from16 v3, v20

    .line 994
    .line 995
    goto :goto_f

    .line 996
    :pswitch_30
    check-cast v15, Ljava/lang/Integer;

    .line 997
    .line 998
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 999
    .line 1000
    .line 1001
    goto :goto_d

    .line 1002
    :pswitch_31
    check-cast v15, Ljava/lang/Long;

    .line 1003
    .line 1004
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1005
    .line 1006
    .line 1007
    goto/16 :goto_c

    .line 1008
    .line 1009
    :pswitch_32
    check-cast v15, Ljava/lang/Integer;

    .line 1010
    .line 1011
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 1012
    .line 1013
    .line 1014
    move-result v3

    .line 1015
    int-to-long v3, v3

    .line 1016
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 1017
    .line 1018
    .line 1019
    move-result v3

    .line 1020
    goto :goto_f

    .line 1021
    :pswitch_33
    check-cast v15, Ljava/lang/Long;

    .line 1022
    .line 1023
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 1024
    .line 1025
    .line 1026
    move-result-wide v3

    .line 1027
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 1028
    .line 1029
    .line 1030
    move-result v3

    .line 1031
    goto :goto_f

    .line 1032
    :pswitch_34
    check-cast v15, Ljava/lang/Long;

    .line 1033
    .line 1034
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 1035
    .line 1036
    .line 1037
    move-result-wide v3

    .line 1038
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 1039
    .line 1040
    .line 1041
    move-result v3

    .line 1042
    goto :goto_f

    .line 1043
    :pswitch_35
    check-cast v15, Ljava/lang/Float;

    .line 1044
    .line 1045
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1046
    .line 1047
    .line 1048
    goto/16 :goto_d

    .line 1049
    .line 1050
    :pswitch_36
    check-cast v15, Ljava/lang/Double;

    .line 1051
    .line 1052
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1053
    .line 1054
    .line 1055
    goto/16 :goto_c

    .line 1056
    .line 1057
    :goto_f
    add-int/2addr v3, v6

    .line 1058
    add-int/2addr v3, v5

    .line 1059
    invoke-virtual {v14, v3}, Landroidx/datastore/preferences/protobuf/l;->K(I)V

    .line 1060
    .line 1061
    .line 1062
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v3

    .line 1066
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v4

    .line 1070
    move/from16 v5, v20

    .line 1071
    .line 1072
    invoke-static {v14, v10, v5, v3}, Landroidx/datastore/preferences/protobuf/r;->b(Landroidx/datastore/preferences/protobuf/l;Landroidx/datastore/preferences/protobuf/v1;ILjava/lang/Object;)V

    .line 1073
    .line 1074
    .line 1075
    move/from16 v3, v19

    .line 1076
    .line 1077
    invoke-static {v14, v13, v3, v4}, Landroidx/datastore/preferences/protobuf/r;->b(Landroidx/datastore/preferences/protobuf/l;Landroidx/datastore/preferences/protobuf/v1;ILjava/lang/Object;)V

    .line 1078
    .line 1079
    .line 1080
    move-object/from16 v6, p2

    .line 1081
    .line 1082
    move v11, v3

    .line 1083
    move/from16 v3, v22

    .line 1084
    .line 1085
    move/from16 v4, v24

    .line 1086
    .line 1087
    move-object/from16 v5, v27

    .line 1088
    .line 1089
    const/4 v15, 0x1

    .line 1090
    goto/16 :goto_5

    .line 1091
    .line 1092
    :cond_b
    move/from16 v22, v3

    .line 1093
    .line 1094
    move/from16 v24, v4

    .line 1095
    .line 1096
    :cond_c
    move-object/from16 v13, p2

    .line 1097
    .line 1098
    :cond_d
    :goto_10
    move/from16 v3, v22

    .line 1099
    .line 1100
    move/from16 v4, v24

    .line 1101
    .line 1102
    goto/16 :goto_4

    .line 1103
    .line 1104
    :pswitch_37
    move/from16 v22, v3

    .line 1105
    .line 1106
    move/from16 v24, v4

    .line 1107
    .line 1108
    aget v3, v7, v2

    .line 1109
    .line 1110
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1111
    .line 1112
    .line 1113
    move-result-object v4

    .line 1114
    check-cast v4, Ljava/util/List;

    .line 1115
    .line 1116
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1117
    .line 1118
    .line 1119
    move-result-object v5

    .line 1120
    sget-object v6, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1121
    .line 1122
    if-eqz v4, :cond_c

    .line 1123
    .line 1124
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1125
    .line 1126
    .line 1127
    move-result v6

    .line 1128
    if-nez v6, :cond_c

    .line 1129
    .line 1130
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1131
    .line 1132
    .line 1133
    const/4 v6, 0x0

    .line 1134
    :goto_11
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1135
    .line 1136
    .line 1137
    move-result v10

    .line 1138
    if-ge v6, v10, :cond_c

    .line 1139
    .line 1140
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v10

    .line 1144
    move-object/from16 v13, p2

    .line 1145
    .line 1146
    invoke-virtual {v13, v3, v10, v5}, Landroidx/datastore/preferences/protobuf/j0;->a(ILjava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;)V

    .line 1147
    .line 1148
    .line 1149
    add-int/lit8 v6, v6, 0x1

    .line 1150
    .line 1151
    goto :goto_11

    .line 1152
    :pswitch_38
    move/from16 v22, v3

    .line 1153
    .line 1154
    move/from16 v24, v4

    .line 1155
    .line 1156
    move-object v13, v6

    .line 1157
    aget v3, v7, v2

    .line 1158
    .line 1159
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1160
    .line 1161
    .line 1162
    move-result-object v4

    .line 1163
    check-cast v4, Ljava/util/List;

    .line 1164
    .line 1165
    const/4 v5, 0x1

    .line 1166
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->x(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1167
    .line 1168
    .line 1169
    goto :goto_10

    .line 1170
    :pswitch_39
    move/from16 v22, v3

    .line 1171
    .line 1172
    move/from16 v24, v4

    .line 1173
    .line 1174
    move-object v13, v6

    .line 1175
    move v5, v15

    .line 1176
    aget v3, v7, v2

    .line 1177
    .line 1178
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1179
    .line 1180
    .line 1181
    move-result-object v4

    .line 1182
    check-cast v4, Ljava/util/List;

    .line 1183
    .line 1184
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->w(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1185
    .line 1186
    .line 1187
    goto :goto_10

    .line 1188
    :pswitch_3a
    move/from16 v22, v3

    .line 1189
    .line 1190
    move/from16 v24, v4

    .line 1191
    .line 1192
    move-object v13, v6

    .line 1193
    move v5, v15

    .line 1194
    aget v3, v7, v2

    .line 1195
    .line 1196
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v4

    .line 1200
    check-cast v4, Ljava/util/List;

    .line 1201
    .line 1202
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->v(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1203
    .line 1204
    .line 1205
    goto :goto_10

    .line 1206
    :pswitch_3b
    move/from16 v22, v3

    .line 1207
    .line 1208
    move/from16 v24, v4

    .line 1209
    .line 1210
    move-object v13, v6

    .line 1211
    move v5, v15

    .line 1212
    aget v3, v7, v2

    .line 1213
    .line 1214
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v4

    .line 1218
    check-cast v4, Ljava/util/List;

    .line 1219
    .line 1220
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->u(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1221
    .line 1222
    .line 1223
    goto :goto_10

    .line 1224
    :pswitch_3c
    move/from16 v22, v3

    .line 1225
    .line 1226
    move/from16 v24, v4

    .line 1227
    .line 1228
    move-object v13, v6

    .line 1229
    move v5, v15

    .line 1230
    aget v3, v7, v2

    .line 1231
    .line 1232
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v4

    .line 1236
    check-cast v4, Ljava/util/List;

    .line 1237
    .line 1238
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->o(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1239
    .line 1240
    .line 1241
    goto/16 :goto_10

    .line 1242
    .line 1243
    :pswitch_3d
    move/from16 v22, v3

    .line 1244
    .line 1245
    move/from16 v24, v4

    .line 1246
    .line 1247
    move-object v13, v6

    .line 1248
    move v5, v15

    .line 1249
    aget v3, v7, v2

    .line 1250
    .line 1251
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1252
    .line 1253
    .line 1254
    move-result-object v4

    .line 1255
    check-cast v4, Ljava/util/List;

    .line 1256
    .line 1257
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->y(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1258
    .line 1259
    .line 1260
    goto/16 :goto_10

    .line 1261
    .line 1262
    :pswitch_3e
    move/from16 v22, v3

    .line 1263
    .line 1264
    move/from16 v24, v4

    .line 1265
    .line 1266
    move-object v13, v6

    .line 1267
    move v5, v15

    .line 1268
    aget v3, v7, v2

    .line 1269
    .line 1270
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v4

    .line 1274
    check-cast v4, Ljava/util/List;

    .line 1275
    .line 1276
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->m(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1277
    .line 1278
    .line 1279
    goto/16 :goto_10

    .line 1280
    .line 1281
    :pswitch_3f
    move/from16 v22, v3

    .line 1282
    .line 1283
    move/from16 v24, v4

    .line 1284
    .line 1285
    move-object v13, v6

    .line 1286
    move v5, v15

    .line 1287
    aget v3, v7, v2

    .line 1288
    .line 1289
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1290
    .line 1291
    .line 1292
    move-result-object v4

    .line 1293
    check-cast v4, Ljava/util/List;

    .line 1294
    .line 1295
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->p(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1296
    .line 1297
    .line 1298
    goto/16 :goto_10

    .line 1299
    .line 1300
    :pswitch_40
    move/from16 v22, v3

    .line 1301
    .line 1302
    move/from16 v24, v4

    .line 1303
    .line 1304
    move-object v13, v6

    .line 1305
    move v5, v15

    .line 1306
    aget v3, v7, v2

    .line 1307
    .line 1308
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v4

    .line 1312
    check-cast v4, Ljava/util/List;

    .line 1313
    .line 1314
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->q(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1315
    .line 1316
    .line 1317
    goto/16 :goto_10

    .line 1318
    .line 1319
    :pswitch_41
    move/from16 v22, v3

    .line 1320
    .line 1321
    move/from16 v24, v4

    .line 1322
    .line 1323
    move-object v13, v6

    .line 1324
    move v5, v15

    .line 1325
    aget v3, v7, v2

    .line 1326
    .line 1327
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1328
    .line 1329
    .line 1330
    move-result-object v4

    .line 1331
    check-cast v4, Ljava/util/List;

    .line 1332
    .line 1333
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->s(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1334
    .line 1335
    .line 1336
    goto/16 :goto_10

    .line 1337
    .line 1338
    :pswitch_42
    move/from16 v22, v3

    .line 1339
    .line 1340
    move/from16 v24, v4

    .line 1341
    .line 1342
    move-object v13, v6

    .line 1343
    move v5, v15

    .line 1344
    aget v3, v7, v2

    .line 1345
    .line 1346
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1347
    .line 1348
    .line 1349
    move-result-object v4

    .line 1350
    check-cast v4, Ljava/util/List;

    .line 1351
    .line 1352
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->z(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1353
    .line 1354
    .line 1355
    goto/16 :goto_10

    .line 1356
    .line 1357
    :pswitch_43
    move/from16 v22, v3

    .line 1358
    .line 1359
    move/from16 v24, v4

    .line 1360
    .line 1361
    move-object v13, v6

    .line 1362
    move v5, v15

    .line 1363
    aget v3, v7, v2

    .line 1364
    .line 1365
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1366
    .line 1367
    .line 1368
    move-result-object v4

    .line 1369
    check-cast v4, Ljava/util/List;

    .line 1370
    .line 1371
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->t(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1372
    .line 1373
    .line 1374
    goto/16 :goto_10

    .line 1375
    .line 1376
    :pswitch_44
    move/from16 v22, v3

    .line 1377
    .line 1378
    move/from16 v24, v4

    .line 1379
    .line 1380
    move-object v13, v6

    .line 1381
    move v5, v15

    .line 1382
    aget v3, v7, v2

    .line 1383
    .line 1384
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1385
    .line 1386
    .line 1387
    move-result-object v4

    .line 1388
    check-cast v4, Ljava/util/List;

    .line 1389
    .line 1390
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->r(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1391
    .line 1392
    .line 1393
    goto/16 :goto_10

    .line 1394
    .line 1395
    :pswitch_45
    move/from16 v22, v3

    .line 1396
    .line 1397
    move/from16 v24, v4

    .line 1398
    .line 1399
    move-object v13, v6

    .line 1400
    move v5, v15

    .line 1401
    aget v3, v7, v2

    .line 1402
    .line 1403
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1404
    .line 1405
    .line 1406
    move-result-object v4

    .line 1407
    check-cast v4, Ljava/util/List;

    .line 1408
    .line 1409
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->n(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1410
    .line 1411
    .line 1412
    goto/16 :goto_10

    .line 1413
    .line 1414
    :pswitch_46
    move/from16 v22, v3

    .line 1415
    .line 1416
    move/from16 v24, v4

    .line 1417
    .line 1418
    move-object v13, v6

    .line 1419
    aget v3, v7, v2

    .line 1420
    .line 1421
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1422
    .line 1423
    .line 1424
    move-result-object v4

    .line 1425
    check-cast v4, Ljava/util/List;

    .line 1426
    .line 1427
    const/4 v5, 0x0

    .line 1428
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->x(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1429
    .line 1430
    .line 1431
    :goto_12
    move v6, v5

    .line 1432
    :goto_13
    move/from16 v3, v22

    .line 1433
    .line 1434
    move/from16 v4, v24

    .line 1435
    .line 1436
    goto/16 :goto_1a

    .line 1437
    .line 1438
    :pswitch_47
    move/from16 v22, v3

    .line 1439
    .line 1440
    move/from16 v24, v4

    .line 1441
    .line 1442
    move-object v13, v6

    .line 1443
    const/4 v5, 0x0

    .line 1444
    aget v3, v7, v2

    .line 1445
    .line 1446
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v4

    .line 1450
    check-cast v4, Ljava/util/List;

    .line 1451
    .line 1452
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->w(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1453
    .line 1454
    .line 1455
    goto :goto_12

    .line 1456
    :pswitch_48
    move/from16 v22, v3

    .line 1457
    .line 1458
    move/from16 v24, v4

    .line 1459
    .line 1460
    move-object v13, v6

    .line 1461
    const/4 v5, 0x0

    .line 1462
    aget v3, v7, v2

    .line 1463
    .line 1464
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1465
    .line 1466
    .line 1467
    move-result-object v4

    .line 1468
    check-cast v4, Ljava/util/List;

    .line 1469
    .line 1470
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->v(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1471
    .line 1472
    .line 1473
    goto :goto_12

    .line 1474
    :pswitch_49
    move/from16 v22, v3

    .line 1475
    .line 1476
    move/from16 v24, v4

    .line 1477
    .line 1478
    move-object v13, v6

    .line 1479
    const/4 v5, 0x0

    .line 1480
    aget v3, v7, v2

    .line 1481
    .line 1482
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1483
    .line 1484
    .line 1485
    move-result-object v4

    .line 1486
    check-cast v4, Ljava/util/List;

    .line 1487
    .line 1488
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->u(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1489
    .line 1490
    .line 1491
    goto :goto_12

    .line 1492
    :pswitch_4a
    move/from16 v22, v3

    .line 1493
    .line 1494
    move/from16 v24, v4

    .line 1495
    .line 1496
    move-object v13, v6

    .line 1497
    const/4 v5, 0x0

    .line 1498
    aget v3, v7, v2

    .line 1499
    .line 1500
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1501
    .line 1502
    .line 1503
    move-result-object v4

    .line 1504
    check-cast v4, Ljava/util/List;

    .line 1505
    .line 1506
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->o(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1507
    .line 1508
    .line 1509
    goto :goto_12

    .line 1510
    :pswitch_4b
    move/from16 v22, v3

    .line 1511
    .line 1512
    move/from16 v24, v4

    .line 1513
    .line 1514
    move-object v13, v6

    .line 1515
    const/4 v5, 0x0

    .line 1516
    aget v3, v7, v2

    .line 1517
    .line 1518
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1519
    .line 1520
    .line 1521
    move-result-object v4

    .line 1522
    check-cast v4, Ljava/util/List;

    .line 1523
    .line 1524
    invoke-static {v3, v4, v13, v5}, Landroidx/datastore/preferences/protobuf/b1;->y(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1525
    .line 1526
    .line 1527
    goto :goto_12

    .line 1528
    :pswitch_4c
    move/from16 v22, v3

    .line 1529
    .line 1530
    move/from16 v24, v4

    .line 1531
    .line 1532
    move-object v13, v6

    .line 1533
    aget v3, v7, v2

    .line 1534
    .line 1535
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1536
    .line 1537
    .line 1538
    move-result-object v4

    .line 1539
    check-cast v4, Ljava/util/List;

    .line 1540
    .line 1541
    sget-object v5, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1542
    .line 1543
    if-eqz v4, :cond_d

    .line 1544
    .line 1545
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1546
    .line 1547
    .line 1548
    move-result v5

    .line 1549
    if-nez v5, :cond_d

    .line 1550
    .line 1551
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1552
    .line 1553
    .line 1554
    const/4 v5, 0x0

    .line 1555
    :goto_14
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1556
    .line 1557
    .line 1558
    move-result v6

    .line 1559
    if-ge v5, v6, :cond_d

    .line 1560
    .line 1561
    iget-object v6, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1562
    .line 1563
    check-cast v6, Landroidx/datastore/preferences/protobuf/l;

    .line 1564
    .line 1565
    invoke-interface {v4, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1566
    .line 1567
    .line 1568
    move-result-object v10

    .line 1569
    check-cast v10, Landroidx/datastore/preferences/protobuf/h;

    .line 1570
    .line 1571
    invoke-virtual {v6, v3, v10}, Landroidx/datastore/preferences/protobuf/l;->x(ILandroidx/datastore/preferences/protobuf/h;)V

    .line 1572
    .line 1573
    .line 1574
    add-int/lit8 v5, v5, 0x1

    .line 1575
    .line 1576
    goto :goto_14

    .line 1577
    :pswitch_4d
    move/from16 v22, v3

    .line 1578
    .line 1579
    move/from16 v24, v4

    .line 1580
    .line 1581
    move-object v13, v6

    .line 1582
    aget v3, v7, v2

    .line 1583
    .line 1584
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1585
    .line 1586
    .line 1587
    move-result-object v4

    .line 1588
    check-cast v4, Ljava/util/List;

    .line 1589
    .line 1590
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1591
    .line 1592
    .line 1593
    move-result-object v5

    .line 1594
    sget-object v6, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1595
    .line 1596
    if-eqz v4, :cond_d

    .line 1597
    .line 1598
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1599
    .line 1600
    .line 1601
    move-result v6

    .line 1602
    if-nez v6, :cond_d

    .line 1603
    .line 1604
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1605
    .line 1606
    .line 1607
    const/4 v6, 0x0

    .line 1608
    :goto_15
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1609
    .line 1610
    .line 1611
    move-result v10

    .line 1612
    if-ge v6, v10, :cond_d

    .line 1613
    .line 1614
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1615
    .line 1616
    .line 1617
    move-result-object v10

    .line 1618
    iget-object v11, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1619
    .line 1620
    check-cast v11, Landroidx/datastore/preferences/protobuf/l;

    .line 1621
    .line 1622
    check-cast v10, Landroidx/datastore/preferences/protobuf/a;

    .line 1623
    .line 1624
    invoke-virtual {v11, v3, v10, v5}, Landroidx/datastore/preferences/protobuf/l;->F(ILandroidx/datastore/preferences/protobuf/a;Landroidx/datastore/preferences/protobuf/a1;)V

    .line 1625
    .line 1626
    .line 1627
    add-int/lit8 v6, v6, 0x1

    .line 1628
    .line 1629
    goto :goto_15

    .line 1630
    :pswitch_4e
    move/from16 v22, v3

    .line 1631
    .line 1632
    move/from16 v24, v4

    .line 1633
    .line 1634
    move-object v13, v6

    .line 1635
    aget v3, v7, v2

    .line 1636
    .line 1637
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1638
    .line 1639
    .line 1640
    move-result-object v4

    .line 1641
    check-cast v4, Ljava/util/List;

    .line 1642
    .line 1643
    sget-object v5, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1644
    .line 1645
    if-eqz v4, :cond_d

    .line 1646
    .line 1647
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1648
    .line 1649
    .line 1650
    move-result v5

    .line 1651
    if-nez v5, :cond_d

    .line 1652
    .line 1653
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1654
    .line 1655
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 1656
    .line 1657
    instance-of v6, v4, Landroidx/datastore/preferences/protobuf/e0;

    .line 1658
    .line 1659
    if-eqz v6, :cond_f

    .line 1660
    .line 1661
    move-object v6, v4

    .line 1662
    check-cast v6, Landroidx/datastore/preferences/protobuf/e0;

    .line 1663
    .line 1664
    const/4 v10, 0x0

    .line 1665
    :goto_16
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1666
    .line 1667
    .line 1668
    move-result v11

    .line 1669
    if-ge v10, v11, :cond_d

    .line 1670
    .line 1671
    invoke-interface {v6}, Landroidx/datastore/preferences/protobuf/e0;->q()Ljava/lang/Object;

    .line 1672
    .line 1673
    .line 1674
    move-result-object v11

    .line 1675
    instance-of v12, v11, Ljava/lang/String;

    .line 1676
    .line 1677
    if-eqz v12, :cond_e

    .line 1678
    .line 1679
    check-cast v11, Ljava/lang/String;

    .line 1680
    .line 1681
    invoke-virtual {v5, v3, v11}, Landroidx/datastore/preferences/protobuf/l;->G(ILjava/lang/String;)V

    .line 1682
    .line 1683
    .line 1684
    goto :goto_17

    .line 1685
    :cond_e
    check-cast v11, Landroidx/datastore/preferences/protobuf/h;

    .line 1686
    .line 1687
    invoke-virtual {v5, v3, v11}, Landroidx/datastore/preferences/protobuf/l;->x(ILandroidx/datastore/preferences/protobuf/h;)V

    .line 1688
    .line 1689
    .line 1690
    :goto_17
    add-int/lit8 v10, v10, 0x1

    .line 1691
    .line 1692
    goto :goto_16

    .line 1693
    :cond_f
    const/4 v6, 0x0

    .line 1694
    :goto_18
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1695
    .line 1696
    .line 1697
    move-result v10

    .line 1698
    if-ge v6, v10, :cond_d

    .line 1699
    .line 1700
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1701
    .line 1702
    .line 1703
    move-result-object v10

    .line 1704
    check-cast v10, Ljava/lang/String;

    .line 1705
    .line 1706
    invoke-virtual {v5, v3, v10}, Landroidx/datastore/preferences/protobuf/l;->G(ILjava/lang/String;)V

    .line 1707
    .line 1708
    .line 1709
    add-int/lit8 v6, v6, 0x1

    .line 1710
    .line 1711
    goto :goto_18

    .line 1712
    :pswitch_4f
    move/from16 v22, v3

    .line 1713
    .line 1714
    move/from16 v24, v4

    .line 1715
    .line 1716
    move-object v13, v6

    .line 1717
    aget v3, v7, v2

    .line 1718
    .line 1719
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1720
    .line 1721
    .line 1722
    move-result-object v4

    .line 1723
    check-cast v4, Ljava/util/List;

    .line 1724
    .line 1725
    const/4 v6, 0x0

    .line 1726
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->m(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1727
    .line 1728
    .line 1729
    goto/16 :goto_13

    .line 1730
    .line 1731
    :pswitch_50
    move/from16 v22, v3

    .line 1732
    .line 1733
    move/from16 v24, v4

    .line 1734
    .line 1735
    move-object v13, v6

    .line 1736
    const/4 v6, 0x0

    .line 1737
    aget v3, v7, v2

    .line 1738
    .line 1739
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1740
    .line 1741
    .line 1742
    move-result-object v4

    .line 1743
    check-cast v4, Ljava/util/List;

    .line 1744
    .line 1745
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->p(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1746
    .line 1747
    .line 1748
    goto/16 :goto_13

    .line 1749
    .line 1750
    :pswitch_51
    move/from16 v22, v3

    .line 1751
    .line 1752
    move/from16 v24, v4

    .line 1753
    .line 1754
    move-object v13, v6

    .line 1755
    const/4 v6, 0x0

    .line 1756
    aget v3, v7, v2

    .line 1757
    .line 1758
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1759
    .line 1760
    .line 1761
    move-result-object v4

    .line 1762
    check-cast v4, Ljava/util/List;

    .line 1763
    .line 1764
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->q(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1765
    .line 1766
    .line 1767
    goto/16 :goto_13

    .line 1768
    .line 1769
    :pswitch_52
    move/from16 v22, v3

    .line 1770
    .line 1771
    move/from16 v24, v4

    .line 1772
    .line 1773
    move-object v13, v6

    .line 1774
    const/4 v6, 0x0

    .line 1775
    aget v3, v7, v2

    .line 1776
    .line 1777
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1778
    .line 1779
    .line 1780
    move-result-object v4

    .line 1781
    check-cast v4, Ljava/util/List;

    .line 1782
    .line 1783
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->s(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1784
    .line 1785
    .line 1786
    goto/16 :goto_13

    .line 1787
    .line 1788
    :pswitch_53
    move/from16 v22, v3

    .line 1789
    .line 1790
    move/from16 v24, v4

    .line 1791
    .line 1792
    move-object v13, v6

    .line 1793
    const/4 v6, 0x0

    .line 1794
    aget v3, v7, v2

    .line 1795
    .line 1796
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1797
    .line 1798
    .line 1799
    move-result-object v4

    .line 1800
    check-cast v4, Ljava/util/List;

    .line 1801
    .line 1802
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->z(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1803
    .line 1804
    .line 1805
    goto/16 :goto_13

    .line 1806
    .line 1807
    :pswitch_54
    move/from16 v22, v3

    .line 1808
    .line 1809
    move/from16 v24, v4

    .line 1810
    .line 1811
    move-object v13, v6

    .line 1812
    const/4 v6, 0x0

    .line 1813
    aget v3, v7, v2

    .line 1814
    .line 1815
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1816
    .line 1817
    .line 1818
    move-result-object v4

    .line 1819
    check-cast v4, Ljava/util/List;

    .line 1820
    .line 1821
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->t(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1822
    .line 1823
    .line 1824
    goto/16 :goto_13

    .line 1825
    .line 1826
    :pswitch_55
    move/from16 v22, v3

    .line 1827
    .line 1828
    move/from16 v24, v4

    .line 1829
    .line 1830
    move-object v13, v6

    .line 1831
    const/4 v6, 0x0

    .line 1832
    aget v3, v7, v2

    .line 1833
    .line 1834
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1835
    .line 1836
    .line 1837
    move-result-object v4

    .line 1838
    check-cast v4, Ljava/util/List;

    .line 1839
    .line 1840
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->r(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1841
    .line 1842
    .line 1843
    goto/16 :goto_13

    .line 1844
    .line 1845
    :pswitch_56
    move/from16 v22, v3

    .line 1846
    .line 1847
    move/from16 v24, v4

    .line 1848
    .line 1849
    move-object v13, v6

    .line 1850
    const/4 v6, 0x0

    .line 1851
    aget v3, v7, v2

    .line 1852
    .line 1853
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1854
    .line 1855
    .line 1856
    move-result-object v4

    .line 1857
    check-cast v4, Ljava/util/List;

    .line 1858
    .line 1859
    invoke-static {v3, v4, v13, v6}, Landroidx/datastore/preferences/protobuf/b1;->n(ILjava/util/List;Landroidx/datastore/preferences/protobuf/j0;Z)V

    .line 1860
    .line 1861
    .line 1862
    goto/16 :goto_13

    .line 1863
    .line 1864
    :pswitch_57
    move-object v13, v6

    .line 1865
    const/4 v6, 0x0

    .line 1866
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 1867
    .line 1868
    .line 1869
    move-result v5

    .line 1870
    if-eqz v5, :cond_12

    .line 1871
    .line 1872
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1873
    .line 1874
    .line 1875
    move-result-object v5

    .line 1876
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1877
    .line 1878
    .line 1879
    move-result-object v10

    .line 1880
    invoke-virtual {v13, v12, v5, v10}, Landroidx/datastore/preferences/protobuf/j0;->a(ILjava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;)V

    .line 1881
    .line 1882
    .line 1883
    goto/16 :goto_1a

    .line 1884
    .line 1885
    :pswitch_58
    move-object v13, v6

    .line 1886
    const/4 v6, 0x0

    .line 1887
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 1888
    .line 1889
    .line 1890
    move-result v5

    .line 1891
    if-eqz v5, :cond_10

    .line 1892
    .line 1893
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1894
    .line 1895
    .line 1896
    move-result-wide v10

    .line 1897
    iget-object v0, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1898
    .line 1899
    check-cast v0, Landroidx/datastore/preferences/protobuf/l;

    .line 1900
    .line 1901
    const/16 v20, 0x1

    .line 1902
    .line 1903
    shl-long v14, v10, v20

    .line 1904
    .line 1905
    shr-long v10, v10, v16

    .line 1906
    .line 1907
    xor-long/2addr v10, v14

    .line 1908
    invoke-virtual {v0, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->L(IJ)V

    .line 1909
    .line 1910
    .line 1911
    :cond_10
    :goto_19
    move-object/from16 v0, p0

    .line 1912
    .line 1913
    goto/16 :goto_1a

    .line 1914
    .line 1915
    :pswitch_59
    move-object v13, v6

    .line 1916
    const/4 v6, 0x0

    .line 1917
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 1918
    .line 1919
    .line 1920
    move-result v5

    .line 1921
    if-eqz v5, :cond_10

    .line 1922
    .line 1923
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1924
    .line 1925
    .line 1926
    move-result v0

    .line 1927
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1928
    .line 1929
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 1930
    .line 1931
    shl-int/lit8 v10, v0, 0x1

    .line 1932
    .line 1933
    shr-int/lit8 v0, v0, 0x1f

    .line 1934
    .line 1935
    xor-int/2addr v0, v10

    .line 1936
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->J(II)V

    .line 1937
    .line 1938
    .line 1939
    goto :goto_19

    .line 1940
    :pswitch_5a
    move-object v13, v6

    .line 1941
    const/4 v6, 0x0

    .line 1942
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 1943
    .line 1944
    .line 1945
    move-result v5

    .line 1946
    if-eqz v5, :cond_10

    .line 1947
    .line 1948
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1949
    .line 1950
    .line 1951
    move-result-wide v10

    .line 1952
    iget-object v0, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1953
    .line 1954
    check-cast v0, Landroidx/datastore/preferences/protobuf/l;

    .line 1955
    .line 1956
    invoke-virtual {v0, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->B(IJ)V

    .line 1957
    .line 1958
    .line 1959
    goto :goto_19

    .line 1960
    :pswitch_5b
    move-object v13, v6

    .line 1961
    const/4 v6, 0x0

    .line 1962
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 1963
    .line 1964
    .line 1965
    move-result v5

    .line 1966
    if-eqz v5, :cond_10

    .line 1967
    .line 1968
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1969
    .line 1970
    .line 1971
    move-result v0

    .line 1972
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1973
    .line 1974
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 1975
    .line 1976
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->z(II)V

    .line 1977
    .line 1978
    .line 1979
    goto :goto_19

    .line 1980
    :pswitch_5c
    move-object v13, v6

    .line 1981
    const/4 v6, 0x0

    .line 1982
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 1983
    .line 1984
    .line 1985
    move-result v5

    .line 1986
    if-eqz v5, :cond_10

    .line 1987
    .line 1988
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1989
    .line 1990
    .line 1991
    move-result v0

    .line 1992
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 1993
    .line 1994
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 1995
    .line 1996
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->D(II)V

    .line 1997
    .line 1998
    .line 1999
    goto :goto_19

    .line 2000
    :pswitch_5d
    move-object v13, v6

    .line 2001
    const/4 v6, 0x0

    .line 2002
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2003
    .line 2004
    .line 2005
    move-result v5

    .line 2006
    if-eqz v5, :cond_10

    .line 2007
    .line 2008
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2009
    .line 2010
    .line 2011
    move-result v0

    .line 2012
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2013
    .line 2014
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2015
    .line 2016
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->J(II)V

    .line 2017
    .line 2018
    .line 2019
    goto :goto_19

    .line 2020
    :pswitch_5e
    move-object v13, v6

    .line 2021
    const/4 v6, 0x0

    .line 2022
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2023
    .line 2024
    .line 2025
    move-result v5

    .line 2026
    if-eqz v5, :cond_10

    .line 2027
    .line 2028
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2029
    .line 2030
    .line 2031
    move-result-object v0

    .line 2032
    check-cast v0, Landroidx/datastore/preferences/protobuf/h;

    .line 2033
    .line 2034
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2035
    .line 2036
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2037
    .line 2038
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->x(ILandroidx/datastore/preferences/protobuf/h;)V

    .line 2039
    .line 2040
    .line 2041
    goto/16 :goto_19

    .line 2042
    .line 2043
    :pswitch_5f
    move-object v13, v6

    .line 2044
    const/4 v6, 0x0

    .line 2045
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2046
    .line 2047
    .line 2048
    move-result v5

    .line 2049
    if-eqz v5, :cond_12

    .line 2050
    .line 2051
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2052
    .line 2053
    .line 2054
    move-result-object v5

    .line 2055
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 2056
    .line 2057
    .line 2058
    move-result-object v10

    .line 2059
    iget-object v11, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2060
    .line 2061
    check-cast v11, Landroidx/datastore/preferences/protobuf/l;

    .line 2062
    .line 2063
    check-cast v5, Landroidx/datastore/preferences/protobuf/a;

    .line 2064
    .line 2065
    invoke-virtual {v11, v12, v5, v10}, Landroidx/datastore/preferences/protobuf/l;->F(ILandroidx/datastore/preferences/protobuf/a;Landroidx/datastore/preferences/protobuf/a1;)V

    .line 2066
    .line 2067
    .line 2068
    goto/16 :goto_1a

    .line 2069
    .line 2070
    :pswitch_60
    move-object v13, v6

    .line 2071
    const/4 v6, 0x0

    .line 2072
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2073
    .line 2074
    .line 2075
    move-result v5

    .line 2076
    if-eqz v5, :cond_10

    .line 2077
    .line 2078
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2079
    .line 2080
    .line 2081
    move-result-object v0

    .line 2082
    instance-of v5, v0, Ljava/lang/String;

    .line 2083
    .line 2084
    if-eqz v5, :cond_11

    .line 2085
    .line 2086
    check-cast v0, Ljava/lang/String;

    .line 2087
    .line 2088
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2089
    .line 2090
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2091
    .line 2092
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->G(ILjava/lang/String;)V

    .line 2093
    .line 2094
    .line 2095
    goto/16 :goto_19

    .line 2096
    .line 2097
    :cond_11
    check-cast v0, Landroidx/datastore/preferences/protobuf/h;

    .line 2098
    .line 2099
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2100
    .line 2101
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2102
    .line 2103
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->x(ILandroidx/datastore/preferences/protobuf/h;)V

    .line 2104
    .line 2105
    .line 2106
    goto/16 :goto_19

    .line 2107
    .line 2108
    :pswitch_61
    move-object v13, v6

    .line 2109
    const/4 v6, 0x0

    .line 2110
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2111
    .line 2112
    .line 2113
    move-result v5

    .line 2114
    if-eqz v5, :cond_10

    .line 2115
    .line 2116
    sget-object v0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 2117
    .line 2118
    invoke-virtual {v0, v10, v11, v1}, Landroidx/datastore/preferences/protobuf/m1;->c(JLjava/lang/Object;)Z

    .line 2119
    .line 2120
    .line 2121
    move-result v0

    .line 2122
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2123
    .line 2124
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2125
    .line 2126
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->w(IZ)V

    .line 2127
    .line 2128
    .line 2129
    goto/16 :goto_19

    .line 2130
    .line 2131
    :pswitch_62
    move-object v13, v6

    .line 2132
    const/4 v6, 0x0

    .line 2133
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2134
    .line 2135
    .line 2136
    move-result v5

    .line 2137
    if-eqz v5, :cond_10

    .line 2138
    .line 2139
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2140
    .line 2141
    .line 2142
    move-result v0

    .line 2143
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2144
    .line 2145
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2146
    .line 2147
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->z(II)V

    .line 2148
    .line 2149
    .line 2150
    goto/16 :goto_19

    .line 2151
    .line 2152
    :pswitch_63
    move-object v13, v6

    .line 2153
    const/4 v6, 0x0

    .line 2154
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2155
    .line 2156
    .line 2157
    move-result v5

    .line 2158
    if-eqz v5, :cond_10

    .line 2159
    .line 2160
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2161
    .line 2162
    .line 2163
    move-result-wide v10

    .line 2164
    iget-object v0, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2165
    .line 2166
    check-cast v0, Landroidx/datastore/preferences/protobuf/l;

    .line 2167
    .line 2168
    invoke-virtual {v0, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->B(IJ)V

    .line 2169
    .line 2170
    .line 2171
    goto/16 :goto_19

    .line 2172
    .line 2173
    :pswitch_64
    move-object v13, v6

    .line 2174
    const/4 v6, 0x0

    .line 2175
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2176
    .line 2177
    .line 2178
    move-result v5

    .line 2179
    if-eqz v5, :cond_10

    .line 2180
    .line 2181
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2182
    .line 2183
    .line 2184
    move-result v0

    .line 2185
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2186
    .line 2187
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2188
    .line 2189
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->D(II)V

    .line 2190
    .line 2191
    .line 2192
    goto/16 :goto_19

    .line 2193
    .line 2194
    :pswitch_65
    move-object v13, v6

    .line 2195
    const/4 v6, 0x0

    .line 2196
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2197
    .line 2198
    .line 2199
    move-result v5

    .line 2200
    if-eqz v5, :cond_10

    .line 2201
    .line 2202
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2203
    .line 2204
    .line 2205
    move-result-wide v10

    .line 2206
    iget-object v0, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2207
    .line 2208
    check-cast v0, Landroidx/datastore/preferences/protobuf/l;

    .line 2209
    .line 2210
    invoke-virtual {v0, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->L(IJ)V

    .line 2211
    .line 2212
    .line 2213
    goto/16 :goto_19

    .line 2214
    .line 2215
    :pswitch_66
    move-object v13, v6

    .line 2216
    const/4 v6, 0x0

    .line 2217
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2218
    .line 2219
    .line 2220
    move-result v5

    .line 2221
    if-eqz v5, :cond_10

    .line 2222
    .line 2223
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2224
    .line 2225
    .line 2226
    move-result-wide v10

    .line 2227
    iget-object v0, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2228
    .line 2229
    check-cast v0, Landroidx/datastore/preferences/protobuf/l;

    .line 2230
    .line 2231
    invoke-virtual {v0, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->L(IJ)V

    .line 2232
    .line 2233
    .line 2234
    goto/16 :goto_19

    .line 2235
    .line 2236
    :pswitch_67
    move-object v13, v6

    .line 2237
    const/4 v6, 0x0

    .line 2238
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2239
    .line 2240
    .line 2241
    move-result v5

    .line 2242
    if-eqz v5, :cond_10

    .line 2243
    .line 2244
    sget-object v0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 2245
    .line 2246
    invoke-virtual {v0, v10, v11, v1}, Landroidx/datastore/preferences/protobuf/m1;->e(JLjava/lang/Object;)F

    .line 2247
    .line 2248
    .line 2249
    move-result v0

    .line 2250
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2251
    .line 2252
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2253
    .line 2254
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2255
    .line 2256
    .line 2257
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 2258
    .line 2259
    .line 2260
    move-result v0

    .line 2261
    invoke-virtual {v5, v12, v0}, Landroidx/datastore/preferences/protobuf/l;->z(II)V

    .line 2262
    .line 2263
    .line 2264
    goto/16 :goto_19

    .line 2265
    .line 2266
    :pswitch_68
    move-object v13, v6

    .line 2267
    const/4 v6, 0x0

    .line 2268
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2269
    .line 2270
    .line 2271
    move-result v5

    .line 2272
    if-eqz v5, :cond_12

    .line 2273
    .line 2274
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 2275
    .line 2276
    invoke-virtual {v5, v10, v11, v1}, Landroidx/datastore/preferences/protobuf/m1;->d(JLjava/lang/Object;)D

    .line 2277
    .line 2278
    .line 2279
    move-result-wide v10

    .line 2280
    iget-object v5, v13, Landroidx/datastore/preferences/protobuf/j0;->a:Ljava/lang/Object;

    .line 2281
    .line 2282
    check-cast v5, Landroidx/datastore/preferences/protobuf/l;

    .line 2283
    .line 2284
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2285
    .line 2286
    .line 2287
    invoke-static {v10, v11}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 2288
    .line 2289
    .line 2290
    move-result-wide v10

    .line 2291
    invoke-virtual {v5, v12, v10, v11}, Landroidx/datastore/preferences/protobuf/l;->B(IJ)V

    .line 2292
    .line 2293
    .line 2294
    :cond_12
    :goto_1a
    add-int/lit8 v2, v2, 0x3

    .line 2295
    .line 2296
    move-object v6, v13

    .line 2297
    const v10, 0xfffff

    .line 2298
    .line 2299
    .line 2300
    goto/16 :goto_0

    .line 2301
    .line 2302
    :cond_13
    move-object v13, v6

    .line 2303
    iget-object v0, v0, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 2304
    .line 2305
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2306
    .line 2307
    .line 2308
    move-object v0, v1

    .line 2309
    check-cast v0, Landroidx/datastore/preferences/protobuf/x;

    .line 2310
    .line 2311
    iget-object v0, v0, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 2312
    .line 2313
    invoke-virtual {v0, v13}, Landroidx/datastore/preferences/protobuf/h1;->d(Landroidx/datastore/preferences/protobuf/j0;)V

    .line 2314
    .line 2315
    .line 2316
    return-void

    .line 2317
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_68
        :pswitch_67
        :pswitch_66
        :pswitch_65
        :pswitch_64
        :pswitch_63
        :pswitch_62
        :pswitch_61
        :pswitch_60
        :pswitch_5f
        :pswitch_5e
        :pswitch_5d
        :pswitch_5c
        :pswitch_5b
        :pswitch_5a
        :pswitch_59
        :pswitch_58
        :pswitch_57
        :pswitch_56
        :pswitch_55
        :pswitch_54
        :pswitch_53
        :pswitch_52
        :pswitch_51
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 2318
    .line 2319
    .line 2320
    .line 2321
    .line 2322
    .line 2323
    .line 2324
    .line 2325
    .line 2326
    .line 2327
    .line 2328
    .line 2329
    .line 2330
    .line 2331
    .line 2332
    .line 2333
    .line 2334
    .line 2335
    .line 2336
    .line 2337
    .line 2338
    .line 2339
    .line 2340
    .line 2341
    .line 2342
    .line 2343
    .line 2344
    .line 2345
    .line 2346
    .line 2347
    .line 2348
    .line 2349
    .line 2350
    .line 2351
    .line 2352
    .line 2353
    .line 2354
    .line 2355
    .line 2356
    .line 2357
    .line 2358
    .line 2359
    .line 2360
    .line 2361
    .line 2362
    .line 2363
    .line 2364
    .line 2365
    .line 2366
    .line 2367
    .line 2368
    .line 2369
    .line 2370
    .line 2371
    .line 2372
    .line 2373
    .line 2374
    .line 2375
    .line 2376
    .line 2377
    .line 2378
    .line 2379
    .line 2380
    .line 2381
    .line 2382
    .line 2383
    .line 2384
    .line 2385
    .line 2386
    .line 2387
    .line 2388
    .line 2389
    .line 2390
    .line 2391
    .line 2392
    .line 2393
    .line 2394
    .line 2395
    .line 2396
    .line 2397
    .line 2398
    .line 2399
    .line 2400
    .line 2401
    .line 2402
    .line 2403
    .line 2404
    .line 2405
    .line 2406
    .line 2407
    .line 2408
    .line 2409
    .line 2410
    .line 2411
    .line 2412
    .line 2413
    .line 2414
    .line 2415
    .line 2416
    .line 2417
    .line 2418
    .line 2419
    .line 2420
    .line 2421
    .line 2422
    .line 2423
    .line 2424
    .line 2425
    .line 2426
    .line 2427
    .line 2428
    .line 2429
    .line 2430
    .line 2431
    .line 2432
    .line 2433
    .line 2434
    .line 2435
    .line 2436
    .line 2437
    .line 2438
    .line 2439
    .line 2440
    .line 2441
    .line 2442
    .line 2443
    .line 2444
    .line 2445
    .line 2446
    .line 2447
    .line 2448
    .line 2449
    .line 2450
    .line 2451
    .line 2452
    .line 2453
    .line 2454
    .line 2455
    .line 2456
    .line 2457
    .line 2458
    .line 2459
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
    .end packed-switch

    .line 2460
    .line 2461
    .line 2462
    .line 2463
    .line 2464
    .line 2465
    .line 2466
    .line 2467
    .line 2468
    .line 2469
    .line 2470
    .line 2471
    .line 2472
    .line 2473
    .line 2474
    .line 2475
    .line 2476
    .line 2477
    .line 2478
    .line 2479
    .line 2480
    .line 2481
    .line 2482
    .line 2483
    .line 2484
    .line 2485
    .line 2486
    .line 2487
    .line 2488
    .line 2489
    .line 2490
    .line 2491
    .line 2492
    .line 2493
    .line 2494
    .line 2495
    .line 2496
    .line 2497
    .line 2498
    .line 2499
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
    .end packed-switch
.end method

.method public final a(Ljava/lang/Object;)V
    .locals 9

    .line 1
    invoke-static {p1}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_2

    .line 8
    .line 9
    :cond_0
    instance-of v0, p1, Landroidx/datastore/preferences/protobuf/x;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    move-object v0, p1

    .line 15
    check-cast v0, Landroidx/datastore/preferences/protobuf/x;

    .line 16
    .line 17
    const v2, 0x7fffffff

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/x;->k(I)V

    .line 21
    .line 22
    .line 23
    iput v1, v0, Landroidx/datastore/preferences/protobuf/a;->memoizedHashCode:I

    .line 24
    .line 25
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/x;->h()V

    .line 26
    .line 27
    .line 28
    :cond_1
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 29
    .line 30
    array-length v2, v0

    .line 31
    move v3, v1

    .line 32
    :goto_0
    if-ge v3, v2, :cond_5

    .line 33
    .line 34
    invoke-virtual {p0, v3}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    const v5, 0xfffff

    .line 39
    .line 40
    .line 41
    and-int/2addr v5, v4

    .line 42
    int-to-long v5, v5

    .line 43
    invoke-static {v4}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    const/16 v7, 0x9

    .line 48
    .line 49
    if-eq v4, v7, :cond_3

    .line 50
    .line 51
    const/16 v7, 0x3c

    .line 52
    .line 53
    if-eq v4, v7, :cond_2

    .line 54
    .line 55
    const/16 v7, 0x44

    .line 56
    .line 57
    if-eq v4, v7, :cond_2

    .line 58
    .line 59
    packed-switch v4, :pswitch_data_0

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :pswitch_0
    sget-object v4, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 64
    .line 65
    invoke-virtual {v4, p1, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    if-eqz v7, :cond_4

    .line 70
    .line 71
    iget-object v8, p0, Landroidx/datastore/preferences/protobuf/r0;->m:Landroidx/datastore/preferences/protobuf/n0;

    .line 72
    .line 73
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    move-object v8, v7

    .line 77
    check-cast v8, Landroidx/datastore/preferences/protobuf/m0;

    .line 78
    .line 79
    iput-boolean v1, v8, Landroidx/datastore/preferences/protobuf/m0;->d:Z

    .line 80
    .line 81
    invoke-virtual {v4, p1, v5, v6, v7}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :pswitch_1
    iget-object v4, p0, Landroidx/datastore/preferences/protobuf/r0;->k:Landroidx/datastore/preferences/protobuf/f0;

    .line 86
    .line 87
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 91
    .line 92
    invoke-virtual {v4, p1, v5, v6}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    check-cast v4, Landroidx/datastore/preferences/protobuf/z;

    .line 97
    .line 98
    check-cast v4, Landroidx/datastore/preferences/protobuf/b;

    .line 99
    .line 100
    iget-boolean v5, v4, Landroidx/datastore/preferences/protobuf/b;->d:Z

    .line 101
    .line 102
    if-eqz v5, :cond_4

    .line 103
    .line 104
    iput-boolean v1, v4, Landroidx/datastore/preferences/protobuf/b;->d:Z

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_2
    aget v4, v0, v3

    .line 108
    .line 109
    invoke-virtual {p0, v4, p1, v3}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    if-eqz v4, :cond_4

    .line 114
    .line 115
    invoke-virtual {p0, v3}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    sget-object v7, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 120
    .line 121
    invoke-virtual {v7, p1, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    invoke-interface {v4, v5}, Landroidx/datastore/preferences/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_3
    :pswitch_2
    invoke-virtual {p0, v3, p1}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-eqz v4, :cond_4

    .line 134
    .line 135
    invoke-virtual {p0, v3}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    sget-object v7, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 140
    .line 141
    invoke-virtual {v7, p1, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    invoke-interface {v4, v5}, Landroidx/datastore/preferences/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_4
    :goto_1
    add-int/lit8 v3, v3, 0x3

    .line 149
    .line 150
    goto :goto_0

    .line 151
    :cond_5
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 152
    .line 153
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    check-cast p1, Landroidx/datastore/preferences/protobuf/x;

    .line 157
    .line 158
    iget-object p0, p1, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 159
    .line 160
    iget-boolean p1, p0, Landroidx/datastore/preferences/protobuf/h1;->e:Z

    .line 161
    .line 162
    if-eqz p1, :cond_6

    .line 163
    .line 164
    iput-boolean v1, p0, Landroidx/datastore/preferences/protobuf/h1;->e:Z

    .line 165
    .line 166
    :cond_6
    :goto_2
    return-void

    .line 167
    :pswitch_data_0
    .packed-switch 0x11
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Ljava/lang/Object;)Z
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const v6, 0xfffff

    .line 6
    .line 7
    .line 8
    const/4 v7, 0x0

    .line 9
    move v2, v6

    .line 10
    move v3, v7

    .line 11
    move v8, v3

    .line 12
    :goto_0
    iget v4, v0, Landroidx/datastore/preferences/protobuf/r0;->h:I

    .line 13
    .line 14
    const/4 v5, 0x1

    .line 15
    if-ge v8, v4, :cond_e

    .line 16
    .line 17
    iget-object v4, v0, Landroidx/datastore/preferences/protobuf/r0;->g:[I

    .line 18
    .line 19
    aget v4, v4, v8

    .line 20
    .line 21
    iget-object v9, v0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 22
    .line 23
    aget v10, v9, v4

    .line 24
    .line 25
    invoke-virtual {v0, v4}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 26
    .line 27
    .line 28
    move-result v11

    .line 29
    add-int/lit8 v12, v4, 0x2

    .line 30
    .line 31
    aget v9, v9, v12

    .line 32
    .line 33
    and-int v12, v9, v6

    .line 34
    .line 35
    ushr-int/lit8 v9, v9, 0x14

    .line 36
    .line 37
    shl-int/2addr v5, v9

    .line 38
    if-eq v12, v2, :cond_1

    .line 39
    .line 40
    if-eq v12, v6, :cond_0

    .line 41
    .line 42
    sget-object v2, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 43
    .line 44
    int-to-long v13, v12

    .line 45
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    :cond_0
    move v2, v4

    .line 50
    move v4, v3

    .line 51
    move v3, v12

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v15, v3

    .line 54
    move v3, v2

    .line 55
    move v2, v4

    .line 56
    move v4, v15

    .line 57
    :goto_1
    const/high16 v9, 0x10000000

    .line 58
    .line 59
    and-int/2addr v9, v11

    .line 60
    if-eqz v9, :cond_2

    .line 61
    .line 62
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    if-nez v9, :cond_2

    .line 67
    .line 68
    goto/16 :goto_3

    .line 69
    .line 70
    :cond_2
    invoke-static {v11}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 71
    .line 72
    .line 73
    move-result v9

    .line 74
    const/16 v12, 0x9

    .line 75
    .line 76
    if-eq v9, v12, :cond_c

    .line 77
    .line 78
    const/16 v12, 0x11

    .line 79
    .line 80
    if-eq v9, v12, :cond_c

    .line 81
    .line 82
    const/16 v5, 0x1b

    .line 83
    .line 84
    if-eq v9, v5, :cond_9

    .line 85
    .line 86
    const/16 v5, 0x3c

    .line 87
    .line 88
    if-eq v9, v5, :cond_8

    .line 89
    .line 90
    const/16 v5, 0x44

    .line 91
    .line 92
    if-eq v9, v5, :cond_8

    .line 93
    .line 94
    const/16 v5, 0x31

    .line 95
    .line 96
    if-eq v9, v5, :cond_9

    .line 97
    .line 98
    const/16 v5, 0x32

    .line 99
    .line 100
    if-eq v9, v5, :cond_3

    .line 101
    .line 102
    goto/16 :goto_4

    .line 103
    .line 104
    :cond_3
    and-int v5, v11, v6

    .line 105
    .line 106
    int-to-long v9, v5

    .line 107
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 108
    .line 109
    invoke-virtual {v5, v1, v9, v10}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    iget-object v9, v0, Landroidx/datastore/preferences/protobuf/r0;->m:Landroidx/datastore/preferences/protobuf/n0;

    .line 114
    .line 115
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    check-cast v5, Landroidx/datastore/preferences/protobuf/m0;

    .line 119
    .line 120
    invoke-virtual {v5}, Ljava/util/HashMap;->isEmpty()Z

    .line 121
    .line 122
    .line 123
    move-result v9

    .line 124
    if-eqz v9, :cond_4

    .line 125
    .line 126
    goto/16 :goto_4

    .line 127
    .line 128
    :cond_4
    div-int/lit8 v2, v2, 0x3

    .line 129
    .line 130
    mul-int/lit8 v2, v2, 0x2

    .line 131
    .line 132
    iget-object v9, v0, Landroidx/datastore/preferences/protobuf/r0;->b:[Ljava/lang/Object;

    .line 133
    .line 134
    aget-object v2, v9, v2

    .line 135
    .line 136
    check-cast v2, Landroidx/datastore/preferences/protobuf/l0;

    .line 137
    .line 138
    iget-object v2, v2, Landroidx/datastore/preferences/protobuf/l0;->a:Landroidx/datastore/preferences/protobuf/k0;

    .line 139
    .line 140
    iget-object v2, v2, Landroidx/datastore/preferences/protobuf/k0;->b:Landroidx/datastore/preferences/protobuf/v1;

    .line 141
    .line 142
    iget-object v2, v2, Landroidx/datastore/preferences/protobuf/v1;->d:Landroidx/datastore/preferences/protobuf/w1;

    .line 143
    .line 144
    sget-object v9, Landroidx/datastore/preferences/protobuf/w1;->l:Landroidx/datastore/preferences/protobuf/w1;

    .line 145
    .line 146
    if-eq v2, v9, :cond_5

    .line 147
    .line 148
    goto/16 :goto_4

    .line 149
    .line 150
    :cond_5
    invoke-virtual {v5}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    const/4 v5, 0x0

    .line 159
    :cond_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 160
    .line 161
    .line 162
    move-result v9

    .line 163
    if-eqz v9, :cond_d

    .line 164
    .line 165
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v9

    .line 169
    if-nez v5, :cond_7

    .line 170
    .line 171
    sget-object v5, Landroidx/datastore/preferences/protobuf/x0;->c:Landroidx/datastore/preferences/protobuf/x0;

    .line 172
    .line 173
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    move-result-object v10

    .line 177
    invoke-virtual {v5, v10}, Landroidx/datastore/preferences/protobuf/x0;->a(Ljava/lang/Class;)Landroidx/datastore/preferences/protobuf/a1;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    :cond_7
    invoke-interface {v5, v9}, Landroidx/datastore/preferences/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v9

    .line 185
    if-nez v9, :cond_6

    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_8
    invoke-virtual {v0, v10, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 189
    .line 190
    .line 191
    move-result v5

    .line 192
    if-eqz v5, :cond_d

    .line 193
    .line 194
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    and-int v5, v11, v6

    .line 199
    .line 200
    int-to-long v9, v5

    .line 201
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 202
    .line 203
    invoke-virtual {v5, v1, v9, v10}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v5

    .line 207
    invoke-interface {v2, v5}, Landroidx/datastore/preferences/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v2

    .line 211
    if-nez v2, :cond_d

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_9
    and-int v5, v11, v6

    .line 215
    .line 216
    int-to-long v9, v5

    .line 217
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 218
    .line 219
    invoke-virtual {v5, v1, v9, v10}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v5

    .line 223
    check-cast v5, Ljava/util/List;

    .line 224
    .line 225
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 226
    .line 227
    .line 228
    move-result v9

    .line 229
    if-eqz v9, :cond_a

    .line 230
    .line 231
    goto :goto_4

    .line 232
    :cond_a
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    move v9, v7

    .line 237
    :goto_2
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 238
    .line 239
    .line 240
    move-result v10

    .line 241
    if-ge v9, v10, :cond_d

    .line 242
    .line 243
    invoke-interface {v5, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v10

    .line 247
    invoke-interface {v2, v10}, Landroidx/datastore/preferences/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v10

    .line 251
    if-nez v10, :cond_b

    .line 252
    .line 253
    goto :goto_3

    .line 254
    :cond_b
    add-int/lit8 v9, v9, 0x1

    .line 255
    .line 256
    goto :goto_2

    .line 257
    :cond_c
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 258
    .line 259
    .line 260
    move-result v5

    .line 261
    if-eqz v5, :cond_d

    .line 262
    .line 263
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    and-int v5, v11, v6

    .line 268
    .line 269
    int-to-long v9, v5

    .line 270
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 271
    .line 272
    invoke-virtual {v5, v1, v9, v10}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v5

    .line 276
    invoke-interface {v2, v5}, Landroidx/datastore/preferences/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v2

    .line 280
    if-nez v2, :cond_d

    .line 281
    .line 282
    :goto_3
    return v7

    .line 283
    :cond_d
    :goto_4
    add-int/lit8 v8, v8, 0x1

    .line 284
    .line 285
    move v2, v3

    .line 286
    move v3, v4

    .line 287
    goto/16 :goto_0

    .line 288
    .line 289
    :cond_e
    return v5
.end method

.method public final c()Landroidx/datastore/preferences/protobuf/x;
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/r0;->j:Landroidx/datastore/preferences/protobuf/t0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->e:Landroidx/datastore/preferences/protobuf/a;

    .line 7
    .line 8
    check-cast p0, Landroidx/datastore/preferences/protobuf/x;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/x;->i()Landroidx/datastore/preferences/protobuf/x;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final d(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 10

    .line 1
    invoke-static {p1}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_5

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    :goto_0
    iget-object v1, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    if-ge v0, v2, :cond_4

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const v3, 0xfffff

    .line 21
    .line 22
    .line 23
    and-int/2addr v3, v2

    .line 24
    int-to-long v6, v3

    .line 25
    aget v1, v1, v0

    .line 26
    .line 27
    invoke-static {v2}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    packed-switch v2, :pswitch_data_0

    .line 32
    .line 33
    .line 34
    goto :goto_1

    .line 35
    :pswitch_0
    invoke-virtual {p0, v0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->t(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    :goto_1
    move-object v5, p1

    .line 39
    goto/16 :goto_2

    .line 40
    .line 41
    :pswitch_1
    invoke-virtual {p0, v1, p2, v0}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-eqz v2, :cond_0

    .line 46
    .line 47
    sget-object v2, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 48
    .line 49
    invoke-virtual {v2, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    invoke-static {p1, v6, v7, v2}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v1, p1, v0}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :pswitch_2
    invoke-virtual {p0, v0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->t(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :pswitch_3
    invoke-virtual {p0, v1, p2, v0}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_0

    .line 69
    .line 70
    sget-object v2, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 71
    .line 72
    invoke-virtual {v2, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-static {p1, v6, v7, v2}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0, v1, p1, v0}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :pswitch_4
    sget-object v1, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 84
    .line 85
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 86
    .line 87
    invoke-virtual {v1, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    iget-object v3, p0, Landroidx/datastore/preferences/protobuf/r0;->m:Landroidx/datastore/preferences/protobuf/n0;

    .line 96
    .line 97
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    invoke-static {v2, v1}, Landroidx/datastore/preferences/protobuf/n0;->a(Ljava/lang/Object;Ljava/lang/Object;)Landroidx/datastore/preferences/protobuf/m0;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    invoke-static {p1, v6, v7, v1}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :pswitch_5
    iget-object v1, p0, Landroidx/datastore/preferences/protobuf/r0;->k:Landroidx/datastore/preferences/protobuf/f0;

    .line 109
    .line 110
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 114
    .line 115
    invoke-virtual {v1, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    check-cast v2, Landroidx/datastore/preferences/protobuf/z;

    .line 120
    .line 121
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    check-cast v1, Landroidx/datastore/preferences/protobuf/z;

    .line 126
    .line 127
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 132
    .line 133
    .line 134
    move-result v4

    .line 135
    if-lez v3, :cond_2

    .line 136
    .line 137
    if-lez v4, :cond_2

    .line 138
    .line 139
    move-object v5, v2

    .line 140
    check-cast v5, Landroidx/datastore/preferences/protobuf/b;

    .line 141
    .line 142
    iget-boolean v5, v5, Landroidx/datastore/preferences/protobuf/b;->d:Z

    .line 143
    .line 144
    if-nez v5, :cond_1

    .line 145
    .line 146
    add-int/2addr v4, v3

    .line 147
    check-cast v2, Landroidx/datastore/preferences/protobuf/y0;

    .line 148
    .line 149
    invoke-virtual {v2, v4}, Landroidx/datastore/preferences/protobuf/y0;->g(I)Landroidx/datastore/preferences/protobuf/y0;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    :cond_1
    invoke-interface {v2, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 154
    .line 155
    .line 156
    :cond_2
    if-lez v3, :cond_3

    .line 157
    .line 158
    move-object v1, v2

    .line 159
    :cond_3
    invoke-static {p1, v6, v7, v1}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    goto :goto_1

    .line 163
    :pswitch_6
    invoke-virtual {p0, v0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->s(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    goto/16 :goto_1

    .line 167
    .line 168
    :pswitch_7
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v1

    .line 172
    if-eqz v1, :cond_0

    .line 173
    .line 174
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 175
    .line 176
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 177
    .line 178
    .line 179
    move-result-wide v1

    .line 180
    invoke-static {v6, v7, p1, v1, v2}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    goto/16 :goto_1

    .line 187
    .line 188
    :pswitch_8
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    if-eqz v1, :cond_0

    .line 193
    .line 194
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 195
    .line 196
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 197
    .line 198
    .line 199
    move-result v1

    .line 200
    invoke-static {v6, v7, p1, v1}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    goto/16 :goto_1

    .line 207
    .line 208
    :pswitch_9
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v1

    .line 212
    if-eqz v1, :cond_0

    .line 213
    .line 214
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 215
    .line 216
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 217
    .line 218
    .line 219
    move-result-wide v1

    .line 220
    invoke-static {v6, v7, p1, v1, v2}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    goto/16 :goto_1

    .line 227
    .line 228
    :pswitch_a
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    move-result v1

    .line 232
    if-eqz v1, :cond_0

    .line 233
    .line 234
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 235
    .line 236
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 237
    .line 238
    .line 239
    move-result v1

    .line 240
    invoke-static {v6, v7, p1, v1}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    goto/16 :goto_1

    .line 247
    .line 248
    :pswitch_b
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result v1

    .line 252
    if-eqz v1, :cond_0

    .line 253
    .line 254
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 255
    .line 256
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 257
    .line 258
    .line 259
    move-result v1

    .line 260
    invoke-static {v6, v7, p1, v1}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    goto/16 :goto_1

    .line 267
    .line 268
    :pswitch_c
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 269
    .line 270
    .line 271
    move-result v1

    .line 272
    if-eqz v1, :cond_0

    .line 273
    .line 274
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 275
    .line 276
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 277
    .line 278
    .line 279
    move-result v1

    .line 280
    invoke-static {v6, v7, p1, v1}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 281
    .line 282
    .line 283
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    goto/16 :goto_1

    .line 287
    .line 288
    :pswitch_d
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    move-result v1

    .line 292
    if-eqz v1, :cond_0

    .line 293
    .line 294
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 295
    .line 296
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v1

    .line 300
    invoke-static {p1, v6, v7, v1}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 304
    .line 305
    .line 306
    goto/16 :goto_1

    .line 307
    .line 308
    :pswitch_e
    invoke-virtual {p0, v0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->s(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    goto/16 :goto_1

    .line 312
    .line 313
    :pswitch_f
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    move-result v1

    .line 317
    if-eqz v1, :cond_0

    .line 318
    .line 319
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 320
    .line 321
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v1

    .line 325
    invoke-static {p1, v6, v7, v1}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    goto/16 :goto_1

    .line 332
    .line 333
    :pswitch_10
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 334
    .line 335
    .line 336
    move-result v1

    .line 337
    if-eqz v1, :cond_0

    .line 338
    .line 339
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 340
    .line 341
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->c(JLjava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    move-result v2

    .line 345
    invoke-virtual {v1, p1, v6, v7, v2}, Landroidx/datastore/preferences/protobuf/m1;->j(Ljava/lang/Object;JZ)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    goto/16 :goto_1

    .line 352
    .line 353
    :pswitch_11
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    move-result v1

    .line 357
    if-eqz v1, :cond_0

    .line 358
    .line 359
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 360
    .line 361
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 362
    .line 363
    .line 364
    move-result v1

    .line 365
    invoke-static {v6, v7, p1, v1}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 369
    .line 370
    .line 371
    goto/16 :goto_1

    .line 372
    .line 373
    :pswitch_12
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 374
    .line 375
    .line 376
    move-result v1

    .line 377
    if-eqz v1, :cond_0

    .line 378
    .line 379
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 380
    .line 381
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 382
    .line 383
    .line 384
    move-result-wide v1

    .line 385
    invoke-static {v6, v7, p1, v1, v2}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 389
    .line 390
    .line 391
    goto/16 :goto_1

    .line 392
    .line 393
    :pswitch_13
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 394
    .line 395
    .line 396
    move-result v1

    .line 397
    if-eqz v1, :cond_0

    .line 398
    .line 399
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 400
    .line 401
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 402
    .line 403
    .line 404
    move-result v1

    .line 405
    invoke-static {v6, v7, p1, v1}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 409
    .line 410
    .line 411
    goto/16 :goto_1

    .line 412
    .line 413
    :pswitch_14
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 414
    .line 415
    .line 416
    move-result v1

    .line 417
    if-eqz v1, :cond_0

    .line 418
    .line 419
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 420
    .line 421
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 422
    .line 423
    .line 424
    move-result-wide v1

    .line 425
    invoke-static {v6, v7, p1, v1, v2}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 426
    .line 427
    .line 428
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    goto/16 :goto_1

    .line 432
    .line 433
    :pswitch_15
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 434
    .line 435
    .line 436
    move-result v1

    .line 437
    if-eqz v1, :cond_0

    .line 438
    .line 439
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 440
    .line 441
    invoke-virtual {v1, p2, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 442
    .line 443
    .line 444
    move-result-wide v1

    .line 445
    invoke-static {v6, v7, p1, v1, v2}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 446
    .line 447
    .line 448
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 449
    .line 450
    .line 451
    goto/16 :goto_1

    .line 452
    .line 453
    :pswitch_16
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 454
    .line 455
    .line 456
    move-result v1

    .line 457
    if-eqz v1, :cond_0

    .line 458
    .line 459
    sget-object v1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 460
    .line 461
    invoke-virtual {v1, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->e(JLjava/lang/Object;)F

    .line 462
    .line 463
    .line 464
    move-result v2

    .line 465
    invoke-virtual {v1, p1, v6, v7, v2}, Landroidx/datastore/preferences/protobuf/m1;->m(Ljava/lang/Object;JF)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    goto/16 :goto_1

    .line 472
    .line 473
    :pswitch_17
    invoke-virtual {p0, v0, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 474
    .line 475
    .line 476
    move-result v1

    .line 477
    if-eqz v1, :cond_0

    .line 478
    .line 479
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 480
    .line 481
    invoke-virtual {v4, v6, v7, p2}, Landroidx/datastore/preferences/protobuf/m1;->d(JLjava/lang/Object;)D

    .line 482
    .line 483
    .line 484
    move-result-wide v8

    .line 485
    move-object v5, p1

    .line 486
    invoke-virtual/range {v4 .. v9}, Landroidx/datastore/preferences/protobuf/m1;->l(Ljava/lang/Object;JD)V

    .line 487
    .line 488
    .line 489
    invoke-virtual {p0, v0, v5}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 490
    .line 491
    .line 492
    :goto_2
    add-int/lit8 v0, v0, 0x3

    .line 493
    .line 494
    move-object p1, v5

    .line 495
    goto/16 :goto_0

    .line 496
    .line 497
    :cond_4
    move-object v5, p1

    .line 498
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 499
    .line 500
    invoke-static {p0, v5, p2}, Landroidx/datastore/preferences/protobuf/b1;->k(Landroidx/datastore/preferences/protobuf/i1;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 501
    .line 502
    .line 503
    return-void

    .line 504
    :cond_5
    move-object v5, p1

    .line 505
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 506
    .line 507
    const-string p1, "Mutating immutable message: "

    .line 508
    .line 509
    invoke-static {v5, p1}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 510
    .line 511
    .line 512
    move-result-object p1

    .line 513
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 514
    .line 515
    .line 516
    throw p0

    .line 517
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/j0;)V
    .locals 0

    .line 1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->M(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/j0;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final f(Landroidx/datastore/preferences/protobuf/x;)I
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    sget-object v6, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 6
    .line 7
    const v8, 0xfffff

    .line 8
    .line 9
    .line 10
    move v3, v8

    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v4, 0x0

    .line 13
    const/4 v9, 0x0

    .line 14
    :goto_0
    iget-object v5, v0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 15
    .line 16
    array-length v10, v5

    .line 17
    if-ge v2, v10, :cond_24

    .line 18
    .line 19
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 20
    .line 21
    .line 22
    move-result v10

    .line 23
    invoke-static {v10}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 24
    .line 25
    .line 26
    move-result v11

    .line 27
    aget v12, v5, v2

    .line 28
    .line 29
    add-int/lit8 v13, v2, 0x2

    .line 30
    .line 31
    aget v5, v5, v13

    .line 32
    .line 33
    and-int v13, v5, v8

    .line 34
    .line 35
    const/16 v14, 0x11

    .line 36
    .line 37
    const/4 v15, 0x1

    .line 38
    if-gt v11, v14, :cond_2

    .line 39
    .line 40
    if-eq v13, v3, :cond_1

    .line 41
    .line 42
    if-ne v13, v8, :cond_0

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    int-to-long v3, v13

    .line 47
    invoke-virtual {v6, v1, v3, v4}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    move v4, v3

    .line 52
    :goto_1
    move v3, v13

    .line 53
    :cond_1
    ushr-int/lit8 v5, v5, 0x14

    .line 54
    .line 55
    shl-int v5, v15, v5

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/4 v5, 0x0

    .line 59
    :goto_2
    and-int/2addr v10, v8

    .line 60
    int-to-long v13, v10

    .line 61
    sget-object v10, Landroidx/datastore/preferences/protobuf/s;->e:Landroidx/datastore/preferences/protobuf/s;

    .line 62
    .line 63
    iget v10, v10, Landroidx/datastore/preferences/protobuf/s;->d:I

    .line 64
    .line 65
    if-lt v11, v10, :cond_3

    .line 66
    .line 67
    sget-object v10, Landroidx/datastore/preferences/protobuf/s;->f:Landroidx/datastore/preferences/protobuf/s;

    .line 68
    .line 69
    iget v10, v10, Landroidx/datastore/preferences/protobuf/s;->d:I

    .line 70
    .line 71
    :cond_3
    const/16 v10, 0x3f

    .line 72
    .line 73
    const/16 v16, 0x2

    .line 74
    .line 75
    const/16 v17, 0x4

    .line 76
    .line 77
    const/16 v18, 0x8

    .line 78
    .line 79
    packed-switch v11, :pswitch_data_0

    .line 80
    .line 81
    .line 82
    goto/16 :goto_2d

    .line 83
    .line 84
    :pswitch_0
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    if-eqz v5, :cond_23

    .line 89
    .line 90
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    check-cast v5, Landroidx/datastore/preferences/protobuf/a;

    .line 95
    .line 96
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 97
    .line 98
    .line 99
    move-result-object v10

    .line 100
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 101
    .line 102
    .line 103
    move-result v11

    .line 104
    mul-int/lit8 v11, v11, 0x2

    .line 105
    .line 106
    invoke-virtual {v5, v10}, Landroidx/datastore/preferences/protobuf/a;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 107
    .line 108
    .line 109
    move-result v5

    .line 110
    add-int/2addr v5, v11

    .line 111
    :goto_3
    add-int/2addr v9, v5

    .line 112
    goto/16 :goto_2d

    .line 113
    .line 114
    :pswitch_1
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    if-eqz v5, :cond_23

    .line 119
    .line 120
    invoke-static {v13, v14, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 121
    .line 122
    .line 123
    move-result-wide v13

    .line 124
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    shl-long v11, v13, v15

    .line 129
    .line 130
    shr-long/2addr v13, v10

    .line 131
    xor-long v10, v11, v13

    .line 132
    .line 133
    invoke-static {v10, v11}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    :goto_4
    add-int/2addr v10, v5

    .line 138
    :goto_5
    add-int/2addr v9, v10

    .line 139
    goto/16 :goto_2d

    .line 140
    .line 141
    :pswitch_2
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-eqz v5, :cond_23

    .line 146
    .line 147
    invoke-static {v13, v14, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 148
    .line 149
    .line 150
    move-result v5

    .line 151
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 152
    .line 153
    .line 154
    move-result v10

    .line 155
    shl-int/lit8 v11, v5, 0x1

    .line 156
    .line 157
    shr-int/lit8 v5, v5, 0x1f

    .line 158
    .line 159
    xor-int/2addr v5, v11

    .line 160
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 161
    .line 162
    .line 163
    move-result v5

    .line 164
    :goto_6
    add-int/2addr v5, v10

    .line 165
    goto :goto_3

    .line 166
    :pswitch_3
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 167
    .line 168
    .line 169
    move-result v5

    .line 170
    if-eqz v5, :cond_23

    .line 171
    .line 172
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 173
    .line 174
    .line 175
    move-result v5

    .line 176
    :goto_7
    add-int/lit8 v5, v5, 0x8

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :pswitch_4
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 180
    .line 181
    .line 182
    move-result v5

    .line 183
    if-eqz v5, :cond_23

    .line 184
    .line 185
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    :goto_8
    add-int/lit8 v5, v5, 0x4

    .line 190
    .line 191
    goto :goto_3

    .line 192
    :pswitch_5
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 193
    .line 194
    .line 195
    move-result v5

    .line 196
    if-eqz v5, :cond_23

    .line 197
    .line 198
    invoke-static {v13, v14, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 199
    .line 200
    .line 201
    move-result v5

    .line 202
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 203
    .line 204
    .line 205
    move-result v10

    .line 206
    int-to-long v11, v5

    .line 207
    invoke-static {v11, v12}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 208
    .line 209
    .line 210
    move-result v5

    .line 211
    goto :goto_6

    .line 212
    :pswitch_6
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 213
    .line 214
    .line 215
    move-result v5

    .line 216
    if-eqz v5, :cond_23

    .line 217
    .line 218
    invoke-static {v13, v14, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 219
    .line 220
    .line 221
    move-result v5

    .line 222
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 223
    .line 224
    .line 225
    move-result v10

    .line 226
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 227
    .line 228
    .line 229
    move-result v5

    .line 230
    goto :goto_6

    .line 231
    :pswitch_7
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 232
    .line 233
    .line 234
    move-result v5

    .line 235
    if-eqz v5, :cond_23

    .line 236
    .line 237
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v5

    .line 241
    check-cast v5, Landroidx/datastore/preferences/protobuf/h;

    .line 242
    .line 243
    invoke-static {v12, v5}, Landroidx/datastore/preferences/protobuf/l;->n(ILandroidx/datastore/preferences/protobuf/h;)I

    .line 244
    .line 245
    .line 246
    move-result v5

    .line 247
    goto/16 :goto_3

    .line 248
    .line 249
    :pswitch_8
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 250
    .line 251
    .line 252
    move-result v5

    .line 253
    if-eqz v5, :cond_23

    .line 254
    .line 255
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v5

    .line 259
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 260
    .line 261
    .line 262
    move-result-object v10

    .line 263
    sget-object v11, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 264
    .line 265
    check-cast v5, Landroidx/datastore/preferences/protobuf/a;

    .line 266
    .line 267
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 268
    .line 269
    .line 270
    move-result v11

    .line 271
    invoke-virtual {v5, v10}, Landroidx/datastore/preferences/protobuf/a;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 272
    .line 273
    .line 274
    move-result v5

    .line 275
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 276
    .line 277
    .line 278
    move-result v10

    .line 279
    add-int/2addr v10, v5

    .line 280
    add-int/2addr v10, v11

    .line 281
    goto/16 :goto_5

    .line 282
    .line 283
    :pswitch_9
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 284
    .line 285
    .line 286
    move-result v5

    .line 287
    if-eqz v5, :cond_23

    .line 288
    .line 289
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v5

    .line 293
    instance-of v10, v5, Landroidx/datastore/preferences/protobuf/h;

    .line 294
    .line 295
    if-eqz v10, :cond_4

    .line 296
    .line 297
    check-cast v5, Landroidx/datastore/preferences/protobuf/h;

    .line 298
    .line 299
    invoke-static {v12, v5}, Landroidx/datastore/preferences/protobuf/l;->n(ILandroidx/datastore/preferences/protobuf/h;)I

    .line 300
    .line 301
    .line 302
    move-result v5

    .line 303
    :goto_9
    add-int/2addr v5, v9

    .line 304
    move v9, v5

    .line 305
    goto/16 :goto_2d

    .line 306
    .line 307
    :cond_4
    check-cast v5, Ljava/lang/String;

    .line 308
    .line 309
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 310
    .line 311
    .line 312
    move-result v10

    .line 313
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 314
    .line 315
    .line 316
    move-result v5

    .line 317
    add-int/2addr v5, v10

    .line 318
    goto :goto_9

    .line 319
    :pswitch_a
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 320
    .line 321
    .line 322
    move-result v5

    .line 323
    if-eqz v5, :cond_23

    .line 324
    .line 325
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 326
    .line 327
    .line 328
    move-result v5

    .line 329
    add-int/2addr v5, v15

    .line 330
    goto/16 :goto_3

    .line 331
    .line 332
    :pswitch_b
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 333
    .line 334
    .line 335
    move-result v5

    .line 336
    if-eqz v5, :cond_23

    .line 337
    .line 338
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 339
    .line 340
    .line 341
    move-result v5

    .line 342
    goto/16 :goto_8

    .line 343
    .line 344
    :pswitch_c
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 345
    .line 346
    .line 347
    move-result v5

    .line 348
    if-eqz v5, :cond_23

    .line 349
    .line 350
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 351
    .line 352
    .line 353
    move-result v5

    .line 354
    goto/16 :goto_7

    .line 355
    .line 356
    :pswitch_d
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 357
    .line 358
    .line 359
    move-result v5

    .line 360
    if-eqz v5, :cond_23

    .line 361
    .line 362
    invoke-static {v13, v14, v1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 363
    .line 364
    .line 365
    move-result v5

    .line 366
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 367
    .line 368
    .line 369
    move-result v10

    .line 370
    int-to-long v11, v5

    .line 371
    invoke-static {v11, v12}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 372
    .line 373
    .line 374
    move-result v5

    .line 375
    goto/16 :goto_6

    .line 376
    .line 377
    :pswitch_e
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 378
    .line 379
    .line 380
    move-result v5

    .line 381
    if-eqz v5, :cond_23

    .line 382
    .line 383
    invoke-static {v13, v14, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 384
    .line 385
    .line 386
    move-result-wide v10

    .line 387
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 388
    .line 389
    .line 390
    move-result v5

    .line 391
    invoke-static {v10, v11}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 392
    .line 393
    .line 394
    move-result v10

    .line 395
    goto/16 :goto_4

    .line 396
    .line 397
    :pswitch_f
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 398
    .line 399
    .line 400
    move-result v5

    .line 401
    if-eqz v5, :cond_23

    .line 402
    .line 403
    invoke-static {v13, v14, v1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 404
    .line 405
    .line 406
    move-result-wide v10

    .line 407
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 408
    .line 409
    .line 410
    move-result v5

    .line 411
    invoke-static {v10, v11}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 412
    .line 413
    .line 414
    move-result v10

    .line 415
    goto/16 :goto_4

    .line 416
    .line 417
    :pswitch_10
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 418
    .line 419
    .line 420
    move-result v5

    .line 421
    if-eqz v5, :cond_23

    .line 422
    .line 423
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 424
    .line 425
    .line 426
    move-result v5

    .line 427
    goto/16 :goto_8

    .line 428
    .line 429
    :pswitch_11
    invoke-virtual {v0, v12, v1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 430
    .line 431
    .line 432
    move-result v5

    .line 433
    if-eqz v5, :cond_23

    .line 434
    .line 435
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 436
    .line 437
    .line 438
    move-result v5

    .line 439
    goto/16 :goto_7

    .line 440
    .line 441
    :pswitch_12
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    move-result-object v5

    .line 445
    div-int/lit8 v11, v2, 0x3

    .line 446
    .line 447
    mul-int/lit8 v11, v11, 0x2

    .line 448
    .line 449
    iget-object v13, v0, Landroidx/datastore/preferences/protobuf/r0;->b:[Ljava/lang/Object;

    .line 450
    .line 451
    aget-object v11, v13, v11

    .line 452
    .line 453
    iget-object v13, v0, Landroidx/datastore/preferences/protobuf/r0;->m:Landroidx/datastore/preferences/protobuf/n0;

    .line 454
    .line 455
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 456
    .line 457
    .line 458
    check-cast v5, Landroidx/datastore/preferences/protobuf/m0;

    .line 459
    .line 460
    check-cast v11, Landroidx/datastore/preferences/protobuf/l0;

    .line 461
    .line 462
    invoke-virtual {v5}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 463
    .line 464
    .line 465
    move-result v13

    .line 466
    if-eqz v13, :cond_6

    .line 467
    .line 468
    const/4 v13, 0x0

    .line 469
    :cond_5
    move/from16 v23, v3

    .line 470
    .line 471
    move/from16 v24, v4

    .line 472
    .line 473
    goto/16 :goto_14

    .line 474
    .line 475
    :cond_6
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/m0;->entrySet()Ljava/util/Set;

    .line 476
    .line 477
    .line 478
    move-result-object v5

    .line 479
    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 480
    .line 481
    .line 482
    move-result-object v5

    .line 483
    const/4 v13, 0x0

    .line 484
    :goto_a
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 485
    .line 486
    .line 487
    move-result v14

    .line 488
    if-eqz v14, :cond_5

    .line 489
    .line 490
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v14

    .line 494
    check-cast v14, Ljava/util/Map$Entry;

    .line 495
    .line 496
    invoke-interface {v14}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v7

    .line 500
    invoke-interface {v14}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v14

    .line 504
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 505
    .line 506
    .line 507
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 508
    .line 509
    .line 510
    move-result v19

    .line 511
    iget-object v8, v11, Landroidx/datastore/preferences/protobuf/l0;->a:Landroidx/datastore/preferences/protobuf/k0;

    .line 512
    .line 513
    move/from16 v20, v10

    .line 514
    .line 515
    iget-object v10, v8, Landroidx/datastore/preferences/protobuf/k0;->a:Landroidx/datastore/preferences/protobuf/v1;

    .line 516
    .line 517
    sget v21, Landroidx/datastore/preferences/protobuf/r;->c:I

    .line 518
    .line 519
    invoke-static {v15}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 520
    .line 521
    .line 522
    move-result v21

    .line 523
    move/from16 v22, v15

    .line 524
    .line 525
    sget-object v15, Landroidx/datastore/preferences/protobuf/v1;->g:Landroidx/datastore/preferences/protobuf/s1;

    .line 526
    .line 527
    if-ne v10, v15, :cond_7

    .line 528
    .line 529
    mul-int/lit8 v21, v21, 0x2

    .line 530
    .line 531
    :cond_7
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 532
    .line 533
    .line 534
    move-result v10

    .line 535
    move/from16 v23, v3

    .line 536
    .line 537
    const-string v3, "There is no way to get here, but the compiler thinks otherwise."

    .line 538
    .line 539
    move/from16 v24, v4

    .line 540
    .line 541
    packed-switch v10, :pswitch_data_1

    .line 542
    .line 543
    .line 544
    new-instance v0, Ljava/lang/RuntimeException;

    .line 545
    .line 546
    invoke-direct {v0, v3}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    throw v0

    .line 550
    :pswitch_13
    check-cast v7, Ljava/lang/Long;

    .line 551
    .line 552
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 553
    .line 554
    .line 555
    move-result-wide v25

    .line 556
    shl-long v27, v25, v22

    .line 557
    .line 558
    shr-long v25, v25, v20

    .line 559
    .line 560
    xor-long v25, v27, v25

    .line 561
    .line 562
    invoke-static/range {v25 .. v26}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 563
    .line 564
    .line 565
    move-result v7

    .line 566
    :goto_b
    move-object v10, v5

    .line 567
    goto/16 :goto_f

    .line 568
    .line 569
    :pswitch_14
    check-cast v7, Ljava/lang/Integer;

    .line 570
    .line 571
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 572
    .line 573
    .line 574
    move-result v7

    .line 575
    shl-int/lit8 v10, v7, 0x1

    .line 576
    .line 577
    shr-int/lit8 v7, v7, 0x1f

    .line 578
    .line 579
    xor-int/2addr v7, v10

    .line 580
    invoke-static {v7}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 581
    .line 582
    .line 583
    move-result v7

    .line 584
    goto :goto_b

    .line 585
    :pswitch_15
    check-cast v7, Ljava/lang/Long;

    .line 586
    .line 587
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 588
    .line 589
    .line 590
    move-object v10, v5

    .line 591
    :goto_c
    move/from16 v7, v18

    .line 592
    .line 593
    goto/16 :goto_f

    .line 594
    .line 595
    :pswitch_16
    check-cast v7, Ljava/lang/Integer;

    .line 596
    .line 597
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 598
    .line 599
    .line 600
    move-object v10, v5

    .line 601
    :goto_d
    move/from16 v7, v17

    .line 602
    .line 603
    goto/16 :goto_f

    .line 604
    .line 605
    :pswitch_17
    check-cast v7, Ljava/lang/Integer;

    .line 606
    .line 607
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 608
    .line 609
    .line 610
    move-result v7

    .line 611
    move-object v10, v5

    .line 612
    int-to-long v4, v7

    .line 613
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 614
    .line 615
    .line 616
    move-result v7

    .line 617
    goto/16 :goto_f

    .line 618
    .line 619
    :pswitch_18
    move-object v10, v5

    .line 620
    check-cast v7, Ljava/lang/Integer;

    .line 621
    .line 622
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 623
    .line 624
    .line 625
    move-result v4

    .line 626
    invoke-static {v4}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 627
    .line 628
    .line 629
    move-result v7

    .line 630
    goto/16 :goto_f

    .line 631
    .line 632
    :pswitch_19
    move-object v10, v5

    .line 633
    instance-of v4, v7, Landroidx/datastore/preferences/protobuf/h;

    .line 634
    .line 635
    if-eqz v4, :cond_8

    .line 636
    .line 637
    check-cast v7, Landroidx/datastore/preferences/protobuf/h;

    .line 638
    .line 639
    invoke-virtual {v7}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 640
    .line 641
    .line 642
    move-result v4

    .line 643
    invoke-static {v4}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 644
    .line 645
    .line 646
    move-result v5

    .line 647
    :goto_e
    add-int v7, v5, v4

    .line 648
    .line 649
    goto/16 :goto_f

    .line 650
    .line 651
    :cond_8
    check-cast v7, [B

    .line 652
    .line 653
    array-length v4, v7

    .line 654
    invoke-static {v4}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 655
    .line 656
    .line 657
    move-result v5

    .line 658
    goto :goto_e

    .line 659
    :pswitch_1a
    move-object v10, v5

    .line 660
    check-cast v7, Landroidx/datastore/preferences/protobuf/a;

    .line 661
    .line 662
    check-cast v7, Landroidx/datastore/preferences/protobuf/x;

    .line 663
    .line 664
    const/4 v4, 0x0

    .line 665
    invoke-virtual {v7, v4}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 666
    .line 667
    .line 668
    move-result v5

    .line 669
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 670
    .line 671
    .line 672
    move-result v7

    .line 673
    add-int/2addr v7, v5

    .line 674
    goto/16 :goto_f

    .line 675
    .line 676
    :pswitch_1b
    move-object v10, v5

    .line 677
    const/4 v4, 0x0

    .line 678
    check-cast v7, Landroidx/datastore/preferences/protobuf/a;

    .line 679
    .line 680
    check-cast v7, Landroidx/datastore/preferences/protobuf/x;

    .line 681
    .line 682
    invoke-virtual {v7, v4}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 683
    .line 684
    .line 685
    move-result v7

    .line 686
    goto/16 :goto_f

    .line 687
    .line 688
    :pswitch_1c
    move-object v10, v5

    .line 689
    instance-of v4, v7, Landroidx/datastore/preferences/protobuf/h;

    .line 690
    .line 691
    if-eqz v4, :cond_9

    .line 692
    .line 693
    check-cast v7, Landroidx/datastore/preferences/protobuf/h;

    .line 694
    .line 695
    invoke-virtual {v7}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 696
    .line 697
    .line 698
    move-result v4

    .line 699
    invoke-static {v4}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 700
    .line 701
    .line 702
    move-result v5

    .line 703
    goto :goto_e

    .line 704
    :cond_9
    check-cast v7, Ljava/lang/String;

    .line 705
    .line 706
    invoke-static {v7}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 707
    .line 708
    .line 709
    move-result v7

    .line 710
    goto :goto_f

    .line 711
    :pswitch_1d
    move-object v10, v5

    .line 712
    check-cast v7, Ljava/lang/Boolean;

    .line 713
    .line 714
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 715
    .line 716
    .line 717
    move/from16 v7, v22

    .line 718
    .line 719
    goto :goto_f

    .line 720
    :pswitch_1e
    move-object v10, v5

    .line 721
    check-cast v7, Ljava/lang/Integer;

    .line 722
    .line 723
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 724
    .line 725
    .line 726
    goto :goto_d

    .line 727
    :pswitch_1f
    move-object v10, v5

    .line 728
    check-cast v7, Ljava/lang/Long;

    .line 729
    .line 730
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 731
    .line 732
    .line 733
    goto/16 :goto_c

    .line 734
    .line 735
    :pswitch_20
    move-object v10, v5

    .line 736
    check-cast v7, Ljava/lang/Integer;

    .line 737
    .line 738
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 739
    .line 740
    .line 741
    move-result v4

    .line 742
    int-to-long v4, v4

    .line 743
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 744
    .line 745
    .line 746
    move-result v7

    .line 747
    goto :goto_f

    .line 748
    :pswitch_21
    move-object v10, v5

    .line 749
    check-cast v7, Ljava/lang/Long;

    .line 750
    .line 751
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 752
    .line 753
    .line 754
    move-result-wide v4

    .line 755
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 756
    .line 757
    .line 758
    move-result v7

    .line 759
    goto :goto_f

    .line 760
    :pswitch_22
    move-object v10, v5

    .line 761
    check-cast v7, Ljava/lang/Long;

    .line 762
    .line 763
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 764
    .line 765
    .line 766
    move-result-wide v4

    .line 767
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 768
    .line 769
    .line 770
    move-result v7

    .line 771
    goto :goto_f

    .line 772
    :pswitch_23
    move-object v10, v5

    .line 773
    check-cast v7, Ljava/lang/Float;

    .line 774
    .line 775
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 776
    .line 777
    .line 778
    goto/16 :goto_d

    .line 779
    .line 780
    :pswitch_24
    move-object v10, v5

    .line 781
    check-cast v7, Ljava/lang/Double;

    .line 782
    .line 783
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 784
    .line 785
    .line 786
    goto/16 :goto_c

    .line 787
    .line 788
    :goto_f
    add-int v7, v7, v21

    .line 789
    .line 790
    iget-object v4, v8, Landroidx/datastore/preferences/protobuf/k0;->b:Landroidx/datastore/preferences/protobuf/v1;

    .line 791
    .line 792
    invoke-static/range {v16 .. v16}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 793
    .line 794
    .line 795
    move-result v5

    .line 796
    if-ne v4, v15, :cond_a

    .line 797
    .line 798
    mul-int/lit8 v5, v5, 0x2

    .line 799
    .line 800
    :cond_a
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 801
    .line 802
    .line 803
    move-result v4

    .line 804
    packed-switch v4, :pswitch_data_2

    .line 805
    .line 806
    .line 807
    new-instance v0, Ljava/lang/RuntimeException;

    .line 808
    .line 809
    invoke-direct {v0, v3}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 810
    .line 811
    .line 812
    throw v0

    .line 813
    :pswitch_25
    check-cast v14, Ljava/lang/Long;

    .line 814
    .line 815
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 816
    .line 817
    .line 818
    move-result-wide v3

    .line 819
    shl-long v14, v3, v22

    .line 820
    .line 821
    shr-long v3, v3, v20

    .line 822
    .line 823
    xor-long/2addr v3, v14

    .line 824
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 825
    .line 826
    .line 827
    move-result v3

    .line 828
    goto/16 :goto_13

    .line 829
    .line 830
    :pswitch_26
    check-cast v14, Ljava/lang/Integer;

    .line 831
    .line 832
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 833
    .line 834
    .line 835
    move-result v3

    .line 836
    shl-int/lit8 v4, v3, 0x1

    .line 837
    .line 838
    shr-int/lit8 v3, v3, 0x1f

    .line 839
    .line 840
    xor-int/2addr v3, v4

    .line 841
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 842
    .line 843
    .line 844
    move-result v3

    .line 845
    goto/16 :goto_13

    .line 846
    .line 847
    :pswitch_27
    check-cast v14, Ljava/lang/Long;

    .line 848
    .line 849
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 850
    .line 851
    .line 852
    :goto_10
    move/from16 v3, v18

    .line 853
    .line 854
    goto/16 :goto_13

    .line 855
    .line 856
    :pswitch_28
    check-cast v14, Ljava/lang/Integer;

    .line 857
    .line 858
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 859
    .line 860
    .line 861
    :goto_11
    move/from16 v3, v17

    .line 862
    .line 863
    goto/16 :goto_13

    .line 864
    .line 865
    :pswitch_29
    check-cast v14, Ljava/lang/Integer;

    .line 866
    .line 867
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 868
    .line 869
    .line 870
    move-result v3

    .line 871
    int-to-long v3, v3

    .line 872
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 873
    .line 874
    .line 875
    move-result v3

    .line 876
    goto/16 :goto_13

    .line 877
    .line 878
    :pswitch_2a
    check-cast v14, Ljava/lang/Integer;

    .line 879
    .line 880
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 881
    .line 882
    .line 883
    move-result v3

    .line 884
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 885
    .line 886
    .line 887
    move-result v3

    .line 888
    goto/16 :goto_13

    .line 889
    .line 890
    :pswitch_2b
    instance-of v3, v14, Landroidx/datastore/preferences/protobuf/h;

    .line 891
    .line 892
    if-eqz v3, :cond_b

    .line 893
    .line 894
    check-cast v14, Landroidx/datastore/preferences/protobuf/h;

    .line 895
    .line 896
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 897
    .line 898
    .line 899
    move-result v3

    .line 900
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 901
    .line 902
    .line 903
    move-result v4

    .line 904
    :goto_12
    add-int/2addr v3, v4

    .line 905
    goto/16 :goto_13

    .line 906
    .line 907
    :cond_b
    check-cast v14, [B

    .line 908
    .line 909
    array-length v3, v14

    .line 910
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 911
    .line 912
    .line 913
    move-result v4

    .line 914
    goto :goto_12

    .line 915
    :pswitch_2c
    check-cast v14, Landroidx/datastore/preferences/protobuf/a;

    .line 916
    .line 917
    check-cast v14, Landroidx/datastore/preferences/protobuf/x;

    .line 918
    .line 919
    const/4 v4, 0x0

    .line 920
    invoke-virtual {v14, v4}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 921
    .line 922
    .line 923
    move-result v3

    .line 924
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 925
    .line 926
    .line 927
    move-result v4

    .line 928
    goto :goto_12

    .line 929
    :pswitch_2d
    const/4 v4, 0x0

    .line 930
    check-cast v14, Landroidx/datastore/preferences/protobuf/a;

    .line 931
    .line 932
    check-cast v14, Landroidx/datastore/preferences/protobuf/x;

    .line 933
    .line 934
    invoke-virtual {v14, v4}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 935
    .line 936
    .line 937
    move-result v3

    .line 938
    goto :goto_13

    .line 939
    :pswitch_2e
    instance-of v3, v14, Landroidx/datastore/preferences/protobuf/h;

    .line 940
    .line 941
    if-eqz v3, :cond_c

    .line 942
    .line 943
    check-cast v14, Landroidx/datastore/preferences/protobuf/h;

    .line 944
    .line 945
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 946
    .line 947
    .line 948
    move-result v3

    .line 949
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 950
    .line 951
    .line 952
    move-result v4

    .line 953
    goto :goto_12

    .line 954
    :cond_c
    check-cast v14, Ljava/lang/String;

    .line 955
    .line 956
    invoke-static {v14}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 957
    .line 958
    .line 959
    move-result v3

    .line 960
    goto :goto_13

    .line 961
    :pswitch_2f
    check-cast v14, Ljava/lang/Boolean;

    .line 962
    .line 963
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 964
    .line 965
    .line 966
    move/from16 v3, v22

    .line 967
    .line 968
    goto :goto_13

    .line 969
    :pswitch_30
    check-cast v14, Ljava/lang/Integer;

    .line 970
    .line 971
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 972
    .line 973
    .line 974
    goto :goto_11

    .line 975
    :pswitch_31
    check-cast v14, Ljava/lang/Long;

    .line 976
    .line 977
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 978
    .line 979
    .line 980
    goto/16 :goto_10

    .line 981
    .line 982
    :pswitch_32
    check-cast v14, Ljava/lang/Integer;

    .line 983
    .line 984
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 985
    .line 986
    .line 987
    move-result v3

    .line 988
    int-to-long v3, v3

    .line 989
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 990
    .line 991
    .line 992
    move-result v3

    .line 993
    goto :goto_13

    .line 994
    :pswitch_33
    check-cast v14, Ljava/lang/Long;

    .line 995
    .line 996
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 997
    .line 998
    .line 999
    move-result-wide v3

    .line 1000
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 1001
    .line 1002
    .line 1003
    move-result v3

    .line 1004
    goto :goto_13

    .line 1005
    :pswitch_34
    check-cast v14, Ljava/lang/Long;

    .line 1006
    .line 1007
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 1008
    .line 1009
    .line 1010
    move-result-wide v3

    .line 1011
    invoke-static {v3, v4}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 1012
    .line 1013
    .line 1014
    move-result v3

    .line 1015
    goto :goto_13

    .line 1016
    :pswitch_35
    check-cast v14, Ljava/lang/Float;

    .line 1017
    .line 1018
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1019
    .line 1020
    .line 1021
    goto/16 :goto_11

    .line 1022
    .line 1023
    :pswitch_36
    check-cast v14, Ljava/lang/Double;

    .line 1024
    .line 1025
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1026
    .line 1027
    .line 1028
    goto/16 :goto_10

    .line 1029
    .line 1030
    :goto_13
    add-int/2addr v3, v5

    .line 1031
    add-int/2addr v3, v7

    .line 1032
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1033
    .line 1034
    .line 1035
    move-result v4

    .line 1036
    add-int/2addr v4, v3

    .line 1037
    add-int v4, v4, v19

    .line 1038
    .line 1039
    add-int/2addr v13, v4

    .line 1040
    move-object v5, v10

    .line 1041
    move/from16 v10, v20

    .line 1042
    .line 1043
    move/from16 v15, v22

    .line 1044
    .line 1045
    move/from16 v3, v23

    .line 1046
    .line 1047
    move/from16 v4, v24

    .line 1048
    .line 1049
    const v8, 0xfffff

    .line 1050
    .line 1051
    .line 1052
    goto/16 :goto_a

    .line 1053
    .line 1054
    :goto_14
    add-int/2addr v9, v13

    .line 1055
    :cond_d
    :goto_15
    move/from16 v3, v23

    .line 1056
    .line 1057
    move/from16 v4, v24

    .line 1058
    .line 1059
    goto/16 :goto_2d

    .line 1060
    .line 1061
    :pswitch_37
    move/from16 v23, v3

    .line 1062
    .line 1063
    move/from16 v24, v4

    .line 1064
    .line 1065
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1066
    .line 1067
    .line 1068
    move-result-object v3

    .line 1069
    check-cast v3, Ljava/util/List;

    .line 1070
    .line 1071
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v4

    .line 1075
    sget-object v5, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1076
    .line 1077
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1078
    .line 1079
    .line 1080
    move-result v5

    .line 1081
    if-nez v5, :cond_e

    .line 1082
    .line 1083
    const/4 v8, 0x0

    .line 1084
    goto :goto_17

    .line 1085
    :cond_e
    const/4 v7, 0x0

    .line 1086
    const/4 v8, 0x0

    .line 1087
    :goto_16
    if-ge v7, v5, :cond_f

    .line 1088
    .line 1089
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v10

    .line 1093
    check-cast v10, Landroidx/datastore/preferences/protobuf/a;

    .line 1094
    .line 1095
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1096
    .line 1097
    .line 1098
    move-result v11

    .line 1099
    mul-int/lit8 v11, v11, 0x2

    .line 1100
    .line 1101
    invoke-virtual {v10, v4}, Landroidx/datastore/preferences/protobuf/a;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 1102
    .line 1103
    .line 1104
    move-result v10

    .line 1105
    add-int/2addr v10, v11

    .line 1106
    add-int/2addr v8, v10

    .line 1107
    add-int/lit8 v7, v7, 0x1

    .line 1108
    .line 1109
    goto :goto_16

    .line 1110
    :cond_f
    :goto_17
    add-int/2addr v9, v8

    .line 1111
    goto :goto_15

    .line 1112
    :pswitch_38
    move/from16 v23, v3

    .line 1113
    .line 1114
    move/from16 v24, v4

    .line 1115
    .line 1116
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1117
    .line 1118
    .line 1119
    move-result-object v3

    .line 1120
    check-cast v3, Ljava/util/List;

    .line 1121
    .line 1122
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->g(Ljava/util/List;)I

    .line 1123
    .line 1124
    .line 1125
    move-result v3

    .line 1126
    if-lez v3, :cond_d

    .line 1127
    .line 1128
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1129
    .line 1130
    .line 1131
    move-result v4

    .line 1132
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1133
    .line 1134
    .line 1135
    move-result v5

    .line 1136
    :goto_18
    add-int/2addr v5, v4

    .line 1137
    add-int/2addr v5, v3

    .line 1138
    add-int/2addr v9, v5

    .line 1139
    goto :goto_15

    .line 1140
    :pswitch_39
    move/from16 v23, v3

    .line 1141
    .line 1142
    move/from16 v24, v4

    .line 1143
    .line 1144
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v3

    .line 1148
    check-cast v3, Ljava/util/List;

    .line 1149
    .line 1150
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->f(Ljava/util/List;)I

    .line 1151
    .line 1152
    .line 1153
    move-result v3

    .line 1154
    if-lez v3, :cond_d

    .line 1155
    .line 1156
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1157
    .line 1158
    .line 1159
    move-result v4

    .line 1160
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1161
    .line 1162
    .line 1163
    move-result v5

    .line 1164
    goto :goto_18

    .line 1165
    :pswitch_3a
    move/from16 v23, v3

    .line 1166
    .line 1167
    move/from16 v24, v4

    .line 1168
    .line 1169
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1170
    .line 1171
    .line 1172
    move-result-object v3

    .line 1173
    check-cast v3, Ljava/util/List;

    .line 1174
    .line 1175
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1176
    .line 1177
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1178
    .line 1179
    .line 1180
    move-result v3

    .line 1181
    mul-int/lit8 v3, v3, 0x8

    .line 1182
    .line 1183
    if-lez v3, :cond_d

    .line 1184
    .line 1185
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1186
    .line 1187
    .line 1188
    move-result v4

    .line 1189
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1190
    .line 1191
    .line 1192
    move-result v5

    .line 1193
    goto :goto_18

    .line 1194
    :pswitch_3b
    move/from16 v23, v3

    .line 1195
    .line 1196
    move/from16 v24, v4

    .line 1197
    .line 1198
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1199
    .line 1200
    .line 1201
    move-result-object v3

    .line 1202
    check-cast v3, Ljava/util/List;

    .line 1203
    .line 1204
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1205
    .line 1206
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1207
    .line 1208
    .line 1209
    move-result v3

    .line 1210
    mul-int/lit8 v3, v3, 0x4

    .line 1211
    .line 1212
    if-lez v3, :cond_d

    .line 1213
    .line 1214
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1215
    .line 1216
    .line 1217
    move-result v4

    .line 1218
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1219
    .line 1220
    .line 1221
    move-result v5

    .line 1222
    goto :goto_18

    .line 1223
    :pswitch_3c
    move/from16 v23, v3

    .line 1224
    .line 1225
    move/from16 v24, v4

    .line 1226
    .line 1227
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1228
    .line 1229
    .line 1230
    move-result-object v3

    .line 1231
    check-cast v3, Ljava/util/List;

    .line 1232
    .line 1233
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->a(Ljava/util/List;)I

    .line 1234
    .line 1235
    .line 1236
    move-result v3

    .line 1237
    if-lez v3, :cond_d

    .line 1238
    .line 1239
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1240
    .line 1241
    .line 1242
    move-result v4

    .line 1243
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1244
    .line 1245
    .line 1246
    move-result v5

    .line 1247
    goto :goto_18

    .line 1248
    :pswitch_3d
    move/from16 v23, v3

    .line 1249
    .line 1250
    move/from16 v24, v4

    .line 1251
    .line 1252
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1253
    .line 1254
    .line 1255
    move-result-object v3

    .line 1256
    check-cast v3, Ljava/util/List;

    .line 1257
    .line 1258
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->h(Ljava/util/List;)I

    .line 1259
    .line 1260
    .line 1261
    move-result v3

    .line 1262
    if-lez v3, :cond_d

    .line 1263
    .line 1264
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1265
    .line 1266
    .line 1267
    move-result v4

    .line 1268
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1269
    .line 1270
    .line 1271
    move-result v5

    .line 1272
    goto/16 :goto_18

    .line 1273
    .line 1274
    :pswitch_3e
    move/from16 v23, v3

    .line 1275
    .line 1276
    move/from16 v24, v4

    .line 1277
    .line 1278
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1279
    .line 1280
    .line 1281
    move-result-object v3

    .line 1282
    check-cast v3, Ljava/util/List;

    .line 1283
    .line 1284
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1285
    .line 1286
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1287
    .line 1288
    .line 1289
    move-result v3

    .line 1290
    if-lez v3, :cond_d

    .line 1291
    .line 1292
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1293
    .line 1294
    .line 1295
    move-result v4

    .line 1296
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1297
    .line 1298
    .line 1299
    move-result v5

    .line 1300
    goto/16 :goto_18

    .line 1301
    .line 1302
    :pswitch_3f
    move/from16 v23, v3

    .line 1303
    .line 1304
    move/from16 v24, v4

    .line 1305
    .line 1306
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1307
    .line 1308
    .line 1309
    move-result-object v3

    .line 1310
    check-cast v3, Ljava/util/List;

    .line 1311
    .line 1312
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1313
    .line 1314
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1315
    .line 1316
    .line 1317
    move-result v3

    .line 1318
    mul-int/lit8 v3, v3, 0x4

    .line 1319
    .line 1320
    if-lez v3, :cond_d

    .line 1321
    .line 1322
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1323
    .line 1324
    .line 1325
    move-result v4

    .line 1326
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1327
    .line 1328
    .line 1329
    move-result v5

    .line 1330
    goto/16 :goto_18

    .line 1331
    .line 1332
    :pswitch_40
    move/from16 v23, v3

    .line 1333
    .line 1334
    move/from16 v24, v4

    .line 1335
    .line 1336
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1337
    .line 1338
    .line 1339
    move-result-object v3

    .line 1340
    check-cast v3, Ljava/util/List;

    .line 1341
    .line 1342
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1343
    .line 1344
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1345
    .line 1346
    .line 1347
    move-result v3

    .line 1348
    mul-int/lit8 v3, v3, 0x8

    .line 1349
    .line 1350
    if-lez v3, :cond_d

    .line 1351
    .line 1352
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1353
    .line 1354
    .line 1355
    move-result v4

    .line 1356
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1357
    .line 1358
    .line 1359
    move-result v5

    .line 1360
    goto/16 :goto_18

    .line 1361
    .line 1362
    :pswitch_41
    move/from16 v23, v3

    .line 1363
    .line 1364
    move/from16 v24, v4

    .line 1365
    .line 1366
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1367
    .line 1368
    .line 1369
    move-result-object v3

    .line 1370
    check-cast v3, Ljava/util/List;

    .line 1371
    .line 1372
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->d(Ljava/util/List;)I

    .line 1373
    .line 1374
    .line 1375
    move-result v3

    .line 1376
    if-lez v3, :cond_d

    .line 1377
    .line 1378
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1379
    .line 1380
    .line 1381
    move-result v4

    .line 1382
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1383
    .line 1384
    .line 1385
    move-result v5

    .line 1386
    goto/16 :goto_18

    .line 1387
    .line 1388
    :pswitch_42
    move/from16 v23, v3

    .line 1389
    .line 1390
    move/from16 v24, v4

    .line 1391
    .line 1392
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1393
    .line 1394
    .line 1395
    move-result-object v3

    .line 1396
    check-cast v3, Ljava/util/List;

    .line 1397
    .line 1398
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->i(Ljava/util/List;)I

    .line 1399
    .line 1400
    .line 1401
    move-result v3

    .line 1402
    if-lez v3, :cond_d

    .line 1403
    .line 1404
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1405
    .line 1406
    .line 1407
    move-result v4

    .line 1408
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1409
    .line 1410
    .line 1411
    move-result v5

    .line 1412
    goto/16 :goto_18

    .line 1413
    .line 1414
    :pswitch_43
    move/from16 v23, v3

    .line 1415
    .line 1416
    move/from16 v24, v4

    .line 1417
    .line 1418
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1419
    .line 1420
    .line 1421
    move-result-object v3

    .line 1422
    check-cast v3, Ljava/util/List;

    .line 1423
    .line 1424
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->e(Ljava/util/List;)I

    .line 1425
    .line 1426
    .line 1427
    move-result v3

    .line 1428
    if-lez v3, :cond_d

    .line 1429
    .line 1430
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1431
    .line 1432
    .line 1433
    move-result v4

    .line 1434
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1435
    .line 1436
    .line 1437
    move-result v5

    .line 1438
    goto/16 :goto_18

    .line 1439
    .line 1440
    :pswitch_44
    move/from16 v23, v3

    .line 1441
    .line 1442
    move/from16 v24, v4

    .line 1443
    .line 1444
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1445
    .line 1446
    .line 1447
    move-result-object v3

    .line 1448
    check-cast v3, Ljava/util/List;

    .line 1449
    .line 1450
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1451
    .line 1452
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1453
    .line 1454
    .line 1455
    move-result v3

    .line 1456
    mul-int/lit8 v3, v3, 0x4

    .line 1457
    .line 1458
    if-lez v3, :cond_d

    .line 1459
    .line 1460
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1461
    .line 1462
    .line 1463
    move-result v4

    .line 1464
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1465
    .line 1466
    .line 1467
    move-result v5

    .line 1468
    goto/16 :goto_18

    .line 1469
    .line 1470
    :pswitch_45
    move/from16 v23, v3

    .line 1471
    .line 1472
    move/from16 v24, v4

    .line 1473
    .line 1474
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1475
    .line 1476
    .line 1477
    move-result-object v3

    .line 1478
    check-cast v3, Ljava/util/List;

    .line 1479
    .line 1480
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1481
    .line 1482
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1483
    .line 1484
    .line 1485
    move-result v3

    .line 1486
    mul-int/lit8 v3, v3, 0x8

    .line 1487
    .line 1488
    if-lez v3, :cond_d

    .line 1489
    .line 1490
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1491
    .line 1492
    .line 1493
    move-result v4

    .line 1494
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1495
    .line 1496
    .line 1497
    move-result v5

    .line 1498
    goto/16 :goto_18

    .line 1499
    .line 1500
    :pswitch_46
    move/from16 v23, v3

    .line 1501
    .line 1502
    move/from16 v24, v4

    .line 1503
    .line 1504
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1505
    .line 1506
    .line 1507
    move-result-object v3

    .line 1508
    check-cast v3, Ljava/util/List;

    .line 1509
    .line 1510
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1511
    .line 1512
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1513
    .line 1514
    .line 1515
    move-result v4

    .line 1516
    if-nez v4, :cond_10

    .line 1517
    .line 1518
    :goto_19
    const/4 v5, 0x0

    .line 1519
    goto :goto_1b

    .line 1520
    :cond_10
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->g(Ljava/util/List;)I

    .line 1521
    .line 1522
    .line 1523
    move-result v3

    .line 1524
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1525
    .line 1526
    .line 1527
    move-result v5

    .line 1528
    :goto_1a
    mul-int/2addr v5, v4

    .line 1529
    add-int/2addr v5, v3

    .line 1530
    :cond_11
    :goto_1b
    add-int/2addr v9, v5

    .line 1531
    goto/16 :goto_15

    .line 1532
    .line 1533
    :pswitch_47
    move/from16 v23, v3

    .line 1534
    .line 1535
    move/from16 v24, v4

    .line 1536
    .line 1537
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1538
    .line 1539
    .line 1540
    move-result-object v3

    .line 1541
    check-cast v3, Ljava/util/List;

    .line 1542
    .line 1543
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1544
    .line 1545
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1546
    .line 1547
    .line 1548
    move-result v4

    .line 1549
    if-nez v4, :cond_12

    .line 1550
    .line 1551
    goto :goto_19

    .line 1552
    :cond_12
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->f(Ljava/util/List;)I

    .line 1553
    .line 1554
    .line 1555
    move-result v3

    .line 1556
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1557
    .line 1558
    .line 1559
    move-result v5

    .line 1560
    goto :goto_1a

    .line 1561
    :pswitch_48
    move/from16 v23, v3

    .line 1562
    .line 1563
    move/from16 v24, v4

    .line 1564
    .line 1565
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1566
    .line 1567
    .line 1568
    move-result-object v3

    .line 1569
    check-cast v3, Ljava/util/List;

    .line 1570
    .line 1571
    invoke-static {v12, v3}, Landroidx/datastore/preferences/protobuf/b1;->c(ILjava/util/List;)I

    .line 1572
    .line 1573
    .line 1574
    move-result v3

    .line 1575
    :goto_1c
    add-int/2addr v9, v3

    .line 1576
    move/from16 v3, v23

    .line 1577
    .line 1578
    goto/16 :goto_2d

    .line 1579
    .line 1580
    :pswitch_49
    move/from16 v23, v3

    .line 1581
    .line 1582
    move/from16 v24, v4

    .line 1583
    .line 1584
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1585
    .line 1586
    .line 1587
    move-result-object v3

    .line 1588
    check-cast v3, Ljava/util/List;

    .line 1589
    .line 1590
    invoke-static {v12, v3}, Landroidx/datastore/preferences/protobuf/b1;->b(ILjava/util/List;)I

    .line 1591
    .line 1592
    .line 1593
    move-result v3

    .line 1594
    goto :goto_1c

    .line 1595
    :pswitch_4a
    move/from16 v23, v3

    .line 1596
    .line 1597
    move/from16 v24, v4

    .line 1598
    .line 1599
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1600
    .line 1601
    .line 1602
    move-result-object v3

    .line 1603
    check-cast v3, Ljava/util/List;

    .line 1604
    .line 1605
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1606
    .line 1607
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1608
    .line 1609
    .line 1610
    move-result v4

    .line 1611
    if-nez v4, :cond_13

    .line 1612
    .line 1613
    goto :goto_19

    .line 1614
    :cond_13
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->a(Ljava/util/List;)I

    .line 1615
    .line 1616
    .line 1617
    move-result v3

    .line 1618
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1619
    .line 1620
    .line 1621
    move-result v5

    .line 1622
    goto :goto_1a

    .line 1623
    :pswitch_4b
    move/from16 v23, v3

    .line 1624
    .line 1625
    move/from16 v24, v4

    .line 1626
    .line 1627
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1628
    .line 1629
    .line 1630
    move-result-object v3

    .line 1631
    check-cast v3, Ljava/util/List;

    .line 1632
    .line 1633
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1634
    .line 1635
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1636
    .line 1637
    .line 1638
    move-result v4

    .line 1639
    if-nez v4, :cond_14

    .line 1640
    .line 1641
    goto :goto_19

    .line 1642
    :cond_14
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->h(Ljava/util/List;)I

    .line 1643
    .line 1644
    .line 1645
    move-result v3

    .line 1646
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1647
    .line 1648
    .line 1649
    move-result v5

    .line 1650
    goto :goto_1a

    .line 1651
    :pswitch_4c
    move/from16 v23, v3

    .line 1652
    .line 1653
    move/from16 v24, v4

    .line 1654
    .line 1655
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1656
    .line 1657
    .line 1658
    move-result-object v3

    .line 1659
    check-cast v3, Ljava/util/List;

    .line 1660
    .line 1661
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1662
    .line 1663
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1664
    .line 1665
    .line 1666
    move-result v4

    .line 1667
    if-nez v4, :cond_15

    .line 1668
    .line 1669
    goto/16 :goto_19

    .line 1670
    .line 1671
    :cond_15
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1672
    .line 1673
    .line 1674
    move-result v5

    .line 1675
    mul-int/2addr v5, v4

    .line 1676
    const/4 v4, 0x0

    .line 1677
    :goto_1d
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1678
    .line 1679
    .line 1680
    move-result v7

    .line 1681
    if-ge v4, v7, :cond_11

    .line 1682
    .line 1683
    invoke-interface {v3, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1684
    .line 1685
    .line 1686
    move-result-object v7

    .line 1687
    check-cast v7, Landroidx/datastore/preferences/protobuf/h;

    .line 1688
    .line 1689
    invoke-virtual {v7}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 1690
    .line 1691
    .line 1692
    move-result v7

    .line 1693
    invoke-static {v7}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1694
    .line 1695
    .line 1696
    move-result v8

    .line 1697
    add-int/2addr v8, v7

    .line 1698
    add-int/2addr v5, v8

    .line 1699
    add-int/lit8 v4, v4, 0x1

    .line 1700
    .line 1701
    goto :goto_1d

    .line 1702
    :pswitch_4d
    move/from16 v23, v3

    .line 1703
    .line 1704
    move/from16 v24, v4

    .line 1705
    .line 1706
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1707
    .line 1708
    .line 1709
    move-result-object v3

    .line 1710
    check-cast v3, Ljava/util/List;

    .line 1711
    .line 1712
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1713
    .line 1714
    .line 1715
    move-result-object v4

    .line 1716
    sget-object v5, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1717
    .line 1718
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1719
    .line 1720
    .line 1721
    move-result v5

    .line 1722
    if-nez v5, :cond_16

    .line 1723
    .line 1724
    const/4 v7, 0x0

    .line 1725
    goto :goto_1f

    .line 1726
    :cond_16
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1727
    .line 1728
    .line 1729
    move-result v7

    .line 1730
    mul-int/2addr v7, v5

    .line 1731
    const/4 v8, 0x0

    .line 1732
    :goto_1e
    if-ge v8, v5, :cond_17

    .line 1733
    .line 1734
    invoke-interface {v3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1735
    .line 1736
    .line 1737
    move-result-object v10

    .line 1738
    check-cast v10, Landroidx/datastore/preferences/protobuf/a;

    .line 1739
    .line 1740
    invoke-virtual {v10, v4}, Landroidx/datastore/preferences/protobuf/a;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 1741
    .line 1742
    .line 1743
    move-result v10

    .line 1744
    invoke-static {v10}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1745
    .line 1746
    .line 1747
    move-result v11

    .line 1748
    add-int/2addr v11, v10

    .line 1749
    add-int/2addr v7, v11

    .line 1750
    add-int/lit8 v8, v8, 0x1

    .line 1751
    .line 1752
    goto :goto_1e

    .line 1753
    :cond_17
    :goto_1f
    add-int/2addr v9, v7

    .line 1754
    goto/16 :goto_15

    .line 1755
    .line 1756
    :pswitch_4e
    move/from16 v23, v3

    .line 1757
    .line 1758
    move/from16 v24, v4

    .line 1759
    .line 1760
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1761
    .line 1762
    .line 1763
    move-result-object v3

    .line 1764
    check-cast v3, Ljava/util/List;

    .line 1765
    .line 1766
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1767
    .line 1768
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1769
    .line 1770
    .line 1771
    move-result v4

    .line 1772
    if-nez v4, :cond_18

    .line 1773
    .line 1774
    goto/16 :goto_19

    .line 1775
    .line 1776
    :cond_18
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1777
    .line 1778
    .line 1779
    move-result v5

    .line 1780
    mul-int/2addr v5, v4

    .line 1781
    instance-of v7, v3, Landroidx/datastore/preferences/protobuf/e0;

    .line 1782
    .line 1783
    if-eqz v7, :cond_1a

    .line 1784
    .line 1785
    check-cast v3, Landroidx/datastore/preferences/protobuf/e0;

    .line 1786
    .line 1787
    const/4 v7, 0x0

    .line 1788
    :goto_20
    if-ge v7, v4, :cond_11

    .line 1789
    .line 1790
    invoke-interface {v3}, Landroidx/datastore/preferences/protobuf/e0;->q()Ljava/lang/Object;

    .line 1791
    .line 1792
    .line 1793
    move-result-object v8

    .line 1794
    instance-of v10, v8, Landroidx/datastore/preferences/protobuf/h;

    .line 1795
    .line 1796
    if-eqz v10, :cond_19

    .line 1797
    .line 1798
    check-cast v8, Landroidx/datastore/preferences/protobuf/h;

    .line 1799
    .line 1800
    invoke-virtual {v8}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 1801
    .line 1802
    .line 1803
    move-result v8

    .line 1804
    invoke-static {v8}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1805
    .line 1806
    .line 1807
    move-result v10

    .line 1808
    add-int/2addr v10, v8

    .line 1809
    add-int/2addr v10, v5

    .line 1810
    move v5, v10

    .line 1811
    goto :goto_21

    .line 1812
    :cond_19
    check-cast v8, Ljava/lang/String;

    .line 1813
    .line 1814
    invoke-static {v8}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 1815
    .line 1816
    .line 1817
    move-result v8

    .line 1818
    add-int/2addr v8, v5

    .line 1819
    move v5, v8

    .line 1820
    :goto_21
    add-int/lit8 v7, v7, 0x1

    .line 1821
    .line 1822
    goto :goto_20

    .line 1823
    :cond_1a
    const/4 v7, 0x0

    .line 1824
    :goto_22
    if-ge v7, v4, :cond_11

    .line 1825
    .line 1826
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1827
    .line 1828
    .line 1829
    move-result-object v8

    .line 1830
    instance-of v10, v8, Landroidx/datastore/preferences/protobuf/h;

    .line 1831
    .line 1832
    if-eqz v10, :cond_1b

    .line 1833
    .line 1834
    check-cast v8, Landroidx/datastore/preferences/protobuf/h;

    .line 1835
    .line 1836
    invoke-virtual {v8}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 1837
    .line 1838
    .line 1839
    move-result v8

    .line 1840
    invoke-static {v8}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 1841
    .line 1842
    .line 1843
    move-result v10

    .line 1844
    add-int/2addr v10, v8

    .line 1845
    add-int/2addr v10, v5

    .line 1846
    move v5, v10

    .line 1847
    goto :goto_23

    .line 1848
    :cond_1b
    check-cast v8, Ljava/lang/String;

    .line 1849
    .line 1850
    invoke-static {v8}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 1851
    .line 1852
    .line 1853
    move-result v8

    .line 1854
    add-int/2addr v8, v5

    .line 1855
    move v5, v8

    .line 1856
    :goto_23
    add-int/lit8 v7, v7, 0x1

    .line 1857
    .line 1858
    goto :goto_22

    .line 1859
    :pswitch_4f
    move/from16 v23, v3

    .line 1860
    .line 1861
    move/from16 v24, v4

    .line 1862
    .line 1863
    move/from16 v22, v15

    .line 1864
    .line 1865
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1866
    .line 1867
    .line 1868
    move-result-object v3

    .line 1869
    check-cast v3, Ljava/util/List;

    .line 1870
    .line 1871
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1872
    .line 1873
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1874
    .line 1875
    .line 1876
    move-result v3

    .line 1877
    if-nez v3, :cond_1c

    .line 1878
    .line 1879
    const/4 v4, 0x0

    .line 1880
    goto :goto_24

    .line 1881
    :cond_1c
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1882
    .line 1883
    .line 1884
    move-result v4

    .line 1885
    add-int/lit8 v4, v4, 0x1

    .line 1886
    .line 1887
    mul-int/2addr v4, v3

    .line 1888
    :goto_24
    add-int/2addr v9, v4

    .line 1889
    goto/16 :goto_15

    .line 1890
    .line 1891
    :pswitch_50
    move/from16 v23, v3

    .line 1892
    .line 1893
    move/from16 v24, v4

    .line 1894
    .line 1895
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1896
    .line 1897
    .line 1898
    move-result-object v3

    .line 1899
    check-cast v3, Ljava/util/List;

    .line 1900
    .line 1901
    invoke-static {v12, v3}, Landroidx/datastore/preferences/protobuf/b1;->b(ILjava/util/List;)I

    .line 1902
    .line 1903
    .line 1904
    move-result v3

    .line 1905
    goto/16 :goto_1c

    .line 1906
    .line 1907
    :pswitch_51
    move/from16 v23, v3

    .line 1908
    .line 1909
    move/from16 v24, v4

    .line 1910
    .line 1911
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1912
    .line 1913
    .line 1914
    move-result-object v3

    .line 1915
    check-cast v3, Ljava/util/List;

    .line 1916
    .line 1917
    invoke-static {v12, v3}, Landroidx/datastore/preferences/protobuf/b1;->c(ILjava/util/List;)I

    .line 1918
    .line 1919
    .line 1920
    move-result v3

    .line 1921
    goto/16 :goto_1c

    .line 1922
    .line 1923
    :pswitch_52
    move/from16 v23, v3

    .line 1924
    .line 1925
    move/from16 v24, v4

    .line 1926
    .line 1927
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1928
    .line 1929
    .line 1930
    move-result-object v3

    .line 1931
    check-cast v3, Ljava/util/List;

    .line 1932
    .line 1933
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1934
    .line 1935
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1936
    .line 1937
    .line 1938
    move-result v4

    .line 1939
    if-nez v4, :cond_1d

    .line 1940
    .line 1941
    goto/16 :goto_19

    .line 1942
    .line 1943
    :cond_1d
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->d(Ljava/util/List;)I

    .line 1944
    .line 1945
    .line 1946
    move-result v3

    .line 1947
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1948
    .line 1949
    .line 1950
    move-result v5

    .line 1951
    goto/16 :goto_1a

    .line 1952
    .line 1953
    :pswitch_53
    move/from16 v23, v3

    .line 1954
    .line 1955
    move/from16 v24, v4

    .line 1956
    .line 1957
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1958
    .line 1959
    .line 1960
    move-result-object v3

    .line 1961
    check-cast v3, Ljava/util/List;

    .line 1962
    .line 1963
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1964
    .line 1965
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1966
    .line 1967
    .line 1968
    move-result v4

    .line 1969
    if-nez v4, :cond_1e

    .line 1970
    .line 1971
    goto/16 :goto_19

    .line 1972
    .line 1973
    :cond_1e
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->i(Ljava/util/List;)I

    .line 1974
    .line 1975
    .line 1976
    move-result v3

    .line 1977
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 1978
    .line 1979
    .line 1980
    move-result v5

    .line 1981
    goto/16 :goto_1a

    .line 1982
    .line 1983
    :pswitch_54
    move/from16 v23, v3

    .line 1984
    .line 1985
    move/from16 v24, v4

    .line 1986
    .line 1987
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1988
    .line 1989
    .line 1990
    move-result-object v3

    .line 1991
    check-cast v3, Ljava/util/List;

    .line 1992
    .line 1993
    sget-object v4, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 1994
    .line 1995
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1996
    .line 1997
    .line 1998
    move-result v4

    .line 1999
    if-nez v4, :cond_1f

    .line 2000
    .line 2001
    goto/16 :goto_19

    .line 2002
    .line 2003
    :cond_1f
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/b1;->e(Ljava/util/List;)I

    .line 2004
    .line 2005
    .line 2006
    move-result v4

    .line 2007
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 2008
    .line 2009
    .line 2010
    move-result v3

    .line 2011
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2012
    .line 2013
    .line 2014
    move-result v5

    .line 2015
    mul-int/2addr v5, v3

    .line 2016
    add-int/2addr v5, v4

    .line 2017
    goto/16 :goto_1b

    .line 2018
    .line 2019
    :pswitch_55
    move/from16 v23, v3

    .line 2020
    .line 2021
    move/from16 v24, v4

    .line 2022
    .line 2023
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2024
    .line 2025
    .line 2026
    move-result-object v3

    .line 2027
    check-cast v3, Ljava/util/List;

    .line 2028
    .line 2029
    invoke-static {v12, v3}, Landroidx/datastore/preferences/protobuf/b1;->b(ILjava/util/List;)I

    .line 2030
    .line 2031
    .line 2032
    move-result v3

    .line 2033
    goto/16 :goto_1c

    .line 2034
    .line 2035
    :pswitch_56
    move/from16 v23, v3

    .line 2036
    .line 2037
    move/from16 v24, v4

    .line 2038
    .line 2039
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2040
    .line 2041
    .line 2042
    move-result-object v3

    .line 2043
    check-cast v3, Ljava/util/List;

    .line 2044
    .line 2045
    invoke-static {v12, v3}, Landroidx/datastore/preferences/protobuf/b1;->c(ILjava/util/List;)I

    .line 2046
    .line 2047
    .line 2048
    move-result v3

    .line 2049
    goto/16 :goto_1c

    .line 2050
    .line 2051
    :pswitch_57
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2052
    .line 2053
    .line 2054
    move-result v5

    .line 2055
    if-eqz v5, :cond_23

    .line 2056
    .line 2057
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2058
    .line 2059
    .line 2060
    move-result-object v5

    .line 2061
    check-cast v5, Landroidx/datastore/preferences/protobuf/a;

    .line 2062
    .line 2063
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 2064
    .line 2065
    .line 2066
    move-result-object v7

    .line 2067
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2068
    .line 2069
    .line 2070
    move-result v8

    .line 2071
    mul-int/lit8 v8, v8, 0x2

    .line 2072
    .line 2073
    invoke-virtual {v5, v7}, Landroidx/datastore/preferences/protobuf/a;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 2074
    .line 2075
    .line 2076
    move-result v5

    .line 2077
    add-int/2addr v5, v8

    .line 2078
    goto/16 :goto_3

    .line 2079
    .line 2080
    :pswitch_58
    move/from16 v20, v10

    .line 2081
    .line 2082
    move/from16 v22, v15

    .line 2083
    .line 2084
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2085
    .line 2086
    .line 2087
    move-result v5

    .line 2088
    if-eqz v5, :cond_20

    .line 2089
    .line 2090
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2091
    .line 2092
    .line 2093
    move-result-wide v7

    .line 2094
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2095
    .line 2096
    .line 2097
    move-result v0

    .line 2098
    shl-long v10, v7, v22

    .line 2099
    .line 2100
    shr-long v7, v7, v20

    .line 2101
    .line 2102
    xor-long/2addr v7, v10

    .line 2103
    invoke-static {v7, v8}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 2104
    .line 2105
    .line 2106
    move-result v5

    .line 2107
    :goto_25
    add-int/2addr v5, v0

    .line 2108
    add-int/2addr v9, v5

    .line 2109
    :cond_20
    :goto_26
    move-object/from16 v0, p0

    .line 2110
    .line 2111
    goto/16 :goto_2d

    .line 2112
    .line 2113
    :pswitch_59
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2114
    .line 2115
    .line 2116
    move-result v5

    .line 2117
    if-eqz v5, :cond_20

    .line 2118
    .line 2119
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2120
    .line 2121
    .line 2122
    move-result v0

    .line 2123
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2124
    .line 2125
    .line 2126
    move-result v5

    .line 2127
    shl-int/lit8 v7, v0, 0x1

    .line 2128
    .line 2129
    shr-int/lit8 v0, v0, 0x1f

    .line 2130
    .line 2131
    xor-int/2addr v0, v7

    .line 2132
    invoke-static {v0}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 2133
    .line 2134
    .line 2135
    move-result v0

    .line 2136
    :goto_27
    add-int/2addr v0, v5

    .line 2137
    :goto_28
    add-int/2addr v9, v0

    .line 2138
    goto :goto_26

    .line 2139
    :pswitch_5a
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2140
    .line 2141
    .line 2142
    move-result v5

    .line 2143
    if-eqz v5, :cond_21

    .line 2144
    .line 2145
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2146
    .line 2147
    .line 2148
    move-result v0

    .line 2149
    :goto_29
    add-int/lit8 v0, v0, 0x8

    .line 2150
    .line 2151
    :goto_2a
    add-int/2addr v9, v0

    .line 2152
    :cond_21
    move-object/from16 v0, p0

    .line 2153
    .line 2154
    move-object/from16 v1, p1

    .line 2155
    .line 2156
    goto/16 :goto_2d

    .line 2157
    .line 2158
    :pswitch_5b
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2159
    .line 2160
    .line 2161
    move-result v5

    .line 2162
    if-eqz v5, :cond_21

    .line 2163
    .line 2164
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2165
    .line 2166
    .line 2167
    move-result v0

    .line 2168
    :goto_2b
    add-int/lit8 v0, v0, 0x4

    .line 2169
    .line 2170
    goto :goto_2a

    .line 2171
    :pswitch_5c
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2172
    .line 2173
    .line 2174
    move-result v5

    .line 2175
    if-eqz v5, :cond_20

    .line 2176
    .line 2177
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2178
    .line 2179
    .line 2180
    move-result v0

    .line 2181
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2182
    .line 2183
    .line 2184
    move-result v5

    .line 2185
    int-to-long v7, v0

    .line 2186
    invoke-static {v7, v8}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 2187
    .line 2188
    .line 2189
    move-result v0

    .line 2190
    goto :goto_27

    .line 2191
    :pswitch_5d
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2192
    .line 2193
    .line 2194
    move-result v5

    .line 2195
    if-eqz v5, :cond_20

    .line 2196
    .line 2197
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2198
    .line 2199
    .line 2200
    move-result v0

    .line 2201
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2202
    .line 2203
    .line 2204
    move-result v5

    .line 2205
    invoke-static {v0}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 2206
    .line 2207
    .line 2208
    move-result v0

    .line 2209
    goto :goto_27

    .line 2210
    :pswitch_5e
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2211
    .line 2212
    .line 2213
    move-result v5

    .line 2214
    if-eqz v5, :cond_20

    .line 2215
    .line 2216
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2217
    .line 2218
    .line 2219
    move-result-object v0

    .line 2220
    check-cast v0, Landroidx/datastore/preferences/protobuf/h;

    .line 2221
    .line 2222
    invoke-static {v12, v0}, Landroidx/datastore/preferences/protobuf/l;->n(ILandroidx/datastore/preferences/protobuf/h;)I

    .line 2223
    .line 2224
    .line 2225
    move-result v0

    .line 2226
    goto :goto_28

    .line 2227
    :pswitch_5f
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2228
    .line 2229
    .line 2230
    move-result v5

    .line 2231
    if-eqz v5, :cond_23

    .line 2232
    .line 2233
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2234
    .line 2235
    .line 2236
    move-result-object v5

    .line 2237
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 2238
    .line 2239
    .line 2240
    move-result-object v7

    .line 2241
    sget-object v8, Landroidx/datastore/preferences/protobuf/b1;->a:Ljava/lang/Class;

    .line 2242
    .line 2243
    check-cast v5, Landroidx/datastore/preferences/protobuf/a;

    .line 2244
    .line 2245
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2246
    .line 2247
    .line 2248
    move-result v8

    .line 2249
    invoke-virtual {v5, v7}, Landroidx/datastore/preferences/protobuf/a;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 2250
    .line 2251
    .line 2252
    move-result v5

    .line 2253
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/l;->q(I)I

    .line 2254
    .line 2255
    .line 2256
    move-result v7

    .line 2257
    add-int/2addr v7, v5

    .line 2258
    add-int/2addr v7, v8

    .line 2259
    add-int/2addr v9, v7

    .line 2260
    goto/16 :goto_2d

    .line 2261
    .line 2262
    :pswitch_60
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2263
    .line 2264
    .line 2265
    move-result v5

    .line 2266
    if-eqz v5, :cond_20

    .line 2267
    .line 2268
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2269
    .line 2270
    .line 2271
    move-result-object v0

    .line 2272
    instance-of v5, v0, Landroidx/datastore/preferences/protobuf/h;

    .line 2273
    .line 2274
    if-eqz v5, :cond_22

    .line 2275
    .line 2276
    check-cast v0, Landroidx/datastore/preferences/protobuf/h;

    .line 2277
    .line 2278
    invoke-static {v12, v0}, Landroidx/datastore/preferences/protobuf/l;->n(ILandroidx/datastore/preferences/protobuf/h;)I

    .line 2279
    .line 2280
    .line 2281
    move-result v0

    .line 2282
    :goto_2c
    add-int/2addr v0, v9

    .line 2283
    move v9, v0

    .line 2284
    goto/16 :goto_26

    .line 2285
    .line 2286
    :cond_22
    check-cast v0, Ljava/lang/String;

    .line 2287
    .line 2288
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2289
    .line 2290
    .line 2291
    move-result v5

    .line 2292
    invoke-static {v0}, Landroidx/datastore/preferences/protobuf/l;->o(Ljava/lang/String;)I

    .line 2293
    .line 2294
    .line 2295
    move-result v0

    .line 2296
    add-int/2addr v0, v5

    .line 2297
    goto :goto_2c

    .line 2298
    :pswitch_61
    move/from16 v22, v15

    .line 2299
    .line 2300
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2301
    .line 2302
    .line 2303
    move-result v5

    .line 2304
    if-eqz v5, :cond_21

    .line 2305
    .line 2306
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2307
    .line 2308
    .line 2309
    move-result v0

    .line 2310
    add-int/lit8 v0, v0, 0x1

    .line 2311
    .line 2312
    goto/16 :goto_2a

    .line 2313
    .line 2314
    :pswitch_62
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2315
    .line 2316
    .line 2317
    move-result v5

    .line 2318
    if-eqz v5, :cond_21

    .line 2319
    .line 2320
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2321
    .line 2322
    .line 2323
    move-result v0

    .line 2324
    goto/16 :goto_2b

    .line 2325
    .line 2326
    :pswitch_63
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2327
    .line 2328
    .line 2329
    move-result v5

    .line 2330
    if-eqz v5, :cond_21

    .line 2331
    .line 2332
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2333
    .line 2334
    .line 2335
    move-result v0

    .line 2336
    goto/16 :goto_29

    .line 2337
    .line 2338
    :pswitch_64
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2339
    .line 2340
    .line 2341
    move-result v5

    .line 2342
    if-eqz v5, :cond_20

    .line 2343
    .line 2344
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2345
    .line 2346
    .line 2347
    move-result v0

    .line 2348
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2349
    .line 2350
    .line 2351
    move-result v5

    .line 2352
    int-to-long v7, v0

    .line 2353
    invoke-static {v7, v8}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 2354
    .line 2355
    .line 2356
    move-result v0

    .line 2357
    goto/16 :goto_27

    .line 2358
    .line 2359
    :pswitch_65
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2360
    .line 2361
    .line 2362
    move-result v5

    .line 2363
    if-eqz v5, :cond_20

    .line 2364
    .line 2365
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2366
    .line 2367
    .line 2368
    move-result-wide v7

    .line 2369
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2370
    .line 2371
    .line 2372
    move-result v0

    .line 2373
    invoke-static {v7, v8}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 2374
    .line 2375
    .line 2376
    move-result v5

    .line 2377
    goto/16 :goto_25

    .line 2378
    .line 2379
    :pswitch_66
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2380
    .line 2381
    .line 2382
    move-result v5

    .line 2383
    if-eqz v5, :cond_20

    .line 2384
    .line 2385
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2386
    .line 2387
    .line 2388
    move-result-wide v7

    .line 2389
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2390
    .line 2391
    .line 2392
    move-result v0

    .line 2393
    invoke-static {v7, v8}, Landroidx/datastore/preferences/protobuf/l;->r(J)I

    .line 2394
    .line 2395
    .line 2396
    move-result v5

    .line 2397
    goto/16 :goto_25

    .line 2398
    .line 2399
    :pswitch_67
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2400
    .line 2401
    .line 2402
    move-result v5

    .line 2403
    if-eqz v5, :cond_21

    .line 2404
    .line 2405
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2406
    .line 2407
    .line 2408
    move-result v0

    .line 2409
    goto/16 :goto_2b

    .line 2410
    .line 2411
    :pswitch_68
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/r0;->o(Ljava/lang/Object;IIII)Z

    .line 2412
    .line 2413
    .line 2414
    move-result v5

    .line 2415
    if-eqz v5, :cond_23

    .line 2416
    .line 2417
    invoke-static {v12}, Landroidx/datastore/preferences/protobuf/l;->p(I)I

    .line 2418
    .line 2419
    .line 2420
    move-result v5

    .line 2421
    goto/16 :goto_7

    .line 2422
    .line 2423
    :cond_23
    :goto_2d
    add-int/lit8 v2, v2, 0x3

    .line 2424
    .line 2425
    const v8, 0xfffff

    .line 2426
    .line 2427
    .line 2428
    goto/16 :goto_0

    .line 2429
    .line 2430
    :cond_24
    iget-object v0, v0, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 2431
    .line 2432
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2433
    .line 2434
    .line 2435
    iget-object v0, v1, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 2436
    .line 2437
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/h1;->b()I

    .line 2438
    .line 2439
    .line 2440
    move-result v0

    .line 2441
    add-int/2addr v0, v9

    .line 2442
    return v0

    .line 2443
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_68
        :pswitch_67
        :pswitch_66
        :pswitch_65
        :pswitch_64
        :pswitch_63
        :pswitch_62
        :pswitch_61
        :pswitch_60
        :pswitch_5f
        :pswitch_5e
        :pswitch_5d
        :pswitch_5c
        :pswitch_5b
        :pswitch_5a
        :pswitch_59
        :pswitch_58
        :pswitch_57
        :pswitch_56
        :pswitch_55
        :pswitch_54
        :pswitch_53
        :pswitch_52
        :pswitch_51
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 2444
    .line 2445
    .line 2446
    .line 2447
    .line 2448
    .line 2449
    .line 2450
    .line 2451
    .line 2452
    .line 2453
    .line 2454
    .line 2455
    .line 2456
    .line 2457
    .line 2458
    .line 2459
    .line 2460
    .line 2461
    .line 2462
    .line 2463
    .line 2464
    .line 2465
    .line 2466
    .line 2467
    .line 2468
    .line 2469
    .line 2470
    .line 2471
    .line 2472
    .line 2473
    .line 2474
    .line 2475
    .line 2476
    .line 2477
    .line 2478
    .line 2479
    .line 2480
    .line 2481
    .line 2482
    .line 2483
    .line 2484
    .line 2485
    .line 2486
    .line 2487
    .line 2488
    .line 2489
    .line 2490
    .line 2491
    .line 2492
    .line 2493
    .line 2494
    .line 2495
    .line 2496
    .line 2497
    .line 2498
    .line 2499
    .line 2500
    .line 2501
    .line 2502
    .line 2503
    .line 2504
    .line 2505
    .line 2506
    .line 2507
    .line 2508
    .line 2509
    .line 2510
    .line 2511
    .line 2512
    .line 2513
    .line 2514
    .line 2515
    .line 2516
    .line 2517
    .line 2518
    .line 2519
    .line 2520
    .line 2521
    .line 2522
    .line 2523
    .line 2524
    .line 2525
    .line 2526
    .line 2527
    .line 2528
    .line 2529
    .line 2530
    .line 2531
    .line 2532
    .line 2533
    .line 2534
    .line 2535
    .line 2536
    .line 2537
    .line 2538
    .line 2539
    .line 2540
    .line 2541
    .line 2542
    .line 2543
    .line 2544
    .line 2545
    .line 2546
    .line 2547
    .line 2548
    .line 2549
    .line 2550
    .line 2551
    .line 2552
    .line 2553
    .line 2554
    .line 2555
    .line 2556
    .line 2557
    .line 2558
    .line 2559
    .line 2560
    .line 2561
    .line 2562
    .line 2563
    .line 2564
    .line 2565
    .line 2566
    .line 2567
    .line 2568
    .line 2569
    .line 2570
    .line 2571
    .line 2572
    .line 2573
    .line 2574
    .line 2575
    .line 2576
    .line 2577
    .line 2578
    .line 2579
    .line 2580
    .line 2581
    .line 2582
    .line 2583
    .line 2584
    .line 2585
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
    .end packed-switch

    .line 2586
    .line 2587
    .line 2588
    .line 2589
    .line 2590
    .line 2591
    .line 2592
    .line 2593
    .line 2594
    .line 2595
    .line 2596
    .line 2597
    .line 2598
    .line 2599
    .line 2600
    .line 2601
    .line 2602
    .line 2603
    .line 2604
    .line 2605
    .line 2606
    .line 2607
    .line 2608
    .line 2609
    .line 2610
    .line 2611
    .line 2612
    .line 2613
    .line 2614
    .line 2615
    .line 2616
    .line 2617
    .line 2618
    .line 2619
    .line 2620
    .line 2621
    .line 2622
    .line 2623
    .line 2624
    .line 2625
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
    .end packed-switch
.end method

.method public final g(Landroidx/datastore/preferences/protobuf/x;)I
    .locals 11

    .line 1
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    :goto_0
    if-ge v2, v1, :cond_3

    .line 7
    .line 8
    invoke-virtual {p0, v2}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 9
    .line 10
    .line 11
    move-result v4

    .line 12
    aget v5, v0, v2

    .line 13
    .line 14
    const v6, 0xfffff

    .line 15
    .line 16
    .line 17
    and-int/2addr v6, v4

    .line 18
    int-to-long v6, v6

    .line 19
    invoke-static {v4}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    const/16 v8, 0x4d5

    .line 24
    .line 25
    const/16 v9, 0x4cf

    .line 26
    .line 27
    const/16 v10, 0x25

    .line 28
    .line 29
    packed-switch v4, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    goto/16 :goto_4

    .line 33
    .line 34
    :pswitch_0
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 41
    .line 42
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    mul-int/lit8 v3, v3, 0x35

    .line 47
    .line 48
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    :goto_1
    add-int/2addr v4, v3

    .line 53
    move v3, v4

    .line 54
    goto/16 :goto_4

    .line 55
    .line 56
    :pswitch_1
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_2

    .line 61
    .line 62
    mul-int/lit8 v3, v3, 0x35

    .line 63
    .line 64
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 65
    .line 66
    .line 67
    move-result-wide v4

    .line 68
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    goto :goto_1

    .line 73
    :pswitch_2
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_2

    .line 78
    .line 79
    mul-int/lit8 v3, v3, 0x35

    .line 80
    .line 81
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    goto :goto_1

    .line 86
    :pswitch_3
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    if-eqz v4, :cond_2

    .line 91
    .line 92
    mul-int/lit8 v3, v3, 0x35

    .line 93
    .line 94
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 95
    .line 96
    .line 97
    move-result-wide v4

    .line 98
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    goto :goto_1

    .line 103
    :pswitch_4
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    if-eqz v4, :cond_2

    .line 108
    .line 109
    mul-int/lit8 v3, v3, 0x35

    .line 110
    .line 111
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    goto :goto_1

    .line 116
    :pswitch_5
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    if-eqz v4, :cond_2

    .line 121
    .line 122
    mul-int/lit8 v3, v3, 0x35

    .line 123
    .line 124
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    goto :goto_1

    .line 129
    :pswitch_6
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-eqz v4, :cond_2

    .line 134
    .line 135
    mul-int/lit8 v3, v3, 0x35

    .line 136
    .line 137
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    goto :goto_1

    .line 142
    :pswitch_7
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    if-eqz v4, :cond_2

    .line 147
    .line 148
    mul-int/lit8 v3, v3, 0x35

    .line 149
    .line 150
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 151
    .line 152
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    goto :goto_1

    .line 161
    :pswitch_8
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-eqz v4, :cond_2

    .line 166
    .line 167
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 168
    .line 169
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v4

    .line 173
    mul-int/lit8 v3, v3, 0x35

    .line 174
    .line 175
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    goto :goto_1

    .line 180
    :pswitch_9
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    if-eqz v4, :cond_2

    .line 185
    .line 186
    mul-int/lit8 v3, v3, 0x35

    .line 187
    .line 188
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 189
    .line 190
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    check-cast v4, Ljava/lang/String;

    .line 195
    .line 196
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    goto/16 :goto_1

    .line 201
    .line 202
    :pswitch_a
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 203
    .line 204
    .line 205
    move-result v4

    .line 206
    if-eqz v4, :cond_2

    .line 207
    .line 208
    mul-int/lit8 v3, v3, 0x35

    .line 209
    .line 210
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 211
    .line 212
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    check-cast v4, Ljava/lang/Boolean;

    .line 217
    .line 218
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 219
    .line 220
    .line 221
    move-result v4

    .line 222
    sget-object v5, Landroidx/datastore/preferences/protobuf/a0;->a:Ljava/nio/charset/Charset;

    .line 223
    .line 224
    if-eqz v4, :cond_0

    .line 225
    .line 226
    :goto_2
    move v8, v9

    .line 227
    :cond_0
    add-int/2addr v8, v3

    .line 228
    move v3, v8

    .line 229
    goto/16 :goto_4

    .line 230
    .line 231
    :pswitch_b
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 232
    .line 233
    .line 234
    move-result v4

    .line 235
    if-eqz v4, :cond_2

    .line 236
    .line 237
    mul-int/lit8 v3, v3, 0x35

    .line 238
    .line 239
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 240
    .line 241
    .line 242
    move-result v4

    .line 243
    goto/16 :goto_1

    .line 244
    .line 245
    :pswitch_c
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    if-eqz v4, :cond_2

    .line 250
    .line 251
    mul-int/lit8 v3, v3, 0x35

    .line 252
    .line 253
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 254
    .line 255
    .line 256
    move-result-wide v4

    .line 257
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    goto/16 :goto_1

    .line 262
    .line 263
    :pswitch_d
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 264
    .line 265
    .line 266
    move-result v4

    .line 267
    if-eqz v4, :cond_2

    .line 268
    .line 269
    mul-int/lit8 v3, v3, 0x35

    .line 270
    .line 271
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->y(JLjava/lang/Object;)I

    .line 272
    .line 273
    .line 274
    move-result v4

    .line 275
    goto/16 :goto_1

    .line 276
    .line 277
    :pswitch_e
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 278
    .line 279
    .line 280
    move-result v4

    .line 281
    if-eqz v4, :cond_2

    .line 282
    .line 283
    mul-int/lit8 v3, v3, 0x35

    .line 284
    .line 285
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 286
    .line 287
    .line 288
    move-result-wide v4

    .line 289
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 290
    .line 291
    .line 292
    move-result v4

    .line 293
    goto/16 :goto_1

    .line 294
    .line 295
    :pswitch_f
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 296
    .line 297
    .line 298
    move-result v4

    .line 299
    if-eqz v4, :cond_2

    .line 300
    .line 301
    mul-int/lit8 v3, v3, 0x35

    .line 302
    .line 303
    invoke-static {v6, v7, p1}, Landroidx/datastore/preferences/protobuf/r0;->z(JLjava/lang/Object;)J

    .line 304
    .line 305
    .line 306
    move-result-wide v4

    .line 307
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 308
    .line 309
    .line 310
    move-result v4

    .line 311
    goto/16 :goto_1

    .line 312
    .line 313
    :pswitch_10
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 314
    .line 315
    .line 316
    move-result v4

    .line 317
    if-eqz v4, :cond_2

    .line 318
    .line 319
    mul-int/lit8 v3, v3, 0x35

    .line 320
    .line 321
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 322
    .line 323
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v4

    .line 327
    check-cast v4, Ljava/lang/Float;

    .line 328
    .line 329
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 330
    .line 331
    .line 332
    move-result v4

    .line 333
    invoke-static {v4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 334
    .line 335
    .line 336
    move-result v4

    .line 337
    goto/16 :goto_1

    .line 338
    .line 339
    :pswitch_11
    invoke-virtual {p0, v5, p1, v2}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 340
    .line 341
    .line 342
    move-result v4

    .line 343
    if-eqz v4, :cond_2

    .line 344
    .line 345
    mul-int/lit8 v3, v3, 0x35

    .line 346
    .line 347
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 348
    .line 349
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v4

    .line 353
    check-cast v4, Ljava/lang/Double;

    .line 354
    .line 355
    invoke-virtual {v4}, Ljava/lang/Double;->doubleValue()D

    .line 356
    .line 357
    .line 358
    move-result-wide v4

    .line 359
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 360
    .line 361
    .line 362
    move-result-wide v4

    .line 363
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 364
    .line 365
    .line 366
    move-result v4

    .line 367
    goto/16 :goto_1

    .line 368
    .line 369
    :pswitch_12
    mul-int/lit8 v3, v3, 0x35

    .line 370
    .line 371
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 372
    .line 373
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v4

    .line 377
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 378
    .line 379
    .line 380
    move-result v4

    .line 381
    goto/16 :goto_1

    .line 382
    .line 383
    :pswitch_13
    mul-int/lit8 v3, v3, 0x35

    .line 384
    .line 385
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 386
    .line 387
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v4

    .line 391
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 392
    .line 393
    .line 394
    move-result v4

    .line 395
    goto/16 :goto_1

    .line 396
    .line 397
    :pswitch_14
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 398
    .line 399
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v4

    .line 403
    if-eqz v4, :cond_1

    .line 404
    .line 405
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 406
    .line 407
    .line 408
    move-result v10

    .line 409
    :cond_1
    :goto_3
    mul-int/lit8 v3, v3, 0x35

    .line 410
    .line 411
    add-int/2addr v3, v10

    .line 412
    goto/16 :goto_4

    .line 413
    .line 414
    :pswitch_15
    mul-int/lit8 v3, v3, 0x35

    .line 415
    .line 416
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 417
    .line 418
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 419
    .line 420
    .line 421
    move-result-wide v4

    .line 422
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 423
    .line 424
    .line 425
    move-result v4

    .line 426
    goto/16 :goto_1

    .line 427
    .line 428
    :pswitch_16
    mul-int/lit8 v3, v3, 0x35

    .line 429
    .line 430
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 431
    .line 432
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 433
    .line 434
    .line 435
    move-result v4

    .line 436
    goto/16 :goto_1

    .line 437
    .line 438
    :pswitch_17
    mul-int/lit8 v3, v3, 0x35

    .line 439
    .line 440
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 441
    .line 442
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 443
    .line 444
    .line 445
    move-result-wide v4

    .line 446
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 447
    .line 448
    .line 449
    move-result v4

    .line 450
    goto/16 :goto_1

    .line 451
    .line 452
    :pswitch_18
    mul-int/lit8 v3, v3, 0x35

    .line 453
    .line 454
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 455
    .line 456
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 457
    .line 458
    .line 459
    move-result v4

    .line 460
    goto/16 :goto_1

    .line 461
    .line 462
    :pswitch_19
    mul-int/lit8 v3, v3, 0x35

    .line 463
    .line 464
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 465
    .line 466
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 467
    .line 468
    .line 469
    move-result v4

    .line 470
    goto/16 :goto_1

    .line 471
    .line 472
    :pswitch_1a
    mul-int/lit8 v3, v3, 0x35

    .line 473
    .line 474
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 475
    .line 476
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 477
    .line 478
    .line 479
    move-result v4

    .line 480
    goto/16 :goto_1

    .line 481
    .line 482
    :pswitch_1b
    mul-int/lit8 v3, v3, 0x35

    .line 483
    .line 484
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 485
    .line 486
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v4

    .line 490
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 491
    .line 492
    .line 493
    move-result v4

    .line 494
    goto/16 :goto_1

    .line 495
    .line 496
    :pswitch_1c
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 497
    .line 498
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v4

    .line 502
    if-eqz v4, :cond_1

    .line 503
    .line 504
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 505
    .line 506
    .line 507
    move-result v10

    .line 508
    goto :goto_3

    .line 509
    :pswitch_1d
    mul-int/lit8 v3, v3, 0x35

    .line 510
    .line 511
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 512
    .line 513
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v4

    .line 517
    check-cast v4, Ljava/lang/String;

    .line 518
    .line 519
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 520
    .line 521
    .line 522
    move-result v4

    .line 523
    goto/16 :goto_1

    .line 524
    .line 525
    :pswitch_1e
    mul-int/lit8 v3, v3, 0x35

    .line 526
    .line 527
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 528
    .line 529
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->c(JLjava/lang/Object;)Z

    .line 530
    .line 531
    .line 532
    move-result v4

    .line 533
    sget-object v5, Landroidx/datastore/preferences/protobuf/a0;->a:Ljava/nio/charset/Charset;

    .line 534
    .line 535
    if-eqz v4, :cond_0

    .line 536
    .line 537
    goto/16 :goto_2

    .line 538
    .line 539
    :pswitch_1f
    mul-int/lit8 v3, v3, 0x35

    .line 540
    .line 541
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 542
    .line 543
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 544
    .line 545
    .line 546
    move-result v4

    .line 547
    goto/16 :goto_1

    .line 548
    .line 549
    :pswitch_20
    mul-int/lit8 v3, v3, 0x35

    .line 550
    .line 551
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 552
    .line 553
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 554
    .line 555
    .line 556
    move-result-wide v4

    .line 557
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 558
    .line 559
    .line 560
    move-result v4

    .line 561
    goto/16 :goto_1

    .line 562
    .line 563
    :pswitch_21
    mul-int/lit8 v3, v3, 0x35

    .line 564
    .line 565
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 566
    .line 567
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 568
    .line 569
    .line 570
    move-result v4

    .line 571
    goto/16 :goto_1

    .line 572
    .line 573
    :pswitch_22
    mul-int/lit8 v3, v3, 0x35

    .line 574
    .line 575
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 576
    .line 577
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 578
    .line 579
    .line 580
    move-result-wide v4

    .line 581
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 582
    .line 583
    .line 584
    move-result v4

    .line 585
    goto/16 :goto_1

    .line 586
    .line 587
    :pswitch_23
    mul-int/lit8 v3, v3, 0x35

    .line 588
    .line 589
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 590
    .line 591
    invoke-virtual {v4, p1, v6, v7}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 592
    .line 593
    .line 594
    move-result-wide v4

    .line 595
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 596
    .line 597
    .line 598
    move-result v4

    .line 599
    goto/16 :goto_1

    .line 600
    .line 601
    :pswitch_24
    mul-int/lit8 v3, v3, 0x35

    .line 602
    .line 603
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 604
    .line 605
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->e(JLjava/lang/Object;)F

    .line 606
    .line 607
    .line 608
    move-result v4

    .line 609
    invoke-static {v4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 610
    .line 611
    .line 612
    move-result v4

    .line 613
    goto/16 :goto_1

    .line 614
    .line 615
    :pswitch_25
    mul-int/lit8 v3, v3, 0x35

    .line 616
    .line 617
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 618
    .line 619
    invoke-virtual {v4, v6, v7, p1}, Landroidx/datastore/preferences/protobuf/m1;->d(JLjava/lang/Object;)D

    .line 620
    .line 621
    .line 622
    move-result-wide v4

    .line 623
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 624
    .line 625
    .line 626
    move-result-wide v4

    .line 627
    invoke-static {v4, v5}, Landroidx/datastore/preferences/protobuf/a0;->b(J)I

    .line 628
    .line 629
    .line 630
    move-result v4

    .line 631
    goto/16 :goto_1

    .line 632
    .line 633
    :cond_2
    :goto_4
    add-int/lit8 v2, v2, 0x3

    .line 634
    .line 635
    goto/16 :goto_0

    .line 636
    .line 637
    :cond_3
    mul-int/lit8 v3, v3, 0x35

    .line 638
    .line 639
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 640
    .line 641
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 642
    .line 643
    .line 644
    iget-object p0, p1, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 645
    .line 646
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/h1;->hashCode()I

    .line 647
    .line 648
    .line 649
    move-result p0

    .line 650
    add-int/2addr p0, v3

    .line 651
    return p0

    .line 652
    nop

    .line 653
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final h(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;)Z
    .locals 11

    .line 1
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    :goto_0
    const/4 v4, 0x1

    .line 7
    if-ge v3, v1, :cond_2

    .line 8
    .line 9
    invoke-virtual {p0, v3}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 10
    .line 11
    .line 12
    move-result v5

    .line 13
    const v6, 0xfffff

    .line 14
    .line 15
    .line 16
    and-int v7, v5, v6

    .line 17
    .line 18
    int-to-long v7, v7

    .line 19
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    packed-switch v5, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    goto/16 :goto_1

    .line 27
    .line 28
    :pswitch_0
    add-int/lit8 v5, v3, 0x2

    .line 29
    .line 30
    aget v5, v0, v5

    .line 31
    .line 32
    and-int/2addr v5, v6

    .line 33
    int-to-long v5, v5

    .line 34
    sget-object v9, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 35
    .line 36
    invoke-virtual {v9, v5, v6, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 37
    .line 38
    .line 39
    move-result v10

    .line 40
    invoke-virtual {v9, v5, v6, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-ne v10, v5, :cond_0

    .line 45
    .line 46
    invoke-virtual {v9, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    invoke-virtual {v9, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v6

    .line 54
    invoke-static {v5, v6}, Landroidx/datastore/preferences/protobuf/b1;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_0

    .line 59
    .line 60
    goto/16 :goto_1

    .line 61
    .line 62
    :cond_0
    move v4, v2

    .line 63
    goto/16 :goto_1

    .line 64
    .line 65
    :pswitch_1
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 66
    .line 67
    invoke-virtual {v4, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-virtual {v4, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    invoke-static {v5, v4}, Landroidx/datastore/preferences/protobuf/b1;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    goto/16 :goto_1

    .line 80
    .line 81
    :pswitch_2
    sget-object v4, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 82
    .line 83
    invoke-virtual {v4, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    invoke-virtual {v4, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    invoke-static {v5, v4}, Landroidx/datastore/preferences/protobuf/b1;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    goto/16 :goto_1

    .line 96
    .line 97
    :pswitch_3
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 98
    .line 99
    .line 100
    move-result v5

    .line 101
    if-eqz v5, :cond_0

    .line 102
    .line 103
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 104
    .line 105
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    invoke-static {v6, v5}, Landroidx/datastore/preferences/protobuf/b1;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    if-eqz v5, :cond_0

    .line 118
    .line 119
    goto/16 :goto_1

    .line 120
    .line 121
    :pswitch_4
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    if-eqz v5, :cond_0

    .line 126
    .line 127
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 128
    .line 129
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 130
    .line 131
    .line 132
    move-result-wide v9

    .line 133
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 134
    .line 135
    .line 136
    move-result-wide v5

    .line 137
    cmp-long v5, v9, v5

    .line 138
    .line 139
    if-nez v5, :cond_0

    .line 140
    .line 141
    goto/16 :goto_1

    .line 142
    .line 143
    :pswitch_5
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    if-eqz v5, :cond_0

    .line 148
    .line 149
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 150
    .line 151
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 152
    .line 153
    .line 154
    move-result v6

    .line 155
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    if-ne v6, v5, :cond_0

    .line 160
    .line 161
    goto/16 :goto_1

    .line 162
    .line 163
    :pswitch_6
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 164
    .line 165
    .line 166
    move-result v5

    .line 167
    if-eqz v5, :cond_0

    .line 168
    .line 169
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 170
    .line 171
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 172
    .line 173
    .line 174
    move-result-wide v9

    .line 175
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 176
    .line 177
    .line 178
    move-result-wide v5

    .line 179
    cmp-long v5, v9, v5

    .line 180
    .line 181
    if-nez v5, :cond_0

    .line 182
    .line 183
    goto/16 :goto_1

    .line 184
    .line 185
    :pswitch_7
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    if-eqz v5, :cond_0

    .line 190
    .line 191
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 192
    .line 193
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 194
    .line 195
    .line 196
    move-result v6

    .line 197
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-ne v6, v5, :cond_0

    .line 202
    .line 203
    goto/16 :goto_1

    .line 204
    .line 205
    :pswitch_8
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 206
    .line 207
    .line 208
    move-result v5

    .line 209
    if-eqz v5, :cond_0

    .line 210
    .line 211
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 212
    .line 213
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    if-ne v6, v5, :cond_0

    .line 222
    .line 223
    goto/16 :goto_1

    .line 224
    .line 225
    :pswitch_9
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    if-eqz v5, :cond_0

    .line 230
    .line 231
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 232
    .line 233
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 234
    .line 235
    .line 236
    move-result v6

    .line 237
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 238
    .line 239
    .line 240
    move-result v5

    .line 241
    if-ne v6, v5, :cond_0

    .line 242
    .line 243
    goto/16 :goto_1

    .line 244
    .line 245
    :pswitch_a
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 246
    .line 247
    .line 248
    move-result v5

    .line 249
    if-eqz v5, :cond_0

    .line 250
    .line 251
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 252
    .line 253
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v6

    .line 257
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v5

    .line 261
    invoke-static {v6, v5}, Landroidx/datastore/preferences/protobuf/b1;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v5

    .line 265
    if-eqz v5, :cond_0

    .line 266
    .line 267
    goto/16 :goto_1

    .line 268
    .line 269
    :pswitch_b
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 270
    .line 271
    .line 272
    move-result v5

    .line 273
    if-eqz v5, :cond_0

    .line 274
    .line 275
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 276
    .line 277
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v6

    .line 281
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v5

    .line 285
    invoke-static {v6, v5}, Landroidx/datastore/preferences/protobuf/b1;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v5

    .line 289
    if-eqz v5, :cond_0

    .line 290
    .line 291
    goto/16 :goto_1

    .line 292
    .line 293
    :pswitch_c
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 294
    .line 295
    .line 296
    move-result v5

    .line 297
    if-eqz v5, :cond_0

    .line 298
    .line 299
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 300
    .line 301
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v6

    .line 305
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v5

    .line 309
    invoke-static {v6, v5}, Landroidx/datastore/preferences/protobuf/b1;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    move-result v5

    .line 313
    if-eqz v5, :cond_0

    .line 314
    .line 315
    goto/16 :goto_1

    .line 316
    .line 317
    :pswitch_d
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 318
    .line 319
    .line 320
    move-result v5

    .line 321
    if-eqz v5, :cond_0

    .line 322
    .line 323
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 324
    .line 325
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->c(JLjava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v6

    .line 329
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->c(JLjava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v5

    .line 333
    if-ne v6, v5, :cond_0

    .line 334
    .line 335
    goto/16 :goto_1

    .line 336
    .line 337
    :pswitch_e
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 338
    .line 339
    .line 340
    move-result v5

    .line 341
    if-eqz v5, :cond_0

    .line 342
    .line 343
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 344
    .line 345
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 350
    .line 351
    .line 352
    move-result v5

    .line 353
    if-ne v6, v5, :cond_0

    .line 354
    .line 355
    goto/16 :goto_1

    .line 356
    .line 357
    :pswitch_f
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 358
    .line 359
    .line 360
    move-result v5

    .line 361
    if-eqz v5, :cond_0

    .line 362
    .line 363
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 364
    .line 365
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 366
    .line 367
    .line 368
    move-result-wide v9

    .line 369
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 370
    .line 371
    .line 372
    move-result-wide v5

    .line 373
    cmp-long v5, v9, v5

    .line 374
    .line 375
    if-nez v5, :cond_0

    .line 376
    .line 377
    goto/16 :goto_1

    .line 378
    .line 379
    :pswitch_10
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 380
    .line 381
    .line 382
    move-result v5

    .line 383
    if-eqz v5, :cond_0

    .line 384
    .line 385
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 386
    .line 387
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 388
    .line 389
    .line 390
    move-result v6

    .line 391
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 392
    .line 393
    .line 394
    move-result v5

    .line 395
    if-ne v6, v5, :cond_0

    .line 396
    .line 397
    goto :goto_1

    .line 398
    :pswitch_11
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 399
    .line 400
    .line 401
    move-result v5

    .line 402
    if-eqz v5, :cond_0

    .line 403
    .line 404
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 405
    .line 406
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 407
    .line 408
    .line 409
    move-result-wide v9

    .line 410
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 411
    .line 412
    .line 413
    move-result-wide v5

    .line 414
    cmp-long v5, v9, v5

    .line 415
    .line 416
    if-nez v5, :cond_0

    .line 417
    .line 418
    goto :goto_1

    .line 419
    :pswitch_12
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 420
    .line 421
    .line 422
    move-result v5

    .line 423
    if-eqz v5, :cond_0

    .line 424
    .line 425
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 426
    .line 427
    invoke-virtual {v5, p1, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 428
    .line 429
    .line 430
    move-result-wide v9

    .line 431
    invoke-virtual {v5, p2, v7, v8}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 432
    .line 433
    .line 434
    move-result-wide v5

    .line 435
    cmp-long v5, v9, v5

    .line 436
    .line 437
    if-nez v5, :cond_0

    .line 438
    .line 439
    goto :goto_1

    .line 440
    :pswitch_13
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 441
    .line 442
    .line 443
    move-result v5

    .line 444
    if-eqz v5, :cond_0

    .line 445
    .line 446
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 447
    .line 448
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->e(JLjava/lang/Object;)F

    .line 449
    .line 450
    .line 451
    move-result v6

    .line 452
    invoke-static {v6}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 453
    .line 454
    .line 455
    move-result v6

    .line 456
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->e(JLjava/lang/Object;)F

    .line 457
    .line 458
    .line 459
    move-result v5

    .line 460
    invoke-static {v5}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 461
    .line 462
    .line 463
    move-result v5

    .line 464
    if-ne v6, v5, :cond_0

    .line 465
    .line 466
    goto :goto_1

    .line 467
    :pswitch_14
    invoke-virtual {p0, p1, p2, v3}, Landroidx/datastore/preferences/protobuf/r0;->j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z

    .line 468
    .line 469
    .line 470
    move-result v5

    .line 471
    if-eqz v5, :cond_0

    .line 472
    .line 473
    sget-object v5, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 474
    .line 475
    invoke-virtual {v5, v7, v8, p1}, Landroidx/datastore/preferences/protobuf/m1;->d(JLjava/lang/Object;)D

    .line 476
    .line 477
    .line 478
    move-result-wide v9

    .line 479
    invoke-static {v9, v10}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 480
    .line 481
    .line 482
    move-result-wide v9

    .line 483
    invoke-virtual {v5, v7, v8, p2}, Landroidx/datastore/preferences/protobuf/m1;->d(JLjava/lang/Object;)D

    .line 484
    .line 485
    .line 486
    move-result-wide v5

    .line 487
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 488
    .line 489
    .line 490
    move-result-wide v5

    .line 491
    cmp-long v5, v9, v5

    .line 492
    .line 493
    if-nez v5, :cond_0

    .line 494
    .line 495
    :goto_1
    if-nez v4, :cond_1

    .line 496
    .line 497
    goto :goto_2

    .line 498
    :cond_1
    add-int/lit8 v3, v3, 0x3

    .line 499
    .line 500
    goto/16 :goto_0

    .line 501
    .line 502
    :cond_2
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 503
    .line 504
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 505
    .line 506
    .line 507
    iget-object p0, p1, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 508
    .line 509
    iget-object p1, p2, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 510
    .line 511
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/h1;->equals(Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    move-result p0

    .line 515
    if-nez p0, :cond_3

    .line 516
    .line 517
    :goto_2
    return v2

    .line 518
    :cond_3
    return v4

    .line 519
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Ljava/lang/Object;Landroidx/collection/h;Landroidx/datastore/preferences/protobuf/o;)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v4, p2

    .line 6
    .line 7
    move-object/from16 v5, p3

    .line 8
    .line 9
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    invoke-static {v2}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_f

    .line 17
    .line 18
    iget-object v8, v1, Landroidx/datastore/preferences/protobuf/r0;->l:Landroidx/datastore/preferences/protobuf/i1;

    .line 19
    .line 20
    iget-object v9, v1, Landroidx/datastore/preferences/protobuf/r0;->g:[I

    .line 21
    .line 22
    iget v10, v1, Landroidx/datastore/preferences/protobuf/r0;->i:I

    .line 23
    .line 24
    iget v11, v1, Landroidx/datastore/preferences/protobuf/r0;->h:I

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    move-object v12, v0

    .line 28
    :goto_0
    :try_start_0
    invoke-virtual {v4}, Landroidx/collection/h;->e()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    invoke-virtual {v1, v0}, Landroidx/datastore/preferences/protobuf/r0;->A(I)I

    .line 33
    .line 34
    .line 35
    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    const/4 v13, 0x0

    .line 37
    if-gez v3, :cond_5

    .line 38
    .line 39
    const v3, 0x7fffffff

    .line 40
    .line 41
    .line 42
    if-ne v0, v3, :cond_1

    .line 43
    .line 44
    :goto_1
    if-ge v11, v10, :cond_0

    .line 45
    .line 46
    aget v0, v9, v11

    .line 47
    .line 48
    invoke-virtual {v1, v0, v2, v12}, Landroidx/datastore/preferences/protobuf/r0;->k(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    add-int/lit8 v11, v11, 0x1

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_0
    if-eqz v12, :cond_b

    .line 55
    .line 56
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    :goto_2
    move-object v0, v2

    .line 60
    check-cast v0, Landroidx/datastore/preferences/protobuf/x;

    .line 61
    .line 62
    iput-object v12, v0, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 63
    .line 64
    goto/16 :goto_e

    .line 65
    .line 66
    :cond_1
    :try_start_1
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    if-nez v12, :cond_2

    .line 70
    .line 71
    invoke-static {v2}, Landroidx/datastore/preferences/protobuf/i1;->a(Ljava/lang/Object;)Landroidx/datastore/preferences/protobuf/h1;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    move-object v12, v0

    .line 76
    goto :goto_4

    .line 77
    :catchall_0
    move-exception v0

    .line 78
    :goto_3
    move-object v6, v1

    .line 79
    goto/16 :goto_10

    .line 80
    .line 81
    :cond_2
    :goto_4
    invoke-static {v13, v4, v12}, Landroidx/datastore/preferences/protobuf/i1;->b(ILandroidx/collection/h;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 85
    if-eqz v0, :cond_3

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_3
    :goto_5
    if-ge v11, v10, :cond_4

    .line 89
    .line 90
    aget v0, v9, v11

    .line 91
    .line 92
    invoke-virtual {v1, v0, v2, v12}, Landroidx/datastore/preferences/protobuf/r0;->k(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    add-int/lit8 v11, v11, 0x1

    .line 96
    .line 97
    goto :goto_5

    .line 98
    :cond_4
    if-eqz v12, :cond_b

    .line 99
    .line 100
    :goto_6
    goto :goto_2

    .line 101
    :cond_5
    :try_start_2
    invoke-virtual {v1, v3}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 102
    .line 103
    .line 104
    move-result v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 105
    :try_start_3
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 106
    .line 107
    .line 108
    move-result v7
    :try_end_3
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 109
    const/4 v15, 0x3

    .line 110
    iget-object v14, v1, Landroidx/datastore/preferences/protobuf/r0;->k:Landroidx/datastore/preferences/protobuf/f0;

    .line 111
    .line 112
    packed-switch v7, :pswitch_data_0

    .line 113
    .line 114
    .line 115
    if-nez v12, :cond_6

    .line 116
    .line 117
    :try_start_4
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    invoke-static {v2}, Landroidx/datastore/preferences/protobuf/i1;->a(Ljava/lang/Object;)Landroidx/datastore/preferences/protobuf/h1;

    .line 121
    .line 122
    .line 123
    move-result-object v12

    .line 124
    goto :goto_8

    .line 125
    :catch_0
    move-object v6, v1

    .line 126
    :goto_7
    move-object v14, v4

    .line 127
    goto/16 :goto_c

    .line 128
    .line 129
    :cond_6
    :goto_8
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 130
    .line 131
    .line 132
    invoke-static {v13, v4, v12}, Landroidx/datastore/preferences/protobuf/i1;->b(ILandroidx/collection/h;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v0
    :try_end_4
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 136
    if-nez v0, :cond_8

    .line 137
    .line 138
    :goto_9
    if-ge v11, v10, :cond_7

    .line 139
    .line 140
    aget v0, v9, v11

    .line 141
    .line 142
    invoke-virtual {v1, v0, v2, v12}, Landroidx/datastore/preferences/protobuf/r0;->k(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    add-int/lit8 v11, v11, 0x1

    .line 146
    .line 147
    goto :goto_9

    .line 148
    :cond_7
    if-eqz v12, :cond_b

    .line 149
    .line 150
    goto :goto_6

    .line 151
    :pswitch_0
    :try_start_5
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->v(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    check-cast v6, Landroidx/datastore/preferences/protobuf/a;

    .line 156
    .line 157
    invoke-virtual {v1, v3}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 158
    .line 159
    .line 160
    move-result-object v7

    .line 161
    invoke-virtual {v4, v15}, Landroidx/collection/h;->J0(I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v4, v6, v7, v5}, Landroidx/collection/h;->i(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v1, v2, v0, v3, v6}, Landroidx/datastore/preferences/protobuf/r0;->J(Ljava/lang/Object;IILandroidx/datastore/preferences/protobuf/a;)V

    .line 168
    .line 169
    .line 170
    :cond_8
    :goto_a
    move-object v6, v1

    .line 171
    move-object v14, v4

    .line 172
    goto/16 :goto_f

    .line 173
    .line 174
    :pswitch_1
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 175
    .line 176
    .line 177
    move-result-wide v6

    .line 178
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 179
    .line 180
    .line 181
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 184
    .line 185
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->z()J

    .line 186
    .line 187
    .line 188
    move-result-wide v14

    .line 189
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 190
    .line 191
    .line 192
    move-result-object v14

    .line 193
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 197
    .line 198
    .line 199
    goto :goto_a

    .line 200
    :pswitch_2
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 201
    .line 202
    .line 203
    move-result-wide v6

    .line 204
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 205
    .line 206
    .line 207
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 208
    .line 209
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 210
    .line 211
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->y()I

    .line 212
    .line 213
    .line 214
    move-result v14

    .line 215
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 216
    .line 217
    .line 218
    move-result-object v14

    .line 219
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 223
    .line 224
    .line 225
    goto :goto_a

    .line 226
    :pswitch_3
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 227
    .line 228
    .line 229
    move-result-wide v6

    .line 230
    const/4 v14, 0x1

    .line 231
    invoke-virtual {v4, v14}, Landroidx/collection/h;->J0(I)V

    .line 232
    .line 233
    .line 234
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 237
    .line 238
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->x()J

    .line 239
    .line 240
    .line 241
    move-result-wide v14

    .line 242
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 243
    .line 244
    .line 245
    move-result-object v14

    .line 246
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 250
    .line 251
    .line 252
    goto :goto_a

    .line 253
    :pswitch_4
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 254
    .line 255
    .line 256
    move-result-wide v6

    .line 257
    const/4 v14, 0x5

    .line 258
    invoke-virtual {v4, v14}, Landroidx/collection/h;->J0(I)V

    .line 259
    .line 260
    .line 261
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 264
    .line 265
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->w()I

    .line 266
    .line 267
    .line 268
    move-result v14

    .line 269
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 270
    .line 271
    .line 272
    move-result-object v14

    .line 273
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 277
    .line 278
    .line 279
    goto :goto_a

    .line 280
    :pswitch_5
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 281
    .line 282
    .line 283
    iget-object v7, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 284
    .line 285
    check-cast v7, Landroidx/datastore/preferences/protobuf/k;

    .line 286
    .line 287
    invoke-virtual {v7}, Landroidx/datastore/preferences/protobuf/k;->q()I

    .line 288
    .line 289
    .line 290
    move-result v7

    .line 291
    invoke-virtual {v1, v3}, Landroidx/datastore/preferences/protobuf/r0;->l(I)V

    .line 292
    .line 293
    .line 294
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 295
    .line 296
    .line 297
    move-result-wide v14

    .line 298
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 299
    .line 300
    .line 301
    move-result-object v6

    .line 302
    invoke-static {v2, v14, v15, v6}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 306
    .line 307
    .line 308
    goto/16 :goto_a

    .line 309
    .line 310
    :pswitch_6
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 311
    .line 312
    .line 313
    move-result-wide v6

    .line 314
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 315
    .line 316
    .line 317
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 318
    .line 319
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 320
    .line 321
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 322
    .line 323
    .line 324
    move-result v14

    .line 325
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 326
    .line 327
    .line 328
    move-result-object v14

    .line 329
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 333
    .line 334
    .line 335
    goto/16 :goto_a

    .line 336
    .line 337
    :pswitch_7
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 338
    .line 339
    .line 340
    move-result-wide v6

    .line 341
    invoke-virtual {v4}, Landroidx/collection/h;->q()Landroidx/datastore/preferences/protobuf/h;

    .line 342
    .line 343
    .line 344
    move-result-object v14

    .line 345
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 349
    .line 350
    .line 351
    goto/16 :goto_a

    .line 352
    .line 353
    :pswitch_8
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->v(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v6

    .line 357
    check-cast v6, Landroidx/datastore/preferences/protobuf/a;

    .line 358
    .line 359
    invoke-virtual {v1, v3}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 360
    .line 361
    .line 362
    move-result-object v7

    .line 363
    const/4 v14, 0x2

    .line 364
    invoke-virtual {v4, v14}, Landroidx/collection/h;->J0(I)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v4, v6, v7, v5}, Landroidx/collection/h;->k(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V

    .line 368
    .line 369
    .line 370
    invoke-virtual {v1, v2, v0, v3, v6}, Landroidx/datastore/preferences/protobuf/r0;->J(Ljava/lang/Object;IILandroidx/datastore/preferences/protobuf/a;)V

    .line 371
    .line 372
    .line 373
    goto/16 :goto_a

    .line 374
    .line 375
    :pswitch_9
    invoke-virtual {v1, v6, v4, v2}, Landroidx/datastore/preferences/protobuf/r0;->D(ILandroidx/collection/h;Ljava/lang/Object;)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 379
    .line 380
    .line 381
    goto/16 :goto_a

    .line 382
    .line 383
    :pswitch_a
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 384
    .line 385
    .line 386
    move-result-wide v6

    .line 387
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 388
    .line 389
    .line 390
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 391
    .line 392
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 393
    .line 394
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->m()Z

    .line 395
    .line 396
    .line 397
    move-result v14

    .line 398
    invoke-static {v14}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 399
    .line 400
    .line 401
    move-result-object v14

    .line 402
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 403
    .line 404
    .line 405
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 406
    .line 407
    .line 408
    goto/16 :goto_a

    .line 409
    .line 410
    :pswitch_b
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 411
    .line 412
    .line 413
    move-result-wide v6

    .line 414
    const/4 v14, 0x5

    .line 415
    invoke-virtual {v4, v14}, Landroidx/collection/h;->J0(I)V

    .line 416
    .line 417
    .line 418
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 419
    .line 420
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 421
    .line 422
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 423
    .line 424
    .line 425
    move-result v14

    .line 426
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 427
    .line 428
    .line 429
    move-result-object v14

    .line 430
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 431
    .line 432
    .line 433
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 434
    .line 435
    .line 436
    goto/16 :goto_a

    .line 437
    .line 438
    :pswitch_c
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 439
    .line 440
    .line 441
    move-result-wide v6

    .line 442
    const/4 v14, 0x1

    .line 443
    invoke-virtual {v4, v14}, Landroidx/collection/h;->J0(I)V

    .line 444
    .line 445
    .line 446
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 447
    .line 448
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 449
    .line 450
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 451
    .line 452
    .line 453
    move-result-wide v14

    .line 454
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 455
    .line 456
    .line 457
    move-result-object v14

    .line 458
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 459
    .line 460
    .line 461
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 462
    .line 463
    .line 464
    goto/16 :goto_a

    .line 465
    .line 466
    :pswitch_d
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 467
    .line 468
    .line 469
    move-result-wide v6

    .line 470
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 471
    .line 472
    .line 473
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 474
    .line 475
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 476
    .line 477
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->u()I

    .line 478
    .line 479
    .line 480
    move-result v14

    .line 481
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 482
    .line 483
    .line 484
    move-result-object v14

    .line 485
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 489
    .line 490
    .line 491
    goto/16 :goto_a

    .line 492
    .line 493
    :pswitch_e
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 494
    .line 495
    .line 496
    move-result-wide v6

    .line 497
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 498
    .line 499
    .line 500
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 501
    .line 502
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 503
    .line 504
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->E()J

    .line 505
    .line 506
    .line 507
    move-result-wide v14

    .line 508
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 509
    .line 510
    .line 511
    move-result-object v14

    .line 512
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 513
    .line 514
    .line 515
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 516
    .line 517
    .line 518
    goto/16 :goto_a

    .line 519
    .line 520
    :pswitch_f
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 521
    .line 522
    .line 523
    move-result-wide v6

    .line 524
    invoke-virtual {v4, v13}, Landroidx/collection/h;->J0(I)V

    .line 525
    .line 526
    .line 527
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 528
    .line 529
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 530
    .line 531
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 532
    .line 533
    .line 534
    move-result-wide v14

    .line 535
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 536
    .line 537
    .line 538
    move-result-object v14

    .line 539
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 540
    .line 541
    .line 542
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 543
    .line 544
    .line 545
    goto/16 :goto_a

    .line 546
    .line 547
    :pswitch_10
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 548
    .line 549
    .line 550
    move-result-wide v6

    .line 551
    const/4 v14, 0x5

    .line 552
    invoke-virtual {v4, v14}, Landroidx/collection/h;->J0(I)V

    .line 553
    .line 554
    .line 555
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 556
    .line 557
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 558
    .line 559
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->t()F

    .line 560
    .line 561
    .line 562
    move-result v14

    .line 563
    invoke-static {v14}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 564
    .line 565
    .line 566
    move-result-object v14

    .line 567
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 568
    .line 569
    .line 570
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 571
    .line 572
    .line 573
    goto/16 :goto_a

    .line 574
    .line 575
    :pswitch_11
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 576
    .line 577
    .line 578
    move-result-wide v6

    .line 579
    const/4 v14, 0x1

    .line 580
    invoke-virtual {v4, v14}, Landroidx/collection/h;->J0(I)V

    .line 581
    .line 582
    .line 583
    iget-object v14, v4, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 584
    .line 585
    check-cast v14, Landroidx/datastore/preferences/protobuf/k;

    .line 586
    .line 587
    invoke-virtual {v14}, Landroidx/datastore/preferences/protobuf/k;->p()D

    .line 588
    .line 589
    .line 590
    move-result-wide v14

    .line 591
    invoke-static {v14, v15}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 592
    .line 593
    .line 594
    move-result-object v14

    .line 595
    invoke-static {v2, v6, v7, v14}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 596
    .line 597
    .line 598
    invoke-virtual {v1, v0, v2, v3}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V
    :try_end_5
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 599
    .line 600
    .line 601
    goto/16 :goto_a

    .line 602
    .line 603
    :pswitch_12
    :try_start_6
    iget-object v0, v1, Landroidx/datastore/preferences/protobuf/r0;->b:[Ljava/lang/Object;

    .line 604
    .line 605
    div-int/lit8 v6, v3, 0x3

    .line 606
    .line 607
    const/16 v16, 0x2

    .line 608
    .line 609
    mul-int/lit8 v6, v6, 0x2

    .line 610
    .line 611
    aget-object v0, v0, v6

    .line 612
    .line 613
    move-object v6, v4

    .line 614
    move-object v4, v0

    .line 615
    invoke-virtual/range {v1 .. v6}, Landroidx/datastore/preferences/protobuf/r0;->r(Ljava/lang/Object;ILjava/lang/Object;Landroidx/datastore/preferences/protobuf/o;Landroidx/collection/h;)V

    .line 616
    .line 617
    .line 618
    move-object/from16 v2, p1

    .line 619
    .line 620
    move-object/from16 v14, p2

    .line 621
    .line 622
    move-object v6, v1

    .line 623
    goto/16 :goto_f

    .line 624
    .line 625
    :catchall_1
    move-exception v0

    .line 626
    move-object/from16 v2, p1

    .line 627
    .line 628
    goto/16 :goto_3

    .line 629
    .line 630
    :catch_1
    move-object/from16 v2, p1

    .line 631
    .line 632
    move-object/from16 v14, p2

    .line 633
    .line 634
    move-object v6, v1

    .line 635
    goto/16 :goto_c

    .line 636
    .line 637
    :pswitch_13
    move v7, v3

    .line 638
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 639
    .line 640
    .line 641
    move-result-wide v3

    .line 642
    invoke-virtual {v1, v7}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 643
    .line 644
    .line 645
    move-result-object v6
    :try_end_6
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 646
    move-object/from16 v2, p1

    .line 647
    .line 648
    move-object/from16 v5, p2

    .line 649
    .line 650
    move-object/from16 v7, p3

    .line 651
    .line 652
    :try_start_7
    invoke-virtual/range {v1 .. v7}, Landroidx/datastore/preferences/protobuf/r0;->B(Ljava/lang/Object;JLandroidx/collection/h;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V
    :try_end_7
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_7 .. :try_end_7} :catch_2
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 653
    .line 654
    .line 655
    move-object v4, v5

    .line 656
    goto/16 :goto_a

    .line 657
    .line 658
    :catch_2
    move-object v6, v1

    .line 659
    move-object v14, v5

    .line 660
    goto/16 :goto_c

    .line 661
    .line 662
    :pswitch_14
    :try_start_8
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 663
    .line 664
    .line 665
    move-result-wide v5

    .line 666
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 667
    .line 668
    .line 669
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 670
    .line 671
    .line 672
    move-result-object v0

    .line 673
    invoke-virtual {v4, v0}, Landroidx/collection/h;->r0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 674
    .line 675
    .line 676
    goto/16 :goto_a

    .line 677
    .line 678
    :pswitch_15
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 679
    .line 680
    .line 681
    move-result-wide v5

    .line 682
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 683
    .line 684
    .line 685
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 686
    .line 687
    .line 688
    move-result-object v0

    .line 689
    invoke-virtual {v4, v0}, Landroidx/collection/h;->n0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 690
    .line 691
    .line 692
    goto/16 :goto_a

    .line 693
    .line 694
    :pswitch_16
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 695
    .line 696
    .line 697
    move-result-wide v5

    .line 698
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 699
    .line 700
    .line 701
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 702
    .line 703
    .line 704
    move-result-object v0

    .line 705
    invoke-virtual {v4, v0}, Landroidx/collection/h;->j0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 706
    .line 707
    .line 708
    goto/16 :goto_a

    .line 709
    .line 710
    :pswitch_17
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 711
    .line 712
    .line 713
    move-result-wide v5

    .line 714
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 715
    .line 716
    .line 717
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 718
    .line 719
    .line 720
    move-result-object v0

    .line 721
    invoke-virtual {v4, v0}, Landroidx/collection/h;->f0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 722
    .line 723
    .line 724
    goto/16 :goto_a

    .line 725
    .line 726
    :pswitch_18
    move v7, v3

    .line 727
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 728
    .line 729
    .line 730
    move-result-wide v5

    .line 731
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 732
    .line 733
    .line 734
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 735
    .line 736
    .line 737
    move-result-object v3

    .line 738
    invoke-virtual {v4, v3}, Landroidx/collection/h;->B(Landroidx/datastore/preferences/protobuf/z;)V

    .line 739
    .line 740
    .line 741
    invoke-virtual {v1, v7}, Landroidx/datastore/preferences/protobuf/r0;->l(I)V

    .line 742
    .line 743
    .line 744
    invoke-static {v2, v0, v3, v12, v8}, Landroidx/datastore/preferences/protobuf/b1;->j(Ljava/lang/Object;ILandroidx/datastore/preferences/protobuf/z;Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/i1;)Ljava/lang/Object;

    .line 745
    .line 746
    .line 747
    goto/16 :goto_a

    .line 748
    .line 749
    :pswitch_19
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 750
    .line 751
    .line 752
    move-result-wide v5

    .line 753
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 754
    .line 755
    .line 756
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 757
    .line 758
    .line 759
    move-result-object v0

    .line 760
    invoke-virtual {v4, v0}, Landroidx/collection/h;->A0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 761
    .line 762
    .line 763
    goto/16 :goto_a

    .line 764
    .line 765
    :pswitch_1a
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 766
    .line 767
    .line 768
    move-result-wide v5

    .line 769
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 770
    .line 771
    .line 772
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 773
    .line 774
    .line 775
    move-result-object v0

    .line 776
    invoke-virtual {v4, v0}, Landroidx/collection/h;->n(Landroidx/datastore/preferences/protobuf/z;)V

    .line 777
    .line 778
    .line 779
    goto/16 :goto_a

    .line 780
    .line 781
    :pswitch_1b
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 782
    .line 783
    .line 784
    move-result-wide v5

    .line 785
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 786
    .line 787
    .line 788
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 789
    .line 790
    .line 791
    move-result-object v0

    .line 792
    invoke-virtual {v4, v0}, Landroidx/collection/h;->G(Landroidx/datastore/preferences/protobuf/z;)V

    .line 793
    .line 794
    .line 795
    goto/16 :goto_a

    .line 796
    .line 797
    :pswitch_1c
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 798
    .line 799
    .line 800
    move-result-wide v5

    .line 801
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 802
    .line 803
    .line 804
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 805
    .line 806
    .line 807
    move-result-object v0

    .line 808
    invoke-virtual {v4, v0}, Landroidx/collection/h;->K(Landroidx/datastore/preferences/protobuf/z;)V

    .line 809
    .line 810
    .line 811
    goto/16 :goto_a

    .line 812
    .line 813
    :pswitch_1d
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 814
    .line 815
    .line 816
    move-result-wide v5

    .line 817
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 818
    .line 819
    .line 820
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 821
    .line 822
    .line 823
    move-result-object v0

    .line 824
    invoke-virtual {v4, v0}, Landroidx/collection/h;->V(Landroidx/datastore/preferences/protobuf/z;)V

    .line 825
    .line 826
    .line 827
    goto/16 :goto_a

    .line 828
    .line 829
    :pswitch_1e
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 830
    .line 831
    .line 832
    move-result-wide v5

    .line 833
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 834
    .line 835
    .line 836
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 837
    .line 838
    .line 839
    move-result-object v0

    .line 840
    invoke-virtual {v4, v0}, Landroidx/collection/h;->E0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 841
    .line 842
    .line 843
    goto/16 :goto_a

    .line 844
    .line 845
    :pswitch_1f
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 846
    .line 847
    .line 848
    move-result-wide v5

    .line 849
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 850
    .line 851
    .line 852
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 853
    .line 854
    .line 855
    move-result-object v0

    .line 856
    invoke-virtual {v4, v0}, Landroidx/collection/h;->Z(Landroidx/datastore/preferences/protobuf/z;)V

    .line 857
    .line 858
    .line 859
    goto/16 :goto_a

    .line 860
    .line 861
    :pswitch_20
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 862
    .line 863
    .line 864
    move-result-wide v5

    .line 865
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 866
    .line 867
    .line 868
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 869
    .line 870
    .line 871
    move-result-object v0

    .line 872
    invoke-virtual {v4, v0}, Landroidx/collection/h;->O(Landroidx/datastore/preferences/protobuf/z;)V

    .line 873
    .line 874
    .line 875
    goto/16 :goto_a

    .line 876
    .line 877
    :pswitch_21
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 878
    .line 879
    .line 880
    move-result-wide v5

    .line 881
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 882
    .line 883
    .line 884
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 885
    .line 886
    .line 887
    move-result-object v0

    .line 888
    invoke-virtual {v4, v0}, Landroidx/collection/h;->x(Landroidx/datastore/preferences/protobuf/z;)V

    .line 889
    .line 890
    .line 891
    goto/16 :goto_a

    .line 892
    .line 893
    :pswitch_22
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 894
    .line 895
    .line 896
    move-result-wide v5

    .line 897
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 898
    .line 899
    .line 900
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 901
    .line 902
    .line 903
    move-result-object v0

    .line 904
    invoke-virtual {v4, v0}, Landroidx/collection/h;->r0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 905
    .line 906
    .line 907
    goto/16 :goto_a

    .line 908
    .line 909
    :pswitch_23
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 910
    .line 911
    .line 912
    move-result-wide v5

    .line 913
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 914
    .line 915
    .line 916
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 917
    .line 918
    .line 919
    move-result-object v0

    .line 920
    invoke-virtual {v4, v0}, Landroidx/collection/h;->n0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 921
    .line 922
    .line 923
    goto/16 :goto_a

    .line 924
    .line 925
    :pswitch_24
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 926
    .line 927
    .line 928
    move-result-wide v5

    .line 929
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 930
    .line 931
    .line 932
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 933
    .line 934
    .line 935
    move-result-object v0

    .line 936
    invoke-virtual {v4, v0}, Landroidx/collection/h;->j0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 937
    .line 938
    .line 939
    goto/16 :goto_a

    .line 940
    .line 941
    :pswitch_25
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 942
    .line 943
    .line 944
    move-result-wide v5

    .line 945
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 946
    .line 947
    .line 948
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 949
    .line 950
    .line 951
    move-result-object v0

    .line 952
    invoke-virtual {v4, v0}, Landroidx/collection/h;->f0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 953
    .line 954
    .line 955
    goto/16 :goto_a

    .line 956
    .line 957
    :pswitch_26
    move v7, v3

    .line 958
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 959
    .line 960
    .line 961
    move-result-wide v5

    .line 962
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 963
    .line 964
    .line 965
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 966
    .line 967
    .line 968
    move-result-object v3

    .line 969
    invoke-virtual {v4, v3}, Landroidx/collection/h;->B(Landroidx/datastore/preferences/protobuf/z;)V

    .line 970
    .line 971
    .line 972
    invoke-virtual {v1, v7}, Landroidx/datastore/preferences/protobuf/r0;->l(I)V

    .line 973
    .line 974
    .line 975
    invoke-static {v2, v0, v3, v12, v8}, Landroidx/datastore/preferences/protobuf/b1;->j(Ljava/lang/Object;ILandroidx/datastore/preferences/protobuf/z;Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/i1;)Ljava/lang/Object;

    .line 976
    .line 977
    .line 978
    goto/16 :goto_a

    .line 979
    .line 980
    :pswitch_27
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 981
    .line 982
    .line 983
    move-result-wide v5

    .line 984
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 985
    .line 986
    .line 987
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 988
    .line 989
    .line 990
    move-result-object v0

    .line 991
    invoke-virtual {v4, v0}, Landroidx/collection/h;->A0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 992
    .line 993
    .line 994
    goto/16 :goto_a

    .line 995
    .line 996
    :pswitch_28
    invoke-static {v6}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 997
    .line 998
    .line 999
    move-result-wide v5

    .line 1000
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1001
    .line 1002
    .line 1003
    invoke-static {v5, v6, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v0

    .line 1007
    invoke-virtual {v4, v0}, Landroidx/collection/h;->t(Landroidx/datastore/preferences/protobuf/z;)V
    :try_end_8
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 1008
    .line 1009
    .line 1010
    goto/16 :goto_a

    .line 1011
    .line 1012
    :pswitch_29
    move v7, v3

    .line 1013
    :try_start_9
    invoke-virtual {v1, v7}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v5
    :try_end_9
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_9 .. :try_end_9} :catch_4
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 1017
    move v3, v6

    .line 1018
    move-object/from16 v6, p3

    .line 1019
    .line 1020
    :try_start_a
    invoke-virtual/range {v1 .. v6}, Landroidx/datastore/preferences/protobuf/r0;->C(Ljava/lang/Object;ILandroidx/collection/h;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V
    :try_end_a
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_a .. :try_end_a} :catch_3
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 1021
    .line 1022
    .line 1023
    move-object v0, v6

    .line 1024
    move-object v6, v1

    .line 1025
    move-object v1, v0

    .line 1026
    move-object v0, v4

    .line 1027
    :goto_b
    move-object v14, v0

    .line 1028
    goto/16 :goto_f

    .line 1029
    .line 1030
    :catch_3
    move-object/from16 v17, v6

    .line 1031
    .line 1032
    move-object v6, v1

    .line 1033
    move-object/from16 v1, v17

    .line 1034
    .line 1035
    goto/16 :goto_7

    .line 1036
    .line 1037
    :catch_4
    move-object v6, v1

    .line 1038
    move-object/from16 v1, p3

    .line 1039
    .line 1040
    goto/16 :goto_7

    .line 1041
    .line 1042
    :pswitch_2a
    move-object v0, v4

    .line 1043
    move v3, v6

    .line 1044
    move-object v6, v1

    .line 1045
    move-object v1, v5

    .line 1046
    :try_start_b
    invoke-virtual {v6, v3, v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->E(ILandroidx/collection/h;Ljava/lang/Object;)V

    .line 1047
    .line 1048
    .line 1049
    goto :goto_b

    .line 1050
    :catch_5
    move-object v14, v0

    .line 1051
    goto/16 :goto_c

    .line 1052
    .line 1053
    :pswitch_2b
    move-object v0, v4

    .line 1054
    move v3, v6

    .line 1055
    move-object v6, v1

    .line 1056
    move-object v1, v5

    .line 1057
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1058
    .line 1059
    .line 1060
    move-result-wide v3

    .line 1061
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1062
    .line 1063
    .line 1064
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1065
    .line 1066
    .line 1067
    move-result-object v3

    .line 1068
    invoke-virtual {v0, v3}, Landroidx/collection/h;->n(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1069
    .line 1070
    .line 1071
    goto :goto_b

    .line 1072
    :catchall_2
    move-exception v0

    .line 1073
    goto/16 :goto_10

    .line 1074
    .line 1075
    :pswitch_2c
    move-object v0, v4

    .line 1076
    move v3, v6

    .line 1077
    move-object v6, v1

    .line 1078
    move-object v1, v5

    .line 1079
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1080
    .line 1081
    .line 1082
    move-result-wide v3

    .line 1083
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1084
    .line 1085
    .line 1086
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v3

    .line 1090
    invoke-virtual {v0, v3}, Landroidx/collection/h;->G(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1091
    .line 1092
    .line 1093
    goto :goto_b

    .line 1094
    :pswitch_2d
    move-object v0, v4

    .line 1095
    move v3, v6

    .line 1096
    move-object v6, v1

    .line 1097
    move-object v1, v5

    .line 1098
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1099
    .line 1100
    .line 1101
    move-result-wide v3

    .line 1102
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1103
    .line 1104
    .line 1105
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v3

    .line 1109
    invoke-virtual {v0, v3}, Landroidx/collection/h;->K(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1110
    .line 1111
    .line 1112
    goto :goto_b

    .line 1113
    :pswitch_2e
    move-object v0, v4

    .line 1114
    move v3, v6

    .line 1115
    move-object v6, v1

    .line 1116
    move-object v1, v5

    .line 1117
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1118
    .line 1119
    .line 1120
    move-result-wide v3

    .line 1121
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1122
    .line 1123
    .line 1124
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1125
    .line 1126
    .line 1127
    move-result-object v3

    .line 1128
    invoke-virtual {v0, v3}, Landroidx/collection/h;->V(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1129
    .line 1130
    .line 1131
    goto :goto_b

    .line 1132
    :pswitch_2f
    move-object v0, v4

    .line 1133
    move v3, v6

    .line 1134
    move-object v6, v1

    .line 1135
    move-object v1, v5

    .line 1136
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1137
    .line 1138
    .line 1139
    move-result-wide v3

    .line 1140
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1141
    .line 1142
    .line 1143
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v3

    .line 1147
    invoke-virtual {v0, v3}, Landroidx/collection/h;->E0(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1148
    .line 1149
    .line 1150
    goto :goto_b

    .line 1151
    :pswitch_30
    move-object v0, v4

    .line 1152
    move v3, v6

    .line 1153
    move-object v6, v1

    .line 1154
    move-object v1, v5

    .line 1155
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1156
    .line 1157
    .line 1158
    move-result-wide v3

    .line 1159
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1160
    .line 1161
    .line 1162
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v3

    .line 1166
    invoke-virtual {v0, v3}, Landroidx/collection/h;->Z(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1167
    .line 1168
    .line 1169
    goto/16 :goto_b

    .line 1170
    .line 1171
    :pswitch_31
    move-object v0, v4

    .line 1172
    move v3, v6

    .line 1173
    move-object v6, v1

    .line 1174
    move-object v1, v5

    .line 1175
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1176
    .line 1177
    .line 1178
    move-result-wide v3

    .line 1179
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1180
    .line 1181
    .line 1182
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v3

    .line 1186
    invoke-virtual {v0, v3}, Landroidx/collection/h;->O(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1187
    .line 1188
    .line 1189
    goto/16 :goto_b

    .line 1190
    .line 1191
    :pswitch_32
    move-object v0, v4

    .line 1192
    move v3, v6

    .line 1193
    move-object v6, v1

    .line 1194
    move-object v1, v5

    .line 1195
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1196
    .line 1197
    .line 1198
    move-result-wide v3

    .line 1199
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1200
    .line 1201
    .line 1202
    invoke-static {v3, v4, v2}, Landroidx/datastore/preferences/protobuf/f0;->a(JLjava/lang/Object;)Landroidx/datastore/preferences/protobuf/z;

    .line 1203
    .line 1204
    .line 1205
    move-result-object v3

    .line 1206
    invoke-virtual {v0, v3}, Landroidx/collection/h;->x(Landroidx/datastore/preferences/protobuf/z;)V

    .line 1207
    .line 1208
    .line 1209
    goto/16 :goto_b

    .line 1210
    .line 1211
    :pswitch_33
    move-object v6, v1

    .line 1212
    move v7, v3

    .line 1213
    move-object v0, v4

    .line 1214
    move-object v1, v5

    .line 1215
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->u(ILjava/lang/Object;)Ljava/lang/Object;

    .line 1216
    .line 1217
    .line 1218
    move-result-object v3

    .line 1219
    check-cast v3, Landroidx/datastore/preferences/protobuf/a;

    .line 1220
    .line 1221
    invoke-virtual {v6, v7}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v4

    .line 1225
    invoke-virtual {v0, v15}, Landroidx/collection/h;->J0(I)V

    .line 1226
    .line 1227
    .line 1228
    invoke-virtual {v0, v3, v4, v1}, Landroidx/collection/h;->i(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V

    .line 1229
    .line 1230
    .line 1231
    invoke-virtual {v6, v2, v7, v3}, Landroidx/datastore/preferences/protobuf/r0;->I(Ljava/lang/Object;ILandroidx/datastore/preferences/protobuf/a;)V

    .line 1232
    .line 1233
    .line 1234
    goto/16 :goto_b

    .line 1235
    .line 1236
    :pswitch_34
    move v7, v3

    .line 1237
    move-object v0, v4

    .line 1238
    move v3, v6

    .line 1239
    move-object v6, v1

    .line 1240
    move-object v1, v5

    .line 1241
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1242
    .line 1243
    .line 1244
    move-result-wide v3

    .line 1245
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1246
    .line 1247
    .line 1248
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1249
    .line 1250
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1251
    .line 1252
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->z()J

    .line 1253
    .line 1254
    .line 1255
    move-result-wide v14

    .line 1256
    invoke-static {v3, v4, v2, v14, v15}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 1257
    .line 1258
    .line 1259
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1260
    .line 1261
    .line 1262
    goto/16 :goto_b

    .line 1263
    .line 1264
    :pswitch_35
    move v7, v3

    .line 1265
    move-object v0, v4

    .line 1266
    move v3, v6

    .line 1267
    move-object v6, v1

    .line 1268
    move-object v1, v5

    .line 1269
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1270
    .line 1271
    .line 1272
    move-result-wide v3

    .line 1273
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1274
    .line 1275
    .line 1276
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1277
    .line 1278
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1279
    .line 1280
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->y()I

    .line 1281
    .line 1282
    .line 1283
    move-result v5

    .line 1284
    invoke-static {v3, v4, v2, v5}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 1285
    .line 1286
    .line 1287
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1288
    .line 1289
    .line 1290
    goto/16 :goto_b

    .line 1291
    .line 1292
    :pswitch_36
    move v7, v3

    .line 1293
    move-object v0, v4

    .line 1294
    move v3, v6

    .line 1295
    move-object v6, v1

    .line 1296
    move-object v1, v5

    .line 1297
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1298
    .line 1299
    .line 1300
    move-result-wide v3

    .line 1301
    const/4 v14, 0x1

    .line 1302
    invoke-virtual {v0, v14}, Landroidx/collection/h;->J0(I)V

    .line 1303
    .line 1304
    .line 1305
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1306
    .line 1307
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1308
    .line 1309
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->x()J

    .line 1310
    .line 1311
    .line 1312
    move-result-wide v14

    .line 1313
    invoke-static {v3, v4, v2, v14, v15}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 1314
    .line 1315
    .line 1316
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1317
    .line 1318
    .line 1319
    goto/16 :goto_b

    .line 1320
    .line 1321
    :pswitch_37
    move v7, v3

    .line 1322
    move-object v0, v4

    .line 1323
    move v3, v6

    .line 1324
    move-object v6, v1

    .line 1325
    move-object v1, v5

    .line 1326
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1327
    .line 1328
    .line 1329
    move-result-wide v3

    .line 1330
    const/4 v14, 0x5

    .line 1331
    invoke-virtual {v0, v14}, Landroidx/collection/h;->J0(I)V

    .line 1332
    .line 1333
    .line 1334
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1335
    .line 1336
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1337
    .line 1338
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->w()I

    .line 1339
    .line 1340
    .line 1341
    move-result v5

    .line 1342
    invoke-static {v3, v4, v2, v5}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 1343
    .line 1344
    .line 1345
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1346
    .line 1347
    .line 1348
    goto/16 :goto_b

    .line 1349
    .line 1350
    :pswitch_38
    move v7, v3

    .line 1351
    move-object v0, v4

    .line 1352
    move v3, v6

    .line 1353
    move-object v6, v1

    .line 1354
    move-object v1, v5

    .line 1355
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1356
    .line 1357
    .line 1358
    iget-object v4, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1359
    .line 1360
    check-cast v4, Landroidx/datastore/preferences/protobuf/k;

    .line 1361
    .line 1362
    invoke-virtual {v4}, Landroidx/datastore/preferences/protobuf/k;->q()I

    .line 1363
    .line 1364
    .line 1365
    move-result v4

    .line 1366
    invoke-virtual {v6, v7}, Landroidx/datastore/preferences/protobuf/r0;->l(I)V

    .line 1367
    .line 1368
    .line 1369
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1370
    .line 1371
    .line 1372
    move-result-wide v14

    .line 1373
    invoke-static {v14, v15, v2, v4}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 1374
    .line 1375
    .line 1376
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1377
    .line 1378
    .line 1379
    goto/16 :goto_b

    .line 1380
    .line 1381
    :pswitch_39
    move v7, v3

    .line 1382
    move-object v0, v4

    .line 1383
    move v3, v6

    .line 1384
    move-object v6, v1

    .line 1385
    move-object v1, v5

    .line 1386
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1387
    .line 1388
    .line 1389
    move-result-wide v3

    .line 1390
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1391
    .line 1392
    .line 1393
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1394
    .line 1395
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1396
    .line 1397
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 1398
    .line 1399
    .line 1400
    move-result v5

    .line 1401
    invoke-static {v3, v4, v2, v5}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 1402
    .line 1403
    .line 1404
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1405
    .line 1406
    .line 1407
    goto/16 :goto_b

    .line 1408
    .line 1409
    :pswitch_3a
    move v7, v3

    .line 1410
    move-object v0, v4

    .line 1411
    move v3, v6

    .line 1412
    move-object v6, v1

    .line 1413
    move-object v1, v5

    .line 1414
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1415
    .line 1416
    .line 1417
    move-result-wide v3

    .line 1418
    invoke-virtual {v0}, Landroidx/collection/h;->q()Landroidx/datastore/preferences/protobuf/h;

    .line 1419
    .line 1420
    .line 1421
    move-result-object v5

    .line 1422
    invoke-static {v2, v3, v4, v5}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1423
    .line 1424
    .line 1425
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1426
    .line 1427
    .line 1428
    goto/16 :goto_b

    .line 1429
    .line 1430
    :pswitch_3b
    move-object v6, v1

    .line 1431
    move v7, v3

    .line 1432
    move-object v0, v4

    .line 1433
    move-object v1, v5

    .line 1434
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->u(ILjava/lang/Object;)Ljava/lang/Object;

    .line 1435
    .line 1436
    .line 1437
    move-result-object v3

    .line 1438
    check-cast v3, Landroidx/datastore/preferences/protobuf/a;

    .line 1439
    .line 1440
    invoke-virtual {v6, v7}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v4

    .line 1444
    const/4 v14, 0x2

    .line 1445
    invoke-virtual {v0, v14}, Landroidx/collection/h;->J0(I)V

    .line 1446
    .line 1447
    .line 1448
    invoke-virtual {v0, v3, v4, v1}, Landroidx/collection/h;->k(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V

    .line 1449
    .line 1450
    .line 1451
    invoke-virtual {v6, v2, v7, v3}, Landroidx/datastore/preferences/protobuf/r0;->I(Ljava/lang/Object;ILandroidx/datastore/preferences/protobuf/a;)V

    .line 1452
    .line 1453
    .line 1454
    goto/16 :goto_b

    .line 1455
    .line 1456
    :pswitch_3c
    move v7, v3

    .line 1457
    move-object v0, v4

    .line 1458
    move v3, v6

    .line 1459
    move-object v6, v1

    .line 1460
    move-object v1, v5

    .line 1461
    invoke-virtual {v6, v3, v0, v2}, Landroidx/datastore/preferences/protobuf/r0;->D(ILandroidx/collection/h;Ljava/lang/Object;)V

    .line 1462
    .line 1463
    .line 1464
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1465
    .line 1466
    .line 1467
    goto/16 :goto_b

    .line 1468
    .line 1469
    :pswitch_3d
    move v7, v3

    .line 1470
    move-object v0, v4

    .line 1471
    move v3, v6

    .line 1472
    move-object v6, v1

    .line 1473
    move-object v1, v5

    .line 1474
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1475
    .line 1476
    .line 1477
    move-result-wide v3

    .line 1478
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1479
    .line 1480
    .line 1481
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1482
    .line 1483
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1484
    .line 1485
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->m()Z

    .line 1486
    .line 1487
    .line 1488
    move-result v5

    .line 1489
    sget-object v14, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 1490
    .line 1491
    invoke-virtual {v14, v2, v3, v4, v5}, Landroidx/datastore/preferences/protobuf/m1;->j(Ljava/lang/Object;JZ)V

    .line 1492
    .line 1493
    .line 1494
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1495
    .line 1496
    .line 1497
    goto/16 :goto_b

    .line 1498
    .line 1499
    :pswitch_3e
    move v7, v3

    .line 1500
    move-object v0, v4

    .line 1501
    move v3, v6

    .line 1502
    move-object v6, v1

    .line 1503
    move-object v1, v5

    .line 1504
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1505
    .line 1506
    .line 1507
    move-result-wide v3

    .line 1508
    const/4 v14, 0x5

    .line 1509
    invoke-virtual {v0, v14}, Landroidx/collection/h;->J0(I)V

    .line 1510
    .line 1511
    .line 1512
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1513
    .line 1514
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1515
    .line 1516
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 1517
    .line 1518
    .line 1519
    move-result v5

    .line 1520
    invoke-static {v3, v4, v2, v5}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 1521
    .line 1522
    .line 1523
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1524
    .line 1525
    .line 1526
    goto/16 :goto_b

    .line 1527
    .line 1528
    :pswitch_3f
    move v7, v3

    .line 1529
    move-object v0, v4

    .line 1530
    move v3, v6

    .line 1531
    move-object v6, v1

    .line 1532
    move-object v1, v5

    .line 1533
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1534
    .line 1535
    .line 1536
    move-result-wide v3

    .line 1537
    const/4 v14, 0x1

    .line 1538
    invoke-virtual {v0, v14}, Landroidx/collection/h;->J0(I)V

    .line 1539
    .line 1540
    .line 1541
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1542
    .line 1543
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1544
    .line 1545
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 1546
    .line 1547
    .line 1548
    move-result-wide v14

    .line 1549
    invoke-static {v3, v4, v2, v14, v15}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 1550
    .line 1551
    .line 1552
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1553
    .line 1554
    .line 1555
    goto/16 :goto_b

    .line 1556
    .line 1557
    :pswitch_40
    move v7, v3

    .line 1558
    move-object v0, v4

    .line 1559
    move v3, v6

    .line 1560
    move-object v6, v1

    .line 1561
    move-object v1, v5

    .line 1562
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1563
    .line 1564
    .line 1565
    move-result-wide v3

    .line 1566
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1567
    .line 1568
    .line 1569
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1570
    .line 1571
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1572
    .line 1573
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->u()I

    .line 1574
    .line 1575
    .line 1576
    move-result v5

    .line 1577
    invoke-static {v3, v4, v2, v5}, Landroidx/datastore/preferences/protobuf/n1;->m(JLjava/lang/Object;I)V

    .line 1578
    .line 1579
    .line 1580
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1581
    .line 1582
    .line 1583
    goto/16 :goto_b

    .line 1584
    .line 1585
    :pswitch_41
    move v7, v3

    .line 1586
    move-object v0, v4

    .line 1587
    move v3, v6

    .line 1588
    move-object v6, v1

    .line 1589
    move-object v1, v5

    .line 1590
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1591
    .line 1592
    .line 1593
    move-result-wide v3

    .line 1594
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1595
    .line 1596
    .line 1597
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1598
    .line 1599
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1600
    .line 1601
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->E()J

    .line 1602
    .line 1603
    .line 1604
    move-result-wide v14

    .line 1605
    invoke-static {v3, v4, v2, v14, v15}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 1606
    .line 1607
    .line 1608
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1609
    .line 1610
    .line 1611
    goto/16 :goto_b

    .line 1612
    .line 1613
    :pswitch_42
    move v7, v3

    .line 1614
    move-object v0, v4

    .line 1615
    move v3, v6

    .line 1616
    move-object v6, v1

    .line 1617
    move-object v1, v5

    .line 1618
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1619
    .line 1620
    .line 1621
    move-result-wide v3

    .line 1622
    invoke-virtual {v0, v13}, Landroidx/collection/h;->J0(I)V

    .line 1623
    .line 1624
    .line 1625
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1626
    .line 1627
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1628
    .line 1629
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 1630
    .line 1631
    .line 1632
    move-result-wide v14

    .line 1633
    invoke-static {v3, v4, v2, v14, v15}, Landroidx/datastore/preferences/protobuf/n1;->n(JLjava/lang/Object;J)V

    .line 1634
    .line 1635
    .line 1636
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1637
    .line 1638
    .line 1639
    goto/16 :goto_b

    .line 1640
    .line 1641
    :pswitch_43
    move v7, v3

    .line 1642
    move-object v0, v4

    .line 1643
    move v3, v6

    .line 1644
    move-object v6, v1

    .line 1645
    move-object v1, v5

    .line 1646
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1647
    .line 1648
    .line 1649
    move-result-wide v3

    .line 1650
    const/4 v14, 0x5

    .line 1651
    invoke-virtual {v0, v14}, Landroidx/collection/h;->J0(I)V

    .line 1652
    .line 1653
    .line 1654
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1655
    .line 1656
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1657
    .line 1658
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->t()F

    .line 1659
    .line 1660
    .line 1661
    move-result v5

    .line 1662
    sget-object v14, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 1663
    .line 1664
    invoke-virtual {v14, v2, v3, v4, v5}, Landroidx/datastore/preferences/protobuf/m1;->m(Ljava/lang/Object;JF)V

    .line 1665
    .line 1666
    .line 1667
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 1668
    .line 1669
    .line 1670
    goto/16 :goto_b

    .line 1671
    .line 1672
    :pswitch_44
    move v7, v3

    .line 1673
    move-object v0, v4

    .line 1674
    move v3, v6

    .line 1675
    move-object v6, v1

    .line 1676
    move-object v1, v5

    .line 1677
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->x(I)J

    .line 1678
    .line 1679
    .line 1680
    move-result-wide v3

    .line 1681
    const/4 v14, 0x1

    .line 1682
    invoke-virtual {v0, v14}, Landroidx/collection/h;->J0(I)V

    .line 1683
    .line 1684
    .line 1685
    iget-object v5, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 1686
    .line 1687
    check-cast v5, Landroidx/datastore/preferences/protobuf/k;

    .line 1688
    .line 1689
    invoke-virtual {v5}, Landroidx/datastore/preferences/protobuf/k;->p()D

    .line 1690
    .line 1691
    .line 1692
    move-result-wide v14
    :try_end_b
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_b .. :try_end_b} :catch_5
    .catchall {:try_start_b .. :try_end_b} :catchall_2

    .line 1693
    :try_start_c
    sget-object v0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;
    :try_end_c
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_c .. :try_end_c} :catch_7
    .catchall {:try_start_c .. :try_end_c} :catchall_2

    .line 1694
    .line 1695
    move-object v1, v2

    .line 1696
    move-wide v2, v3

    .line 1697
    move-wide v4, v14

    .line 1698
    move-object/from16 v14, p2

    .line 1699
    .line 1700
    :try_start_d
    invoke-virtual/range {v0 .. v5}, Landroidx/datastore/preferences/protobuf/m1;->l(Ljava/lang/Object;JD)V
    :try_end_d
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_d .. :try_end_d} :catch_6
    .catchall {:try_start_d .. :try_end_d} :catchall_3

    .line 1701
    .line 1702
    .line 1703
    move-object v2, v1

    .line 1704
    :try_start_e
    invoke-virtual {v6, v7, v2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V
    :try_end_e
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_e .. :try_end_e} :catch_8
    .catchall {:try_start_e .. :try_end_e} :catchall_2

    .line 1705
    .line 1706
    .line 1707
    goto :goto_f

    .line 1708
    :catchall_3
    move-exception v0

    .line 1709
    move-object v2, v1

    .line 1710
    goto :goto_10

    .line 1711
    :catch_6
    move-object v2, v1

    .line 1712
    goto :goto_c

    .line 1713
    :catch_7
    move-object/from16 v14, p2

    .line 1714
    .line 1715
    :catch_8
    :goto_c
    :try_start_f
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1716
    .line 1717
    .line 1718
    if-nez v12, :cond_9

    .line 1719
    .line 1720
    invoke-static {v2}, Landroidx/datastore/preferences/protobuf/i1;->a(Ljava/lang/Object;)Landroidx/datastore/preferences/protobuf/h1;

    .line 1721
    .line 1722
    .line 1723
    move-result-object v0

    .line 1724
    move-object v12, v0

    .line 1725
    :cond_9
    invoke-static {v13, v14, v12}, Landroidx/datastore/preferences/protobuf/i1;->b(ILandroidx/collection/h;Ljava/lang/Object;)Z

    .line 1726
    .line 1727
    .line 1728
    move-result v0
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_2

    .line 1729
    if-nez v0, :cond_c

    .line 1730
    .line 1731
    :goto_d
    if-ge v11, v10, :cond_a

    .line 1732
    .line 1733
    aget v0, v9, v11

    .line 1734
    .line 1735
    invoke-virtual {v6, v0, v2, v12}, Landroidx/datastore/preferences/protobuf/r0;->k(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1736
    .line 1737
    .line 1738
    add-int/lit8 v11, v11, 0x1

    .line 1739
    .line 1740
    goto :goto_d

    .line 1741
    :cond_a
    if-eqz v12, :cond_b

    .line 1742
    .line 1743
    goto/16 :goto_6

    .line 1744
    .line 1745
    :cond_b
    :goto_e
    return-void

    .line 1746
    :cond_c
    :goto_f
    move-object/from16 v5, p3

    .line 1747
    .line 1748
    move-object v1, v6

    .line 1749
    move-object v4, v14

    .line 1750
    goto/16 :goto_0

    .line 1751
    .line 1752
    :goto_10
    if-ge v11, v10, :cond_d

    .line 1753
    .line 1754
    aget v1, v9, v11

    .line 1755
    .line 1756
    invoke-virtual {v6, v1, v2, v12}, Landroidx/datastore/preferences/protobuf/r0;->k(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1757
    .line 1758
    .line 1759
    add-int/lit8 v11, v11, 0x1

    .line 1760
    .line 1761
    goto :goto_10

    .line 1762
    :cond_d
    if-eqz v12, :cond_e

    .line 1763
    .line 1764
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1765
    .line 1766
    .line 1767
    move-object v1, v2

    .line 1768
    check-cast v1, Landroidx/datastore/preferences/protobuf/x;

    .line 1769
    .line 1770
    iput-object v12, v1, Landroidx/datastore/preferences/protobuf/x;->unknownFields:Landroidx/datastore/preferences/protobuf/h1;

    .line 1771
    .line 1772
    :cond_e
    throw v0

    .line 1773
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1774
    .line 1775
    const-string v1, "Mutating immutable message: "

    .line 1776
    .line 1777
    invoke-static {v2, v1}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 1778
    .line 1779
    .line 1780
    move-result-object v1

    .line 1781
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1782
    .line 1783
    .line 1784
    throw v0

    .line 1785
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final j(Landroidx/datastore/preferences/protobuf/x;Landroidx/datastore/preferences/protobuf/x;I)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p3, p1}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p0, p3, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-ne p1, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final k(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object p3, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 2
    .line 3
    aget p3, p3, p1

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 6
    .line 7
    .line 8
    move-result p3

    .line 9
    const v0, 0xfffff

    .line 10
    .line 11
    .line 12
    and-int/2addr p3, v0

    .line 13
    int-to-long v0, p3

    .line 14
    sget-object p3, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 15
    .line 16
    invoke-virtual {p3, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    if-nez p2, :cond_0

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->l(I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final l(I)V
    .locals 3

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x1

    .line 3
    const/4 v2, 0x3

    .line 4
    invoke-static {p1, v2, v0, v1}, La7/g0;->d(IIII)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->b:[Ljava/lang/Object;

    .line 9
    .line 10
    aget-object p0, p0, p1

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public final m(I)Landroidx/datastore/preferences/protobuf/a1;
    .locals 2

    .line 1
    div-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    mul-int/lit8 p1, p1, 0x2

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->b:[Ljava/lang/Object;

    .line 6
    .line 7
    aget-object v0, p0, p1

    .line 8
    .line 9
    check-cast v0, Landroidx/datastore/preferences/protobuf/a1;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    sget-object v0, Landroidx/datastore/preferences/protobuf/x0;->c:Landroidx/datastore/preferences/protobuf/x0;

    .line 15
    .line 16
    add-int/lit8 v1, p1, 0x1

    .line 17
    .line 18
    aget-object v1, p0, v1

    .line 19
    .line 20
    check-cast v1, Ljava/lang/Class;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Landroidx/datastore/preferences/protobuf/x0;->a(Ljava/lang/Class;)Landroidx/datastore/preferences/protobuf/a1;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    aput-object v0, p0, p1

    .line 27
    .line 28
    return-object v0
.end method

.method public final n(ILjava/lang/Object;)Z
    .locals 6

    .line 1
    add-int/lit8 v0, p1, 0x2

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget v0, v1, v0

    .line 6
    .line 7
    const v1, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int v2, v0, v1

    .line 11
    .line 12
    int-to-long v2, v2

    .line 13
    const-wide/32 v4, 0xfffff

    .line 14
    .line 15
    .line 16
    cmp-long v4, v2, v4

    .line 17
    .line 18
    const/4 v5, 0x1

    .line 19
    if-nez v4, :cond_2

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    and-int p1, p0, v1

    .line 26
    .line 27
    int-to-long v0, p1

    .line 28
    invoke-static {p0}, Landroidx/datastore/preferences/protobuf/r0;->K(I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    const-wide/16 v2, 0x0

    .line 33
    .line 34
    packed-switch p0, :pswitch_data_0

    .line 35
    .line 36
    .line 37
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 38
    .line 39
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :pswitch_0
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 44
    .line 45
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    if-eqz p0, :cond_3

    .line 50
    .line 51
    goto/16 :goto_0

    .line 52
    .line 53
    :pswitch_1
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 54
    .line 55
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 56
    .line 57
    .line 58
    move-result-wide p0

    .line 59
    cmp-long p0, p0, v2

    .line 60
    .line 61
    if-eqz p0, :cond_3

    .line 62
    .line 63
    goto/16 :goto_0

    .line 64
    .line 65
    :pswitch_2
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 66
    .line 67
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    goto/16 :goto_0

    .line 74
    .line 75
    :pswitch_3
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 76
    .line 77
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 78
    .line 79
    .line 80
    move-result-wide p0

    .line 81
    cmp-long p0, p0, v2

    .line 82
    .line 83
    if-eqz p0, :cond_3

    .line 84
    .line 85
    goto/16 :goto_0

    .line 86
    .line 87
    :pswitch_4
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 88
    .line 89
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-eqz p0, :cond_3

    .line 94
    .line 95
    goto/16 :goto_0

    .line 96
    .line 97
    :pswitch_5
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 98
    .line 99
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    if-eqz p0, :cond_3

    .line 104
    .line 105
    goto/16 :goto_0

    .line 106
    .line 107
    :pswitch_6
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 108
    .line 109
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    if-eqz p0, :cond_3

    .line 114
    .line 115
    goto/16 :goto_0

    .line 116
    .line 117
    :pswitch_7
    sget-object p0, Landroidx/datastore/preferences/protobuf/h;->f:Landroidx/datastore/preferences/protobuf/h;

    .line 118
    .line 119
    sget-object p1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 120
    .line 121
    invoke-virtual {p1, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/h;->equals(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result p0

    .line 129
    xor-int/2addr p0, v5

    .line 130
    return p0

    .line 131
    :pswitch_8
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 132
    .line 133
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-eqz p0, :cond_3

    .line 138
    .line 139
    goto/16 :goto_0

    .line 140
    .line 141
    :pswitch_9
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 142
    .line 143
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    instance-of p1, p0, Ljava/lang/String;

    .line 148
    .line 149
    if-eqz p1, :cond_0

    .line 150
    .line 151
    check-cast p0, Ljava/lang/String;

    .line 152
    .line 153
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    xor-int/2addr p0, v5

    .line 158
    return p0

    .line 159
    :cond_0
    instance-of p1, p0, Landroidx/datastore/preferences/protobuf/h;

    .line 160
    .line 161
    if-eqz p1, :cond_1

    .line 162
    .line 163
    sget-object p1, Landroidx/datastore/preferences/protobuf/h;->f:Landroidx/datastore/preferences/protobuf/h;

    .line 164
    .line 165
    invoke-virtual {p1, p0}, Landroidx/datastore/preferences/protobuf/h;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result p0

    .line 169
    xor-int/2addr p0, v5

    .line 170
    return p0

    .line 171
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 172
    .line 173
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 174
    .line 175
    .line 176
    throw p0

    .line 177
    :pswitch_a
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 178
    .line 179
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->c(JLjava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result p0

    .line 183
    return p0

    .line 184
    :pswitch_b
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 185
    .line 186
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 187
    .line 188
    .line 189
    move-result p0

    .line 190
    if-eqz p0, :cond_3

    .line 191
    .line 192
    goto :goto_0

    .line 193
    :pswitch_c
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 194
    .line 195
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 196
    .line 197
    .line 198
    move-result-wide p0

    .line 199
    cmp-long p0, p0, v2

    .line 200
    .line 201
    if-eqz p0, :cond_3

    .line 202
    .line 203
    goto :goto_0

    .line 204
    :pswitch_d
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 205
    .line 206
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    if-eqz p0, :cond_3

    .line 211
    .line 212
    goto :goto_0

    .line 213
    :pswitch_e
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 214
    .line 215
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 216
    .line 217
    .line 218
    move-result-wide p0

    .line 219
    cmp-long p0, p0, v2

    .line 220
    .line 221
    if-eqz p0, :cond_3

    .line 222
    .line 223
    goto :goto_0

    .line 224
    :pswitch_f
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 225
    .line 226
    invoke-virtual {p0, p2, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->g(Ljava/lang/Object;J)J

    .line 227
    .line 228
    .line 229
    move-result-wide p0

    .line 230
    cmp-long p0, p0, v2

    .line 231
    .line 232
    if-eqz p0, :cond_3

    .line 233
    .line 234
    goto :goto_0

    .line 235
    :pswitch_10
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 236
    .line 237
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->e(JLjava/lang/Object;)F

    .line 238
    .line 239
    .line 240
    move-result p0

    .line 241
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 242
    .line 243
    .line 244
    move-result p0

    .line 245
    if-eqz p0, :cond_3

    .line 246
    .line 247
    goto :goto_0

    .line 248
    :pswitch_11
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 249
    .line 250
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->d(JLjava/lang/Object;)D

    .line 251
    .line 252
    .line 253
    move-result-wide p0

    .line 254
    invoke-static {p0, p1}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 255
    .line 256
    .line 257
    move-result-wide p0

    .line 258
    cmp-long p0, p0, v2

    .line 259
    .line 260
    if-eqz p0, :cond_3

    .line 261
    .line 262
    goto :goto_0

    .line 263
    :cond_2
    ushr-int/lit8 p0, v0, 0x14

    .line 264
    .line 265
    shl-int p0, v5, p0

    .line 266
    .line 267
    sget-object p1, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 268
    .line 269
    invoke-virtual {p1, v2, v3, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 270
    .line 271
    .line 272
    move-result p1

    .line 273
    and-int/2addr p0, p1

    .line 274
    if-eqz p0, :cond_3

    .line 275
    .line 276
    :goto_0
    return v5

    .line 277
    :cond_3
    const/4 p0, 0x0

    .line 278
    return p0

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final o(Ljava/lang/Object;IIII)Z
    .locals 1

    .line 1
    const v0, 0xfffff

    .line 2
    .line 3
    .line 4
    if-ne p3, v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, p2, p1}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :cond_0
    and-int p0, p4, p5

    .line 12
    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_1
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final q(ILjava/lang/Object;I)Z
    .locals 2

    .line 1
    add-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p3

    .line 6
    .line 7
    const p3, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr p0, p3

    .line 11
    int-to-long v0, p0

    .line 12
    sget-object p0, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 13
    .line 14
    invoke-virtual {p0, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/m1;->f(JLjava/lang/Object;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-ne p0, p1, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final r(Ljava/lang/Object;ILjava/lang/Object;Landroidx/datastore/preferences/protobuf/o;Landroidx/collection/h;)V
    .locals 7

    .line 1
    invoke-virtual {p0, p2}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    const v0, 0xfffff

    .line 6
    .line 7
    .line 8
    and-int/2addr p2, v0

    .line 9
    int-to-long v0, p2

    .line 10
    sget-object p2, Landroidx/datastore/preferences/protobuf/n1;->c:Landroidx/datastore/preferences/protobuf/m1;

    .line 11
    .line 12
    invoke-virtual {p2, p1, v0, v1}, Landroidx/datastore/preferences/protobuf/m1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->m:Landroidx/datastore/preferences/protobuf/n0;

    .line 17
    .line 18
    if-nez p2, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    sget-object p2, Landroidx/datastore/preferences/protobuf/m0;->e:Landroidx/datastore/preferences/protobuf/m0;

    .line 24
    .line 25
    invoke-virtual {p2}, Landroidx/datastore/preferences/protobuf/m0;->b()Landroidx/datastore/preferences/protobuf/m0;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    invoke-static {p1, v0, v1, p2}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    move-object v2, p2

    .line 37
    check-cast v2, Landroidx/datastore/preferences/protobuf/m0;

    .line 38
    .line 39
    iget-boolean v2, v2, Landroidx/datastore/preferences/protobuf/m0;->d:Z

    .line 40
    .line 41
    if-nez v2, :cond_1

    .line 42
    .line 43
    sget-object v2, Landroidx/datastore/preferences/protobuf/m0;->e:Landroidx/datastore/preferences/protobuf/m0;

    .line 44
    .line 45
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/m0;->b()Landroidx/datastore/preferences/protobuf/m0;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-static {v2, p2}, Landroidx/datastore/preferences/protobuf/n0;->a(Ljava/lang/Object;Ljava/lang/Object;)Landroidx/datastore/preferences/protobuf/m0;

    .line 50
    .line 51
    .line 52
    invoke-static {p1, v0, v1, v2}, Landroidx/datastore/preferences/protobuf/n1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    move-object p2, v2

    .line 56
    :cond_1
    :goto_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    check-cast p2, Landroidx/datastore/preferences/protobuf/m0;

    .line 60
    .line 61
    check-cast p3, Landroidx/datastore/preferences/protobuf/l0;

    .line 62
    .line 63
    iget-object p0, p3, Landroidx/datastore/preferences/protobuf/l0;->a:Landroidx/datastore/preferences/protobuf/k0;

    .line 64
    .line 65
    const/4 p1, 0x2

    .line 66
    invoke-virtual {p5, p1}, Landroidx/collection/h;->J0(I)V

    .line 67
    .line 68
    .line 69
    iget-object p3, p5, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p3, Landroidx/datastore/preferences/protobuf/k;

    .line 72
    .line 73
    invoke-virtual {p3}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    invoke-virtual {p3, v0}, Landroidx/datastore/preferences/protobuf/k;->l(I)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    iget-object v1, p0, Landroidx/datastore/preferences/protobuf/k0;->c:Ljava/lang/Object;

    .line 82
    .line 83
    const-string v2, ""

    .line 84
    .line 85
    move-object v3, v1

    .line 86
    :goto_1
    :try_start_0
    invoke-virtual {p5}, Landroidx/collection/h;->e()I

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    const v5, 0x7fffffff

    .line 91
    .line 92
    .line 93
    if-eq v4, v5, :cond_7

    .line 94
    .line 95
    invoke-virtual {p3}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 96
    .line 97
    .line 98
    move-result v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 99
    if-eqz v5, :cond_2

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_2
    const/4 v5, 0x1

    .line 103
    const-string v6, "Unable to parse map entry."

    .line 104
    .line 105
    if-eq v4, v5, :cond_5

    .line 106
    .line 107
    if-eq v4, p1, :cond_4

    .line 108
    .line 109
    :try_start_1
    invoke-virtual {p5}, Landroidx/collection/h;->L0()Z

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    if-eqz v4, :cond_3

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_3
    new-instance v4, Landroidx/datastore/preferences/protobuf/c0;

    .line 117
    .line 118
    invoke-direct {v4, v6}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw v4

    .line 122
    :catchall_0
    move-exception p0

    .line 123
    goto :goto_3

    .line 124
    :cond_4
    iget-object v4, p0, Landroidx/datastore/preferences/protobuf/k0;->b:Landroidx/datastore/preferences/protobuf/v1;

    .line 125
    .line 126
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    invoke-virtual {p5, v4, v5, p4}, Landroidx/collection/h;->E(Landroidx/datastore/preferences/protobuf/v1;Ljava/lang/Class;Landroidx/datastore/preferences/protobuf/o;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    goto :goto_1

    .line 135
    :cond_5
    iget-object v4, p0, Landroidx/datastore/preferences/protobuf/k0;->a:Landroidx/datastore/preferences/protobuf/v1;

    .line 136
    .line 137
    const/4 v5, 0x0

    .line 138
    invoke-virtual {p5, v4, v5, v5}, Landroidx/collection/h;->E(Landroidx/datastore/preferences/protobuf/v1;Ljava/lang/Class;Landroidx/datastore/preferences/protobuf/o;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v2
    :try_end_1
    .catch Landroidx/datastore/preferences/protobuf/b0; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 142
    goto :goto_1

    .line 143
    :catch_0
    :try_start_2
    invoke-virtual {p5}, Landroidx/collection/h;->L0()Z

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    if-eqz v4, :cond_6

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_6
    new-instance p0, Landroidx/datastore/preferences/protobuf/c0;

    .line 151
    .line 152
    invoke-direct {p0, v6}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw p0

    .line 156
    :cond_7
    :goto_2
    invoke-virtual {p2, v2, v3}, Landroidx/datastore/preferences/protobuf/m0;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 157
    .line 158
    .line 159
    invoke-virtual {p3, v0}, Landroidx/datastore/preferences/protobuf/k;->k(I)V

    .line 160
    .line 161
    .line 162
    return-void

    .line 163
    :goto_3
    invoke-virtual {p3, v0}, Landroidx/datastore/preferences/protobuf/k;->k(I)V

    .line 164
    .line 165
    .line 166
    throw p0
.end method

.method public final s(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    invoke-virtual {p0, p1, p3}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const v1, 0xfffff

    .line 13
    .line 14
    .line 15
    and-int/2addr v0, v1

    .line 16
    int-to-long v0, v0

    .line 17
    sget-object v2, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 18
    .line 19
    invoke-virtual {v2, p3, v0, v1}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    if-eqz v3, :cond_4

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    if-nez v4, :cond_2

    .line 34
    .line 35
    invoke-static {v3}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-nez v4, :cond_1

    .line 40
    .line 41
    invoke-virtual {v2, p2, v0, v1, v3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-interface {p3}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-interface {p3, v4, v3}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v2, p2, v0, v1, v4}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :goto_0
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->G(ILjava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    invoke-virtual {v2, p2, v0, v1}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-nez p1, :cond_3

    .line 68
    .line 69
    invoke-interface {p3}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-interface {p3, p1, p0}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v2, p2, v0, v1, p1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    move-object p0, p1

    .line 80
    :cond_3
    invoke-interface {p3, p0, v3}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_4
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    new-instance v0, Ljava/lang/StringBuilder;

    .line 87
    .line 88
    const-string v1, "Source subfield "

    .line 89
    .line 90
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 94
    .line 95
    aget p0, p0, p1

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string p0, " is present but null: "

    .line 101
    .line 102
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    invoke-direct {p2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p2
.end method

.method public final t(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 6

    .line 1
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/r0;->a:[I

    .line 2
    .line 3
    aget v1, v0, p1

    .line 4
    .line 5
    invoke-virtual {p0, v1, p3, p1}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const v3, 0xfffff

    .line 17
    .line 18
    .line 19
    and-int/2addr v2, v3

    .line 20
    int-to-long v2, v2

    .line 21
    sget-object v4, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 22
    .line 23
    invoke-virtual {v4, p3, v2, v3}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v5

    .line 27
    if-eqz v5, :cond_4

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 30
    .line 31
    .line 32
    move-result-object p3

    .line 33
    invoke-virtual {p0, v1, p2, p1}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_2

    .line 38
    .line 39
    invoke-static {v5}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_1

    .line 44
    .line 45
    invoke-virtual {v4, p2, v2, v3, v5}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-interface {p3}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-interface {p3, v0, v5}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v4, p2, v2, v3, v0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :goto_0
    invoke-virtual {p0, v1, p2, p1}, Landroidx/datastore/preferences/protobuf/r0;->H(ILjava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_2
    invoke-virtual {v4, p2, v2, v3}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-static {p0}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-nez p1, :cond_3

    .line 72
    .line 73
    invoke-interface {p3}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-interface {p3, p1, p0}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v4, p2, v2, v3, p1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    move-object p0, p1

    .line 84
    :cond_3
    invoke-interface {p3, p0, v5}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 89
    .line 90
    new-instance p2, Ljava/lang/StringBuilder;

    .line 91
    .line 92
    const-string v1, "Source subfield "

    .line 93
    .line 94
    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    aget p1, v0, p1

    .line 98
    .line 99
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string p1, " is present but null: "

    .line 103
    .line 104
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw p0
.end method

.method public final u(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const v2, 0xfffff

    .line 10
    .line 11
    .line 12
    and-int/2addr v1, v2

    .line 13
    int-to-long v1, v1

    .line 14
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/r0;->n(ILjava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    invoke-interface {v0}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    sget-object p0, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 26
    .line 27
    invoke-virtual {p0, p2, v1, v2}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    invoke-interface {v0}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    invoke-interface {v0, p1, p0}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    return-object p1
.end method

.method public final v(ILjava/lang/Object;I)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0, p3}, Landroidx/datastore/preferences/protobuf/r0;->m(I)Landroidx/datastore/preferences/protobuf/a1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, p1, p2, p3}, Landroidx/datastore/preferences/protobuf/r0;->q(ILjava/lang/Object;I)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    invoke-interface {v0}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-object p1, Landroidx/datastore/preferences/protobuf/r0;->o:Lsun/misc/Unsafe;

    .line 17
    .line 18
    invoke-virtual {p0, p3}, Landroidx/datastore/preferences/protobuf/r0;->L(I)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    const p3, 0xfffff

    .line 23
    .line 24
    .line 25
    and-int/2addr p0, p3

    .line 26
    int-to-long v1, p0

    .line 27
    invoke-virtual {p1, p2, v1, v2}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, Landroidx/datastore/preferences/protobuf/r0;->p(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    invoke-interface {v0}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    invoke-interface {v0, p1, p0}, Landroidx/datastore/preferences/protobuf/a1;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    return-object p1
.end method
