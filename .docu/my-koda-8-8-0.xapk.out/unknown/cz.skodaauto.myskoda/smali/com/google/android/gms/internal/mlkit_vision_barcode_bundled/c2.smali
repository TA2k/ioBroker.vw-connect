.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;


# static fields
.field public static final l:[I

.field public static final m:Lsun/misc/Unsafe;


# instance fields
.field public final a:[I

.field public final b:[Ljava/lang/Object;

.field public final c:I

.field public final d:I

.field public final e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

.field public final f:Z

.field public final g:[I

.field public final h:I

.field public final i:I

.field public final j:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

.field public final k:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l:[I

    .line 5
    .line 6
    invoke-static {}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->i()Lsun/misc/Unsafe;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>([I[Ljava/lang/Object;IILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;[IIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->b:[Ljava/lang/Object;

    .line 7
    .line 8
    iput p3, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->c:I

    .line 9
    .line 10
    iput p4, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->d:I

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    if-eqz p10, :cond_0

    .line 14
    .line 15
    instance-of p2, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 16
    .line 17
    if-eqz p2, :cond_0

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    :cond_0
    iput-boolean p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 21
    .line 22
    iput-object p6, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->g:[I

    .line 23
    .line 24
    iput p7, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->h:I

    .line 25
    .line 26
    iput p8, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->i:I

    .line 27
    .line 28
    iput-object p9, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->j:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 29
    .line 30
    iput-object p10, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->k:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 31
    .line 32
    iput-object p5, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 33
    .line 34
    return-void
.end method

.method public static A(JLjava/lang/Object;)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Ljava/lang/Long;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    return-wide p0
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
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {v0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    const-string v2, " for "

    .line 41
    .line 42
    const-string v3, " not found. Known fields are "

    .line 43
    .line 44
    const-string v4, "Field "

    .line 45
    .line 46
    invoke-static {v4, p1, v2, p0, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v1
.end method

.method public static r(Ljava/lang/Object;)Z
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
    instance-of v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->k()Z

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

.method public static u(Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;
    .locals 2

    .line 1
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 4
    .line 5
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    invoke-static {}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 14
    .line 15
    :cond_0
    return-object v0
.end method

.method public static v(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    instance-of v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 4
    .line 5
    if-eqz v1, :cond_37

    .line 6
    .line 7
    iget-object v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->b:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    const v5, 0xd800

    .line 19
    .line 20
    .line 21
    if-lt v4, v5, :cond_0

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    :goto_0
    add-int/lit8 v7, v4, 0x1

    .line 25
    .line 26
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-lt v4, v5, :cond_1

    .line 31
    .line 32
    move v4, v7

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v7, 0x1

    .line 35
    :cond_1
    add-int/lit8 v4, v7, 0x1

    .line 36
    .line 37
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 38
    .line 39
    .line 40
    move-result v7

    .line 41
    if-lt v7, v5, :cond_3

    .line 42
    .line 43
    and-int/lit16 v7, v7, 0x1fff

    .line 44
    .line 45
    const/16 v9, 0xd

    .line 46
    .line 47
    :goto_1
    add-int/lit8 v10, v4, 0x1

    .line 48
    .line 49
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-lt v4, v5, :cond_2

    .line 54
    .line 55
    and-int/lit16 v4, v4, 0x1fff

    .line 56
    .line 57
    shl-int/2addr v4, v9

    .line 58
    or-int/2addr v7, v4

    .line 59
    add-int/lit8 v9, v9, 0xd

    .line 60
    .line 61
    move v4, v10

    .line 62
    goto :goto_1

    .line 63
    :cond_2
    shl-int/2addr v4, v9

    .line 64
    or-int/2addr v7, v4

    .line 65
    move v4, v10

    .line 66
    :cond_3
    if-nez v7, :cond_4

    .line 67
    .line 68
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l:[I

    .line 69
    .line 70
    move v9, v3

    .line 71
    move v10, v9

    .line 72
    move v11, v10

    .line 73
    move v12, v11

    .line 74
    move v13, v12

    .line 75
    move/from16 v16, v13

    .line 76
    .line 77
    move-object v15, v7

    .line 78
    move/from16 v7, v16

    .line 79
    .line 80
    goto/16 :goto_a

    .line 81
    .line 82
    :cond_4
    add-int/lit8 v7, v4, 0x1

    .line 83
    .line 84
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    if-lt v4, v5, :cond_6

    .line 89
    .line 90
    and-int/lit16 v4, v4, 0x1fff

    .line 91
    .line 92
    const/16 v9, 0xd

    .line 93
    .line 94
    :goto_2
    add-int/lit8 v10, v7, 0x1

    .line 95
    .line 96
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 97
    .line 98
    .line 99
    move-result v7

    .line 100
    if-lt v7, v5, :cond_5

    .line 101
    .line 102
    and-int/lit16 v7, v7, 0x1fff

    .line 103
    .line 104
    shl-int/2addr v7, v9

    .line 105
    or-int/2addr v4, v7

    .line 106
    add-int/lit8 v9, v9, 0xd

    .line 107
    .line 108
    move v7, v10

    .line 109
    goto :goto_2

    .line 110
    :cond_5
    shl-int/2addr v7, v9

    .line 111
    or-int/2addr v4, v7

    .line 112
    move v7, v10

    .line 113
    :cond_6
    add-int/lit8 v9, v7, 0x1

    .line 114
    .line 115
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 116
    .line 117
    .line 118
    move-result v7

    .line 119
    if-lt v7, v5, :cond_8

    .line 120
    .line 121
    and-int/lit16 v7, v7, 0x1fff

    .line 122
    .line 123
    const/16 v10, 0xd

    .line 124
    .line 125
    :goto_3
    add-int/lit8 v11, v9, 0x1

    .line 126
    .line 127
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 128
    .line 129
    .line 130
    move-result v9

    .line 131
    if-lt v9, v5, :cond_7

    .line 132
    .line 133
    and-int/lit16 v9, v9, 0x1fff

    .line 134
    .line 135
    shl-int/2addr v9, v10

    .line 136
    or-int/2addr v7, v9

    .line 137
    add-int/lit8 v10, v10, 0xd

    .line 138
    .line 139
    move v9, v11

    .line 140
    goto :goto_3

    .line 141
    :cond_7
    shl-int/2addr v9, v10

    .line 142
    or-int/2addr v7, v9

    .line 143
    move v9, v11

    .line 144
    :cond_8
    add-int/lit8 v10, v9, 0x1

    .line 145
    .line 146
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 147
    .line 148
    .line 149
    move-result v9

    .line 150
    if-lt v9, v5, :cond_a

    .line 151
    .line 152
    and-int/lit16 v9, v9, 0x1fff

    .line 153
    .line 154
    const/16 v11, 0xd

    .line 155
    .line 156
    :goto_4
    add-int/lit8 v12, v10, 0x1

    .line 157
    .line 158
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 159
    .line 160
    .line 161
    move-result v10

    .line 162
    if-lt v10, v5, :cond_9

    .line 163
    .line 164
    and-int/lit16 v10, v10, 0x1fff

    .line 165
    .line 166
    shl-int/2addr v10, v11

    .line 167
    or-int/2addr v9, v10

    .line 168
    add-int/lit8 v11, v11, 0xd

    .line 169
    .line 170
    move v10, v12

    .line 171
    goto :goto_4

    .line 172
    :cond_9
    shl-int/2addr v10, v11

    .line 173
    or-int/2addr v9, v10

    .line 174
    move v10, v12

    .line 175
    :cond_a
    add-int/lit8 v11, v10, 0x1

    .line 176
    .line 177
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 178
    .line 179
    .line 180
    move-result v10

    .line 181
    if-lt v10, v5, :cond_c

    .line 182
    .line 183
    and-int/lit16 v10, v10, 0x1fff

    .line 184
    .line 185
    const/16 v12, 0xd

    .line 186
    .line 187
    :goto_5
    add-int/lit8 v13, v11, 0x1

    .line 188
    .line 189
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 190
    .line 191
    .line 192
    move-result v11

    .line 193
    if-lt v11, v5, :cond_b

    .line 194
    .line 195
    and-int/lit16 v11, v11, 0x1fff

    .line 196
    .line 197
    shl-int/2addr v11, v12

    .line 198
    or-int/2addr v10, v11

    .line 199
    add-int/lit8 v12, v12, 0xd

    .line 200
    .line 201
    move v11, v13

    .line 202
    goto :goto_5

    .line 203
    :cond_b
    shl-int/2addr v11, v12

    .line 204
    or-int/2addr v10, v11

    .line 205
    move v11, v13

    .line 206
    :cond_c
    add-int/lit8 v12, v11, 0x1

    .line 207
    .line 208
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 209
    .line 210
    .line 211
    move-result v11

    .line 212
    if-lt v11, v5, :cond_e

    .line 213
    .line 214
    and-int/lit16 v11, v11, 0x1fff

    .line 215
    .line 216
    const/16 v13, 0xd

    .line 217
    .line 218
    :goto_6
    add-int/lit8 v14, v12, 0x1

    .line 219
    .line 220
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 221
    .line 222
    .line 223
    move-result v12

    .line 224
    if-lt v12, v5, :cond_d

    .line 225
    .line 226
    and-int/lit16 v12, v12, 0x1fff

    .line 227
    .line 228
    shl-int/2addr v12, v13

    .line 229
    or-int/2addr v11, v12

    .line 230
    add-int/lit8 v13, v13, 0xd

    .line 231
    .line 232
    move v12, v14

    .line 233
    goto :goto_6

    .line 234
    :cond_d
    shl-int/2addr v12, v13

    .line 235
    or-int/2addr v11, v12

    .line 236
    move v12, v14

    .line 237
    :cond_e
    add-int/lit8 v13, v12, 0x1

    .line 238
    .line 239
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 240
    .line 241
    .line 242
    move-result v12

    .line 243
    if-lt v12, v5, :cond_10

    .line 244
    .line 245
    and-int/lit16 v12, v12, 0x1fff

    .line 246
    .line 247
    const/16 v14, 0xd

    .line 248
    .line 249
    :goto_7
    add-int/lit8 v15, v13, 0x1

    .line 250
    .line 251
    invoke-virtual {v1, v13}, Ljava/lang/String;->charAt(I)C

    .line 252
    .line 253
    .line 254
    move-result v13

    .line 255
    if-lt v13, v5, :cond_f

    .line 256
    .line 257
    and-int/lit16 v13, v13, 0x1fff

    .line 258
    .line 259
    shl-int/2addr v13, v14

    .line 260
    or-int/2addr v12, v13

    .line 261
    add-int/lit8 v14, v14, 0xd

    .line 262
    .line 263
    move v13, v15

    .line 264
    goto :goto_7

    .line 265
    :cond_f
    shl-int/2addr v13, v14

    .line 266
    or-int/2addr v12, v13

    .line 267
    move v13, v15

    .line 268
    :cond_10
    add-int/lit8 v14, v13, 0x1

    .line 269
    .line 270
    invoke-virtual {v1, v13}, Ljava/lang/String;->charAt(I)C

    .line 271
    .line 272
    .line 273
    move-result v13

    .line 274
    if-lt v13, v5, :cond_12

    .line 275
    .line 276
    and-int/lit16 v13, v13, 0x1fff

    .line 277
    .line 278
    const/16 v15, 0xd

    .line 279
    .line 280
    :goto_8
    add-int/lit8 v16, v14, 0x1

    .line 281
    .line 282
    invoke-virtual {v1, v14}, Ljava/lang/String;->charAt(I)C

    .line 283
    .line 284
    .line 285
    move-result v14

    .line 286
    if-lt v14, v5, :cond_11

    .line 287
    .line 288
    and-int/lit16 v14, v14, 0x1fff

    .line 289
    .line 290
    shl-int/2addr v14, v15

    .line 291
    or-int/2addr v13, v14

    .line 292
    add-int/lit8 v15, v15, 0xd

    .line 293
    .line 294
    move/from16 v14, v16

    .line 295
    .line 296
    goto :goto_8

    .line 297
    :cond_11
    shl-int/2addr v14, v15

    .line 298
    or-int/2addr v13, v14

    .line 299
    move/from16 v14, v16

    .line 300
    .line 301
    :cond_12
    add-int/lit8 v15, v14, 0x1

    .line 302
    .line 303
    invoke-virtual {v1, v14}, Ljava/lang/String;->charAt(I)C

    .line 304
    .line 305
    .line 306
    move-result v14

    .line 307
    if-lt v14, v5, :cond_14

    .line 308
    .line 309
    and-int/lit16 v14, v14, 0x1fff

    .line 310
    .line 311
    const/16 v16, 0xd

    .line 312
    .line 313
    :goto_9
    add-int/lit8 v17, v15, 0x1

    .line 314
    .line 315
    invoke-virtual {v1, v15}, Ljava/lang/String;->charAt(I)C

    .line 316
    .line 317
    .line 318
    move-result v15

    .line 319
    if-lt v15, v5, :cond_13

    .line 320
    .line 321
    and-int/lit16 v15, v15, 0x1fff

    .line 322
    .line 323
    shl-int v15, v15, v16

    .line 324
    .line 325
    or-int/2addr v14, v15

    .line 326
    add-int/lit8 v16, v16, 0xd

    .line 327
    .line 328
    move/from16 v15, v17

    .line 329
    .line 330
    goto :goto_9

    .line 331
    :cond_13
    shl-int v15, v15, v16

    .line 332
    .line 333
    or-int/2addr v14, v15

    .line 334
    move/from16 v15, v17

    .line 335
    .line 336
    :cond_14
    add-int v16, v14, v12

    .line 337
    .line 338
    add-int v13, v16, v13

    .line 339
    .line 340
    add-int v16, v4, v4

    .line 341
    .line 342
    add-int v16, v16, v7

    .line 343
    .line 344
    new-array v7, v13, [I

    .line 345
    .line 346
    move-object v13, v7

    .line 347
    move v7, v4

    .line 348
    move v4, v15

    .line 349
    move-object v15, v13

    .line 350
    move v13, v12

    .line 351
    move v12, v9

    .line 352
    move v9, v13

    .line 353
    move v13, v10

    .line 354
    move/from16 v10, v16

    .line 355
    .line 356
    move/from16 v16, v14

    .line 357
    .line 358
    :goto_a
    sget-object v14, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 359
    .line 360
    iget-object v3, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->c:[Ljava/lang/Object;

    .line 361
    .line 362
    iget-object v8, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 363
    .line 364
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 365
    .line 366
    .line 367
    move-result-object v8

    .line 368
    add-int v9, v16, v9

    .line 369
    .line 370
    add-int v6, v11, v11

    .line 371
    .line 372
    mul-int/lit8 v11, v11, 0x3

    .line 373
    .line 374
    new-array v11, v11, [I

    .line 375
    .line 376
    new-array v6, v6, [Ljava/lang/Object;

    .line 377
    .line 378
    move/from16 v23, v9

    .line 379
    .line 380
    move/from16 v22, v16

    .line 381
    .line 382
    const/16 v20, 0x0

    .line 383
    .line 384
    const/16 v21, 0x0

    .line 385
    .line 386
    :goto_b
    if-ge v4, v2, :cond_36

    .line 387
    .line 388
    add-int/lit8 v24, v4, 0x1

    .line 389
    .line 390
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 391
    .line 392
    .line 393
    move-result v4

    .line 394
    if-lt v4, v5, :cond_16

    .line 395
    .line 396
    and-int/lit16 v4, v4, 0x1fff

    .line 397
    .line 398
    move/from16 v5, v24

    .line 399
    .line 400
    const/16 v24, 0xd

    .line 401
    .line 402
    :goto_c
    add-int/lit8 v26, v5, 0x1

    .line 403
    .line 404
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 405
    .line 406
    .line 407
    move-result v5

    .line 408
    move/from16 v27, v2

    .line 409
    .line 410
    const v2, 0xd800

    .line 411
    .line 412
    .line 413
    if-lt v5, v2, :cond_15

    .line 414
    .line 415
    and-int/lit16 v2, v5, 0x1fff

    .line 416
    .line 417
    shl-int v2, v2, v24

    .line 418
    .line 419
    or-int/2addr v4, v2

    .line 420
    add-int/lit8 v24, v24, 0xd

    .line 421
    .line 422
    move/from16 v5, v26

    .line 423
    .line 424
    move/from16 v2, v27

    .line 425
    .line 426
    goto :goto_c

    .line 427
    :cond_15
    shl-int v2, v5, v24

    .line 428
    .line 429
    or-int/2addr v4, v2

    .line 430
    move/from16 v2, v26

    .line 431
    .line 432
    goto :goto_d

    .line 433
    :cond_16
    move/from16 v27, v2

    .line 434
    .line 435
    move/from16 v2, v24

    .line 436
    .line 437
    :goto_d
    add-int/lit8 v5, v2, 0x1

    .line 438
    .line 439
    invoke-virtual {v1, v2}, Ljava/lang/String;->charAt(I)C

    .line 440
    .line 441
    .line 442
    move-result v2

    .line 443
    move-object/from16 v24, v3

    .line 444
    .line 445
    const v3, 0xd800

    .line 446
    .line 447
    .line 448
    if-lt v2, v3, :cond_18

    .line 449
    .line 450
    and-int/lit16 v2, v2, 0x1fff

    .line 451
    .line 452
    const/16 v26, 0xd

    .line 453
    .line 454
    :goto_e
    add-int/lit8 v28, v5, 0x1

    .line 455
    .line 456
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 457
    .line 458
    .line 459
    move-result v5

    .line 460
    if-lt v5, v3, :cond_17

    .line 461
    .line 462
    and-int/lit16 v3, v5, 0x1fff

    .line 463
    .line 464
    shl-int v3, v3, v26

    .line 465
    .line 466
    or-int/2addr v2, v3

    .line 467
    add-int/lit8 v26, v26, 0xd

    .line 468
    .line 469
    move/from16 v5, v28

    .line 470
    .line 471
    const v3, 0xd800

    .line 472
    .line 473
    .line 474
    goto :goto_e

    .line 475
    :cond_17
    shl-int v3, v5, v26

    .line 476
    .line 477
    or-int/2addr v2, v3

    .line 478
    move/from16 v5, v28

    .line 479
    .line 480
    :cond_18
    and-int/lit16 v3, v2, 0x400

    .line 481
    .line 482
    if-eqz v3, :cond_19

    .line 483
    .line 484
    add-int/lit8 v3, v20, 0x1

    .line 485
    .line 486
    aput v21, v15, v20

    .line 487
    .line 488
    move/from16 v20, v3

    .line 489
    .line 490
    :cond_19
    and-int/lit16 v3, v2, 0xff

    .line 491
    .line 492
    move/from16 v26, v4

    .line 493
    .line 494
    and-int/lit16 v4, v2, 0x800

    .line 495
    .line 496
    move/from16 v28, v4

    .line 497
    .line 498
    const/16 v4, 0x33

    .line 499
    .line 500
    if-lt v3, v4, :cond_23

    .line 501
    .line 502
    add-int/lit8 v4, v5, 0x1

    .line 503
    .line 504
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 505
    .line 506
    .line 507
    move-result v5

    .line 508
    move/from16 v29, v4

    .line 509
    .line 510
    const v4, 0xd800

    .line 511
    .line 512
    .line 513
    if-lt v5, v4, :cond_1b

    .line 514
    .line 515
    and-int/lit16 v5, v5, 0x1fff

    .line 516
    .line 517
    move/from16 v33, v29

    .line 518
    .line 519
    move/from16 v29, v5

    .line 520
    .line 521
    move/from16 v5, v33

    .line 522
    .line 523
    const/16 v33, 0xd

    .line 524
    .line 525
    :goto_f
    add-int/lit8 v34, v5, 0x1

    .line 526
    .line 527
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 528
    .line 529
    .line 530
    move-result v5

    .line 531
    if-lt v5, v4, :cond_1a

    .line 532
    .line 533
    and-int/lit16 v4, v5, 0x1fff

    .line 534
    .line 535
    shl-int v4, v4, v33

    .line 536
    .line 537
    or-int v29, v29, v4

    .line 538
    .line 539
    add-int/lit8 v33, v33, 0xd

    .line 540
    .line 541
    move/from16 v5, v34

    .line 542
    .line 543
    const v4, 0xd800

    .line 544
    .line 545
    .line 546
    goto :goto_f

    .line 547
    :cond_1a
    shl-int v4, v5, v33

    .line 548
    .line 549
    or-int v5, v29, v4

    .line 550
    .line 551
    move/from16 v4, v34

    .line 552
    .line 553
    goto :goto_10

    .line 554
    :cond_1b
    move/from16 v4, v29

    .line 555
    .line 556
    :goto_10
    move/from16 v29, v4

    .line 557
    .line 558
    add-int/lit8 v4, v3, -0x33

    .line 559
    .line 560
    move/from16 v33, v5

    .line 561
    .line 562
    const/16 v5, 0x9

    .line 563
    .line 564
    if-eq v4, v5, :cond_1c

    .line 565
    .line 566
    const/16 v5, 0x11

    .line 567
    .line 568
    if-ne v4, v5, :cond_1d

    .line 569
    .line 570
    :cond_1c
    const/4 v5, 0x1

    .line 571
    goto :goto_13

    .line 572
    :cond_1d
    const/16 v5, 0xc

    .line 573
    .line 574
    if-ne v4, v5, :cond_20

    .line 575
    .line 576
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->a()I

    .line 577
    .line 578
    .line 579
    move-result v4

    .line 580
    const/4 v5, 0x1

    .line 581
    if-eq v4, v5, :cond_1f

    .line 582
    .line 583
    if-eqz v28, :cond_1e

    .line 584
    .line 585
    goto :goto_11

    .line 586
    :cond_1e
    const/4 v4, 0x0

    .line 587
    goto :goto_14

    .line 588
    :cond_1f
    :goto_11
    add-int/lit8 v4, v10, 0x1

    .line 589
    .line 590
    div-int/lit8 v19, v21, 0x3

    .line 591
    .line 592
    add-int v19, v19, v19

    .line 593
    .line 594
    add-int/lit8 v19, v19, 0x1

    .line 595
    .line 596
    aget-object v10, v24, v10

    .line 597
    .line 598
    aput-object v10, v6, v19

    .line 599
    .line 600
    :goto_12
    move v10, v4

    .line 601
    :cond_20
    move/from16 v4, v28

    .line 602
    .line 603
    goto :goto_14

    .line 604
    :goto_13
    add-int/lit8 v4, v10, 0x1

    .line 605
    .line 606
    div-int/lit8 v19, v21, 0x3

    .line 607
    .line 608
    add-int v19, v19, v19

    .line 609
    .line 610
    add-int/lit8 v30, v19, 0x1

    .line 611
    .line 612
    aget-object v5, v24, v10

    .line 613
    .line 614
    aput-object v5, v6, v30

    .line 615
    .line 616
    goto :goto_12

    .line 617
    :goto_14
    add-int v5, v33, v33

    .line 618
    .line 619
    move/from16 v28, v4

    .line 620
    .line 621
    aget-object v4, v24, v5

    .line 622
    .line 623
    move/from16 v30, v5

    .line 624
    .line 625
    instance-of v5, v4, Ljava/lang/reflect/Field;

    .line 626
    .line 627
    if-eqz v5, :cond_21

    .line 628
    .line 629
    check-cast v4, Ljava/lang/reflect/Field;

    .line 630
    .line 631
    goto :goto_15

    .line 632
    :cond_21
    check-cast v4, Ljava/lang/String;

    .line 633
    .line 634
    invoke-static {v8, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 635
    .line 636
    .line 637
    move-result-object v4

    .line 638
    aput-object v4, v24, v30

    .line 639
    .line 640
    :goto_15
    invoke-virtual {v14, v4}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 641
    .line 642
    .line 643
    move-result-wide v4

    .line 644
    long-to-int v4, v4

    .line 645
    add-int/lit8 v5, v30, 0x1

    .line 646
    .line 647
    move/from16 v30, v4

    .line 648
    .line 649
    aget-object v4, v24, v5

    .line 650
    .line 651
    move/from16 v31, v5

    .line 652
    .line 653
    instance-of v5, v4, Ljava/lang/reflect/Field;

    .line 654
    .line 655
    if-eqz v5, :cond_22

    .line 656
    .line 657
    check-cast v4, Ljava/lang/reflect/Field;

    .line 658
    .line 659
    goto :goto_16

    .line 660
    :cond_22
    check-cast v4, Ljava/lang/String;

    .line 661
    .line 662
    invoke-static {v8, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 663
    .line 664
    .line 665
    move-result-object v4

    .line 666
    aput-object v4, v24, v31

    .line 667
    .line 668
    :goto_16
    invoke-virtual {v14, v4}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 669
    .line 670
    .line 671
    move-result-wide v4

    .line 672
    long-to-int v4, v4

    .line 673
    move/from16 v31, v29

    .line 674
    .line 675
    move/from16 v5, v30

    .line 676
    .line 677
    const v25, 0xd800

    .line 678
    .line 679
    .line 680
    move-object/from16 v29, v6

    .line 681
    .line 682
    move/from16 v30, v7

    .line 683
    .line 684
    move-object v6, v8

    .line 685
    const/4 v7, 0x0

    .line 686
    move v8, v4

    .line 687
    :goto_17
    move/from16 v4, v28

    .line 688
    .line 689
    goto/16 :goto_24

    .line 690
    .line 691
    :cond_23
    add-int/lit8 v4, v10, 0x1

    .line 692
    .line 693
    aget-object v29, v24, v10

    .line 694
    .line 695
    move/from16 v33, v4

    .line 696
    .line 697
    move-object/from16 v4, v29

    .line 698
    .line 699
    check-cast v4, Ljava/lang/String;

    .line 700
    .line 701
    invoke-static {v8, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 702
    .line 703
    .line 704
    move-result-object v4

    .line 705
    move-object/from16 v29, v6

    .line 706
    .line 707
    const/16 v6, 0x9

    .line 708
    .line 709
    if-eq v3, v6, :cond_24

    .line 710
    .line 711
    const/16 v6, 0x11

    .line 712
    .line 713
    if-ne v3, v6, :cond_25

    .line 714
    .line 715
    :cond_24
    move/from16 v30, v7

    .line 716
    .line 717
    const/4 v7, 0x1

    .line 718
    goto/16 :goto_1d

    .line 719
    .line 720
    :cond_25
    const/16 v6, 0x1b

    .line 721
    .line 722
    if-eq v3, v6, :cond_2d

    .line 723
    .line 724
    const/16 v6, 0x31

    .line 725
    .line 726
    if-ne v3, v6, :cond_26

    .line 727
    .line 728
    add-int/lit8 v10, v10, 0x2

    .line 729
    .line 730
    move/from16 v30, v7

    .line 731
    .line 732
    const/4 v7, 0x1

    .line 733
    goto/16 :goto_1c

    .line 734
    .line 735
    :cond_26
    const/16 v6, 0xc

    .line 736
    .line 737
    if-eq v3, v6, :cond_2a

    .line 738
    .line 739
    const/16 v6, 0x1e

    .line 740
    .line 741
    if-eq v3, v6, :cond_2a

    .line 742
    .line 743
    const/16 v6, 0x2c

    .line 744
    .line 745
    if-ne v3, v6, :cond_27

    .line 746
    .line 747
    goto :goto_19

    .line 748
    :cond_27
    const/16 v6, 0x32

    .line 749
    .line 750
    if-ne v3, v6, :cond_29

    .line 751
    .line 752
    add-int/lit8 v6, v10, 0x2

    .line 753
    .line 754
    add-int/lit8 v30, v22, 0x1

    .line 755
    .line 756
    aput v21, v15, v22

    .line 757
    .line 758
    div-int/lit8 v22, v21, 0x3

    .line 759
    .line 760
    aget-object v31, v24, v33

    .line 761
    .line 762
    add-int v22, v22, v22

    .line 763
    .line 764
    aput-object v31, v29, v22

    .line 765
    .line 766
    if-eqz v28, :cond_28

    .line 767
    .line 768
    add-int/lit8 v22, v22, 0x1

    .line 769
    .line 770
    add-int/lit8 v10, v10, 0x3

    .line 771
    .line 772
    aget-object v6, v24, v6

    .line 773
    .line 774
    aput-object v6, v29, v22

    .line 775
    .line 776
    move-object v6, v8

    .line 777
    move/from16 v22, v30

    .line 778
    .line 779
    :goto_18
    move/from16 v30, v7

    .line 780
    .line 781
    goto :goto_1f

    .line 782
    :cond_28
    move v10, v6

    .line 783
    move-object v6, v8

    .line 784
    move/from16 v22, v30

    .line 785
    .line 786
    const/16 v28, 0x0

    .line 787
    .line 788
    goto :goto_18

    .line 789
    :cond_29
    move/from16 v30, v7

    .line 790
    .line 791
    const/4 v7, 0x1

    .line 792
    goto :goto_1e

    .line 793
    :cond_2a
    :goto_19
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->a()I

    .line 794
    .line 795
    .line 796
    move-result v6

    .line 797
    move/from16 v30, v7

    .line 798
    .line 799
    const/4 v7, 0x1

    .line 800
    if-eq v6, v7, :cond_2c

    .line 801
    .line 802
    if-eqz v28, :cond_2b

    .line 803
    .line 804
    goto :goto_1a

    .line 805
    :cond_2b
    move-object v6, v8

    .line 806
    move/from16 v10, v33

    .line 807
    .line 808
    const/16 v28, 0x0

    .line 809
    .line 810
    goto :goto_1f

    .line 811
    :cond_2c
    :goto_1a
    add-int/lit8 v10, v10, 0x2

    .line 812
    .line 813
    div-int/lit8 v6, v21, 0x3

    .line 814
    .line 815
    add-int/2addr v6, v6

    .line 816
    add-int/2addr v6, v7

    .line 817
    aget-object v19, v24, v33

    .line 818
    .line 819
    aput-object v19, v29, v6

    .line 820
    .line 821
    :goto_1b
    move-object v6, v8

    .line 822
    goto :goto_1f

    .line 823
    :cond_2d
    move/from16 v30, v7

    .line 824
    .line 825
    const/4 v7, 0x1

    .line 826
    add-int/lit8 v10, v10, 0x2

    .line 827
    .line 828
    :goto_1c
    div-int/lit8 v6, v21, 0x3

    .line 829
    .line 830
    add-int/2addr v6, v6

    .line 831
    add-int/2addr v6, v7

    .line 832
    aget-object v19, v24, v33

    .line 833
    .line 834
    aput-object v19, v29, v6

    .line 835
    .line 836
    goto :goto_1b

    .line 837
    :goto_1d
    div-int/lit8 v6, v21, 0x3

    .line 838
    .line 839
    add-int/2addr v6, v6

    .line 840
    add-int/2addr v6, v7

    .line 841
    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 842
    .line 843
    .line 844
    move-result-object v10

    .line 845
    aput-object v10, v29, v6

    .line 846
    .line 847
    :goto_1e
    move-object v6, v8

    .line 848
    move/from16 v10, v33

    .line 849
    .line 850
    :goto_1f
    invoke-virtual {v14, v4}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 851
    .line 852
    .line 853
    move-result-wide v7

    .line 854
    long-to-int v4, v7

    .line 855
    and-int/lit16 v7, v2, 0x1000

    .line 856
    .line 857
    const v8, 0xfffff

    .line 858
    .line 859
    .line 860
    if-eqz v7, :cond_31

    .line 861
    .line 862
    const/16 v7, 0x11

    .line 863
    .line 864
    if-gt v3, v7, :cond_31

    .line 865
    .line 866
    add-int/lit8 v7, v5, 0x1

    .line 867
    .line 868
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 869
    .line 870
    .line 871
    move-result v5

    .line 872
    const v8, 0xd800

    .line 873
    .line 874
    .line 875
    if-lt v5, v8, :cond_2f

    .line 876
    .line 877
    and-int/lit16 v5, v5, 0x1fff

    .line 878
    .line 879
    const/16 v25, 0xd

    .line 880
    .line 881
    :goto_20
    add-int/lit8 v31, v7, 0x1

    .line 882
    .line 883
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 884
    .line 885
    .line 886
    move-result v7

    .line 887
    if-lt v7, v8, :cond_2e

    .line 888
    .line 889
    and-int/lit16 v7, v7, 0x1fff

    .line 890
    .line 891
    shl-int v7, v7, v25

    .line 892
    .line 893
    or-int/2addr v5, v7

    .line 894
    add-int/lit8 v25, v25, 0xd

    .line 895
    .line 896
    move/from16 v7, v31

    .line 897
    .line 898
    goto :goto_20

    .line 899
    :cond_2e
    shl-int v7, v7, v25

    .line 900
    .line 901
    or-int/2addr v5, v7

    .line 902
    goto :goto_21

    .line 903
    :cond_2f
    move/from16 v31, v7

    .line 904
    .line 905
    :goto_21
    add-int v7, v30, v30

    .line 906
    .line 907
    div-int/lit8 v25, v5, 0x20

    .line 908
    .line 909
    add-int v25, v25, v7

    .line 910
    .line 911
    aget-object v7, v24, v25

    .line 912
    .line 913
    instance-of v8, v7, Ljava/lang/reflect/Field;

    .line 914
    .line 915
    if-eqz v8, :cond_30

    .line 916
    .line 917
    check-cast v7, Ljava/lang/reflect/Field;

    .line 918
    .line 919
    goto :goto_22

    .line 920
    :cond_30
    check-cast v7, Ljava/lang/String;

    .line 921
    .line 922
    invoke-static {v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->F(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 923
    .line 924
    .line 925
    move-result-object v7

    .line 926
    aput-object v7, v24, v25

    .line 927
    .line 928
    :goto_22
    invoke-virtual {v14, v7}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 929
    .line 930
    .line 931
    move-result-wide v7

    .line 932
    long-to-int v7, v7

    .line 933
    rem-int/lit8 v5, v5, 0x20

    .line 934
    .line 935
    move v8, v7

    .line 936
    const v25, 0xd800

    .line 937
    .line 938
    .line 939
    goto :goto_23

    .line 940
    :cond_31
    const v25, 0xd800

    .line 941
    .line 942
    .line 943
    move/from16 v31, v5

    .line 944
    .line 945
    const/4 v5, 0x0

    .line 946
    :goto_23
    const/16 v7, 0x12

    .line 947
    .line 948
    if-lt v3, v7, :cond_32

    .line 949
    .line 950
    const/16 v7, 0x31

    .line 951
    .line 952
    if-gt v3, v7, :cond_32

    .line 953
    .line 954
    add-int/lit8 v7, v23, 0x1

    .line 955
    .line 956
    aput v4, v15, v23

    .line 957
    .line 958
    move/from16 v23, v7

    .line 959
    .line 960
    :cond_32
    move v7, v5

    .line 961
    move v5, v4

    .line 962
    goto/16 :goto_17

    .line 963
    .line 964
    :goto_24
    add-int/lit8 v28, v21, 0x1

    .line 965
    .line 966
    aput v26, v11, v21

    .line 967
    .line 968
    add-int/lit8 v26, v21, 0x2

    .line 969
    .line 970
    move-object/from16 v32, v1

    .line 971
    .line 972
    and-int/lit16 v1, v2, 0x200

    .line 973
    .line 974
    if-eqz v1, :cond_33

    .line 975
    .line 976
    const/high16 v1, 0x20000000

    .line 977
    .line 978
    goto :goto_25

    .line 979
    :cond_33
    const/4 v1, 0x0

    .line 980
    :goto_25
    and-int/lit16 v2, v2, 0x100

    .line 981
    .line 982
    if-eqz v2, :cond_34

    .line 983
    .line 984
    const/high16 v2, 0x10000000

    .line 985
    .line 986
    goto :goto_26

    .line 987
    :cond_34
    const/4 v2, 0x0

    .line 988
    :goto_26
    if-eqz v4, :cond_35

    .line 989
    .line 990
    const/high16 v4, -0x80000000

    .line 991
    .line 992
    goto :goto_27

    .line 993
    :cond_35
    const/4 v4, 0x0

    .line 994
    :goto_27
    shl-int/lit8 v3, v3, 0x14

    .line 995
    .line 996
    or-int/2addr v1, v2

    .line 997
    or-int/2addr v1, v4

    .line 998
    or-int/2addr v1, v3

    .line 999
    or-int/2addr v1, v5

    .line 1000
    aput v1, v11, v28

    .line 1001
    .line 1002
    add-int/lit8 v21, v21, 0x3

    .line 1003
    .line 1004
    shl-int/lit8 v1, v7, 0x14

    .line 1005
    .line 1006
    or-int/2addr v1, v8

    .line 1007
    aput v1, v11, v26

    .line 1008
    .line 1009
    move-object v8, v6

    .line 1010
    move-object/from16 v3, v24

    .line 1011
    .line 1012
    move/from16 v5, v25

    .line 1013
    .line 1014
    move/from16 v2, v27

    .line 1015
    .line 1016
    move-object/from16 v6, v29

    .line 1017
    .line 1018
    move/from16 v7, v30

    .line 1019
    .line 1020
    move/from16 v4, v31

    .line 1021
    .line 1022
    move-object/from16 v1, v32

    .line 1023
    .line 1024
    goto/16 :goto_b

    .line 1025
    .line 1026
    :cond_36
    move-object/from16 v29, v6

    .line 1027
    .line 1028
    new-instance v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;

    .line 1029
    .line 1030
    iget-object v14, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 1031
    .line 1032
    move-object/from16 v18, p1

    .line 1033
    .line 1034
    move-object/from16 v19, p2

    .line 1035
    .line 1036
    move/from16 v17, v9

    .line 1037
    .line 1038
    move-object v10, v11

    .line 1039
    move-object/from16 v11, v29

    .line 1040
    .line 1041
    move-object v9, v1

    .line 1042
    invoke-direct/range {v9 .. v19}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;-><init>([I[Ljava/lang/Object;IILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;[IIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;)V

    .line 1043
    .line 1044
    .line 1045
    return-object v9

    .line 1046
    :cond_37
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1047
    .line 1048
    .line 1049
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1050
    .line 1051
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1052
    .line 1053
    .line 1054
    throw v0
.end method

.method public static w(JLjava/lang/Object;)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public static y(I)I
    .locals 0

    .line 1
    ushr-int/lit8 p0, p0, 0x14

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0xff

    .line 4
    .line 5
    return p0
.end method


# virtual methods
.method public final B(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;
    .locals 0

    .line 1
    div-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    add-int/2addr p1, p1

    .line 4
    add-int/lit8 p1, p1, 0x1

    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->b:[Ljava/lang/Object;

    .line 7
    .line 8
    aget-object p0, p0, p1

    .line 9
    .line 10
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;

    .line 11
    .line 12
    return-object p0
.end method

.method public final C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;
    .locals 2

    .line 1
    div-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    add-int/2addr p1, p1

    .line 4
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->b:[Ljava/lang/Object;

    .line 5
    .line 6
    aget-object v0, p0, p1

    .line 7
    .line 8
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    return-object v0

    .line 13
    :cond_0
    add-int/lit8 v0, p1, 0x1

    .line 14
    .line 15
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;

    .line 16
    .line 17
    aget-object v0, p0, v0

    .line 18
    .line 19
    check-cast v0, Ljava/lang/Class;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    aput-object v0, p0, p1

    .line 26
    .line 27
    return-object v0
.end method

.method public final D(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

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
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    invoke-interface {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_0
    int-to-long p0, v1

    .line 25
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 26
    .line 27
    invoke-virtual {v1, p2, p0, p1}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

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
    invoke-interface {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    invoke-interface {v0, p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    return-object p1
.end method

.method public final E(ILjava/lang/Object;I)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    invoke-interface {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-object p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 17
    .line 18
    invoke-virtual {p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

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
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

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
    invoke-interface {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    invoke-interface {v0, p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    return-object p1
.end method

.method public final a(Ljava/lang/Object;)Z
    .locals 14

    .line 1
    const/4 v6, 0x0

    .line 2
    const v7, 0xfffff

    .line 3
    .line 4
    .line 5
    move v3, v6

    .line 6
    move v8, v3

    .line 7
    move v2, v7

    .line 8
    :goto_0
    iget v4, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->h:I

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    if-ge v8, v4, :cond_a

    .line 12
    .line 13
    iget-object v4, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->g:[I

    .line 14
    .line 15
    aget v4, v4, v8

    .line 16
    .line 17
    iget-object v9, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 18
    .line 19
    aget v10, v9, v4

    .line 20
    .line 21
    invoke-virtual {p0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 22
    .line 23
    .line 24
    move-result v11

    .line 25
    add-int/lit8 v12, v4, 0x2

    .line 26
    .line 27
    aget v9, v9, v12

    .line 28
    .line 29
    and-int v12, v9, v7

    .line 30
    .line 31
    ushr-int/lit8 v9, v9, 0x14

    .line 32
    .line 33
    shl-int/2addr v5, v9

    .line 34
    if-eq v12, v2, :cond_1

    .line 35
    .line 36
    if-eq v12, v7, :cond_0

    .line 37
    .line 38
    int-to-long v2, v12

    .line 39
    sget-object v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 40
    .line 41
    invoke-virtual {v9, p1, v2, v3}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    :cond_0
    move v2, v4

    .line 46
    move v4, v3

    .line 47
    move v3, v12

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move v13, v3

    .line 50
    move v3, v2

    .line 51
    move v2, v4

    .line 52
    move v4, v13

    .line 53
    :goto_1
    const/high16 v9, 0x10000000

    .line 54
    .line 55
    and-int/2addr v9, v11

    .line 56
    if-eqz v9, :cond_2

    .line 57
    .line 58
    move-object v0, p0

    .line 59
    move-object v1, p1

    .line 60
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 61
    .line 62
    .line 63
    move-result v9

    .line 64
    if-eqz v9, :cond_b

    .line 65
    .line 66
    :cond_2
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    const/16 v12, 0x9

    .line 71
    .line 72
    if-eq v9, v12, :cond_8

    .line 73
    .line 74
    const/16 v12, 0x11

    .line 75
    .line 76
    if-eq v9, v12, :cond_8

    .line 77
    .line 78
    const/16 v5, 0x1b

    .line 79
    .line 80
    if-eq v9, v5, :cond_6

    .line 81
    .line 82
    const/16 v5, 0x3c

    .line 83
    .line 84
    if-eq v9, v5, :cond_5

    .line 85
    .line 86
    const/16 v5, 0x44

    .line 87
    .line 88
    if-eq v9, v5, :cond_5

    .line 89
    .line 90
    const/16 v5, 0x31

    .line 91
    .line 92
    if-eq v9, v5, :cond_6

    .line 93
    .line 94
    const/16 v5, 0x32

    .line 95
    .line 96
    if-eq v9, v5, :cond_3

    .line 97
    .line 98
    goto/16 :goto_3

    .line 99
    .line 100
    :cond_3
    and-int v5, v11, v7

    .line 101
    .line 102
    int-to-long v9, v5

    .line 103
    invoke-static {v9, v10, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 108
    .line 109
    invoke-virtual {v5}, Ljava/util/HashMap;->isEmpty()Z

    .line 110
    .line 111
    .line 112
    move-result v5

    .line 113
    if-eqz v5, :cond_4

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_4
    div-int/lit8 v4, v2, 0x3

    .line 117
    .line 118
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->b:[Ljava/lang/Object;

    .line 119
    .line 120
    add-int/2addr v4, v4

    .line 121
    aget-object v0, v0, v4

    .line 122
    .line 123
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    throw v0

    .line 128
    :cond_5
    invoke-virtual {p0, v10, p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    if-eqz v5, :cond_9

    .line 133
    .line 134
    invoke-virtual {p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    and-int v5, v11, v7

    .line 139
    .line 140
    int-to-long v9, v5

    .line 141
    invoke-static {v9, v10, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    invoke-interface {v2, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->a(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    if-nez v2, :cond_9

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_6
    and-int v5, v11, v7

    .line 153
    .line 154
    int-to-long v9, v5

    .line 155
    invoke-static {v9, v10, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v5

    .line 159
    check-cast v5, Ljava/util/List;

    .line 160
    .line 161
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 162
    .line 163
    .line 164
    move-result v9

    .line 165
    if-nez v9, :cond_9

    .line 166
    .line 167
    invoke-virtual {p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    move v9, v6

    .line 172
    :goto_2
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 173
    .line 174
    .line 175
    move-result v10

    .line 176
    if-ge v9, v10, :cond_9

    .line 177
    .line 178
    invoke-interface {v5, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v10

    .line 182
    invoke-interface {v2, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->a(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v10

    .line 186
    if-nez v10, :cond_7

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_7
    add-int/lit8 v9, v9, 0x1

    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_8
    move-object v0, p0

    .line 193
    move-object v1, p1

    .line 194
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 195
    .line 196
    .line 197
    move-result v5

    .line 198
    if-eqz v5, :cond_9

    .line 199
    .line 200
    invoke-virtual {p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    and-int v5, v11, v7

    .line 205
    .line 206
    int-to-long v9, v5

    .line 207
    invoke-static {v9, v10, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v5

    .line 211
    invoke-interface {v2, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->a(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v2

    .line 215
    if-nez v2, :cond_9

    .line 216
    .line 217
    goto :goto_4

    .line 218
    :cond_9
    :goto_3
    add-int/lit8 v8, v8, 0x1

    .line 219
    .line 220
    move v2, v3

    .line 221
    move v3, v4

    .line 222
    goto/16 :goto_0

    .line 223
    .line 224
    :cond_a
    iget-boolean v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 225
    .line 226
    if-eqz v0, :cond_c

    .line 227
    .line 228
    move-object v0, p1

    .line 229
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 230
    .line 231
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 232
    .line 233
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->f()Z

    .line 234
    .line 235
    .line 236
    move-result v0

    .line 237
    if-nez v0, :cond_c

    .line 238
    .line 239
    :cond_b
    :goto_4
    return v6

    .line 240
    :cond_c
    return v5
.end method

.method public final b(Ljava/lang/Object;)V
    .locals 7

    .line 1
    invoke-static {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

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
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    move-object v0, p1

    .line 15
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 16
    .line 17
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->i()V

    .line 18
    .line 19
    .line 20
    iput v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;->zza:I

    .line 21
    .line 22
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->g()V

    .line 23
    .line 24
    .line 25
    :cond_1
    move v0, v1

    .line 26
    :goto_0
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 27
    .line 28
    array-length v3, v2

    .line 29
    if-ge v0, v3, :cond_5

    .line 30
    .line 31
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    const v4, 0xfffff

    .line 36
    .line 37
    .line 38
    and-int/2addr v4, v3

    .line 39
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    int-to-long v4, v4

    .line 44
    const/16 v6, 0x9

    .line 45
    .line 46
    if-eq v3, v6, :cond_3

    .line 47
    .line 48
    const/16 v6, 0x3c

    .line 49
    .line 50
    if-eq v3, v6, :cond_2

    .line 51
    .line 52
    const/16 v6, 0x44

    .line 53
    .line 54
    if-eq v3, v6, :cond_2

    .line 55
    .line 56
    packed-switch v3, :pswitch_data_0

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :pswitch_0
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 61
    .line 62
    invoke-virtual {v2, p1, v4, v5}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    if-eqz v3, :cond_4

    .line 67
    .line 68
    move-object v6, v3

    .line 69
    check-cast v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 70
    .line 71
    iput-boolean v1, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->d:Z

    .line 72
    .line 73
    invoke-virtual {v2, p1, v4, v5, v3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :pswitch_1
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 82
    .line 83
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;

    .line 84
    .line 85
    iget-boolean v3, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;->d:Z

    .line 86
    .line 87
    if-eqz v3, :cond_4

    .line 88
    .line 89
    iput-boolean v1, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;->d:Z

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_2
    aget v2, v2, v0

    .line 93
    .line 94
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-eqz v2, :cond_4

    .line 99
    .line 100
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 105
    .line 106
    invoke-virtual {v3, p1, v4, v5}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    invoke-interface {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->b(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_3
    :pswitch_2
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    if-eqz v2, :cond_4

    .line 119
    .line 120
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 125
    .line 126
    invoke-virtual {v3, p1, v4, v5}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    invoke-interface {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->b(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_4
    :goto_1
    add-int/lit8 v0, v0, 0x3

    .line 134
    .line 135
    goto :goto_0

    .line 136
    :cond_5
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->j:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 137
    .line 138
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    move-object v0, p1

    .line 142
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 143
    .line 144
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 145
    .line 146
    iget-boolean v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->e:Z

    .line 147
    .line 148
    if-eqz v2, :cond_6

    .line 149
    .line 150
    iput-boolean v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->e:Z

    .line 151
    .line 152
    :cond_6
    iget-boolean v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 153
    .line 154
    if-eqz v0, :cond_7

    .line 155
    .line 156
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->k:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 157
    .line 158
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 162
    .line 163
    iget-object p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 164
    .line 165
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->d()V

    .line 166
    .line 167
    .line 168
    :cond_7
    :goto_2
    return-void

    .line 169
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

.method public final c(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 12

    .line 1
    invoke-static {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_6

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    :goto_0
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    if-ge v0, v2, :cond_4

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const v3, 0xfffff

    .line 21
    .line 22
    .line 23
    and-int v4, v2, v3

    .line 24
    .line 25
    invoke-static {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    aget v5, v1, v0

    .line 30
    .line 31
    int-to-long v8, v4

    .line 32
    packed-switch v2, :pswitch_data_0

    .line 33
    .line 34
    .line 35
    :cond_0
    :goto_1
    move-object v7, p1

    .line 36
    goto/16 :goto_3

    .line 37
    .line 38
    :pswitch_0
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->j(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :pswitch_1
    invoke-virtual {p0, v5, p2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-static {p1, v8, v9, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->l(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    add-int/lit8 v2, v0, 0x2

    .line 56
    .line 57
    aget v1, v1, v2

    .line 58
    .line 59
    and-int/2addr v1, v3

    .line 60
    int-to-long v1, v1

    .line 61
    invoke-static {v1, v2, p1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :pswitch_2
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->j(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :pswitch_3
    invoke-virtual {p0, v5, p2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_0

    .line 74
    .line 75
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-static {p1, v8, v9, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->l(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    add-int/lit8 v2, v0, 0x2

    .line 83
    .line 84
    aget v1, v1, v2

    .line 85
    .line 86
    and-int/2addr v1, v3

    .line 87
    int-to-long v1, v1

    .line 88
    invoke-static {v1, v2, p1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :pswitch_4
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 93
    .line 94
    invoke-static {v8, v9, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->d(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    invoke-static {p1, v8, v9, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->l(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :pswitch_5
    invoke-static {v8, v9, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 115
    .line 116
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 121
    .line 122
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    if-lez v3, :cond_2

    .line 131
    .line 132
    if-lez v4, :cond_2

    .line 133
    .line 134
    move-object v5, v1

    .line 135
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;

    .line 136
    .line 137
    iget-boolean v5, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;->d:Z

    .line 138
    .line 139
    if-nez v5, :cond_1

    .line 140
    .line 141
    add-int/2addr v4, v3

    .line 142
    invoke-interface {v1, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;->d(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    :cond_1
    invoke-interface {v1, v2}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 147
    .line 148
    .line 149
    :cond_2
    if-gtz v3, :cond_3

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_3
    move-object v2, v1

    .line 153
    :goto_2
    invoke-static {p1, v8, v9, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->l(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    goto :goto_1

    .line 157
    :pswitch_6
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->i(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    goto :goto_1

    .line 161
    :pswitch_7
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-eqz v1, :cond_0

    .line 166
    .line 167
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 168
    .line 169
    .line 170
    move-result-wide v1

    .line 171
    invoke-static {v8, v9, p1, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->k(JLjava/lang/Object;J)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    goto/16 :goto_1

    .line 178
    .line 179
    :pswitch_8
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v1

    .line 183
    if-eqz v1, :cond_0

    .line 184
    .line 185
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    invoke-static {v8, v9, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    goto/16 :goto_1

    .line 196
    .line 197
    :pswitch_9
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    if-eqz v1, :cond_0

    .line 202
    .line 203
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 204
    .line 205
    .line 206
    move-result-wide v1

    .line 207
    invoke-static {v8, v9, p1, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->k(JLjava/lang/Object;J)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    goto/16 :goto_1

    .line 214
    .line 215
    :pswitch_a
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    if-eqz v1, :cond_0

    .line 220
    .line 221
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 222
    .line 223
    .line 224
    move-result v1

    .line 225
    invoke-static {v8, v9, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    goto/16 :goto_1

    .line 232
    .line 233
    :pswitch_b
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v1

    .line 237
    if-eqz v1, :cond_0

    .line 238
    .line 239
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 240
    .line 241
    .line 242
    move-result v1

    .line 243
    invoke-static {v8, v9, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    goto/16 :goto_1

    .line 250
    .line 251
    :pswitch_c
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v1

    .line 255
    if-eqz v1, :cond_0

    .line 256
    .line 257
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 258
    .line 259
    .line 260
    move-result v1

    .line 261
    invoke-static {v8, v9, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 265
    .line 266
    .line 267
    goto/16 :goto_1

    .line 268
    .line 269
    :pswitch_d
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    move-result v1

    .line 273
    if-eqz v1, :cond_0

    .line 274
    .line 275
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    invoke-static {p1, v8, v9, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->l(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    goto/16 :goto_1

    .line 286
    .line 287
    :pswitch_e
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->i(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    goto/16 :goto_1

    .line 291
    .line 292
    :pswitch_f
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 293
    .line 294
    .line 295
    move-result v1

    .line 296
    if-eqz v1, :cond_0

    .line 297
    .line 298
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v1

    .line 302
    invoke-static {p1, v8, v9, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->l(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 306
    .line 307
    .line 308
    goto/16 :goto_1

    .line 309
    .line 310
    :pswitch_10
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    move-result v1

    .line 314
    if-eqz v1, :cond_0

    .line 315
    .line 316
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 317
    .line 318
    invoke-virtual {v1, v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->g(JLjava/lang/Object;)Z

    .line 319
    .line 320
    .line 321
    move-result v2

    .line 322
    invoke-virtual {v1, p1, v8, v9, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->c(Ljava/lang/Object;JZ)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    goto/16 :goto_1

    .line 329
    .line 330
    :pswitch_11
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 331
    .line 332
    .line 333
    move-result v1

    .line 334
    if-eqz v1, :cond_0

    .line 335
    .line 336
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 337
    .line 338
    .line 339
    move-result v1

    .line 340
    invoke-static {v8, v9, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 344
    .line 345
    .line 346
    goto/16 :goto_1

    .line 347
    .line 348
    :pswitch_12
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 349
    .line 350
    .line 351
    move-result v1

    .line 352
    if-eqz v1, :cond_0

    .line 353
    .line 354
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 355
    .line 356
    .line 357
    move-result-wide v1

    .line 358
    invoke-static {v8, v9, p1, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->k(JLjava/lang/Object;J)V

    .line 359
    .line 360
    .line 361
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 362
    .line 363
    .line 364
    goto/16 :goto_1

    .line 365
    .line 366
    :pswitch_13
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 367
    .line 368
    .line 369
    move-result v1

    .line 370
    if-eqz v1, :cond_0

    .line 371
    .line 372
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 373
    .line 374
    .line 375
    move-result v1

    .line 376
    invoke-static {v8, v9, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 377
    .line 378
    .line 379
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 380
    .line 381
    .line 382
    goto/16 :goto_1

    .line 383
    .line 384
    :pswitch_14
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 385
    .line 386
    .line 387
    move-result v1

    .line 388
    if-eqz v1, :cond_0

    .line 389
    .line 390
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 391
    .line 392
    .line 393
    move-result-wide v1

    .line 394
    invoke-static {v8, v9, p1, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->k(JLjava/lang/Object;J)V

    .line 395
    .line 396
    .line 397
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 398
    .line 399
    .line 400
    goto/16 :goto_1

    .line 401
    .line 402
    :pswitch_15
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 403
    .line 404
    .line 405
    move-result v1

    .line 406
    if-eqz v1, :cond_0

    .line 407
    .line 408
    invoke-static {v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 409
    .line 410
    .line 411
    move-result-wide v1

    .line 412
    invoke-static {v8, v9, p1, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->k(JLjava/lang/Object;J)V

    .line 413
    .line 414
    .line 415
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 416
    .line 417
    .line 418
    goto/16 :goto_1

    .line 419
    .line 420
    :pswitch_16
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 421
    .line 422
    .line 423
    move-result v1

    .line 424
    if-eqz v1, :cond_0

    .line 425
    .line 426
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 427
    .line 428
    invoke-virtual {v1, v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->b(JLjava/lang/Object;)F

    .line 429
    .line 430
    .line 431
    move-result v2

    .line 432
    invoke-virtual {v1, p1, v8, v9, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->f(Ljava/lang/Object;JF)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 436
    .line 437
    .line 438
    goto/16 :goto_1

    .line 439
    .line 440
    :pswitch_17
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 441
    .line 442
    .line 443
    move-result v1

    .line 444
    if-eqz v1, :cond_0

    .line 445
    .line 446
    sget-object v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 447
    .line 448
    invoke-virtual {v6, v8, v9, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->a(JLjava/lang/Object;)D

    .line 449
    .line 450
    .line 451
    move-result-wide v10

    .line 452
    move-object v7, p1

    .line 453
    invoke-virtual/range {v6 .. v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->e(Ljava/lang/Object;JD)V

    .line 454
    .line 455
    .line 456
    invoke-virtual {p0, v0, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 457
    .line 458
    .line 459
    :goto_3
    add-int/lit8 v0, v0, 0x3

    .line 460
    .line 461
    move-object p1, v7

    .line 462
    goto/16 :goto_0

    .line 463
    .line 464
    :cond_4
    move-object v7, p1

    .line 465
    invoke-static {v7, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 466
    .line 467
    .line 468
    iget-boolean p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 469
    .line 470
    if-eqz p0, :cond_5

    .line 471
    .line 472
    invoke-static {v7, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->p(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 473
    .line 474
    .line 475
    :cond_5
    return-void

    .line 476
    :cond_6
    move-object v7, p1

    .line 477
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 478
    .line 479
    invoke-static {v7}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 480
    .line 481
    .line 482
    move-result-object p1

    .line 483
    const-string p2, "Mutating immutable message: "

    .line 484
    .line 485
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 486
    .line 487
    .line 488
    move-result-object p1

    .line 489
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 490
    .line 491
    .line 492
    throw p0

    .line 493
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

.method public final d(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Z
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 4
    .line 5
    array-length v3, v2

    .line 6
    if-ge v1, v3, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    const v4, 0xfffff

    .line 13
    .line 14
    .line 15
    and-int v5, v3, v4

    .line 16
    .line 17
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    int-to-long v5, v5

    .line 22
    packed-switch v3, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    goto/16 :goto_2

    .line 26
    .line 27
    :pswitch_0
    add-int/lit8 v3, v1, 0x2

    .line 28
    .line 29
    aget v2, v2, v3

    .line 30
    .line 31
    and-int/2addr v2, v4

    .line 32
    int-to-long v2, v2

    .line 33
    invoke-static {v2, v3, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    invoke-static {v2, v3, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-ne v4, v2, :cond_2

    .line 42
    .line 43
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->e(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-nez v2, :cond_0

    .line 56
    .line 57
    goto/16 :goto_3

    .line 58
    .line 59
    :pswitch_1
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->e(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    goto :goto_1

    .line 72
    :pswitch_2
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->e(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    :goto_1
    if-nez v2, :cond_0

    .line 85
    .line 86
    goto/16 :goto_3

    .line 87
    .line 88
    :pswitch_3
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    if-eqz v2, :cond_2

    .line 93
    .line 94
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->e(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    if-eqz v2, :cond_2

    .line 107
    .line 108
    goto/16 :goto_2

    .line 109
    .line 110
    :pswitch_4
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    if-eqz v2, :cond_2

    .line 115
    .line 116
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 117
    .line 118
    .line 119
    move-result-wide v2

    .line 120
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 121
    .line 122
    .line 123
    move-result-wide v4

    .line 124
    cmp-long v2, v2, v4

    .line 125
    .line 126
    if-nez v2, :cond_2

    .line 127
    .line 128
    goto/16 :goto_2

    .line 129
    .line 130
    :pswitch_5
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-eqz v2, :cond_2

    .line 135
    .line 136
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 137
    .line 138
    .line 139
    move-result v2

    .line 140
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 141
    .line 142
    .line 143
    move-result v3

    .line 144
    if-ne v2, v3, :cond_2

    .line 145
    .line 146
    goto/16 :goto_2

    .line 147
    .line 148
    :pswitch_6
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 149
    .line 150
    .line 151
    move-result v2

    .line 152
    if-eqz v2, :cond_2

    .line 153
    .line 154
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 155
    .line 156
    .line 157
    move-result-wide v2

    .line 158
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 159
    .line 160
    .line 161
    move-result-wide v4

    .line 162
    cmp-long v2, v2, v4

    .line 163
    .line 164
    if-nez v2, :cond_2

    .line 165
    .line 166
    goto/16 :goto_2

    .line 167
    .line 168
    :pswitch_7
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 169
    .line 170
    .line 171
    move-result v2

    .line 172
    if-eqz v2, :cond_2

    .line 173
    .line 174
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 179
    .line 180
    .line 181
    move-result v3

    .line 182
    if-ne v2, v3, :cond_2

    .line 183
    .line 184
    goto/16 :goto_2

    .line 185
    .line 186
    :pswitch_8
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 187
    .line 188
    .line 189
    move-result v2

    .line 190
    if-eqz v2, :cond_2

    .line 191
    .line 192
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 193
    .line 194
    .line 195
    move-result v2

    .line 196
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 197
    .line 198
    .line 199
    move-result v3

    .line 200
    if-ne v2, v3, :cond_2

    .line 201
    .line 202
    goto/16 :goto_2

    .line 203
    .line 204
    :pswitch_9
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 205
    .line 206
    .line 207
    move-result v2

    .line 208
    if-eqz v2, :cond_2

    .line 209
    .line 210
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 211
    .line 212
    .line 213
    move-result v2

    .line 214
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 215
    .line 216
    .line 217
    move-result v3

    .line 218
    if-ne v2, v3, :cond_2

    .line 219
    .line 220
    goto/16 :goto_2

    .line 221
    .line 222
    :pswitch_a
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    if-eqz v2, :cond_2

    .line 227
    .line 228
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v3

    .line 236
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->e(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v2

    .line 240
    if-eqz v2, :cond_2

    .line 241
    .line 242
    goto/16 :goto_2

    .line 243
    .line 244
    :pswitch_b
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 245
    .line 246
    .line 247
    move-result v2

    .line 248
    if-eqz v2, :cond_2

    .line 249
    .line 250
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v2

    .line 254
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->e(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v2

    .line 262
    if-eqz v2, :cond_2

    .line 263
    .line 264
    goto/16 :goto_2

    .line 265
    .line 266
    :pswitch_c
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    if-eqz v2, :cond_2

    .line 271
    .line 272
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v2

    .line 276
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v3

    .line 280
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->e(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result v2

    .line 284
    if-eqz v2, :cond_2

    .line 285
    .line 286
    goto/16 :goto_2

    .line 287
    .line 288
    :pswitch_d
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 289
    .line 290
    .line 291
    move-result v2

    .line 292
    if-eqz v2, :cond_2

    .line 293
    .line 294
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 295
    .line 296
    invoke-virtual {v2, v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->g(JLjava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    move-result v3

    .line 300
    invoke-virtual {v2, v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->g(JLjava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v2

    .line 304
    if-ne v3, v2, :cond_2

    .line 305
    .line 306
    goto/16 :goto_2

    .line 307
    .line 308
    :pswitch_e
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 309
    .line 310
    .line 311
    move-result v2

    .line 312
    if-eqz v2, :cond_2

    .line 313
    .line 314
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 315
    .line 316
    .line 317
    move-result v2

    .line 318
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 319
    .line 320
    .line 321
    move-result v3

    .line 322
    if-ne v2, v3, :cond_2

    .line 323
    .line 324
    goto/16 :goto_2

    .line 325
    .line 326
    :pswitch_f
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 327
    .line 328
    .line 329
    move-result v2

    .line 330
    if-eqz v2, :cond_2

    .line 331
    .line 332
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 333
    .line 334
    .line 335
    move-result-wide v2

    .line 336
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 337
    .line 338
    .line 339
    move-result-wide v4

    .line 340
    cmp-long v2, v2, v4

    .line 341
    .line 342
    if-nez v2, :cond_2

    .line 343
    .line 344
    goto/16 :goto_2

    .line 345
    .line 346
    :pswitch_10
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 347
    .line 348
    .line 349
    move-result v2

    .line 350
    if-eqz v2, :cond_2

    .line 351
    .line 352
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 353
    .line 354
    .line 355
    move-result v2

    .line 356
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 357
    .line 358
    .line 359
    move-result v3

    .line 360
    if-ne v2, v3, :cond_2

    .line 361
    .line 362
    goto :goto_2

    .line 363
    :pswitch_11
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 364
    .line 365
    .line 366
    move-result v2

    .line 367
    if-eqz v2, :cond_2

    .line 368
    .line 369
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 370
    .line 371
    .line 372
    move-result-wide v2

    .line 373
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 374
    .line 375
    .line 376
    move-result-wide v4

    .line 377
    cmp-long v2, v2, v4

    .line 378
    .line 379
    if-nez v2, :cond_2

    .line 380
    .line 381
    goto :goto_2

    .line 382
    :pswitch_12
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 383
    .line 384
    .line 385
    move-result v2

    .line 386
    if-eqz v2, :cond_2

    .line 387
    .line 388
    invoke-static {v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 389
    .line 390
    .line 391
    move-result-wide v2

    .line 392
    invoke-static {v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 393
    .line 394
    .line 395
    move-result-wide v4

    .line 396
    cmp-long v2, v2, v4

    .line 397
    .line 398
    if-nez v2, :cond_2

    .line 399
    .line 400
    goto :goto_2

    .line 401
    :pswitch_13
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 402
    .line 403
    .line 404
    move-result v2

    .line 405
    if-eqz v2, :cond_2

    .line 406
    .line 407
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 408
    .line 409
    invoke-virtual {v2, v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->b(JLjava/lang/Object;)F

    .line 410
    .line 411
    .line 412
    move-result v3

    .line 413
    invoke-static {v3}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 414
    .line 415
    .line 416
    move-result v3

    .line 417
    invoke-virtual {v2, v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->b(JLjava/lang/Object;)F

    .line 418
    .line 419
    .line 420
    move-result v2

    .line 421
    invoke-static {v2}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 422
    .line 423
    .line 424
    move-result v2

    .line 425
    if-ne v3, v2, :cond_2

    .line 426
    .line 427
    goto :goto_2

    .line 428
    :pswitch_14
    invoke-virtual {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z

    .line 429
    .line 430
    .line 431
    move-result v2

    .line 432
    if-eqz v2, :cond_2

    .line 433
    .line 434
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 435
    .line 436
    invoke-virtual {v2, v5, v6, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->a(JLjava/lang/Object;)D

    .line 437
    .line 438
    .line 439
    move-result-wide v3

    .line 440
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 441
    .line 442
    .line 443
    move-result-wide v3

    .line 444
    invoke-virtual {v2, v5, v6, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->a(JLjava/lang/Object;)D

    .line 445
    .line 446
    .line 447
    move-result-wide v5

    .line 448
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 449
    .line 450
    .line 451
    move-result-wide v5

    .line 452
    cmp-long v2, v3, v5

    .line 453
    .line 454
    if-nez v2, :cond_2

    .line 455
    .line 456
    :cond_0
    :goto_2
    add-int/lit8 v1, v1, 0x3

    .line 457
    .line 458
    goto/16 :goto_0

    .line 459
    .line 460
    :cond_1
    iget-object v1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 461
    .line 462
    iget-object v2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 463
    .line 464
    invoke-virtual {v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->equals(Ljava/lang/Object;)Z

    .line 465
    .line 466
    .line 467
    move-result v1

    .line 468
    if-nez v1, :cond_3

    .line 469
    .line 470
    :cond_2
    :goto_3
    return v0

    .line 471
    :cond_3
    iget-boolean p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 472
    .line 473
    if-eqz p0, :cond_4

    .line 474
    .line 475
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 476
    .line 477
    iget-object p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 478
    .line 479
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 480
    .line 481
    iget-object p1, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 482
    .line 483
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->equals(Ljava/lang/Object;)Z

    .line 484
    .line 485
    .line 486
    move-result p0

    .line 487
    return p0

    .line 488
    :cond_4
    const/4 p0, 0x1

    .line 489
    return p0

    .line 490
    nop

    .line 491
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

.method public final e(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;)V
    .locals 19

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
    iget-boolean v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    move-object v2, v1

    .line 12
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 13
    .line 14
    iget-object v2, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 15
    .line 16
    iget-object v3, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 17
    .line 18
    invoke-virtual {v3}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-nez v3, :cond_0

    .line 23
    .line 24
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->c()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Ljava/util/Map$Entry;

    .line 33
    .line 34
    move-object v8, v2

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v3, 0x0

    .line 37
    const/4 v8, 0x0

    .line 38
    :goto_0
    sget-object v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    const v4, 0xfffff

    .line 42
    .line 43
    .line 44
    const/4 v5, 0x0

    .line 45
    :goto_1
    iget-object v12, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 46
    .line 47
    array-length v13, v12

    .line 48
    iget-object v14, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->k:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 49
    .line 50
    if-ge v2, v13, :cond_d

    .line 51
    .line 52
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 53
    .line 54
    .line 55
    move-result v13

    .line 56
    invoke-static {v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 57
    .line 58
    .line 59
    move-result v15

    .line 60
    aget v7, v12, v2

    .line 61
    .line 62
    const/16 v11, 0x11

    .line 63
    .line 64
    const v16, 0xfffff

    .line 65
    .line 66
    .line 67
    if-gt v15, v11, :cond_3

    .line 68
    .line 69
    add-int/lit8 v11, v2, 0x2

    .line 70
    .line 71
    aget v11, v12, v11

    .line 72
    .line 73
    const/16 v17, 0x1

    .line 74
    .line 75
    and-int v10, v11, v16

    .line 76
    .line 77
    move-object/from16 v18, v3

    .line 78
    .line 79
    if-eq v10, v4, :cond_2

    .line 80
    .line 81
    move/from16 v3, v16

    .line 82
    .line 83
    if-ne v10, v3, :cond_1

    .line 84
    .line 85
    const/4 v5, 0x0

    .line 86
    goto :goto_2

    .line 87
    :cond_1
    int-to-long v3, v10

    .line 88
    invoke-virtual {v9, v1, v3, v4}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    move v5, v3

    .line 93
    :goto_2
    move v4, v10

    .line 94
    :cond_2
    ushr-int/lit8 v3, v11, 0x14

    .line 95
    .line 96
    shl-int v3, v17, v3

    .line 97
    .line 98
    move v10, v5

    .line 99
    move v5, v3

    .line 100
    move v3, v4

    .line 101
    move v4, v10

    .line 102
    move-object/from16 v10, v18

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_3
    move-object/from16 v18, v3

    .line 106
    .line 107
    const/16 v17, 0x1

    .line 108
    .line 109
    move v3, v4

    .line 110
    move v4, v5

    .line 111
    move-object/from16 v10, v18

    .line 112
    .line 113
    const/4 v5, 0x0

    .line 114
    :goto_3
    if-eqz v10, :cond_5

    .line 115
    .line 116
    invoke-interface {v10}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v11

    .line 120
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 121
    .line 122
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    if-ltz v7, :cond_5

    .line 126
    .line 127
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    invoke-static {v6, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->e(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Ljava/util/Map$Entry;)V

    .line 131
    .line 132
    .line 133
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    if-eqz v10, :cond_4

    .line 138
    .line 139
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v10

    .line 143
    check-cast v10, Ljava/util/Map$Entry;

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_4
    const/4 v10, 0x0

    .line 147
    goto :goto_3

    .line 148
    :cond_5
    const v16, 0xfffff

    .line 149
    .line 150
    .line 151
    and-int v11, v13, v16

    .line 152
    .line 153
    int-to-long v13, v11

    .line 154
    const/16 v11, 0x3f

    .line 155
    .line 156
    packed-switch v15, :pswitch_data_0

    .line 157
    .line 158
    .line 159
    :cond_6
    :goto_4
    const/4 v15, 0x0

    .line 160
    goto/16 :goto_c

    .line 161
    .line 162
    :pswitch_0
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 163
    .line 164
    .line 165
    move-result v5

    .line 166
    if-eqz v5, :cond_6

    .line 167
    .line 168
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 173
    .line 174
    .line 175
    move-result-object v11

    .line 176
    invoke-virtual {v6, v7, v5, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->d(ILjava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)V

    .line 177
    .line 178
    .line 179
    goto :goto_4

    .line 180
    :pswitch_1
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 181
    .line 182
    .line 183
    move-result v5

    .line 184
    if-eqz v5, :cond_6

    .line 185
    .line 186
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 187
    .line 188
    .line 189
    move-result-wide v12

    .line 190
    add-long v14, v12, v12

    .line 191
    .line 192
    shr-long v11, v12, v11

    .line 193
    .line 194
    xor-long/2addr v11, v14

    .line 195
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 198
    .line 199
    invoke-virtual {v5, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 200
    .line 201
    .line 202
    goto :goto_4

    .line 203
    :pswitch_2
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 204
    .line 205
    .line 206
    move-result v5

    .line 207
    if-eqz v5, :cond_6

    .line 208
    .line 209
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 210
    .line 211
    .line 212
    move-result v5

    .line 213
    add-int v11, v5, v5

    .line 214
    .line 215
    shr-int/lit8 v5, v5, 0x1f

    .line 216
    .line 217
    xor-int/2addr v5, v11

    .line 218
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 221
    .line 222
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 223
    .line 224
    .line 225
    goto :goto_4

    .line 226
    :pswitch_3
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 227
    .line 228
    .line 229
    move-result v5

    .line 230
    if-eqz v5, :cond_6

    .line 231
    .line 232
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 233
    .line 234
    .line 235
    move-result-wide v11

    .line 236
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 239
    .line 240
    invoke-virtual {v5, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 241
    .line 242
    .line 243
    goto :goto_4

    .line 244
    :pswitch_4
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 245
    .line 246
    .line 247
    move-result v5

    .line 248
    if-eqz v5, :cond_6

    .line 249
    .line 250
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 251
    .line 252
    .line 253
    move-result v5

    .line 254
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 255
    .line 256
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 257
    .line 258
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 259
    .line 260
    .line 261
    goto :goto_4

    .line 262
    :pswitch_5
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 263
    .line 264
    .line 265
    move-result v5

    .line 266
    if-eqz v5, :cond_6

    .line 267
    .line 268
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 269
    .line 270
    .line 271
    move-result v5

    .line 272
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 275
    .line 276
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 277
    .line 278
    .line 279
    goto :goto_4

    .line 280
    :pswitch_6
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 281
    .line 282
    .line 283
    move-result v5

    .line 284
    if-eqz v5, :cond_6

    .line 285
    .line 286
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 287
    .line 288
    .line 289
    move-result v5

    .line 290
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 293
    .line 294
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 295
    .line 296
    .line 297
    goto/16 :goto_4

    .line 298
    .line 299
    :pswitch_7
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 300
    .line 301
    .line 302
    move-result v5

    .line 303
    if-eqz v5, :cond_6

    .line 304
    .line 305
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v5

    .line 309
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 310
    .line 311
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 314
    .line 315
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->i(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 316
    .line 317
    .line 318
    goto/16 :goto_4

    .line 319
    .line 320
    :pswitch_8
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 321
    .line 322
    .line 323
    move-result v5

    .line 324
    if-eqz v5, :cond_6

    .line 325
    .line 326
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v5

    .line 330
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 331
    .line 332
    .line 333
    move-result-object v11

    .line 334
    invoke-virtual {v6, v7, v5, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->e(ILjava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)V

    .line 335
    .line 336
    .line 337
    goto/16 :goto_4

    .line 338
    .line 339
    :pswitch_9
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 340
    .line 341
    .line 342
    move-result v5

    .line 343
    if-eqz v5, :cond_6

    .line 344
    .line 345
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v5

    .line 349
    instance-of v11, v5, Ljava/lang/String;

    .line 350
    .line 351
    if-eqz v11, :cond_7

    .line 352
    .line 353
    check-cast v5, Ljava/lang/String;

    .line 354
    .line 355
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 358
    .line 359
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->p(ILjava/lang/String;)V

    .line 360
    .line 361
    .line 362
    goto/16 :goto_4

    .line 363
    .line 364
    :cond_7
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 365
    .line 366
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 367
    .line 368
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 369
    .line 370
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->i(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 371
    .line 372
    .line 373
    goto/16 :goto_4

    .line 374
    .line 375
    :pswitch_a
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 376
    .line 377
    .line 378
    move-result v5

    .line 379
    if-eqz v5, :cond_6

    .line 380
    .line 381
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v5

    .line 385
    check-cast v5, Ljava/lang/Boolean;

    .line 386
    .line 387
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 388
    .line 389
    .line 390
    move-result v5

    .line 391
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 392
    .line 393
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 394
    .line 395
    shl-int/lit8 v7, v7, 0x3

    .line 396
    .line 397
    invoke-virtual {v11, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v11, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->g(B)V

    .line 401
    .line 402
    .line 403
    goto/16 :goto_4

    .line 404
    .line 405
    :pswitch_b
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 406
    .line 407
    .line 408
    move-result v5

    .line 409
    if-eqz v5, :cond_6

    .line 410
    .line 411
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 412
    .line 413
    .line 414
    move-result v5

    .line 415
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 416
    .line 417
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 418
    .line 419
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 420
    .line 421
    .line 422
    goto/16 :goto_4

    .line 423
    .line 424
    :pswitch_c
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 425
    .line 426
    .line 427
    move-result v5

    .line 428
    if-eqz v5, :cond_6

    .line 429
    .line 430
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 431
    .line 432
    .line 433
    move-result-wide v11

    .line 434
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 435
    .line 436
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 437
    .line 438
    invoke-virtual {v5, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 439
    .line 440
    .line 441
    goto/16 :goto_4

    .line 442
    .line 443
    :pswitch_d
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 444
    .line 445
    .line 446
    move-result v5

    .line 447
    if-eqz v5, :cond_6

    .line 448
    .line 449
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 450
    .line 451
    .line 452
    move-result v5

    .line 453
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 454
    .line 455
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 456
    .line 457
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 458
    .line 459
    .line 460
    goto/16 :goto_4

    .line 461
    .line 462
    :pswitch_e
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 463
    .line 464
    .line 465
    move-result v5

    .line 466
    if-eqz v5, :cond_6

    .line 467
    .line 468
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 469
    .line 470
    .line 471
    move-result-wide v11

    .line 472
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 473
    .line 474
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 475
    .line 476
    invoke-virtual {v5, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 477
    .line 478
    .line 479
    goto/16 :goto_4

    .line 480
    .line 481
    :pswitch_f
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 482
    .line 483
    .line 484
    move-result v5

    .line 485
    if-eqz v5, :cond_6

    .line 486
    .line 487
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 488
    .line 489
    .line 490
    move-result-wide v11

    .line 491
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 492
    .line 493
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 494
    .line 495
    invoke-virtual {v5, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 496
    .line 497
    .line 498
    goto/16 :goto_4

    .line 499
    .line 500
    :pswitch_10
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 501
    .line 502
    .line 503
    move-result v5

    .line 504
    if-eqz v5, :cond_6

    .line 505
    .line 506
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 507
    .line 508
    .line 509
    move-result-object v5

    .line 510
    check-cast v5, Ljava/lang/Float;

    .line 511
    .line 512
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 513
    .line 514
    .line 515
    move-result v5

    .line 516
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 519
    .line 520
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 521
    .line 522
    .line 523
    move-result v5

    .line 524
    invoke-virtual {v11, v7, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 525
    .line 526
    .line 527
    goto/16 :goto_4

    .line 528
    .line 529
    :pswitch_11
    invoke-virtual {v0, v7, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 530
    .line 531
    .line 532
    move-result v5

    .line 533
    if-eqz v5, :cond_6

    .line 534
    .line 535
    invoke-static {v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 536
    .line 537
    .line 538
    move-result-object v5

    .line 539
    check-cast v5, Ljava/lang/Double;

    .line 540
    .line 541
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 542
    .line 543
    .line 544
    move-result-wide v11

    .line 545
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 546
    .line 547
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 548
    .line 549
    invoke-static {v11, v12}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 550
    .line 551
    .line 552
    move-result-wide v11

    .line 553
    invoke-virtual {v5, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 554
    .line 555
    .line 556
    goto/16 :goto_4

    .line 557
    .line 558
    :pswitch_12
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 559
    .line 560
    .line 561
    move-result-object v5

    .line 562
    if-nez v5, :cond_8

    .line 563
    .line 564
    goto/16 :goto_4

    .line 565
    .line 566
    :cond_8
    div-int/lit8 v2, v2, 0x3

    .line 567
    .line 568
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->b:[Ljava/lang/Object;

    .line 569
    .line 570
    add-int/2addr v2, v2

    .line 571
    aget-object v0, v0, v2

    .line 572
    .line 573
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 574
    .line 575
    .line 576
    move-result-object v0

    .line 577
    throw v0

    .line 578
    :pswitch_13
    aget v5, v12, v2

    .line 579
    .line 580
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 581
    .line 582
    .line 583
    move-result-object v7

    .line 584
    check-cast v7, Ljava/util/List;

    .line 585
    .line 586
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 587
    .line 588
    .line 589
    move-result-object v11

    .line 590
    sget-object v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 591
    .line 592
    if-eqz v7, :cond_6

    .line 593
    .line 594
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 595
    .line 596
    .line 597
    move-result v12

    .line 598
    if-nez v12, :cond_6

    .line 599
    .line 600
    const/4 v12, 0x0

    .line 601
    :goto_5
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 602
    .line 603
    .line 604
    move-result v13

    .line 605
    if-ge v12, v13, :cond_6

    .line 606
    .line 607
    invoke-interface {v7, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 608
    .line 609
    .line 610
    move-result-object v13

    .line 611
    invoke-virtual {v6, v5, v13, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->d(ILjava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)V

    .line 612
    .line 613
    .line 614
    add-int/lit8 v12, v12, 0x1

    .line 615
    .line 616
    goto :goto_5

    .line 617
    :pswitch_14
    aget v5, v12, v2

    .line 618
    .line 619
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v7

    .line 623
    check-cast v7, Ljava/util/List;

    .line 624
    .line 625
    move/from16 v11, v17

    .line 626
    .line 627
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->b(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 628
    .line 629
    .line 630
    goto/16 :goto_4

    .line 631
    .line 632
    :pswitch_15
    move/from16 v11, v17

    .line 633
    .line 634
    aget v5, v12, v2

    .line 635
    .line 636
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    move-result-object v7

    .line 640
    check-cast v7, Ljava/util/List;

    .line 641
    .line 642
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 643
    .line 644
    .line 645
    goto/16 :goto_4

    .line 646
    .line 647
    :pswitch_16
    move/from16 v11, v17

    .line 648
    .line 649
    aget v5, v12, v2

    .line 650
    .line 651
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v7

    .line 655
    check-cast v7, Ljava/util/List;

    .line 656
    .line 657
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->A(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 658
    .line 659
    .line 660
    goto/16 :goto_4

    .line 661
    .line 662
    :pswitch_17
    move/from16 v11, v17

    .line 663
    .line 664
    aget v5, v12, v2

    .line 665
    .line 666
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    move-result-object v7

    .line 670
    check-cast v7, Ljava/util/List;

    .line 671
    .line 672
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->z(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 673
    .line 674
    .line 675
    goto/16 :goto_4

    .line 676
    .line 677
    :pswitch_18
    move/from16 v11, v17

    .line 678
    .line 679
    aget v5, v12, v2

    .line 680
    .line 681
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 682
    .line 683
    .line 684
    move-result-object v7

    .line 685
    check-cast v7, Ljava/util/List;

    .line 686
    .line 687
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->t(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 688
    .line 689
    .line 690
    goto/16 :goto_4

    .line 691
    .line 692
    :pswitch_19
    move/from16 v11, v17

    .line 693
    .line 694
    aget v5, v12, v2

    .line 695
    .line 696
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    move-result-object v7

    .line 700
    check-cast v7, Ljava/util/List;

    .line 701
    .line 702
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->c(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 703
    .line 704
    .line 705
    goto/16 :goto_4

    .line 706
    .line 707
    :pswitch_1a
    move/from16 v11, v17

    .line 708
    .line 709
    aget v5, v12, v2

    .line 710
    .line 711
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    move-result-object v7

    .line 715
    check-cast v7, Ljava/util/List;

    .line 716
    .line 717
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->r(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 718
    .line 719
    .line 720
    goto/16 :goto_4

    .line 721
    .line 722
    :pswitch_1b
    move/from16 v11, v17

    .line 723
    .line 724
    aget v5, v12, v2

    .line 725
    .line 726
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 727
    .line 728
    .line 729
    move-result-object v7

    .line 730
    check-cast v7, Ljava/util/List;

    .line 731
    .line 732
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->u(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 733
    .line 734
    .line 735
    goto/16 :goto_4

    .line 736
    .line 737
    :pswitch_1c
    move/from16 v11, v17

    .line 738
    .line 739
    aget v5, v12, v2

    .line 740
    .line 741
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 742
    .line 743
    .line 744
    move-result-object v7

    .line 745
    check-cast v7, Ljava/util/List;

    .line 746
    .line 747
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->v(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 748
    .line 749
    .line 750
    goto/16 :goto_4

    .line 751
    .line 752
    :pswitch_1d
    move/from16 v11, v17

    .line 753
    .line 754
    aget v5, v12, v2

    .line 755
    .line 756
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 757
    .line 758
    .line 759
    move-result-object v7

    .line 760
    check-cast v7, Ljava/util/List;

    .line 761
    .line 762
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->x(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 763
    .line 764
    .line 765
    goto/16 :goto_4

    .line 766
    .line 767
    :pswitch_1e
    move/from16 v11, v17

    .line 768
    .line 769
    aget v5, v12, v2

    .line 770
    .line 771
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 772
    .line 773
    .line 774
    move-result-object v7

    .line 775
    check-cast v7, Ljava/util/List;

    .line 776
    .line 777
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->d(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 778
    .line 779
    .line 780
    goto/16 :goto_4

    .line 781
    .line 782
    :pswitch_1f
    move/from16 v11, v17

    .line 783
    .line 784
    aget v5, v12, v2

    .line 785
    .line 786
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 787
    .line 788
    .line 789
    move-result-object v7

    .line 790
    check-cast v7, Ljava/util/List;

    .line 791
    .line 792
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->y(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 793
    .line 794
    .line 795
    goto/16 :goto_4

    .line 796
    .line 797
    :pswitch_20
    move/from16 v11, v17

    .line 798
    .line 799
    aget v5, v12, v2

    .line 800
    .line 801
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 802
    .line 803
    .line 804
    move-result-object v7

    .line 805
    check-cast v7, Ljava/util/List;

    .line 806
    .line 807
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->w(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 808
    .line 809
    .line 810
    goto/16 :goto_4

    .line 811
    .line 812
    :pswitch_21
    move/from16 v11, v17

    .line 813
    .line 814
    aget v5, v12, v2

    .line 815
    .line 816
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 817
    .line 818
    .line 819
    move-result-object v7

    .line 820
    check-cast v7, Ljava/util/List;

    .line 821
    .line 822
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->s(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 823
    .line 824
    .line 825
    goto/16 :goto_4

    .line 826
    .line 827
    :pswitch_22
    aget v5, v12, v2

    .line 828
    .line 829
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 830
    .line 831
    .line 832
    move-result-object v7

    .line 833
    check-cast v7, Ljava/util/List;

    .line 834
    .line 835
    const/4 v11, 0x0

    .line 836
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->b(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 837
    .line 838
    .line 839
    :goto_6
    move v15, v11

    .line 840
    goto/16 :goto_c

    .line 841
    .line 842
    :pswitch_23
    const/4 v11, 0x0

    .line 843
    aget v5, v12, v2

    .line 844
    .line 845
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 846
    .line 847
    .line 848
    move-result-object v7

    .line 849
    check-cast v7, Ljava/util/List;

    .line 850
    .line 851
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 852
    .line 853
    .line 854
    goto :goto_6

    .line 855
    :pswitch_24
    const/4 v11, 0x0

    .line 856
    aget v5, v12, v2

    .line 857
    .line 858
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 859
    .line 860
    .line 861
    move-result-object v7

    .line 862
    check-cast v7, Ljava/util/List;

    .line 863
    .line 864
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->A(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 865
    .line 866
    .line 867
    goto :goto_6

    .line 868
    :pswitch_25
    const/4 v11, 0x0

    .line 869
    aget v5, v12, v2

    .line 870
    .line 871
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 872
    .line 873
    .line 874
    move-result-object v7

    .line 875
    check-cast v7, Ljava/util/List;

    .line 876
    .line 877
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->z(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 878
    .line 879
    .line 880
    goto :goto_6

    .line 881
    :pswitch_26
    const/4 v11, 0x0

    .line 882
    aget v5, v12, v2

    .line 883
    .line 884
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 885
    .line 886
    .line 887
    move-result-object v7

    .line 888
    check-cast v7, Ljava/util/List;

    .line 889
    .line 890
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->t(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 891
    .line 892
    .line 893
    goto :goto_6

    .line 894
    :pswitch_27
    const/4 v11, 0x0

    .line 895
    aget v5, v12, v2

    .line 896
    .line 897
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 898
    .line 899
    .line 900
    move-result-object v7

    .line 901
    check-cast v7, Ljava/util/List;

    .line 902
    .line 903
    invoke-static {v5, v7, v6, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->c(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 904
    .line 905
    .line 906
    goto :goto_6

    .line 907
    :pswitch_28
    aget v5, v12, v2

    .line 908
    .line 909
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 910
    .line 911
    .line 912
    move-result-object v7

    .line 913
    check-cast v7, Ljava/util/List;

    .line 914
    .line 915
    sget-object v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 916
    .line 917
    if-eqz v7, :cond_6

    .line 918
    .line 919
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 920
    .line 921
    .line 922
    move-result v11

    .line 923
    if-nez v11, :cond_6

    .line 924
    .line 925
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 926
    .line 927
    .line 928
    const/4 v11, 0x0

    .line 929
    :goto_7
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 930
    .line 931
    .line 932
    move-result v12

    .line 933
    if-ge v11, v12, :cond_6

    .line 934
    .line 935
    iget-object v12, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 936
    .line 937
    check-cast v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 938
    .line 939
    invoke-interface {v7, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 940
    .line 941
    .line 942
    move-result-object v13

    .line 943
    check-cast v13, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 944
    .line 945
    invoke-virtual {v12, v5, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->i(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 946
    .line 947
    .line 948
    add-int/lit8 v11, v11, 0x1

    .line 949
    .line 950
    goto :goto_7

    .line 951
    :pswitch_29
    aget v5, v12, v2

    .line 952
    .line 953
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 954
    .line 955
    .line 956
    move-result-object v7

    .line 957
    check-cast v7, Ljava/util/List;

    .line 958
    .line 959
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 960
    .line 961
    .line 962
    move-result-object v11

    .line 963
    sget-object v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 964
    .line 965
    if-eqz v7, :cond_6

    .line 966
    .line 967
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 968
    .line 969
    .line 970
    move-result v12

    .line 971
    if-nez v12, :cond_6

    .line 972
    .line 973
    const/4 v12, 0x0

    .line 974
    :goto_8
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 975
    .line 976
    .line 977
    move-result v13

    .line 978
    if-ge v12, v13, :cond_6

    .line 979
    .line 980
    invoke-interface {v7, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 981
    .line 982
    .line 983
    move-result-object v13

    .line 984
    invoke-virtual {v6, v5, v13, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->e(ILjava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)V

    .line 985
    .line 986
    .line 987
    add-int/lit8 v12, v12, 0x1

    .line 988
    .line 989
    goto :goto_8

    .line 990
    :pswitch_2a
    aget v5, v12, v2

    .line 991
    .line 992
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 993
    .line 994
    .line 995
    move-result-object v7

    .line 996
    check-cast v7, Ljava/util/List;

    .line 997
    .line 998
    sget-object v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 999
    .line 1000
    if-eqz v7, :cond_6

    .line 1001
    .line 1002
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 1003
    .line 1004
    .line 1005
    move-result v11

    .line 1006
    if-nez v11, :cond_6

    .line 1007
    .line 1008
    iget-object v11, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1009
    .line 1010
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1011
    .line 1012
    instance-of v12, v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r1;

    .line 1013
    .line 1014
    if-eqz v12, :cond_a

    .line 1015
    .line 1016
    move-object v12, v7

    .line 1017
    check-cast v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r1;

    .line 1018
    .line 1019
    const/4 v13, 0x0

    .line 1020
    :goto_9
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 1021
    .line 1022
    .line 1023
    move-result v14

    .line 1024
    if-ge v13, v14, :cond_6

    .line 1025
    .line 1026
    invoke-interface {v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r1;->h()Ljava/lang/Object;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v14

    .line 1030
    instance-of v15, v14, Ljava/lang/String;

    .line 1031
    .line 1032
    if-eqz v15, :cond_9

    .line 1033
    .line 1034
    check-cast v14, Ljava/lang/String;

    .line 1035
    .line 1036
    invoke-virtual {v11, v5, v14}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->p(ILjava/lang/String;)V

    .line 1037
    .line 1038
    .line 1039
    goto :goto_a

    .line 1040
    :cond_9
    check-cast v14, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1041
    .line 1042
    invoke-virtual {v11, v5, v14}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->i(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 1043
    .line 1044
    .line 1045
    :goto_a
    add-int/lit8 v13, v13, 0x1

    .line 1046
    .line 1047
    goto :goto_9

    .line 1048
    :cond_a
    const/4 v12, 0x0

    .line 1049
    :goto_b
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 1050
    .line 1051
    .line 1052
    move-result v13

    .line 1053
    if-ge v12, v13, :cond_6

    .line 1054
    .line 1055
    invoke-interface {v7, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1056
    .line 1057
    .line 1058
    move-result-object v13

    .line 1059
    check-cast v13, Ljava/lang/String;

    .line 1060
    .line 1061
    invoke-virtual {v11, v5, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->p(ILjava/lang/String;)V

    .line 1062
    .line 1063
    .line 1064
    add-int/lit8 v12, v12, 0x1

    .line 1065
    .line 1066
    goto :goto_b

    .line 1067
    :pswitch_2b
    aget v5, v12, v2

    .line 1068
    .line 1069
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1070
    .line 1071
    .line 1072
    move-result-object v7

    .line 1073
    check-cast v7, Ljava/util/List;

    .line 1074
    .line 1075
    const/4 v15, 0x0

    .line 1076
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->r(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1077
    .line 1078
    .line 1079
    goto/16 :goto_c

    .line 1080
    .line 1081
    :pswitch_2c
    const/4 v15, 0x0

    .line 1082
    aget v5, v12, v2

    .line 1083
    .line 1084
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1085
    .line 1086
    .line 1087
    move-result-object v7

    .line 1088
    check-cast v7, Ljava/util/List;

    .line 1089
    .line 1090
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->u(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1091
    .line 1092
    .line 1093
    goto/16 :goto_c

    .line 1094
    .line 1095
    :pswitch_2d
    const/4 v15, 0x0

    .line 1096
    aget v5, v12, v2

    .line 1097
    .line 1098
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v7

    .line 1102
    check-cast v7, Ljava/util/List;

    .line 1103
    .line 1104
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->v(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1105
    .line 1106
    .line 1107
    goto/16 :goto_c

    .line 1108
    .line 1109
    :pswitch_2e
    const/4 v15, 0x0

    .line 1110
    aget v5, v12, v2

    .line 1111
    .line 1112
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v7

    .line 1116
    check-cast v7, Ljava/util/List;

    .line 1117
    .line 1118
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->x(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1119
    .line 1120
    .line 1121
    goto/16 :goto_c

    .line 1122
    .line 1123
    :pswitch_2f
    const/4 v15, 0x0

    .line 1124
    aget v5, v12, v2

    .line 1125
    .line 1126
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v7

    .line 1130
    check-cast v7, Ljava/util/List;

    .line 1131
    .line 1132
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->d(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1133
    .line 1134
    .line 1135
    goto/16 :goto_c

    .line 1136
    .line 1137
    :pswitch_30
    const/4 v15, 0x0

    .line 1138
    aget v5, v12, v2

    .line 1139
    .line 1140
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v7

    .line 1144
    check-cast v7, Ljava/util/List;

    .line 1145
    .line 1146
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->y(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1147
    .line 1148
    .line 1149
    goto/16 :goto_c

    .line 1150
    .line 1151
    :pswitch_31
    const/4 v15, 0x0

    .line 1152
    aget v5, v12, v2

    .line 1153
    .line 1154
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v7

    .line 1158
    check-cast v7, Ljava/util/List;

    .line 1159
    .line 1160
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->w(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1161
    .line 1162
    .line 1163
    goto/16 :goto_c

    .line 1164
    .line 1165
    :pswitch_32
    const/4 v15, 0x0

    .line 1166
    aget v5, v12, v2

    .line 1167
    .line 1168
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v7

    .line 1172
    check-cast v7, Ljava/util/List;

    .line 1173
    .line 1174
    invoke-static {v5, v7, v6, v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->s(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V

    .line 1175
    .line 1176
    .line 1177
    goto/16 :goto_c

    .line 1178
    .line 1179
    :pswitch_33
    const/4 v15, 0x0

    .line 1180
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1181
    .line 1182
    .line 1183
    move-result v5

    .line 1184
    if-eqz v5, :cond_c

    .line 1185
    .line 1186
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v5

    .line 1190
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1191
    .line 1192
    .line 1193
    move-result-object v11

    .line 1194
    invoke-virtual {v6, v7, v5, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->d(ILjava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)V

    .line 1195
    .line 1196
    .line 1197
    goto/16 :goto_c

    .line 1198
    .line 1199
    :pswitch_34
    const/4 v15, 0x0

    .line 1200
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1201
    .line 1202
    .line 1203
    move-result v5

    .line 1204
    if-eqz v5, :cond_c

    .line 1205
    .line 1206
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1207
    .line 1208
    .line 1209
    move-result-wide v12

    .line 1210
    add-long v17, v12, v12

    .line 1211
    .line 1212
    shr-long v11, v12, v11

    .line 1213
    .line 1214
    xor-long v11, v17, v11

    .line 1215
    .line 1216
    iget-object v0, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1217
    .line 1218
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1219
    .line 1220
    invoke-virtual {v0, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 1221
    .line 1222
    .line 1223
    goto/16 :goto_c

    .line 1224
    .line 1225
    :pswitch_35
    const/4 v15, 0x0

    .line 1226
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1227
    .line 1228
    .line 1229
    move-result v5

    .line 1230
    if-eqz v5, :cond_c

    .line 1231
    .line 1232
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1233
    .line 1234
    .line 1235
    move-result v0

    .line 1236
    add-int v5, v0, v0

    .line 1237
    .line 1238
    shr-int/lit8 v0, v0, 0x1f

    .line 1239
    .line 1240
    xor-int/2addr v0, v5

    .line 1241
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1242
    .line 1243
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1244
    .line 1245
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 1246
    .line 1247
    .line 1248
    goto/16 :goto_c

    .line 1249
    .line 1250
    :pswitch_36
    const/4 v15, 0x0

    .line 1251
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1252
    .line 1253
    .line 1254
    move-result v5

    .line 1255
    if-eqz v5, :cond_c

    .line 1256
    .line 1257
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1258
    .line 1259
    .line 1260
    move-result-wide v11

    .line 1261
    iget-object v0, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1262
    .line 1263
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1264
    .line 1265
    invoke-virtual {v0, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 1266
    .line 1267
    .line 1268
    goto/16 :goto_c

    .line 1269
    .line 1270
    :pswitch_37
    const/4 v15, 0x0

    .line 1271
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1272
    .line 1273
    .line 1274
    move-result v5

    .line 1275
    if-eqz v5, :cond_c

    .line 1276
    .line 1277
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1278
    .line 1279
    .line 1280
    move-result v0

    .line 1281
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1282
    .line 1283
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1284
    .line 1285
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 1286
    .line 1287
    .line 1288
    goto/16 :goto_c

    .line 1289
    .line 1290
    :pswitch_38
    const/4 v15, 0x0

    .line 1291
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1292
    .line 1293
    .line 1294
    move-result v5

    .line 1295
    if-eqz v5, :cond_c

    .line 1296
    .line 1297
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1298
    .line 1299
    .line 1300
    move-result v0

    .line 1301
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1302
    .line 1303
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1304
    .line 1305
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 1306
    .line 1307
    .line 1308
    goto/16 :goto_c

    .line 1309
    .line 1310
    :pswitch_39
    const/4 v15, 0x0

    .line 1311
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1312
    .line 1313
    .line 1314
    move-result v5

    .line 1315
    if-eqz v5, :cond_c

    .line 1316
    .line 1317
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1318
    .line 1319
    .line 1320
    move-result v0

    .line 1321
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1322
    .line 1323
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1324
    .line 1325
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 1326
    .line 1327
    .line 1328
    goto/16 :goto_c

    .line 1329
    .line 1330
    :pswitch_3a
    const/4 v15, 0x0

    .line 1331
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1332
    .line 1333
    .line 1334
    move-result v5

    .line 1335
    if-eqz v5, :cond_c

    .line 1336
    .line 1337
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1338
    .line 1339
    .line 1340
    move-result-object v0

    .line 1341
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1342
    .line 1343
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1344
    .line 1345
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1346
    .line 1347
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->i(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 1348
    .line 1349
    .line 1350
    goto/16 :goto_c

    .line 1351
    .line 1352
    :pswitch_3b
    const/4 v15, 0x0

    .line 1353
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1354
    .line 1355
    .line 1356
    move-result v5

    .line 1357
    if-eqz v5, :cond_c

    .line 1358
    .line 1359
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1360
    .line 1361
    .line 1362
    move-result-object v5

    .line 1363
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v11

    .line 1367
    invoke-virtual {v6, v7, v5, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->e(ILjava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)V

    .line 1368
    .line 1369
    .line 1370
    goto/16 :goto_c

    .line 1371
    .line 1372
    :pswitch_3c
    const/4 v15, 0x0

    .line 1373
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1374
    .line 1375
    .line 1376
    move-result v5

    .line 1377
    if-eqz v5, :cond_c

    .line 1378
    .line 1379
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1380
    .line 1381
    .line 1382
    move-result-object v0

    .line 1383
    instance-of v5, v0, Ljava/lang/String;

    .line 1384
    .line 1385
    if-eqz v5, :cond_b

    .line 1386
    .line 1387
    check-cast v0, Ljava/lang/String;

    .line 1388
    .line 1389
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1390
    .line 1391
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1392
    .line 1393
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->p(ILjava/lang/String;)V

    .line 1394
    .line 1395
    .line 1396
    goto/16 :goto_c

    .line 1397
    .line 1398
    :cond_b
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1399
    .line 1400
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1401
    .line 1402
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1403
    .line 1404
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->i(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 1405
    .line 1406
    .line 1407
    goto/16 :goto_c

    .line 1408
    .line 1409
    :pswitch_3d
    const/4 v15, 0x0

    .line 1410
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1411
    .line 1412
    .line 1413
    move-result v5

    .line 1414
    if-eqz v5, :cond_c

    .line 1415
    .line 1416
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 1417
    .line 1418
    invoke-virtual {v0, v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->g(JLjava/lang/Object;)Z

    .line 1419
    .line 1420
    .line 1421
    move-result v0

    .line 1422
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1423
    .line 1424
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1425
    .line 1426
    shl-int/lit8 v7, v7, 0x3

    .line 1427
    .line 1428
    invoke-virtual {v5, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 1429
    .line 1430
    .line 1431
    invoke-virtual {v5, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->g(B)V

    .line 1432
    .line 1433
    .line 1434
    goto/16 :goto_c

    .line 1435
    .line 1436
    :pswitch_3e
    const/4 v15, 0x0

    .line 1437
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1438
    .line 1439
    .line 1440
    move-result v5

    .line 1441
    if-eqz v5, :cond_c

    .line 1442
    .line 1443
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1444
    .line 1445
    .line 1446
    move-result v0

    .line 1447
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1448
    .line 1449
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1450
    .line 1451
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 1452
    .line 1453
    .line 1454
    goto/16 :goto_c

    .line 1455
    .line 1456
    :pswitch_3f
    const/4 v15, 0x0

    .line 1457
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1458
    .line 1459
    .line 1460
    move-result v5

    .line 1461
    if-eqz v5, :cond_c

    .line 1462
    .line 1463
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1464
    .line 1465
    .line 1466
    move-result-wide v11

    .line 1467
    iget-object v0, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1468
    .line 1469
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1470
    .line 1471
    invoke-virtual {v0, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 1472
    .line 1473
    .line 1474
    goto :goto_c

    .line 1475
    :pswitch_40
    const/4 v15, 0x0

    .line 1476
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1477
    .line 1478
    .line 1479
    move-result v5

    .line 1480
    if-eqz v5, :cond_c

    .line 1481
    .line 1482
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1483
    .line 1484
    .line 1485
    move-result v0

    .line 1486
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1487
    .line 1488
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1489
    .line 1490
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 1491
    .line 1492
    .line 1493
    goto :goto_c

    .line 1494
    :pswitch_41
    const/4 v15, 0x0

    .line 1495
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1496
    .line 1497
    .line 1498
    move-result v5

    .line 1499
    if-eqz v5, :cond_c

    .line 1500
    .line 1501
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1502
    .line 1503
    .line 1504
    move-result-wide v11

    .line 1505
    iget-object v0, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1506
    .line 1507
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1508
    .line 1509
    invoke-virtual {v0, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 1510
    .line 1511
    .line 1512
    goto :goto_c

    .line 1513
    :pswitch_42
    const/4 v15, 0x0

    .line 1514
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1515
    .line 1516
    .line 1517
    move-result v5

    .line 1518
    if-eqz v5, :cond_c

    .line 1519
    .line 1520
    invoke-virtual {v9, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1521
    .line 1522
    .line 1523
    move-result-wide v11

    .line 1524
    iget-object v0, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1525
    .line 1526
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1527
    .line 1528
    invoke-virtual {v0, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 1529
    .line 1530
    .line 1531
    goto :goto_c

    .line 1532
    :pswitch_43
    const/4 v15, 0x0

    .line 1533
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1534
    .line 1535
    .line 1536
    move-result v5

    .line 1537
    if-eqz v5, :cond_c

    .line 1538
    .line 1539
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 1540
    .line 1541
    invoke-virtual {v0, v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->b(JLjava/lang/Object;)F

    .line 1542
    .line 1543
    .line 1544
    move-result v0

    .line 1545
    iget-object v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1546
    .line 1547
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1548
    .line 1549
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1550
    .line 1551
    .line 1552
    move-result v0

    .line 1553
    invoke-virtual {v5, v7, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 1554
    .line 1555
    .line 1556
    goto :goto_c

    .line 1557
    :pswitch_44
    const/4 v15, 0x0

    .line 1558
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1559
    .line 1560
    .line 1561
    move-result v5

    .line 1562
    if-eqz v5, :cond_c

    .line 1563
    .line 1564
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 1565
    .line 1566
    invoke-virtual {v0, v13, v14, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->a(JLjava/lang/Object;)D

    .line 1567
    .line 1568
    .line 1569
    move-result-wide v11

    .line 1570
    iget-object v0, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 1571
    .line 1572
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 1573
    .line 1574
    invoke-static {v11, v12}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 1575
    .line 1576
    .line 1577
    move-result-wide v11

    .line 1578
    invoke-virtual {v0, v7, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 1579
    .line 1580
    .line 1581
    :cond_c
    :goto_c
    add-int/lit8 v2, v2, 0x3

    .line 1582
    .line 1583
    move-object/from16 v0, p0

    .line 1584
    .line 1585
    move v5, v4

    .line 1586
    move v4, v3

    .line 1587
    move-object v3, v10

    .line 1588
    goto/16 :goto_1

    .line 1589
    .line 1590
    :cond_d
    move-object/from16 v18, v3

    .line 1591
    .line 1592
    :goto_d
    if-eqz v3, :cond_f

    .line 1593
    .line 1594
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1595
    .line 1596
    .line 1597
    invoke-static {v6, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->e(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Ljava/util/Map$Entry;)V

    .line 1598
    .line 1599
    .line 1600
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 1601
    .line 1602
    .line 1603
    move-result v0

    .line 1604
    if-eqz v0, :cond_e

    .line 1605
    .line 1606
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1607
    .line 1608
    .line 1609
    move-result-object v0

    .line 1610
    move-object v3, v0

    .line 1611
    check-cast v3, Ljava/util/Map$Entry;

    .line 1612
    .line 1613
    goto :goto_d

    .line 1614
    :cond_e
    const/4 v3, 0x0

    .line 1615
    goto :goto_d

    .line 1616
    :cond_f
    move-object v0, v1

    .line 1617
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 1618
    .line 1619
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 1620
    .line 1621
    invoke-virtual {v0, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->d(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;)V

    .line 1622
    .line 1623
    .line 1624
    return-void

    .line 1625
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

.method public final f(Ljava/lang/Object;[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)V
    .locals 7

    .line 1
    const/4 v5, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-object v1, p1

    .line 4
    move-object v2, p2

    .line 5
    move v3, p3

    .line 6
    move v4, p4

    .line 7
    move-object v6, p5

    .line 8
    invoke-virtual/range {v0 .. v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->t(Ljava/lang/Object;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final g(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)I
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 4
    .line 5
    array-length v3, v2

    .line 6
    if-ge v0, v3, :cond_3

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    const v4, 0xfffff

    .line 13
    .line 14
    .line 15
    and-int/2addr v4, v3

    .line 16
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    aget v2, v2, v0

    .line 21
    .line 22
    int-to-long v4, v4

    .line 23
    const/16 v6, 0x4d5

    .line 24
    .line 25
    const/16 v7, 0x4cf

    .line 26
    .line 27
    const/16 v8, 0x25

    .line 28
    .line 29
    const/16 v9, 0x20

    .line 30
    .line 31
    packed-switch v3, :pswitch_data_0

    .line 32
    .line 33
    .line 34
    goto/16 :goto_5

    .line 35
    .line 36
    :pswitch_0
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_2

    .line 41
    .line 42
    mul-int/lit8 v1, v1, 0x35

    .line 43
    .line 44
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    :goto_1
    add-int/2addr v2, v1

    .line 53
    move v1, v2

    .line 54
    goto/16 :goto_5

    .line 55
    .line 56
    :pswitch_1
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_2

    .line 61
    .line 62
    mul-int/lit8 v1, v1, 0x35

    .line 63
    .line 64
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 65
    .line 66
    .line 67
    move-result-wide v2

    .line 68
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 69
    .line 70
    :goto_2
    ushr-long v4, v2, v9

    .line 71
    .line 72
    xor-long/2addr v2, v4

    .line 73
    long-to-int v2, v2

    .line 74
    add-int/2addr v1, v2

    .line 75
    goto/16 :goto_5

    .line 76
    .line 77
    :pswitch_2
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    if-eqz v2, :cond_2

    .line 82
    .line 83
    mul-int/lit8 v1, v1, 0x35

    .line 84
    .line 85
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    goto :goto_1

    .line 90
    :pswitch_3
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    if-eqz v2, :cond_2

    .line 95
    .line 96
    mul-int/lit8 v1, v1, 0x35

    .line 97
    .line 98
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 99
    .line 100
    .line 101
    move-result-wide v2

    .line 102
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :pswitch_4
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_2

    .line 110
    .line 111
    mul-int/lit8 v1, v1, 0x35

    .line 112
    .line 113
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    goto :goto_1

    .line 118
    :pswitch_5
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    if-eqz v2, :cond_2

    .line 123
    .line 124
    mul-int/lit8 v1, v1, 0x35

    .line 125
    .line 126
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    goto :goto_1

    .line 131
    :pswitch_6
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 132
    .line 133
    .line 134
    move-result v2

    .line 135
    if-eqz v2, :cond_2

    .line 136
    .line 137
    mul-int/lit8 v1, v1, 0x35

    .line 138
    .line 139
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    goto :goto_1

    .line 144
    :pswitch_7
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    if-eqz v2, :cond_2

    .line 149
    .line 150
    mul-int/lit8 v1, v1, 0x35

    .line 151
    .line 152
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    goto :goto_1

    .line 161
    :pswitch_8
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    if-eqz v2, :cond_2

    .line 166
    .line 167
    mul-int/lit8 v1, v1, 0x35

    .line 168
    .line 169
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v2

    .line 173
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 174
    .line 175
    .line 176
    move-result v2

    .line 177
    goto :goto_1

    .line 178
    :pswitch_9
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    if-eqz v2, :cond_2

    .line 183
    .line 184
    mul-int/lit8 v1, v1, 0x35

    .line 185
    .line 186
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v2

    .line 190
    check-cast v2, Ljava/lang/String;

    .line 191
    .line 192
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 193
    .line 194
    .line 195
    move-result v2

    .line 196
    goto/16 :goto_1

    .line 197
    .line 198
    :pswitch_a
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 199
    .line 200
    .line 201
    move-result v2

    .line 202
    if-eqz v2, :cond_2

    .line 203
    .line 204
    mul-int/lit8 v1, v1, 0x35

    .line 205
    .line 206
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    check-cast v2, Ljava/lang/Boolean;

    .line 211
    .line 212
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 213
    .line 214
    .line 215
    move-result v2

    .line 216
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 217
    .line 218
    if-eqz v2, :cond_0

    .line 219
    .line 220
    :goto_3
    move v6, v7

    .line 221
    :cond_0
    add-int/2addr v6, v1

    .line 222
    move v1, v6

    .line 223
    goto/16 :goto_5

    .line 224
    .line 225
    :pswitch_b
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 226
    .line 227
    .line 228
    move-result v2

    .line 229
    if-eqz v2, :cond_2

    .line 230
    .line 231
    mul-int/lit8 v1, v1, 0x35

    .line 232
    .line 233
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 234
    .line 235
    .line 236
    move-result v2

    .line 237
    goto/16 :goto_1

    .line 238
    .line 239
    :pswitch_c
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 240
    .line 241
    .line 242
    move-result v2

    .line 243
    if-eqz v2, :cond_2

    .line 244
    .line 245
    mul-int/lit8 v1, v1, 0x35

    .line 246
    .line 247
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 248
    .line 249
    .line 250
    move-result-wide v2

    .line 251
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 252
    .line 253
    goto/16 :goto_2

    .line 254
    .line 255
    :pswitch_d
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 256
    .line 257
    .line 258
    move-result v2

    .line 259
    if-eqz v2, :cond_2

    .line 260
    .line 261
    mul-int/lit8 v1, v1, 0x35

    .line 262
    .line 263
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 264
    .line 265
    .line 266
    move-result v2

    .line 267
    goto/16 :goto_1

    .line 268
    .line 269
    :pswitch_e
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 270
    .line 271
    .line 272
    move-result v2

    .line 273
    if-eqz v2, :cond_2

    .line 274
    .line 275
    mul-int/lit8 v1, v1, 0x35

    .line 276
    .line 277
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 278
    .line 279
    .line 280
    move-result-wide v2

    .line 281
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 282
    .line 283
    goto/16 :goto_2

    .line 284
    .line 285
    :pswitch_f
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 286
    .line 287
    .line 288
    move-result v2

    .line 289
    if-eqz v2, :cond_2

    .line 290
    .line 291
    mul-int/lit8 v1, v1, 0x35

    .line 292
    .line 293
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 294
    .line 295
    .line 296
    move-result-wide v2

    .line 297
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 298
    .line 299
    goto/16 :goto_2

    .line 300
    .line 301
    :pswitch_10
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 302
    .line 303
    .line 304
    move-result v2

    .line 305
    if-eqz v2, :cond_2

    .line 306
    .line 307
    mul-int/lit8 v1, v1, 0x35

    .line 308
    .line 309
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v2

    .line 313
    check-cast v2, Ljava/lang/Float;

    .line 314
    .line 315
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 316
    .line 317
    .line 318
    move-result v2

    .line 319
    invoke-static {v2}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 320
    .line 321
    .line 322
    move-result v2

    .line 323
    goto/16 :goto_1

    .line 324
    .line 325
    :pswitch_11
    invoke-virtual {p0, v2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 326
    .line 327
    .line 328
    move-result v2

    .line 329
    if-eqz v2, :cond_2

    .line 330
    .line 331
    mul-int/lit8 v1, v1, 0x35

    .line 332
    .line 333
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v2

    .line 337
    check-cast v2, Ljava/lang/Double;

    .line 338
    .line 339
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 340
    .line 341
    .line 342
    move-result-wide v2

    .line 343
    invoke-static {v2, v3}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 344
    .line 345
    .line 346
    move-result-wide v2

    .line 347
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 348
    .line 349
    goto/16 :goto_2

    .line 350
    .line 351
    :pswitch_12
    mul-int/lit8 v1, v1, 0x35

    .line 352
    .line 353
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v2

    .line 357
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 358
    .line 359
    .line 360
    move-result v2

    .line 361
    goto/16 :goto_1

    .line 362
    .line 363
    :pswitch_13
    mul-int/lit8 v1, v1, 0x35

    .line 364
    .line 365
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v2

    .line 369
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 370
    .line 371
    .line 372
    move-result v2

    .line 373
    goto/16 :goto_1

    .line 374
    .line 375
    :pswitch_14
    mul-int/lit8 v1, v1, 0x35

    .line 376
    .line 377
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v2

    .line 381
    if-eqz v2, :cond_1

    .line 382
    .line 383
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 384
    .line 385
    .line 386
    move-result v8

    .line 387
    :cond_1
    :goto_4
    add-int/2addr v1, v8

    .line 388
    goto/16 :goto_5

    .line 389
    .line 390
    :pswitch_15
    mul-int/lit8 v1, v1, 0x35

    .line 391
    .line 392
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 393
    .line 394
    .line 395
    move-result-wide v2

    .line 396
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 397
    .line 398
    goto/16 :goto_2

    .line 399
    .line 400
    :pswitch_16
    mul-int/lit8 v1, v1, 0x35

    .line 401
    .line 402
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 403
    .line 404
    .line 405
    move-result v2

    .line 406
    goto/16 :goto_1

    .line 407
    .line 408
    :pswitch_17
    mul-int/lit8 v1, v1, 0x35

    .line 409
    .line 410
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 411
    .line 412
    .line 413
    move-result-wide v2

    .line 414
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 415
    .line 416
    goto/16 :goto_2

    .line 417
    .line 418
    :pswitch_18
    mul-int/lit8 v1, v1, 0x35

    .line 419
    .line 420
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 421
    .line 422
    .line 423
    move-result v2

    .line 424
    goto/16 :goto_1

    .line 425
    .line 426
    :pswitch_19
    mul-int/lit8 v1, v1, 0x35

    .line 427
    .line 428
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 429
    .line 430
    .line 431
    move-result v2

    .line 432
    goto/16 :goto_1

    .line 433
    .line 434
    :pswitch_1a
    mul-int/lit8 v1, v1, 0x35

    .line 435
    .line 436
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 437
    .line 438
    .line 439
    move-result v2

    .line 440
    goto/16 :goto_1

    .line 441
    .line 442
    :pswitch_1b
    mul-int/lit8 v1, v1, 0x35

    .line 443
    .line 444
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v2

    .line 448
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 449
    .line 450
    .line 451
    move-result v2

    .line 452
    goto/16 :goto_1

    .line 453
    .line 454
    :pswitch_1c
    mul-int/lit8 v1, v1, 0x35

    .line 455
    .line 456
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v2

    .line 460
    if-eqz v2, :cond_1

    .line 461
    .line 462
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 463
    .line 464
    .line 465
    move-result v8

    .line 466
    goto :goto_4

    .line 467
    :pswitch_1d
    mul-int/lit8 v1, v1, 0x35

    .line 468
    .line 469
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v2

    .line 473
    check-cast v2, Ljava/lang/String;

    .line 474
    .line 475
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 476
    .line 477
    .line 478
    move-result v2

    .line 479
    goto/16 :goto_1

    .line 480
    .line 481
    :pswitch_1e
    mul-int/lit8 v1, v1, 0x35

    .line 482
    .line 483
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 484
    .line 485
    invoke-virtual {v2, v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->g(JLjava/lang/Object;)Z

    .line 486
    .line 487
    .line 488
    move-result v2

    .line 489
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 490
    .line 491
    if-eqz v2, :cond_0

    .line 492
    .line 493
    goto/16 :goto_3

    .line 494
    .line 495
    :pswitch_1f
    mul-int/lit8 v1, v1, 0x35

    .line 496
    .line 497
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 498
    .line 499
    .line 500
    move-result v2

    .line 501
    goto/16 :goto_1

    .line 502
    .line 503
    :pswitch_20
    mul-int/lit8 v1, v1, 0x35

    .line 504
    .line 505
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 506
    .line 507
    .line 508
    move-result-wide v2

    .line 509
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 510
    .line 511
    goto/16 :goto_2

    .line 512
    .line 513
    :pswitch_21
    mul-int/lit8 v1, v1, 0x35

    .line 514
    .line 515
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 516
    .line 517
    .line 518
    move-result v2

    .line 519
    goto/16 :goto_1

    .line 520
    .line 521
    :pswitch_22
    mul-int/lit8 v1, v1, 0x35

    .line 522
    .line 523
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 524
    .line 525
    .line 526
    move-result-wide v2

    .line 527
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 528
    .line 529
    goto/16 :goto_2

    .line 530
    .line 531
    :pswitch_23
    mul-int/lit8 v1, v1, 0x35

    .line 532
    .line 533
    invoke-static {v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 534
    .line 535
    .line 536
    move-result-wide v2

    .line 537
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 538
    .line 539
    goto/16 :goto_2

    .line 540
    .line 541
    :pswitch_24
    mul-int/lit8 v1, v1, 0x35

    .line 542
    .line 543
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 544
    .line 545
    invoke-virtual {v2, v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->b(JLjava/lang/Object;)F

    .line 546
    .line 547
    .line 548
    move-result v2

    .line 549
    invoke-static {v2}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 550
    .line 551
    .line 552
    move-result v2

    .line 553
    goto/16 :goto_1

    .line 554
    .line 555
    :pswitch_25
    mul-int/lit8 v1, v1, 0x35

    .line 556
    .line 557
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 558
    .line 559
    invoke-virtual {v2, v4, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->a(JLjava/lang/Object;)D

    .line 560
    .line 561
    .line 562
    move-result-wide v2

    .line 563
    invoke-static {v2, v3}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 564
    .line 565
    .line 566
    move-result-wide v2

    .line 567
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 568
    .line 569
    goto/16 :goto_2

    .line 570
    .line 571
    :cond_2
    :goto_5
    add-int/lit8 v0, v0, 0x3

    .line 572
    .line 573
    goto/16 :goto_0

    .line 574
    .line 575
    :cond_3
    mul-int/lit8 v1, v1, 0x35

    .line 576
    .line 577
    iget-object v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 578
    .line 579
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->hashCode()I

    .line 580
    .line 581
    .line 582
    move-result v0

    .line 583
    add-int/2addr v0, v1

    .line 584
    iget-boolean p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 585
    .line 586
    if-eqz p0, :cond_4

    .line 587
    .line 588
    mul-int/lit8 v0, v0, 0x35

    .line 589
    .line 590
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 591
    .line 592
    iget-object p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 593
    .line 594
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 595
    .line 596
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->hashCode()I

    .line 597
    .line 598
    .line 599
    move-result p0

    .line 600
    add-int/2addr p0, v0

    .line 601
    return p0

    .line 602
    :cond_4
    return v0

    .line 603
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

.method public final h(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;)I
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    sget-object v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

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
    iget-object v5, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 15
    .line 16
    array-length v10, v5

    .line 17
    if-ge v2, v10, :cond_1c

    .line 18
    .line 19
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 20
    .line 21
    .line 22
    move-result v10

    .line 23
    invoke-static {v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 24
    .line 25
    .line 26
    move-result v11

    .line 27
    add-int/lit8 v12, v2, 0x2

    .line 28
    .line 29
    aget v13, v5, v2

    .line 30
    .line 31
    aget v5, v5, v12

    .line 32
    .line 33
    and-int v12, v5, v8

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
    if-eq v12, v3, :cond_1

    .line 41
    .line 42
    if-ne v12, v8, :cond_0

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    int-to-long v3, v12

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
    move v3, v12

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
    sget-object v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z0;

    .line 61
    .line 62
    iget v12, v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z0;->d:I

    .line 63
    .line 64
    if-lt v11, v12, :cond_3

    .line 65
    .line 66
    sget-object v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z0;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z0;

    .line 67
    .line 68
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    :cond_3
    int-to-long v7, v10

    .line 72
    const/16 v16, 0x3f

    .line 73
    .line 74
    const/4 v10, 0x4

    .line 75
    const/16 v12, 0x8

    .line 76
    .line 77
    packed-switch v11, :pswitch_data_0

    .line 78
    .line 79
    .line 80
    goto/16 :goto_16

    .line 81
    .line 82
    :pswitch_0
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    if-eqz v5, :cond_1b

    .line 87
    .line 88
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 93
    .line 94
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 95
    .line 96
    .line 97
    move-result-object v7

    .line 98
    shl-int/lit8 v8, v13, 0x3

    .line 99
    .line 100
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    add-int/2addr v8, v8

    .line 105
    invoke-virtual {v5, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)I

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    :goto_3
    add-int/2addr v5, v8

    .line 110
    :goto_4
    add-int/2addr v9, v5

    .line 111
    goto/16 :goto_16

    .line 112
    .line 113
    :pswitch_1
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    if-eqz v5, :cond_1b

    .line 118
    .line 119
    shl-int/lit8 v5, v13, 0x3

    .line 120
    .line 121
    invoke-static {v7, v8, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 122
    .line 123
    .line 124
    move-result-wide v7

    .line 125
    add-long v10, v7, v7

    .line 126
    .line 127
    shr-long v7, v7, v16

    .line 128
    .line 129
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 130
    .line 131
    .line 132
    move-result v5

    .line 133
    xor-long/2addr v7, v10

    .line 134
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 135
    .line 136
    .line 137
    move-result v7

    .line 138
    :goto_5
    add-int/2addr v7, v5

    .line 139
    add-int/2addr v9, v7

    .line 140
    goto/16 :goto_16

    .line 141
    .line 142
    :pswitch_2
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    if-eqz v5, :cond_1b

    .line 147
    .line 148
    shl-int/lit8 v5, v13, 0x3

    .line 149
    .line 150
    invoke-static {v7, v8, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 151
    .line 152
    .line 153
    move-result v7

    .line 154
    add-int v8, v7, v7

    .line 155
    .line 156
    shr-int/lit8 v7, v7, 0x1f

    .line 157
    .line 158
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 159
    .line 160
    .line 161
    move-result v5

    .line 162
    xor-int/2addr v7, v8

    .line 163
    invoke-static {v7, v5, v9}, Lc1/j0;->u(III)I

    .line 164
    .line 165
    .line 166
    move-result v9

    .line 167
    goto/16 :goto_16

    .line 168
    .line 169
    :pswitch_3
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 170
    .line 171
    .line 172
    move-result v5

    .line 173
    if-eqz v5, :cond_1b

    .line 174
    .line 175
    shl-int/lit8 v5, v13, 0x3

    .line 176
    .line 177
    invoke-static {v5, v12, v9}, Lc1/j0;->u(III)I

    .line 178
    .line 179
    .line 180
    move-result v9

    .line 181
    goto/16 :goto_16

    .line 182
    .line 183
    :pswitch_4
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 184
    .line 185
    .line 186
    move-result v5

    .line 187
    if-eqz v5, :cond_1b

    .line 188
    .line 189
    shl-int/lit8 v5, v13, 0x3

    .line 190
    .line 191
    invoke-static {v5, v10, v9}, Lc1/j0;->u(III)I

    .line 192
    .line 193
    .line 194
    move-result v9

    .line 195
    goto/16 :goto_16

    .line 196
    .line 197
    :pswitch_5
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-eqz v5, :cond_1b

    .line 202
    .line 203
    shl-int/lit8 v5, v13, 0x3

    .line 204
    .line 205
    invoke-static {v7, v8, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 206
    .line 207
    .line 208
    move-result v7

    .line 209
    int-to-long v7, v7

    .line 210
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 211
    .line 212
    .line 213
    move-result v5

    .line 214
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 215
    .line 216
    .line 217
    move-result v7

    .line 218
    goto :goto_5

    .line 219
    :pswitch_6
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 220
    .line 221
    .line 222
    move-result v5

    .line 223
    if-eqz v5, :cond_1b

    .line 224
    .line 225
    shl-int/lit8 v5, v13, 0x3

    .line 226
    .line 227
    invoke-static {v7, v8, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 228
    .line 229
    .line 230
    move-result v7

    .line 231
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 232
    .line 233
    .line 234
    move-result v5

    .line 235
    invoke-static {v7, v5, v9}, Lc1/j0;->u(III)I

    .line 236
    .line 237
    .line 238
    move-result v9

    .line 239
    goto/16 :goto_16

    .line 240
    .line 241
    :pswitch_7
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 242
    .line 243
    .line 244
    move-result v5

    .line 245
    if-eqz v5, :cond_1b

    .line 246
    .line 247
    shl-int/lit8 v5, v13, 0x3

    .line 248
    .line 249
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v7

    .line 253
    check-cast v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 254
    .line 255
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 256
    .line 257
    .line 258
    move-result v5

    .line 259
    invoke-virtual {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 260
    .line 261
    .line 262
    move-result v7

    .line 263
    invoke-static {v7, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 264
    .line 265
    .line 266
    move-result v9

    .line 267
    goto/16 :goto_16

    .line 268
    .line 269
    :pswitch_8
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 270
    .line 271
    .line 272
    move-result v5

    .line 273
    if-eqz v5, :cond_1b

    .line 274
    .line 275
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 280
    .line 281
    .line 282
    move-result-object v7

    .line 283
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 284
    .line 285
    shl-int/lit8 v8, v13, 0x3

    .line 286
    .line 287
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 288
    .line 289
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 290
    .line 291
    .line 292
    move-result v8

    .line 293
    invoke-virtual {v5, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)I

    .line 294
    .line 295
    .line 296
    move-result v5

    .line 297
    invoke-static {v5, v5, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 298
    .line 299
    .line 300
    move-result v9

    .line 301
    goto/16 :goto_16

    .line 302
    .line 303
    :pswitch_9
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 304
    .line 305
    .line 306
    move-result v5

    .line 307
    if-eqz v5, :cond_1b

    .line 308
    .line 309
    shl-int/lit8 v5, v13, 0x3

    .line 310
    .line 311
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v7

    .line 315
    instance-of v8, v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 316
    .line 317
    if-eqz v8, :cond_4

    .line 318
    .line 319
    check-cast v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 320
    .line 321
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 322
    .line 323
    .line 324
    move-result v5

    .line 325
    invoke-virtual {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 326
    .line 327
    .line 328
    move-result v7

    .line 329
    invoke-static {v7, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 330
    .line 331
    .line 332
    move-result v9

    .line 333
    goto/16 :goto_16

    .line 334
    .line 335
    :cond_4
    check-cast v7, Ljava/lang/String;

    .line 336
    .line 337
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 338
    .line 339
    .line 340
    move-result v5

    .line 341
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->v(Ljava/lang/String;)I

    .line 342
    .line 343
    .line 344
    move-result v7

    .line 345
    goto/16 :goto_5

    .line 346
    .line 347
    :pswitch_a
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 348
    .line 349
    .line 350
    move-result v5

    .line 351
    if-eqz v5, :cond_1b

    .line 352
    .line 353
    shl-int/lit8 v5, v13, 0x3

    .line 354
    .line 355
    invoke-static {v5, v15, v9}, Lc1/j0;->u(III)I

    .line 356
    .line 357
    .line 358
    move-result v9

    .line 359
    goto/16 :goto_16

    .line 360
    .line 361
    :pswitch_b
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 362
    .line 363
    .line 364
    move-result v5

    .line 365
    if-eqz v5, :cond_1b

    .line 366
    .line 367
    shl-int/lit8 v5, v13, 0x3

    .line 368
    .line 369
    invoke-static {v5, v10, v9}, Lc1/j0;->u(III)I

    .line 370
    .line 371
    .line 372
    move-result v9

    .line 373
    goto/16 :goto_16

    .line 374
    .line 375
    :pswitch_c
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 376
    .line 377
    .line 378
    move-result v5

    .line 379
    if-eqz v5, :cond_1b

    .line 380
    .line 381
    shl-int/lit8 v5, v13, 0x3

    .line 382
    .line 383
    invoke-static {v5, v12, v9}, Lc1/j0;->u(III)I

    .line 384
    .line 385
    .line 386
    move-result v9

    .line 387
    goto/16 :goto_16

    .line 388
    .line 389
    :pswitch_d
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 390
    .line 391
    .line 392
    move-result v5

    .line 393
    if-eqz v5, :cond_1b

    .line 394
    .line 395
    shl-int/lit8 v5, v13, 0x3

    .line 396
    .line 397
    invoke-static {v7, v8, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->w(JLjava/lang/Object;)I

    .line 398
    .line 399
    .line 400
    move-result v7

    .line 401
    int-to-long v7, v7

    .line 402
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 403
    .line 404
    .line 405
    move-result v5

    .line 406
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 407
    .line 408
    .line 409
    move-result v7

    .line 410
    goto/16 :goto_5

    .line 411
    .line 412
    :pswitch_e
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 413
    .line 414
    .line 415
    move-result v5

    .line 416
    if-eqz v5, :cond_1b

    .line 417
    .line 418
    shl-int/lit8 v5, v13, 0x3

    .line 419
    .line 420
    invoke-static {v7, v8, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 421
    .line 422
    .line 423
    move-result-wide v7

    .line 424
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 425
    .line 426
    .line 427
    move-result v5

    .line 428
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 429
    .line 430
    .line 431
    move-result v7

    .line 432
    goto/16 :goto_5

    .line 433
    .line 434
    :pswitch_f
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 435
    .line 436
    .line 437
    move-result v5

    .line 438
    if-eqz v5, :cond_1b

    .line 439
    .line 440
    shl-int/lit8 v5, v13, 0x3

    .line 441
    .line 442
    invoke-static {v7, v8, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->A(JLjava/lang/Object;)J

    .line 443
    .line 444
    .line 445
    move-result-wide v7

    .line 446
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 447
    .line 448
    .line 449
    move-result v5

    .line 450
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 451
    .line 452
    .line 453
    move-result v7

    .line 454
    goto/16 :goto_5

    .line 455
    .line 456
    :pswitch_10
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 457
    .line 458
    .line 459
    move-result v5

    .line 460
    if-eqz v5, :cond_1b

    .line 461
    .line 462
    shl-int/lit8 v5, v13, 0x3

    .line 463
    .line 464
    invoke-static {v5, v10, v9}, Lc1/j0;->u(III)I

    .line 465
    .line 466
    .line 467
    move-result v9

    .line 468
    goto/16 :goto_16

    .line 469
    .line 470
    :pswitch_11
    invoke-virtual {v0, v13, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 471
    .line 472
    .line 473
    move-result v5

    .line 474
    if-eqz v5, :cond_1b

    .line 475
    .line 476
    shl-int/lit8 v5, v13, 0x3

    .line 477
    .line 478
    invoke-static {v5, v12, v9}, Lc1/j0;->u(III)I

    .line 479
    .line 480
    .line 481
    move-result v9

    .line 482
    goto/16 :goto_16

    .line 483
    .line 484
    :pswitch_12
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object v5

    .line 488
    div-int/lit8 v7, v2, 0x3

    .line 489
    .line 490
    iget-object v8, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->b:[Ljava/lang/Object;

    .line 491
    .line 492
    add-int/2addr v7, v7

    .line 493
    aget-object v7, v8, v7

    .line 494
    .line 495
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 496
    .line 497
    if-nez v7, :cond_6

    .line 498
    .line 499
    invoke-virtual {v5}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 500
    .line 501
    .line 502
    move-result v7

    .line 503
    if-nez v7, :cond_1b

    .line 504
    .line 505
    invoke-virtual {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->entrySet()Ljava/util/Set;

    .line 506
    .line 507
    .line 508
    move-result-object v5

    .line 509
    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 510
    .line 511
    .line 512
    move-result-object v5

    .line 513
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 514
    .line 515
    .line 516
    move-result v7

    .line 517
    if-nez v7, :cond_5

    .line 518
    .line 519
    goto/16 :goto_16

    .line 520
    .line 521
    :cond_5
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    move-result-object v0

    .line 525
    check-cast v0, Ljava/util/Map$Entry;

    .line 526
    .line 527
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 531
    .line 532
    .line 533
    const/4 v0, 0x0

    .line 534
    throw v0

    .line 535
    :cond_6
    new-instance v0, Ljava/lang/ClassCastException;

    .line 536
    .line 537
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 538
    .line 539
    .line 540
    throw v0

    .line 541
    :pswitch_13
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 542
    .line 543
    .line 544
    move-result-object v5

    .line 545
    check-cast v5, Ljava/util/List;

    .line 546
    .line 547
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 548
    .line 549
    .line 550
    move-result-object v7

    .line 551
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 552
    .line 553
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 554
    .line 555
    .line 556
    move-result v8

    .line 557
    if-nez v8, :cond_7

    .line 558
    .line 559
    const/4 v11, 0x0

    .line 560
    goto :goto_7

    .line 561
    :cond_7
    const/4 v10, 0x0

    .line 562
    const/4 v11, 0x0

    .line 563
    :goto_6
    if-ge v10, v8, :cond_8

    .line 564
    .line 565
    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 566
    .line 567
    .line 568
    move-result-object v12

    .line 569
    check-cast v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 570
    .line 571
    shl-int/lit8 v15, v13, 0x3

    .line 572
    .line 573
    invoke-static {v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 574
    .line 575
    .line 576
    move-result v15

    .line 577
    add-int/2addr v15, v15

    .line 578
    invoke-virtual {v12, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)I

    .line 579
    .line 580
    .line 581
    move-result v12

    .line 582
    add-int/2addr v12, v15

    .line 583
    add-int/2addr v11, v12

    .line 584
    add-int/lit8 v10, v10, 0x1

    .line 585
    .line 586
    goto :goto_6

    .line 587
    :cond_8
    :goto_7
    add-int/2addr v9, v11

    .line 588
    goto/16 :goto_16

    .line 589
    .line 590
    :pswitch_14
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 591
    .line 592
    .line 593
    move-result-object v5

    .line 594
    check-cast v5, Ljava/util/List;

    .line 595
    .line 596
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->l(Ljava/util/List;)I

    .line 597
    .line 598
    .line 599
    move-result v5

    .line 600
    if-lez v5, :cond_1b

    .line 601
    .line 602
    shl-int/lit8 v7, v13, 0x3

    .line 603
    .line 604
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 605
    .line 606
    .line 607
    move-result v7

    .line 608
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 609
    .line 610
    .line 611
    move-result v9

    .line 612
    goto/16 :goto_16

    .line 613
    .line 614
    :pswitch_15
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 615
    .line 616
    .line 617
    move-result-object v5

    .line 618
    check-cast v5, Ljava/util/List;

    .line 619
    .line 620
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->k(Ljava/util/List;)I

    .line 621
    .line 622
    .line 623
    move-result v5

    .line 624
    if-lez v5, :cond_1b

    .line 625
    .line 626
    shl-int/lit8 v7, v13, 0x3

    .line 627
    .line 628
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 629
    .line 630
    .line 631
    move-result v7

    .line 632
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 633
    .line 634
    .line 635
    move-result v9

    .line 636
    goto/16 :goto_16

    .line 637
    .line 638
    :pswitch_16
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 639
    .line 640
    .line 641
    move-result-object v5

    .line 642
    check-cast v5, Ljava/util/List;

    .line 643
    .line 644
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 645
    .line 646
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 647
    .line 648
    .line 649
    move-result v5

    .line 650
    mul-int/2addr v5, v12

    .line 651
    if-lez v5, :cond_1b

    .line 652
    .line 653
    shl-int/lit8 v7, v13, 0x3

    .line 654
    .line 655
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 656
    .line 657
    .line 658
    move-result v7

    .line 659
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 660
    .line 661
    .line 662
    move-result v9

    .line 663
    goto/16 :goto_16

    .line 664
    .line 665
    :pswitch_17
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 666
    .line 667
    .line 668
    move-result-object v5

    .line 669
    check-cast v5, Ljava/util/List;

    .line 670
    .line 671
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 672
    .line 673
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 674
    .line 675
    .line 676
    move-result v5

    .line 677
    mul-int/2addr v5, v10

    .line 678
    if-lez v5, :cond_1b

    .line 679
    .line 680
    shl-int/lit8 v7, v13, 0x3

    .line 681
    .line 682
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 683
    .line 684
    .line 685
    move-result v7

    .line 686
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 687
    .line 688
    .line 689
    move-result v9

    .line 690
    goto/16 :goto_16

    .line 691
    .line 692
    :pswitch_18
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 693
    .line 694
    .line 695
    move-result-object v5

    .line 696
    check-cast v5, Ljava/util/List;

    .line 697
    .line 698
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->f(Ljava/util/List;)I

    .line 699
    .line 700
    .line 701
    move-result v5

    .line 702
    if-lez v5, :cond_1b

    .line 703
    .line 704
    shl-int/lit8 v7, v13, 0x3

    .line 705
    .line 706
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 707
    .line 708
    .line 709
    move-result v7

    .line 710
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 711
    .line 712
    .line 713
    move-result v9

    .line 714
    goto/16 :goto_16

    .line 715
    .line 716
    :pswitch_19
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 717
    .line 718
    .line 719
    move-result-object v5

    .line 720
    check-cast v5, Ljava/util/List;

    .line 721
    .line 722
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->m(Ljava/util/List;)I

    .line 723
    .line 724
    .line 725
    move-result v5

    .line 726
    if-lez v5, :cond_1b

    .line 727
    .line 728
    shl-int/lit8 v7, v13, 0x3

    .line 729
    .line 730
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 731
    .line 732
    .line 733
    move-result v7

    .line 734
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 735
    .line 736
    .line 737
    move-result v9

    .line 738
    goto/16 :goto_16

    .line 739
    .line 740
    :pswitch_1a
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 741
    .line 742
    .line 743
    move-result-object v5

    .line 744
    check-cast v5, Ljava/util/List;

    .line 745
    .line 746
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 747
    .line 748
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 749
    .line 750
    .line 751
    move-result v5

    .line 752
    if-lez v5, :cond_1b

    .line 753
    .line 754
    shl-int/lit8 v7, v13, 0x3

    .line 755
    .line 756
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 757
    .line 758
    .line 759
    move-result v7

    .line 760
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 761
    .line 762
    .line 763
    move-result v9

    .line 764
    goto/16 :goto_16

    .line 765
    .line 766
    :pswitch_1b
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 767
    .line 768
    .line 769
    move-result-object v5

    .line 770
    check-cast v5, Ljava/util/List;

    .line 771
    .line 772
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 773
    .line 774
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 775
    .line 776
    .line 777
    move-result v5

    .line 778
    mul-int/2addr v5, v10

    .line 779
    if-lez v5, :cond_1b

    .line 780
    .line 781
    shl-int/lit8 v7, v13, 0x3

    .line 782
    .line 783
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 784
    .line 785
    .line 786
    move-result v7

    .line 787
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 788
    .line 789
    .line 790
    move-result v9

    .line 791
    goto/16 :goto_16

    .line 792
    .line 793
    :pswitch_1c
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    move-result-object v5

    .line 797
    check-cast v5, Ljava/util/List;

    .line 798
    .line 799
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 800
    .line 801
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 802
    .line 803
    .line 804
    move-result v5

    .line 805
    mul-int/2addr v5, v12

    .line 806
    if-lez v5, :cond_1b

    .line 807
    .line 808
    shl-int/lit8 v7, v13, 0x3

    .line 809
    .line 810
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 811
    .line 812
    .line 813
    move-result v7

    .line 814
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 815
    .line 816
    .line 817
    move-result v9

    .line 818
    goto/16 :goto_16

    .line 819
    .line 820
    :pswitch_1d
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 821
    .line 822
    .line 823
    move-result-object v5

    .line 824
    check-cast v5, Ljava/util/List;

    .line 825
    .line 826
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->i(Ljava/util/List;)I

    .line 827
    .line 828
    .line 829
    move-result v5

    .line 830
    if-lez v5, :cond_1b

    .line 831
    .line 832
    shl-int/lit8 v7, v13, 0x3

    .line 833
    .line 834
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 835
    .line 836
    .line 837
    move-result v7

    .line 838
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 839
    .line 840
    .line 841
    move-result v9

    .line 842
    goto/16 :goto_16

    .line 843
    .line 844
    :pswitch_1e
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v5

    .line 848
    check-cast v5, Ljava/util/List;

    .line 849
    .line 850
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->n(Ljava/util/List;)I

    .line 851
    .line 852
    .line 853
    move-result v5

    .line 854
    if-lez v5, :cond_1b

    .line 855
    .line 856
    shl-int/lit8 v7, v13, 0x3

    .line 857
    .line 858
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 859
    .line 860
    .line 861
    move-result v7

    .line 862
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 863
    .line 864
    .line 865
    move-result v9

    .line 866
    goto/16 :goto_16

    .line 867
    .line 868
    :pswitch_1f
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 869
    .line 870
    .line 871
    move-result-object v5

    .line 872
    check-cast v5, Ljava/util/List;

    .line 873
    .line 874
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->j(Ljava/util/List;)I

    .line 875
    .line 876
    .line 877
    move-result v5

    .line 878
    if-lez v5, :cond_1b

    .line 879
    .line 880
    shl-int/lit8 v7, v13, 0x3

    .line 881
    .line 882
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 883
    .line 884
    .line 885
    move-result v7

    .line 886
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 887
    .line 888
    .line 889
    move-result v9

    .line 890
    goto/16 :goto_16

    .line 891
    .line 892
    :pswitch_20
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 893
    .line 894
    .line 895
    move-result-object v5

    .line 896
    check-cast v5, Ljava/util/List;

    .line 897
    .line 898
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 899
    .line 900
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 901
    .line 902
    .line 903
    move-result v5

    .line 904
    mul-int/2addr v5, v10

    .line 905
    if-lez v5, :cond_1b

    .line 906
    .line 907
    shl-int/lit8 v7, v13, 0x3

    .line 908
    .line 909
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 910
    .line 911
    .line 912
    move-result v7

    .line 913
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 914
    .line 915
    .line 916
    move-result v9

    .line 917
    goto/16 :goto_16

    .line 918
    .line 919
    :pswitch_21
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 920
    .line 921
    .line 922
    move-result-object v5

    .line 923
    check-cast v5, Ljava/util/List;

    .line 924
    .line 925
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 926
    .line 927
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 928
    .line 929
    .line 930
    move-result v5

    .line 931
    mul-int/2addr v5, v12

    .line 932
    if-lez v5, :cond_1b

    .line 933
    .line 934
    shl-int/lit8 v7, v13, 0x3

    .line 935
    .line 936
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 937
    .line 938
    .line 939
    move-result v7

    .line 940
    invoke-static {v5, v7, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 941
    .line 942
    .line 943
    move-result v9

    .line 944
    goto/16 :goto_16

    .line 945
    .line 946
    :pswitch_22
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 947
    .line 948
    .line 949
    move-result-object v5

    .line 950
    check-cast v5, Ljava/util/List;

    .line 951
    .line 952
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 953
    .line 954
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 955
    .line 956
    .line 957
    move-result v7

    .line 958
    if-nez v7, :cond_9

    .line 959
    .line 960
    :goto_8
    const/4 v8, 0x0

    .line 961
    goto :goto_a

    .line 962
    :cond_9
    shl-int/lit8 v8, v13, 0x3

    .line 963
    .line 964
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->l(Ljava/util/List;)I

    .line 965
    .line 966
    .line 967
    move-result v5

    .line 968
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 969
    .line 970
    .line 971
    move-result v8

    .line 972
    :goto_9
    mul-int/2addr v8, v7

    .line 973
    add-int/2addr v8, v5

    .line 974
    :cond_a
    :goto_a
    add-int/2addr v9, v8

    .line 975
    goto/16 :goto_16

    .line 976
    .line 977
    :pswitch_23
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 978
    .line 979
    .line 980
    move-result-object v5

    .line 981
    check-cast v5, Ljava/util/List;

    .line 982
    .line 983
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 984
    .line 985
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 986
    .line 987
    .line 988
    move-result v7

    .line 989
    if-nez v7, :cond_b

    .line 990
    .line 991
    goto :goto_8

    .line 992
    :cond_b
    shl-int/lit8 v8, v13, 0x3

    .line 993
    .line 994
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->k(Ljava/util/List;)I

    .line 995
    .line 996
    .line 997
    move-result v5

    .line 998
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 999
    .line 1000
    .line 1001
    move-result v8

    .line 1002
    goto :goto_9

    .line 1003
    :pswitch_24
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v5

    .line 1007
    check-cast v5, Ljava/util/List;

    .line 1008
    .line 1009
    invoke-static {v13, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->h(ILjava/util/List;)I

    .line 1010
    .line 1011
    .line 1012
    move-result v5

    .line 1013
    goto/16 :goto_4

    .line 1014
    .line 1015
    :pswitch_25
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v5

    .line 1019
    check-cast v5, Ljava/util/List;

    .line 1020
    .line 1021
    invoke-static {v13, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->g(ILjava/util/List;)I

    .line 1022
    .line 1023
    .line 1024
    move-result v5

    .line 1025
    goto/16 :goto_4

    .line 1026
    .line 1027
    :pswitch_26
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v5

    .line 1031
    check-cast v5, Ljava/util/List;

    .line 1032
    .line 1033
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1034
    .line 1035
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1036
    .line 1037
    .line 1038
    move-result v7

    .line 1039
    if-nez v7, :cond_c

    .line 1040
    .line 1041
    goto :goto_8

    .line 1042
    :cond_c
    shl-int/lit8 v8, v13, 0x3

    .line 1043
    .line 1044
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->f(Ljava/util/List;)I

    .line 1045
    .line 1046
    .line 1047
    move-result v5

    .line 1048
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1049
    .line 1050
    .line 1051
    move-result v8

    .line 1052
    goto :goto_9

    .line 1053
    :pswitch_27
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v5

    .line 1057
    check-cast v5, Ljava/util/List;

    .line 1058
    .line 1059
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1060
    .line 1061
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1062
    .line 1063
    .line 1064
    move-result v7

    .line 1065
    if-nez v7, :cond_d

    .line 1066
    .line 1067
    goto :goto_8

    .line 1068
    :cond_d
    shl-int/lit8 v8, v13, 0x3

    .line 1069
    .line 1070
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->m(Ljava/util/List;)I

    .line 1071
    .line 1072
    .line 1073
    move-result v5

    .line 1074
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1075
    .line 1076
    .line 1077
    move-result v8

    .line 1078
    goto :goto_9

    .line 1079
    :pswitch_28
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1080
    .line 1081
    .line 1082
    move-result-object v5

    .line 1083
    check-cast v5, Ljava/util/List;

    .line 1084
    .line 1085
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1086
    .line 1087
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1088
    .line 1089
    .line 1090
    move-result v7

    .line 1091
    if-nez v7, :cond_e

    .line 1092
    .line 1093
    goto/16 :goto_8

    .line 1094
    .line 1095
    :cond_e
    shl-int/lit8 v8, v13, 0x3

    .line 1096
    .line 1097
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1098
    .line 1099
    .line 1100
    move-result v8

    .line 1101
    mul-int/2addr v8, v7

    .line 1102
    const/4 v7, 0x0

    .line 1103
    :goto_b
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1104
    .line 1105
    .line 1106
    move-result v10

    .line 1107
    if-ge v7, v10, :cond_a

    .line 1108
    .line 1109
    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v10

    .line 1113
    check-cast v10, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1114
    .line 1115
    invoke-virtual {v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 1116
    .line 1117
    .line 1118
    move-result v10

    .line 1119
    invoke-static {v10, v10, v8}, Lc1/j0;->u(III)I

    .line 1120
    .line 1121
    .line 1122
    move-result v8

    .line 1123
    add-int/lit8 v7, v7, 0x1

    .line 1124
    .line 1125
    goto :goto_b

    .line 1126
    :pswitch_29
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v5

    .line 1130
    check-cast v5, Ljava/util/List;

    .line 1131
    .line 1132
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v7

    .line 1136
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1137
    .line 1138
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1139
    .line 1140
    .line 1141
    move-result v8

    .line 1142
    if-nez v8, :cond_f

    .line 1143
    .line 1144
    const/4 v10, 0x0

    .line 1145
    goto :goto_d

    .line 1146
    :cond_f
    shl-int/lit8 v10, v13, 0x3

    .line 1147
    .line 1148
    invoke-static {v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1149
    .line 1150
    .line 1151
    move-result v10

    .line 1152
    mul-int/2addr v10, v8

    .line 1153
    const/4 v11, 0x0

    .line 1154
    :goto_c
    if-ge v11, v8, :cond_10

    .line 1155
    .line 1156
    invoke-interface {v5, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v12

    .line 1160
    check-cast v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 1161
    .line 1162
    invoke-virtual {v12, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)I

    .line 1163
    .line 1164
    .line 1165
    move-result v12

    .line 1166
    invoke-static {v12, v12, v10}, Lc1/j0;->u(III)I

    .line 1167
    .line 1168
    .line 1169
    move-result v10

    .line 1170
    add-int/lit8 v11, v11, 0x1

    .line 1171
    .line 1172
    goto :goto_c

    .line 1173
    :cond_10
    :goto_d
    add-int/2addr v9, v10

    .line 1174
    goto/16 :goto_16

    .line 1175
    .line 1176
    :pswitch_2a
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1177
    .line 1178
    .line 1179
    move-result-object v5

    .line 1180
    check-cast v5, Ljava/util/List;

    .line 1181
    .line 1182
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1183
    .line 1184
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1185
    .line 1186
    .line 1187
    move-result v7

    .line 1188
    if-nez v7, :cond_11

    .line 1189
    .line 1190
    goto/16 :goto_8

    .line 1191
    .line 1192
    :cond_11
    shl-int/lit8 v8, v13, 0x3

    .line 1193
    .line 1194
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1195
    .line 1196
    .line 1197
    move-result v8

    .line 1198
    mul-int/2addr v8, v7

    .line 1199
    instance-of v10, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r1;

    .line 1200
    .line 1201
    if-eqz v10, :cond_13

    .line 1202
    .line 1203
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r1;

    .line 1204
    .line 1205
    const/4 v10, 0x0

    .line 1206
    :goto_e
    if-ge v10, v7, :cond_a

    .line 1207
    .line 1208
    invoke-interface {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r1;->h()Ljava/lang/Object;

    .line 1209
    .line 1210
    .line 1211
    move-result-object v11

    .line 1212
    instance-of v12, v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1213
    .line 1214
    if-eqz v12, :cond_12

    .line 1215
    .line 1216
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1217
    .line 1218
    invoke-virtual {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 1219
    .line 1220
    .line 1221
    move-result v11

    .line 1222
    invoke-static {v11, v11, v8}, Lc1/j0;->u(III)I

    .line 1223
    .line 1224
    .line 1225
    move-result v8

    .line 1226
    goto :goto_f

    .line 1227
    :cond_12
    check-cast v11, Ljava/lang/String;

    .line 1228
    .line 1229
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->v(Ljava/lang/String;)I

    .line 1230
    .line 1231
    .line 1232
    move-result v11

    .line 1233
    add-int/2addr v11, v8

    .line 1234
    move v8, v11

    .line 1235
    :goto_f
    add-int/lit8 v10, v10, 0x1

    .line 1236
    .line 1237
    goto :goto_e

    .line 1238
    :cond_13
    const/4 v10, 0x0

    .line 1239
    :goto_10
    if-ge v10, v7, :cond_a

    .line 1240
    .line 1241
    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1242
    .line 1243
    .line 1244
    move-result-object v11

    .line 1245
    instance-of v12, v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1246
    .line 1247
    if-eqz v12, :cond_14

    .line 1248
    .line 1249
    check-cast v11, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1250
    .line 1251
    invoke-virtual {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 1252
    .line 1253
    .line 1254
    move-result v11

    .line 1255
    invoke-static {v11, v11, v8}, Lc1/j0;->u(III)I

    .line 1256
    .line 1257
    .line 1258
    move-result v8

    .line 1259
    goto :goto_11

    .line 1260
    :cond_14
    check-cast v11, Ljava/lang/String;

    .line 1261
    .line 1262
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->v(Ljava/lang/String;)I

    .line 1263
    .line 1264
    .line 1265
    move-result v11

    .line 1266
    add-int/2addr v11, v8

    .line 1267
    move v8, v11

    .line 1268
    :goto_11
    add-int/lit8 v10, v10, 0x1

    .line 1269
    .line 1270
    goto :goto_10

    .line 1271
    :pswitch_2b
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v5

    .line 1275
    check-cast v5, Ljava/util/List;

    .line 1276
    .line 1277
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1278
    .line 1279
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1280
    .line 1281
    .line 1282
    move-result v5

    .line 1283
    if-nez v5, :cond_15

    .line 1284
    .line 1285
    :goto_12
    const/4 v7, 0x0

    .line 1286
    goto :goto_13

    .line 1287
    :cond_15
    shl-int/lit8 v7, v13, 0x3

    .line 1288
    .line 1289
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1290
    .line 1291
    .line 1292
    move-result v7

    .line 1293
    add-int/2addr v7, v15

    .line 1294
    mul-int/2addr v7, v5

    .line 1295
    :goto_13
    add-int/2addr v9, v7

    .line 1296
    goto/16 :goto_16

    .line 1297
    .line 1298
    :pswitch_2c
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1299
    .line 1300
    .line 1301
    move-result-object v5

    .line 1302
    check-cast v5, Ljava/util/List;

    .line 1303
    .line 1304
    invoke-static {v13, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->g(ILjava/util/List;)I

    .line 1305
    .line 1306
    .line 1307
    move-result v5

    .line 1308
    goto/16 :goto_4

    .line 1309
    .line 1310
    :pswitch_2d
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1311
    .line 1312
    .line 1313
    move-result-object v5

    .line 1314
    check-cast v5, Ljava/util/List;

    .line 1315
    .line 1316
    invoke-static {v13, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->h(ILjava/util/List;)I

    .line 1317
    .line 1318
    .line 1319
    move-result v5

    .line 1320
    goto/16 :goto_4

    .line 1321
    .line 1322
    :pswitch_2e
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1323
    .line 1324
    .line 1325
    move-result-object v5

    .line 1326
    check-cast v5, Ljava/util/List;

    .line 1327
    .line 1328
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1329
    .line 1330
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1331
    .line 1332
    .line 1333
    move-result v7

    .line 1334
    if-nez v7, :cond_16

    .line 1335
    .line 1336
    goto/16 :goto_8

    .line 1337
    .line 1338
    :cond_16
    shl-int/lit8 v8, v13, 0x3

    .line 1339
    .line 1340
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->i(Ljava/util/List;)I

    .line 1341
    .line 1342
    .line 1343
    move-result v5

    .line 1344
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1345
    .line 1346
    .line 1347
    move-result v8

    .line 1348
    goto/16 :goto_9

    .line 1349
    .line 1350
    :pswitch_2f
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v5

    .line 1354
    check-cast v5, Ljava/util/List;

    .line 1355
    .line 1356
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1357
    .line 1358
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1359
    .line 1360
    .line 1361
    move-result v7

    .line 1362
    if-nez v7, :cond_17

    .line 1363
    .line 1364
    goto/16 :goto_8

    .line 1365
    .line 1366
    :cond_17
    shl-int/lit8 v8, v13, 0x3

    .line 1367
    .line 1368
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->n(Ljava/util/List;)I

    .line 1369
    .line 1370
    .line 1371
    move-result v5

    .line 1372
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1373
    .line 1374
    .line 1375
    move-result v8

    .line 1376
    goto/16 :goto_9

    .line 1377
    .line 1378
    :pswitch_30
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1379
    .line 1380
    .line 1381
    move-result-object v5

    .line 1382
    check-cast v5, Ljava/util/List;

    .line 1383
    .line 1384
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1385
    .line 1386
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1387
    .line 1388
    .line 1389
    move-result v7

    .line 1390
    if-nez v7, :cond_18

    .line 1391
    .line 1392
    goto :goto_12

    .line 1393
    :cond_18
    shl-int/lit8 v7, v13, 0x3

    .line 1394
    .line 1395
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->j(Ljava/util/List;)I

    .line 1396
    .line 1397
    .line 1398
    move-result v8

    .line 1399
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 1400
    .line 1401
    .line 1402
    move-result v5

    .line 1403
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1404
    .line 1405
    .line 1406
    move-result v7

    .line 1407
    mul-int/2addr v7, v5

    .line 1408
    add-int/2addr v7, v8

    .line 1409
    goto :goto_13

    .line 1410
    :pswitch_31
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1411
    .line 1412
    .line 1413
    move-result-object v5

    .line 1414
    check-cast v5, Ljava/util/List;

    .line 1415
    .line 1416
    invoke-static {v13, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->g(ILjava/util/List;)I

    .line 1417
    .line 1418
    .line 1419
    move-result v5

    .line 1420
    goto/16 :goto_4

    .line 1421
    .line 1422
    :pswitch_32
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1423
    .line 1424
    .line 1425
    move-result-object v5

    .line 1426
    check-cast v5, Ljava/util/List;

    .line 1427
    .line 1428
    invoke-static {v13, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->h(ILjava/util/List;)I

    .line 1429
    .line 1430
    .line 1431
    move-result v5

    .line 1432
    goto/16 :goto_4

    .line 1433
    .line 1434
    :pswitch_33
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1435
    .line 1436
    .line 1437
    move-result v5

    .line 1438
    if-eqz v5, :cond_1b

    .line 1439
    .line 1440
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v5

    .line 1444
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 1445
    .line 1446
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v7

    .line 1450
    shl-int/lit8 v8, v13, 0x3

    .line 1451
    .line 1452
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1453
    .line 1454
    .line 1455
    move-result v8

    .line 1456
    add-int/2addr v8, v8

    .line 1457
    invoke-virtual {v5, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)I

    .line 1458
    .line 1459
    .line 1460
    move-result v5

    .line 1461
    goto/16 :goto_3

    .line 1462
    .line 1463
    :pswitch_34
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1464
    .line 1465
    .line 1466
    move-result v5

    .line 1467
    if-eqz v5, :cond_19

    .line 1468
    .line 1469
    shl-int/lit8 v0, v13, 0x3

    .line 1470
    .line 1471
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1472
    .line 1473
    .line 1474
    move-result-wide v7

    .line 1475
    add-long v10, v7, v7

    .line 1476
    .line 1477
    shr-long v7, v7, v16

    .line 1478
    .line 1479
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1480
    .line 1481
    .line 1482
    move-result v0

    .line 1483
    xor-long/2addr v7, v10

    .line 1484
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 1485
    .line 1486
    .line 1487
    move-result v5

    .line 1488
    :goto_14
    add-int/2addr v5, v0

    .line 1489
    add-int/2addr v9, v5

    .line 1490
    :cond_19
    :goto_15
    move-object/from16 v0, p0

    .line 1491
    .line 1492
    goto/16 :goto_16

    .line 1493
    .line 1494
    :pswitch_35
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1495
    .line 1496
    .line 1497
    move-result v5

    .line 1498
    if-eqz v5, :cond_19

    .line 1499
    .line 1500
    shl-int/lit8 v0, v13, 0x3

    .line 1501
    .line 1502
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1503
    .line 1504
    .line 1505
    move-result v5

    .line 1506
    add-int v7, v5, v5

    .line 1507
    .line 1508
    shr-int/lit8 v5, v5, 0x1f

    .line 1509
    .line 1510
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1511
    .line 1512
    .line 1513
    move-result v0

    .line 1514
    xor-int/2addr v5, v7

    .line 1515
    invoke-static {v5, v0, v9}, Lc1/j0;->u(III)I

    .line 1516
    .line 1517
    .line 1518
    move-result v9

    .line 1519
    goto :goto_15

    .line 1520
    :pswitch_36
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1521
    .line 1522
    .line 1523
    move-result v5

    .line 1524
    if-eqz v5, :cond_19

    .line 1525
    .line 1526
    shl-int/lit8 v0, v13, 0x3

    .line 1527
    .line 1528
    invoke-static {v0, v12, v9}, Lc1/j0;->u(III)I

    .line 1529
    .line 1530
    .line 1531
    move-result v9

    .line 1532
    goto :goto_15

    .line 1533
    :pswitch_37
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1534
    .line 1535
    .line 1536
    move-result v5

    .line 1537
    if-eqz v5, :cond_19

    .line 1538
    .line 1539
    shl-int/lit8 v0, v13, 0x3

    .line 1540
    .line 1541
    invoke-static {v0, v10, v9}, Lc1/j0;->u(III)I

    .line 1542
    .line 1543
    .line 1544
    move-result v9

    .line 1545
    goto :goto_15

    .line 1546
    :pswitch_38
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1547
    .line 1548
    .line 1549
    move-result v5

    .line 1550
    if-eqz v5, :cond_19

    .line 1551
    .line 1552
    shl-int/lit8 v0, v13, 0x3

    .line 1553
    .line 1554
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1555
    .line 1556
    .line 1557
    move-result v5

    .line 1558
    int-to-long v7, v5

    .line 1559
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1560
    .line 1561
    .line 1562
    move-result v0

    .line 1563
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 1564
    .line 1565
    .line 1566
    move-result v5

    .line 1567
    goto :goto_14

    .line 1568
    :pswitch_39
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1569
    .line 1570
    .line 1571
    move-result v5

    .line 1572
    if-eqz v5, :cond_19

    .line 1573
    .line 1574
    shl-int/lit8 v0, v13, 0x3

    .line 1575
    .line 1576
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1577
    .line 1578
    .line 1579
    move-result v5

    .line 1580
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1581
    .line 1582
    .line 1583
    move-result v0

    .line 1584
    invoke-static {v5, v0, v9}, Lc1/j0;->u(III)I

    .line 1585
    .line 1586
    .line 1587
    move-result v9

    .line 1588
    goto :goto_15

    .line 1589
    :pswitch_3a
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1590
    .line 1591
    .line 1592
    move-result v5

    .line 1593
    if-eqz v5, :cond_19

    .line 1594
    .line 1595
    shl-int/lit8 v0, v13, 0x3

    .line 1596
    .line 1597
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1598
    .line 1599
    .line 1600
    move-result-object v5

    .line 1601
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1602
    .line 1603
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1604
    .line 1605
    .line 1606
    move-result v0

    .line 1607
    invoke-virtual {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 1608
    .line 1609
    .line 1610
    move-result v5

    .line 1611
    invoke-static {v5, v5, v0, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 1612
    .line 1613
    .line 1614
    move-result v9

    .line 1615
    goto :goto_15

    .line 1616
    :pswitch_3b
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1617
    .line 1618
    .line 1619
    move-result v5

    .line 1620
    if-eqz v5, :cond_1b

    .line 1621
    .line 1622
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1623
    .line 1624
    .line 1625
    move-result-object v5

    .line 1626
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1627
    .line 1628
    .line 1629
    move-result-object v7

    .line 1630
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1631
    .line 1632
    shl-int/lit8 v8, v13, 0x3

    .line 1633
    .line 1634
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 1635
    .line 1636
    invoke-static {v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1637
    .line 1638
    .line 1639
    move-result v8

    .line 1640
    invoke-virtual {v5, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;->b(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;)I

    .line 1641
    .line 1642
    .line 1643
    move-result v5

    .line 1644
    invoke-static {v5, v5, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 1645
    .line 1646
    .line 1647
    move-result v9

    .line 1648
    goto/16 :goto_16

    .line 1649
    .line 1650
    :pswitch_3c
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1651
    .line 1652
    .line 1653
    move-result v5

    .line 1654
    if-eqz v5, :cond_19

    .line 1655
    .line 1656
    shl-int/lit8 v0, v13, 0x3

    .line 1657
    .line 1658
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1659
    .line 1660
    .line 1661
    move-result-object v5

    .line 1662
    instance-of v7, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1663
    .line 1664
    if-eqz v7, :cond_1a

    .line 1665
    .line 1666
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 1667
    .line 1668
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1669
    .line 1670
    .line 1671
    move-result v0

    .line 1672
    invoke-virtual {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 1673
    .line 1674
    .line 1675
    move-result v5

    .line 1676
    invoke-static {v5, v5, v0, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->b(IIII)I

    .line 1677
    .line 1678
    .line 1679
    move-result v9

    .line 1680
    goto/16 :goto_15

    .line 1681
    .line 1682
    :cond_1a
    check-cast v5, Ljava/lang/String;

    .line 1683
    .line 1684
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1685
    .line 1686
    .line 1687
    move-result v0

    .line 1688
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->v(Ljava/lang/String;)I

    .line 1689
    .line 1690
    .line 1691
    move-result v5

    .line 1692
    goto/16 :goto_14

    .line 1693
    .line 1694
    :pswitch_3d
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1695
    .line 1696
    .line 1697
    move-result v5

    .line 1698
    if-eqz v5, :cond_19

    .line 1699
    .line 1700
    shl-int/lit8 v0, v13, 0x3

    .line 1701
    .line 1702
    invoke-static {v0, v15, v9}, Lc1/j0;->u(III)I

    .line 1703
    .line 1704
    .line 1705
    move-result v9

    .line 1706
    goto/16 :goto_15

    .line 1707
    .line 1708
    :pswitch_3e
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1709
    .line 1710
    .line 1711
    move-result v5

    .line 1712
    if-eqz v5, :cond_19

    .line 1713
    .line 1714
    shl-int/lit8 v0, v13, 0x3

    .line 1715
    .line 1716
    invoke-static {v0, v10, v9}, Lc1/j0;->u(III)I

    .line 1717
    .line 1718
    .line 1719
    move-result v9

    .line 1720
    goto/16 :goto_15

    .line 1721
    .line 1722
    :pswitch_3f
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1723
    .line 1724
    .line 1725
    move-result v5

    .line 1726
    if-eqz v5, :cond_19

    .line 1727
    .line 1728
    shl-int/lit8 v0, v13, 0x3

    .line 1729
    .line 1730
    invoke-static {v0, v12, v9}, Lc1/j0;->u(III)I

    .line 1731
    .line 1732
    .line 1733
    move-result v9

    .line 1734
    goto/16 :goto_15

    .line 1735
    .line 1736
    :pswitch_40
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1737
    .line 1738
    .line 1739
    move-result v5

    .line 1740
    if-eqz v5, :cond_19

    .line 1741
    .line 1742
    shl-int/lit8 v0, v13, 0x3

    .line 1743
    .line 1744
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1745
    .line 1746
    .line 1747
    move-result v5

    .line 1748
    int-to-long v7, v5

    .line 1749
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1750
    .line 1751
    .line 1752
    move-result v0

    .line 1753
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 1754
    .line 1755
    .line 1756
    move-result v5

    .line 1757
    goto/16 :goto_14

    .line 1758
    .line 1759
    :pswitch_41
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1760
    .line 1761
    .line 1762
    move-result v5

    .line 1763
    if-eqz v5, :cond_19

    .line 1764
    .line 1765
    shl-int/lit8 v0, v13, 0x3

    .line 1766
    .line 1767
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1768
    .line 1769
    .line 1770
    move-result-wide v7

    .line 1771
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1772
    .line 1773
    .line 1774
    move-result v0

    .line 1775
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 1776
    .line 1777
    .line 1778
    move-result v5

    .line 1779
    goto/16 :goto_14

    .line 1780
    .line 1781
    :pswitch_42
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1782
    .line 1783
    .line 1784
    move-result v5

    .line 1785
    if-eqz v5, :cond_19

    .line 1786
    .line 1787
    shl-int/lit8 v0, v13, 0x3

    .line 1788
    .line 1789
    invoke-virtual {v6, v1, v7, v8}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1790
    .line 1791
    .line 1792
    move-result-wide v7

    .line 1793
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 1794
    .line 1795
    .line 1796
    move-result v0

    .line 1797
    invoke-static {v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 1798
    .line 1799
    .line 1800
    move-result v5

    .line 1801
    goto/16 :goto_14

    .line 1802
    .line 1803
    :pswitch_43
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1804
    .line 1805
    .line 1806
    move-result v5

    .line 1807
    if-eqz v5, :cond_19

    .line 1808
    .line 1809
    shl-int/lit8 v0, v13, 0x3

    .line 1810
    .line 1811
    invoke-static {v0, v10, v9}, Lc1/j0;->u(III)I

    .line 1812
    .line 1813
    .line 1814
    move-result v9

    .line 1815
    goto/16 :goto_15

    .line 1816
    .line 1817
    :pswitch_44
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->q(Ljava/lang/Object;IIII)Z

    .line 1818
    .line 1819
    .line 1820
    move-result v5

    .line 1821
    if-eqz v5, :cond_1b

    .line 1822
    .line 1823
    shl-int/lit8 v1, v13, 0x3

    .line 1824
    .line 1825
    invoke-static {v1, v12, v9}, Lc1/j0;->u(III)I

    .line 1826
    .line 1827
    .line 1828
    move-result v9

    .line 1829
    :cond_1b
    :goto_16
    add-int/lit8 v2, v2, 0x3

    .line 1830
    .line 1831
    move-object/from16 v1, p1

    .line 1832
    .line 1833
    const v8, 0xfffff

    .line 1834
    .line 1835
    .line 1836
    goto/16 :goto_0

    .line 1837
    .line 1838
    :cond_1c
    move-object/from16 v1, p1

    .line 1839
    .line 1840
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 1841
    .line 1842
    iget-object v1, v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 1843
    .line 1844
    invoke-virtual {v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a()I

    .line 1845
    .line 1846
    .line 1847
    move-result v1

    .line 1848
    add-int/2addr v1, v9

    .line 1849
    iget-boolean v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 1850
    .line 1851
    if-eqz v0, :cond_1f

    .line 1852
    .line 1853
    move-object/from16 v0, p1

    .line 1854
    .line 1855
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 1856
    .line 1857
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 1858
    .line 1859
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 1860
    .line 1861
    iget v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 1862
    .line 1863
    const/4 v7, 0x0

    .line 1864
    const/16 v17, 0x0

    .line 1865
    .line 1866
    :goto_17
    if-ge v7, v2, :cond_1d

    .line 1867
    .line 1868
    invoke-virtual {v0, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 1869
    .line 1870
    .line 1871
    move-result-object v3

    .line 1872
    iget-object v4, v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->d:Ljava/lang/Comparable;

    .line 1873
    .line 1874
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 1875
    .line 1876
    iget-object v3, v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->e:Ljava/lang/Object;

    .line 1877
    .line 1878
    invoke-static {v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;Ljava/lang/Object;)I

    .line 1879
    .line 1880
    .line 1881
    move-result v3

    .line 1882
    add-int v17, v3, v17

    .line 1883
    .line 1884
    add-int/lit8 v7, v7, 0x1

    .line 1885
    .line 1886
    goto :goto_17

    .line 1887
    :cond_1d
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->a()Ljava/util/Set;

    .line 1888
    .line 1889
    .line 1890
    move-result-object v0

    .line 1891
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1892
    .line 1893
    .line 1894
    move-result-object v0

    .line 1895
    :goto_18
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1896
    .line 1897
    .line 1898
    move-result v2

    .line 1899
    if-eqz v2, :cond_1e

    .line 1900
    .line 1901
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1902
    .line 1903
    .line 1904
    move-result-object v2

    .line 1905
    check-cast v2, Ljava/util/Map$Entry;

    .line 1906
    .line 1907
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1908
    .line 1909
    .line 1910
    move-result-object v3

    .line 1911
    check-cast v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 1912
    .line 1913
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1914
    .line 1915
    .line 1916
    move-result-object v2

    .line 1917
    invoke-static {v3, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;Ljava/lang/Object;)I

    .line 1918
    .line 1919
    .line 1920
    move-result v2

    .line 1921
    add-int v17, v2, v17

    .line 1922
    .line 1923
    goto :goto_18

    .line 1924
    :cond_1e
    add-int v1, v1, v17

    .line 1925
    .line 1926
    :cond_1f
    return v1

    .line 1927
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

.method public final i(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    invoke-virtual {p0, p1, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

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
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

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
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 17
    .line 18
    int-to-long v2, v0

    .line 19
    invoke-virtual {v1, p3, v2, v3}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    if-eqz v0, :cond_4

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    if-nez v4, :cond_2

    .line 34
    .line 35
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-nez v4, :cond_1

    .line 40
    .line 41
    invoke-virtual {v1, p2, v2, v3, v0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-interface {p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-interface {p3, v4, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1, p2, v2, v3, v4}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :goto_0
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    invoke-virtual {v1, p2, v2, v3}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-nez p1, :cond_3

    .line 68
    .line 69
    invoke-interface {p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-interface {p3, p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1, p2, v2, v3, p1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    move-object p0, p1

    .line 80
    :cond_3
    invoke-interface {p3, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_4
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 87
    .line 88
    aget p0, p0, p1

    .line 89
    .line 90
    invoke-virtual {p3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    new-instance p3, Ljava/lang/StringBuilder;

    .line 95
    .line 96
    const-string v0, "Source subfield "

    .line 97
    .line 98
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string p0, " is present but null: "

    .line 105
    .line 106
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    invoke-direct {p2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p2
.end method

.method public final j(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 2
    .line 3
    aget v1, v0, p1

    .line 4
    .line 5
    invoke-virtual {p0, v1, p3, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

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
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

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
    sget-object v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 21
    .line 22
    int-to-long v5, v2

    .line 23
    invoke-virtual {v4, p3, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    if-eqz v2, :cond_4

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 30
    .line 31
    .line 32
    move-result-object p3

    .line 33
    invoke-virtual {p0, v1, p2, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->s(ILjava/lang/Object;I)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-nez p0, :cond_2

    .line 38
    .line 39
    invoke-static {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_1

    .line 44
    .line 45
    invoke-virtual {v4, p2, v5, v6, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-interface {p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-interface {p3, p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v4, p2, v5, v6, p0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :goto_0
    add-int/lit8 p1, p1, 0x2

    .line 60
    .line 61
    aget p0, v0, p1

    .line 62
    .line 63
    and-int/2addr p0, v3

    .line 64
    int-to-long p0, p0

    .line 65
    invoke-static {p0, p1, p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_2
    invoke-virtual {v4, p2, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    if-nez p1, :cond_3

    .line 78
    .line 79
    invoke-interface {p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-interface {p3, p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v4, p2, v5, v6, p1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    move-object p0, p1

    .line 90
    :cond_3
    invoke-interface {p3, p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    aget p1, v0, p1

    .line 97
    .line 98
    invoke-virtual {p3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    new-instance p3, Ljava/lang/StringBuilder;

    .line 103
    .line 104
    const-string v0, "Source subfield "

    .line 105
    .line 106
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string p1, " is present but null: "

    .line 113
    .line 114
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p0
.end method

.method public final k()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 4
    .line 5
    const/4 v0, 0x4

    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-virtual {p0, v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 12
    .line 13
    return-object p0
.end method

.method public final l(ILjava/lang/Object;)V
    .locals 4

    .line 1
    add-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

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
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    const/4 v2, 0x1

    .line 27
    shl-int p0, v2, p0

    .line 28
    .line 29
    or-int/2addr p0, p1

    .line 30
    invoke-static {v0, v1, p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final m(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

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
    invoke-virtual {v0, p2, v1, v2, p3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->l(ILjava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final n(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

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
    int-to-long v3, v1

    .line 12
    invoke-virtual {v0, p3, v3, v4, p4}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    add-int/lit8 p2, p2, 0x2

    .line 16
    .line 17
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 18
    .line 19
    aget p0, p0, p2

    .line 20
    .line 21
    and-int/2addr p0, v2

    .line 22
    int-to-long v0, p0

    .line 23
    invoke-static {v0, v1, p3, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->j(JLjava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final o(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;I)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p3, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p0, p3, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

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

.method public final p(ILjava/lang/Object;)Z
    .locals 6

    .line 1
    add-int/lit8 v0, p1, 0x2

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

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
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    and-int p1, p0, v1

    .line 26
    .line 27
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    int-to-long v0, p1

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
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    if-eqz p0, :cond_3

    .line 48
    .line 49
    goto/16 :goto_0

    .line 50
    .line 51
    :pswitch_1
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 52
    .line 53
    .line 54
    move-result-wide p0

    .line 55
    cmp-long p0, p0, v2

    .line 56
    .line 57
    if-eqz p0, :cond_3

    .line 58
    .line 59
    goto/16 :goto_0

    .line 60
    .line 61
    :pswitch_2
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-eqz p0, :cond_3

    .line 66
    .line 67
    goto/16 :goto_0

    .line 68
    .line 69
    :pswitch_3
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 70
    .line 71
    .line 72
    move-result-wide p0

    .line 73
    cmp-long p0, p0, v2

    .line 74
    .line 75
    if-eqz p0, :cond_3

    .line 76
    .line 77
    goto/16 :goto_0

    .line 78
    .line 79
    :pswitch_4
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-eqz p0, :cond_3

    .line 84
    .line 85
    goto/16 :goto_0

    .line 86
    .line 87
    :pswitch_5
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    if-eqz p0, :cond_3

    .line 92
    .line 93
    goto/16 :goto_0

    .line 94
    .line 95
    :pswitch_6
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-eqz p0, :cond_3

    .line 100
    .line 101
    goto/16 :goto_0

    .line 102
    .line 103
    :pswitch_7
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 104
    .line 105
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->equals(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    if-nez p0, :cond_3

    .line 114
    .line 115
    goto/16 :goto_0

    .line 116
    .line 117
    :pswitch_8
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    if-eqz p0, :cond_3

    .line 122
    .line 123
    goto/16 :goto_0

    .line 124
    .line 125
    :pswitch_9
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    instance-of p1, p0, Ljava/lang/String;

    .line 130
    .line 131
    if-eqz p1, :cond_0

    .line 132
    .line 133
    check-cast p0, Ljava/lang/String;

    .line 134
    .line 135
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    if-nez p0, :cond_3

    .line 140
    .line 141
    goto/16 :goto_0

    .line 142
    .line 143
    :cond_0
    instance-of p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 144
    .line 145
    if-eqz p1, :cond_1

    .line 146
    .line 147
    sget-object p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 148
    .line 149
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->equals(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result p0

    .line 153
    if-nez p0, :cond_3

    .line 154
    .line 155
    goto :goto_0

    .line 156
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 157
    .line 158
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :pswitch_a
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 163
    .line 164
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->g(JLjava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result p0

    .line 168
    return p0

    .line 169
    :pswitch_b
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 170
    .line 171
    .line 172
    move-result p0

    .line 173
    if-eqz p0, :cond_3

    .line 174
    .line 175
    goto :goto_0

    .line 176
    :pswitch_c
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 177
    .line 178
    .line 179
    move-result-wide p0

    .line 180
    cmp-long p0, p0, v2

    .line 181
    .line 182
    if-eqz p0, :cond_3

    .line 183
    .line 184
    goto :goto_0

    .line 185
    :pswitch_d
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    if-eqz p0, :cond_3

    .line 190
    .line 191
    goto :goto_0

    .line 192
    :pswitch_e
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 193
    .line 194
    .line 195
    move-result-wide p0

    .line 196
    cmp-long p0, p0, v2

    .line 197
    .line 198
    if-eqz p0, :cond_3

    .line 199
    .line 200
    goto :goto_0

    .line 201
    :pswitch_f
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->f(JLjava/lang/Object;)J

    .line 202
    .line 203
    .line 204
    move-result-wide p0

    .line 205
    cmp-long p0, p0, v2

    .line 206
    .line 207
    if-eqz p0, :cond_3

    .line 208
    .line 209
    goto :goto_0

    .line 210
    :pswitch_10
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 211
    .line 212
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->b(JLjava/lang/Object;)F

    .line 213
    .line 214
    .line 215
    move-result p0

    .line 216
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 217
    .line 218
    .line 219
    move-result p0

    .line 220
    if-eqz p0, :cond_3

    .line 221
    .line 222
    goto :goto_0

    .line 223
    :pswitch_11
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 224
    .line 225
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->a(JLjava/lang/Object;)D

    .line 226
    .line 227
    .line 228
    move-result-wide p0

    .line 229
    invoke-static {p0, p1}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 230
    .line 231
    .line 232
    move-result-wide p0

    .line 233
    cmp-long p0, p0, v2

    .line 234
    .line 235
    if-eqz p0, :cond_3

    .line 236
    .line 237
    goto :goto_0

    .line 238
    :cond_2
    ushr-int/lit8 p0, v0, 0x14

    .line 239
    .line 240
    shl-int p0, v5, p0

    .line 241
    .line 242
    invoke-static {v2, v3, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 243
    .line 244
    .line 245
    move-result p1

    .line 246
    and-int/2addr p0, p1

    .line 247
    if-eqz p0, :cond_3

    .line 248
    .line 249
    :goto_0
    return v5

    .line 250
    :cond_3
    const/4 p0, 0x0

    .line 251
    return p0

    .line 252
    nop

    .line 253
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

.method public final q(Ljava/lang/Object;IIII)Z
    .locals 1

    .line 1
    const v0, 0xfffff

    .line 2
    .line 3
    .line 4
    if-ne p3, v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, p2, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->p(ILjava/lang/Object;)Z

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

.method public final s(ILjava/lang/Object;I)Z
    .locals 2

    .line 1
    add-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

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
    invoke-static {v0, v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e(JLjava/lang/Object;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-ne p0, p1, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final t(Ljava/lang/Object;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move/from16 v5, p4

    .line 8
    .line 9
    move-object/from16 v6, p6

    .line 10
    .line 11
    invoke-static {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->r(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_91

    .line 16
    .line 17
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 18
    .line 19
    move/from16 v4, p3

    .line 20
    .line 21
    const/4 v7, -0x1

    .line 22
    const/4 v8, 0x0

    .line 23
    const v9, 0xfffff

    .line 24
    .line 25
    .line 26
    const/4 v14, 0x0

    .line 27
    const/4 v15, 0x0

    .line 28
    :goto_0
    const v16, 0xfffff

    .line 29
    .line 30
    .line 31
    :goto_1
    iget-object v13, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->b:[Ljava/lang/Object;

    .line 32
    .line 33
    iget-object v12, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 34
    .line 35
    if-ge v4, v5, :cond_89

    .line 36
    .line 37
    add-int/lit8 v15, v4, 0x1

    .line 38
    .line 39
    aget-byte v4, v3, v4

    .line 40
    .line 41
    if-gez v4, :cond_0

    .line 42
    .line 43
    invoke-static {v4, v3, v15, v6}, Ljp/ce;->h(I[BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 44
    .line 45
    .line 46
    move-result v15

    .line 47
    iget v4, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 48
    .line 49
    :cond_0
    move/from16 v33, v15

    .line 50
    .line 51
    move v15, v4

    .line 52
    move/from16 v4, v33

    .line 53
    .line 54
    const/16 p3, 0x3

    .line 55
    .line 56
    ushr-int/lit8 v11, v15, 0x3

    .line 57
    .line 58
    iget v3, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->d:I

    .line 59
    .line 60
    move/from16 v18, v4

    .line 61
    .line 62
    iget v4, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->c:I

    .line 63
    .line 64
    if-le v11, v7, :cond_1

    .line 65
    .line 66
    div-int/lit8 v8, v8, 0x3

    .line 67
    .line 68
    if-lt v11, v4, :cond_2

    .line 69
    .line 70
    if-gt v11, v3, :cond_2

    .line 71
    .line 72
    invoke-virtual {v0, v11, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->x(II)I

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    goto :goto_2

    .line 77
    :cond_1
    if-lt v11, v4, :cond_2

    .line 78
    .line 79
    if-gt v11, v3, :cond_2

    .line 80
    .line 81
    const/4 v3, 0x0

    .line 82
    invoke-virtual {v0, v11, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->x(II)I

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    move v3, v4

    .line 87
    goto :goto_2

    .line 88
    :cond_2
    const/4 v3, -0x1

    .line 89
    :goto_2
    const/4 v4, -0x1

    .line 90
    if-ne v3, v4, :cond_3

    .line 91
    .line 92
    move-object/from16 v7, p2

    .line 93
    .line 94
    move/from16 v10, p5

    .line 95
    .line 96
    move-object/from16 v32, v1

    .line 97
    .line 98
    move/from16 v19, v4

    .line 99
    .line 100
    move/from16 v31, v9

    .line 101
    .line 102
    move-object/from16 v28, v12

    .line 103
    .line 104
    move-object/from16 v29, v13

    .line 105
    .line 106
    move/from16 v20, v14

    .line 107
    .line 108
    move/from16 v3, v18

    .line 109
    .line 110
    const/4 v8, 0x0

    .line 111
    move-object v9, v6

    .line 112
    move v14, v11

    .line 113
    move-object v11, v2

    .line 114
    goto/16 :goto_52

    .line 115
    .line 116
    :cond_3
    and-int/lit8 v8, v15, 0x7

    .line 117
    .line 118
    add-int/lit8 v17, v3, 0x1

    .line 119
    .line 120
    aget v4, v12, v17

    .line 121
    .line 122
    const/16 v17, 0x0

    .line 123
    .line 124
    invoke-static {v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->y(I)I

    .line 125
    .line 126
    .line 127
    move-result v7

    .line 128
    and-int v5, v4, v16

    .line 129
    .line 130
    int-to-long v5, v5

    .line 131
    move-wide/from16 v20, v5

    .line 132
    .line 133
    const-wide/16 v22, 0x1

    .line 134
    .line 135
    const-wide/16 v24, 0x0

    .line 136
    .line 137
    const/high16 v26, 0x20000000

    .line 138
    .line 139
    const-string v6, ""

    .line 140
    .line 141
    const-string v5, "CodedInputStream encountered an embedded string or message which claimed to have negative size."

    .line 142
    .line 143
    move-object/from16 v28, v12

    .line 144
    .line 145
    const-string v12, "Protocol message had invalid UTF-8."

    .line 146
    .line 147
    move-object/from16 v29, v13

    .line 148
    .line 149
    const/16 v30, 0x1

    .line 150
    .line 151
    const/16 v13, 0x11

    .line 152
    .line 153
    if-gt v7, v13, :cond_23

    .line 154
    .line 155
    add-int/lit8 v13, v3, 0x2

    .line 156
    .line 157
    aget v13, v28, v13

    .line 158
    .line 159
    ushr-int/lit8 v17, v13, 0x14

    .line 160
    .line 161
    shl-int v17, v30, v17

    .line 162
    .line 163
    and-int v13, v13, v16

    .line 164
    .line 165
    if-eq v13, v9, :cond_6

    .line 166
    .line 167
    move/from16 v10, v16

    .line 168
    .line 169
    move/from16 v27, v11

    .line 170
    .line 171
    if-eq v9, v10, :cond_4

    .line 172
    .line 173
    int-to-long v10, v9

    .line 174
    invoke-virtual {v1, v2, v10, v11, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 175
    .line 176
    .line 177
    const v10, 0xfffff

    .line 178
    .line 179
    .line 180
    :cond_4
    if-ne v13, v10, :cond_5

    .line 181
    .line 182
    const/4 v9, 0x0

    .line 183
    goto :goto_3

    .line 184
    :cond_5
    int-to-long v9, v13

    .line 185
    invoke-virtual {v1, v2, v9, v10}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 186
    .line 187
    .line 188
    move-result v9

    .line 189
    :goto_3
    move v14, v9

    .line 190
    goto :goto_4

    .line 191
    :cond_6
    move/from16 v27, v11

    .line 192
    .line 193
    move v13, v9

    .line 194
    :goto_4
    packed-switch v7, :pswitch_data_0

    .line 195
    .line 196
    .line 197
    move/from16 v7, p3

    .line 198
    .line 199
    if-ne v8, v7, :cond_7

    .line 200
    .line 201
    or-int v14, v14, v17

    .line 202
    .line 203
    invoke-virtual {v0, v3, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->D(ILjava/lang/Object;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v4

    .line 207
    shl-int/lit8 v5, v27, 0x3

    .line 208
    .line 209
    or-int/lit8 v8, v5, 0x4

    .line 210
    .line 211
    move-object v5, v4

    .line 212
    invoke-virtual {v0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    move/from16 v7, p4

    .line 217
    .line 218
    move-object/from16 v9, p6

    .line 219
    .line 220
    move v10, v3

    .line 221
    move-object v3, v5

    .line 222
    move/from16 v6, v18

    .line 223
    .line 224
    const/16 v19, -0x1

    .line 225
    .line 226
    move-object/from16 v5, p2

    .line 227
    .line 228
    invoke-static/range {v3 .. v9}, Ljp/ce;->k(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 229
    .line 230
    .line 231
    move-result v4

    .line 232
    move-object v7, v5

    .line 233
    invoke-virtual {v0, v10, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    move/from16 v5, p4

    .line 237
    .line 238
    move-object v3, v7

    .line 239
    :goto_5
    move-object v6, v9

    .line 240
    move v8, v10

    .line 241
    :goto_6
    move v9, v13

    .line 242
    :goto_7
    move/from16 v7, v27

    .line 243
    .line 244
    goto/16 :goto_0

    .line 245
    .line 246
    :cond_7
    move v10, v3

    .line 247
    const/16 v19, -0x1

    .line 248
    .line 249
    move-object/from16 v7, p2

    .line 250
    .line 251
    move-object/from16 v9, p6

    .line 252
    .line 253
    move-object v11, v2

    .line 254
    move/from16 v20, v14

    .line 255
    .line 256
    move/from16 v3, v18

    .line 257
    .line 258
    move/from16 v18, v13

    .line 259
    .line 260
    :goto_8
    move-object v13, v1

    .line 261
    goto/16 :goto_1d

    .line 262
    .line 263
    :pswitch_0
    move-object/from16 v7, p2

    .line 264
    .line 265
    move-object/from16 v9, p6

    .line 266
    .line 267
    move v10, v3

    .line 268
    move/from16 v3, v18

    .line 269
    .line 270
    const/16 v19, -0x1

    .line 271
    .line 272
    if-nez v8, :cond_8

    .line 273
    .line 274
    or-int v14, v14, v17

    .line 275
    .line 276
    invoke-static {v7, v3, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 277
    .line 278
    .line 279
    move-result v8

    .line 280
    iget-wide v3, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 281
    .line 282
    and-long v5, v3, v22

    .line 283
    .line 284
    ushr-long v3, v3, v30

    .line 285
    .line 286
    neg-long v5, v5

    .line 287
    xor-long/2addr v5, v3

    .line 288
    move-wide/from16 v3, v20

    .line 289
    .line 290
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 291
    .line 292
    .line 293
    move/from16 v5, p4

    .line 294
    .line 295
    move-object v3, v7

    .line 296
    move v4, v8

    .line 297
    goto :goto_5

    .line 298
    :cond_8
    move-object v11, v2

    .line 299
    move/from16 v18, v13

    .line 300
    .line 301
    move/from16 v20, v14

    .line 302
    .line 303
    goto :goto_8

    .line 304
    :pswitch_1
    move-object/from16 v7, p2

    .line 305
    .line 306
    move-object/from16 v9, p6

    .line 307
    .line 308
    move-object v12, v1

    .line 309
    move-object v11, v2

    .line 310
    move v10, v3

    .line 311
    move/from16 v3, v18

    .line 312
    .line 313
    move-wide/from16 v1, v20

    .line 314
    .line 315
    const/16 v19, -0x1

    .line 316
    .line 317
    if-nez v8, :cond_9

    .line 318
    .line 319
    or-int v14, v14, v17

    .line 320
    .line 321
    invoke-static {v7, v3, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 322
    .line 323
    .line 324
    move-result v4

    .line 325
    iget v3, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 326
    .line 327
    invoke-static {v3}, Ljp/ee;->b(I)I

    .line 328
    .line 329
    .line 330
    move-result v3

    .line 331
    invoke-virtual {v12, v11, v1, v2, v3}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 332
    .line 333
    .line 334
    :goto_9
    move/from16 v5, p4

    .line 335
    .line 336
    :goto_a
    move-object v3, v7

    .line 337
    move-object v6, v9

    .line 338
    :goto_b
    move v8, v10

    .line 339
    move-object v2, v11

    .line 340
    move-object v1, v12

    .line 341
    goto :goto_6

    .line 342
    :cond_9
    move/from16 v18, v13

    .line 343
    .line 344
    move/from16 v20, v14

    .line 345
    .line 346
    move-object v13, v12

    .line 347
    goto/16 :goto_1d

    .line 348
    .line 349
    :pswitch_2
    move-object/from16 v7, p2

    .line 350
    .line 351
    move-object/from16 v9, p6

    .line 352
    .line 353
    move-object v12, v1

    .line 354
    move-object v11, v2

    .line 355
    move v10, v3

    .line 356
    move/from16 v3, v18

    .line 357
    .line 358
    move-wide/from16 v1, v20

    .line 359
    .line 360
    const/16 v19, -0x1

    .line 361
    .line 362
    if-nez v8, :cond_9

    .line 363
    .line 364
    invoke-static {v7, v3, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 365
    .line 366
    .line 367
    move-result v3

    .line 368
    iget v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 369
    .line 370
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->B(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;

    .line 371
    .line 372
    .line 373
    move-result-object v6

    .line 374
    const/high16 v8, -0x80000000

    .line 375
    .line 376
    and-int/2addr v4, v8

    .line 377
    if-eqz v4, :cond_b

    .line 378
    .line 379
    if-eqz v6, :cond_b

    .line 380
    .line 381
    invoke-interface {v6, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;->a(I)Z

    .line 382
    .line 383
    .line 384
    move-result v4

    .line 385
    if-eqz v4, :cond_a

    .line 386
    .line 387
    goto :goto_d

    .line 388
    :cond_a
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->u(Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 389
    .line 390
    .line 391
    move-result-object v1

    .line 392
    int-to-long v4, v5

    .line 393
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 394
    .line 395
    .line 396
    move-result-object v2

    .line 397
    invoke-virtual {v1, v15, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 398
    .line 399
    .line 400
    :goto_c
    move/from16 v5, p4

    .line 401
    .line 402
    move v4, v3

    .line 403
    goto :goto_a

    .line 404
    :cond_b
    :goto_d
    or-int v14, v14, v17

    .line 405
    .line 406
    invoke-virtual {v12, v11, v1, v2, v5}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 407
    .line 408
    .line 409
    goto :goto_c

    .line 410
    :pswitch_3
    move-object/from16 v7, p2

    .line 411
    .line 412
    move-object/from16 v9, p6

    .line 413
    .line 414
    move-object v12, v1

    .line 415
    move-object v11, v2

    .line 416
    move v10, v3

    .line 417
    move/from16 v3, v18

    .line 418
    .line 419
    move-wide/from16 v1, v20

    .line 420
    .line 421
    const/4 v4, 0x2

    .line 422
    const/16 v19, -0x1

    .line 423
    .line 424
    if-ne v8, v4, :cond_9

    .line 425
    .line 426
    or-int v14, v14, v17

    .line 427
    .line 428
    invoke-static {v7, v3, v9}, Ljp/ce;->b([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 429
    .line 430
    .line 431
    move-result v4

    .line 432
    iget-object v3, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 433
    .line 434
    invoke-virtual {v12, v11, v1, v2, v3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 435
    .line 436
    .line 437
    goto :goto_9

    .line 438
    :pswitch_4
    move-object/from16 v7, p2

    .line 439
    .line 440
    move-object/from16 v9, p6

    .line 441
    .line 442
    move-object v12, v1

    .line 443
    move-object v11, v2

    .line 444
    move v10, v3

    .line 445
    move/from16 v3, v18

    .line 446
    .line 447
    const/4 v4, 0x2

    .line 448
    const/16 v19, -0x1

    .line 449
    .line 450
    if-ne v8, v4, :cond_9

    .line 451
    .line 452
    or-int v14, v14, v17

    .line 453
    .line 454
    invoke-virtual {v0, v10, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->D(ILjava/lang/Object;)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 459
    .line 460
    .line 461
    move-result-object v2

    .line 462
    move/from16 v5, p4

    .line 463
    .line 464
    move v4, v3

    .line 465
    move-object v3, v7

    .line 466
    move-object v6, v9

    .line 467
    invoke-static/range {v1 .. v6}, Ljp/ce;->l(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 468
    .line 469
    .line 470
    move-result v4

    .line 471
    invoke-virtual {v0, v10, v11, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 472
    .line 473
    .line 474
    goto/16 :goto_b

    .line 475
    .line 476
    :pswitch_5
    move-object/from16 v7, p2

    .line 477
    .line 478
    move-object/from16 v9, p6

    .line 479
    .line 480
    move-object v11, v2

    .line 481
    move v10, v3

    .line 482
    move/from16 v3, v18

    .line 483
    .line 484
    const/16 v19, -0x1

    .line 485
    .line 486
    move/from16 v18, v13

    .line 487
    .line 488
    move-object v13, v1

    .line 489
    move-wide/from16 v1, v20

    .line 490
    .line 491
    move/from16 v20, v14

    .line 492
    .line 493
    const/4 v14, 0x2

    .line 494
    if-ne v8, v14, :cond_22

    .line 495
    .line 496
    and-int v4, v4, v26

    .line 497
    .line 498
    if-eqz v4, :cond_1c

    .line 499
    .line 500
    invoke-static {v7, v3, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 501
    .line 502
    .line 503
    move-result v3

    .line 504
    iget v4, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 505
    .line 506
    if-ltz v4, :cond_1b

    .line 507
    .line 508
    or-int v5, v20, v17

    .line 509
    .line 510
    if-nez v4, :cond_c

    .line 511
    .line 512
    iput-object v6, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 513
    .line 514
    move/from16 p3, v5

    .line 515
    .line 516
    goto/16 :goto_12

    .line 517
    .line 518
    :cond_c
    or-int v6, v3, v4

    .line 519
    .line 520
    array-length v8, v7

    .line 521
    sub-int v14, v8, v3

    .line 522
    .line 523
    sub-int/2addr v14, v4

    .line 524
    sget-object v17, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 525
    .line 526
    or-int/2addr v6, v14

    .line 527
    if-ltz v6, :cond_1a

    .line 528
    .line 529
    add-int v6, v3, v4

    .line 530
    .line 531
    new-array v4, v4, [C

    .line 532
    .line 533
    const/4 v8, 0x0

    .line 534
    :goto_e
    if-ge v3, v6, :cond_d

    .line 535
    .line 536
    aget-byte v14, v7, v3

    .line 537
    .line 538
    if-ltz v14, :cond_d

    .line 539
    .line 540
    add-int/lit8 v3, v3, 0x1

    .line 541
    .line 542
    add-int/lit8 v17, v8, 0x1

    .line 543
    .line 544
    int-to-char v14, v14

    .line 545
    aput-char v14, v4, v8

    .line 546
    .line 547
    move/from16 v8, v17

    .line 548
    .line 549
    goto :goto_e

    .line 550
    :cond_d
    :goto_f
    if-ge v3, v6, :cond_19

    .line 551
    .line 552
    add-int/lit8 v14, v3, 0x1

    .line 553
    .line 554
    move/from16 v17, v3

    .line 555
    .line 556
    aget-byte v3, v7, v17

    .line 557
    .line 558
    if-ltz v3, :cond_e

    .line 559
    .line 560
    add-int/lit8 v17, v8, 0x1

    .line 561
    .line 562
    int-to-char v3, v3

    .line 563
    aput-char v3, v4, v8

    .line 564
    .line 565
    move v3, v14

    .line 566
    :goto_10
    move/from16 v8, v17

    .line 567
    .line 568
    if-ge v3, v6, :cond_d

    .line 569
    .line 570
    aget-byte v14, v7, v3

    .line 571
    .line 572
    if-ltz v14, :cond_d

    .line 573
    .line 574
    add-int/lit8 v3, v3, 0x1

    .line 575
    .line 576
    add-int/lit8 v17, v8, 0x1

    .line 577
    .line 578
    int-to-char v14, v14

    .line 579
    aput-char v14, v4, v8

    .line 580
    .line 581
    goto :goto_10

    .line 582
    :cond_e
    move/from16 p3, v5

    .line 583
    .line 584
    const/16 v5, -0x20

    .line 585
    .line 586
    if-ge v3, v5, :cond_11

    .line 587
    .line 588
    if-ge v14, v6, :cond_10

    .line 589
    .line 590
    add-int/lit8 v5, v8, 0x1

    .line 591
    .line 592
    add-int/lit8 v17, v17, 0x2

    .line 593
    .line 594
    aget-byte v14, v7, v14

    .line 595
    .line 596
    move/from16 v20, v5

    .line 597
    .line 598
    const/16 v5, -0x3e

    .line 599
    .line 600
    if-lt v3, v5, :cond_f

    .line 601
    .line 602
    invoke-static {v14}, Ljp/ge;->c(B)Z

    .line 603
    .line 604
    .line 605
    move-result v5

    .line 606
    if-nez v5, :cond_f

    .line 607
    .line 608
    and-int/lit8 v3, v3, 0x1f

    .line 609
    .line 610
    shl-int/lit8 v3, v3, 0x6

    .line 611
    .line 612
    and-int/lit8 v5, v14, 0x3f

    .line 613
    .line 614
    or-int/2addr v3, v5

    .line 615
    int-to-char v3, v3

    .line 616
    aput-char v3, v4, v8

    .line 617
    .line 618
    move/from16 v5, p3

    .line 619
    .line 620
    move/from16 v3, v17

    .line 621
    .line 622
    move/from16 v8, v20

    .line 623
    .line 624
    goto :goto_f

    .line 625
    :cond_f
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 626
    .line 627
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 628
    .line 629
    .line 630
    throw v0

    .line 631
    :cond_10
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 632
    .line 633
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 634
    .line 635
    .line 636
    throw v0

    .line 637
    :cond_11
    const/16 v5, -0x10

    .line 638
    .line 639
    if-ge v3, v5, :cond_16

    .line 640
    .line 641
    add-int/lit8 v5, v6, -0x1

    .line 642
    .line 643
    if-ge v14, v5, :cond_15

    .line 644
    .line 645
    add-int/lit8 v5, v8, 0x1

    .line 646
    .line 647
    add-int/lit8 v21, v17, 0x2

    .line 648
    .line 649
    aget-byte v14, v7, v14

    .line 650
    .line 651
    add-int/lit8 v17, v17, 0x3

    .line 652
    .line 653
    aget-byte v21, v7, v21

    .line 654
    .line 655
    invoke-static {v14}, Ljp/ge;->c(B)Z

    .line 656
    .line 657
    .line 658
    move-result v22

    .line 659
    if-nez v22, :cond_14

    .line 660
    .line 661
    move/from16 v22, v5

    .line 662
    .line 663
    const/16 v5, -0x60

    .line 664
    .line 665
    move/from16 v23, v6

    .line 666
    .line 667
    const/16 v6, -0x20

    .line 668
    .line 669
    if-ne v3, v6, :cond_12

    .line 670
    .line 671
    if-lt v14, v5, :cond_14

    .line 672
    .line 673
    move v3, v6

    .line 674
    :cond_12
    const/16 v6, -0x13

    .line 675
    .line 676
    if-ne v3, v6, :cond_13

    .line 677
    .line 678
    if-ge v14, v5, :cond_14

    .line 679
    .line 680
    move v3, v6

    .line 681
    :cond_13
    invoke-static/range {v21 .. v21}, Ljp/ge;->c(B)Z

    .line 682
    .line 683
    .line 684
    move-result v5

    .line 685
    if-nez v5, :cond_14

    .line 686
    .line 687
    and-int/lit8 v3, v3, 0xf

    .line 688
    .line 689
    and-int/lit8 v5, v14, 0x3f

    .line 690
    .line 691
    and-int/lit8 v6, v21, 0x3f

    .line 692
    .line 693
    shl-int/lit8 v3, v3, 0xc

    .line 694
    .line 695
    shl-int/lit8 v5, v5, 0x6

    .line 696
    .line 697
    or-int/2addr v3, v5

    .line 698
    or-int/2addr v3, v6

    .line 699
    int-to-char v3, v3

    .line 700
    aput-char v3, v4, v8

    .line 701
    .line 702
    move/from16 v5, p3

    .line 703
    .line 704
    move/from16 v3, v17

    .line 705
    .line 706
    move/from16 v8, v22

    .line 707
    .line 708
    :goto_11
    move/from16 v6, v23

    .line 709
    .line 710
    goto/16 :goto_f

    .line 711
    .line 712
    :cond_14
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 713
    .line 714
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 715
    .line 716
    .line 717
    throw v0

    .line 718
    :cond_15
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 719
    .line 720
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 721
    .line 722
    .line 723
    throw v0

    .line 724
    :cond_16
    move/from16 v23, v6

    .line 725
    .line 726
    add-int/lit8 v6, v23, -0x2

    .line 727
    .line 728
    if-ge v14, v6, :cond_18

    .line 729
    .line 730
    add-int/lit8 v5, v17, 0x2

    .line 731
    .line 732
    aget-byte v6, v7, v14

    .line 733
    .line 734
    add-int/lit8 v14, v17, 0x3

    .line 735
    .line 736
    aget-byte v5, v7, v5

    .line 737
    .line 738
    add-int/lit8 v17, v17, 0x4

    .line 739
    .line 740
    aget-byte v14, v7, v14

    .line 741
    .line 742
    invoke-static {v6}, Ljp/ge;->c(B)Z

    .line 743
    .line 744
    .line 745
    move-result v20

    .line 746
    if-nez v20, :cond_17

    .line 747
    .line 748
    shl-int/lit8 v20, v3, 0x1c

    .line 749
    .line 750
    add-int/lit8 v21, v6, 0x70

    .line 751
    .line 752
    add-int v21, v21, v20

    .line 753
    .line 754
    shr-int/lit8 v20, v21, 0x1e

    .line 755
    .line 756
    if-nez v20, :cond_17

    .line 757
    .line 758
    invoke-static {v5}, Ljp/ge;->c(B)Z

    .line 759
    .line 760
    .line 761
    move-result v20

    .line 762
    if-nez v20, :cond_17

    .line 763
    .line 764
    invoke-static {v14}, Ljp/ge;->c(B)Z

    .line 765
    .line 766
    .line 767
    move-result v20

    .line 768
    if-nez v20, :cond_17

    .line 769
    .line 770
    and-int/lit8 v3, v3, 0x7

    .line 771
    .line 772
    and-int/lit8 v6, v6, 0x3f

    .line 773
    .line 774
    and-int/lit8 v5, v5, 0x3f

    .line 775
    .line 776
    and-int/lit8 v14, v14, 0x3f

    .line 777
    .line 778
    shl-int/lit8 v3, v3, 0x12

    .line 779
    .line 780
    shl-int/lit8 v6, v6, 0xc

    .line 781
    .line 782
    or-int/2addr v3, v6

    .line 783
    shl-int/lit8 v5, v5, 0x6

    .line 784
    .line 785
    or-int/2addr v3, v5

    .line 786
    or-int/2addr v3, v14

    .line 787
    ushr-int/lit8 v5, v3, 0xa

    .line 788
    .line 789
    const v6, 0xd7c0

    .line 790
    .line 791
    .line 792
    add-int/2addr v5, v6

    .line 793
    int-to-char v5, v5

    .line 794
    aput-char v5, v4, v8

    .line 795
    .line 796
    add-int/lit8 v5, v8, 0x1

    .line 797
    .line 798
    and-int/lit16 v3, v3, 0x3ff

    .line 799
    .line 800
    const v6, 0xdc00

    .line 801
    .line 802
    .line 803
    add-int/2addr v3, v6

    .line 804
    int-to-char v3, v3

    .line 805
    aput-char v3, v4, v5

    .line 806
    .line 807
    add-int/lit8 v8, v8, 0x2

    .line 808
    .line 809
    move/from16 v5, p3

    .line 810
    .line 811
    move/from16 v3, v17

    .line 812
    .line 813
    goto :goto_11

    .line 814
    :cond_17
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 815
    .line 816
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 817
    .line 818
    .line 819
    throw v0

    .line 820
    :cond_18
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 821
    .line 822
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 823
    .line 824
    .line 825
    throw v0

    .line 826
    :cond_19
    move/from16 p3, v5

    .line 827
    .line 828
    move/from16 v23, v6

    .line 829
    .line 830
    new-instance v3, Ljava/lang/String;

    .line 831
    .line 832
    const/4 v5, 0x0

    .line 833
    invoke-direct {v3, v4, v5, v8}, Ljava/lang/String;-><init>([CII)V

    .line 834
    .line 835
    .line 836
    iput-object v3, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 837
    .line 838
    move/from16 v3, v23

    .line 839
    .line 840
    :goto_12
    move/from16 v14, p3

    .line 841
    .line 842
    :goto_13
    move v4, v3

    .line 843
    goto :goto_15

    .line 844
    :cond_1a
    new-instance v0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 845
    .line 846
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 847
    .line 848
    .line 849
    move-result-object v1

    .line 850
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 851
    .line 852
    .line 853
    move-result-object v2

    .line 854
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 855
    .line 856
    .line 857
    move-result-object v3

    .line 858
    filled-new-array {v1, v2, v3}, [Ljava/lang/Object;

    .line 859
    .line 860
    .line 861
    move-result-object v1

    .line 862
    const-string v2, "buffer length=%d, index=%d, size=%d"

    .line 863
    .line 864
    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 865
    .line 866
    .line 867
    move-result-object v1

    .line 868
    invoke-direct {v0, v1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 869
    .line 870
    .line 871
    throw v0

    .line 872
    :cond_1b
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 873
    .line 874
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 875
    .line 876
    .line 877
    throw v0

    .line 878
    :cond_1c
    or-int v4, v20, v17

    .line 879
    .line 880
    invoke-static {v7, v3, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 881
    .line 882
    .line 883
    move-result v3

    .line 884
    iget v8, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 885
    .line 886
    if-ltz v8, :cond_1e

    .line 887
    .line 888
    if-nez v8, :cond_1d

    .line 889
    .line 890
    iput-object v6, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 891
    .line 892
    goto :goto_14

    .line 893
    :cond_1d
    new-instance v5, Ljava/lang/String;

    .line 894
    .line 895
    sget-object v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 896
    .line 897
    invoke-direct {v5, v7, v3, v8, v6}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 898
    .line 899
    .line 900
    iput-object v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 901
    .line 902
    add-int/2addr v3, v8

    .line 903
    :goto_14
    move v14, v4

    .line 904
    goto :goto_13

    .line 905
    :goto_15
    iget-object v3, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 906
    .line 907
    invoke-virtual {v13, v11, v1, v2, v3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 908
    .line 909
    .line 910
    :goto_16
    move/from16 v5, p4

    .line 911
    .line 912
    move-object v3, v7

    .line 913
    move-object v6, v9

    .line 914
    move v8, v10

    .line 915
    move-object v2, v11

    .line 916
    :goto_17
    move-object v1, v13

    .line 917
    :goto_18
    move/from16 v9, v18

    .line 918
    .line 919
    goto/16 :goto_7

    .line 920
    .line 921
    :cond_1e
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 922
    .line 923
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 924
    .line 925
    .line 926
    throw v0

    .line 927
    :pswitch_6
    move-object/from16 v7, p2

    .line 928
    .line 929
    move-object/from16 v9, p6

    .line 930
    .line 931
    move-object v11, v2

    .line 932
    move v10, v3

    .line 933
    move/from16 v3, v18

    .line 934
    .line 935
    const/16 v19, -0x1

    .line 936
    .line 937
    move/from16 v18, v13

    .line 938
    .line 939
    move-object v13, v1

    .line 940
    move-wide/from16 v1, v20

    .line 941
    .line 942
    move/from16 v20, v14

    .line 943
    .line 944
    if-nez v8, :cond_22

    .line 945
    .line 946
    or-int v14, v20, v17

    .line 947
    .line 948
    invoke-static {v7, v3, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 949
    .line 950
    .line 951
    move-result v4

    .line 952
    iget-wide v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 953
    .line 954
    cmp-long v3, v5, v24

    .line 955
    .line 956
    if-eqz v3, :cond_1f

    .line 957
    .line 958
    move/from16 v3, v30

    .line 959
    .line 960
    goto :goto_19

    .line 961
    :cond_1f
    const/4 v3, 0x0

    .line 962
    :goto_19
    sget-object v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 963
    .line 964
    invoke-virtual {v5, v11, v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->c(Ljava/lang/Object;JZ)V

    .line 965
    .line 966
    .line 967
    goto :goto_16

    .line 968
    :pswitch_7
    move-object/from16 v7, p2

    .line 969
    .line 970
    move-object/from16 v9, p6

    .line 971
    .line 972
    move-object v11, v2

    .line 973
    move v10, v3

    .line 974
    move/from16 v3, v18

    .line 975
    .line 976
    const/4 v4, 0x5

    .line 977
    const/16 v19, -0x1

    .line 978
    .line 979
    move/from16 v18, v13

    .line 980
    .line 981
    move-object v13, v1

    .line 982
    move-wide/from16 v1, v20

    .line 983
    .line 984
    move/from16 v20, v14

    .line 985
    .line 986
    if-ne v8, v4, :cond_22

    .line 987
    .line 988
    add-int/lit8 v4, v3, 0x4

    .line 989
    .line 990
    or-int v14, v20, v17

    .line 991
    .line 992
    invoke-static {v3, v7}, Ljp/ce;->c(I[B)I

    .line 993
    .line 994
    .line 995
    move-result v3

    .line 996
    invoke-virtual {v13, v11, v1, v2, v3}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 997
    .line 998
    .line 999
    goto :goto_16

    .line 1000
    :pswitch_8
    move-object/from16 v7, p2

    .line 1001
    .line 1002
    move-object/from16 v9, p6

    .line 1003
    .line 1004
    move-object v11, v2

    .line 1005
    move v10, v3

    .line 1006
    move/from16 v3, v18

    .line 1007
    .line 1008
    move/from16 v4, v30

    .line 1009
    .line 1010
    const/16 v19, -0x1

    .line 1011
    .line 1012
    move/from16 v18, v13

    .line 1013
    .line 1014
    move-object v13, v1

    .line 1015
    move-wide/from16 v1, v20

    .line 1016
    .line 1017
    move/from16 v20, v14

    .line 1018
    .line 1019
    if-ne v8, v4, :cond_22

    .line 1020
    .line 1021
    add-int/lit8 v8, v3, 0x8

    .line 1022
    .line 1023
    or-int v14, v20, v17

    .line 1024
    .line 1025
    invoke-static {v3, v7}, Ljp/ce;->n(I[B)J

    .line 1026
    .line 1027
    .line 1028
    move-result-wide v5

    .line 1029
    move-wide v3, v1

    .line 1030
    move-object v2, v11

    .line 1031
    move-object v1, v13

    .line 1032
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 1033
    .line 1034
    .line 1035
    :goto_1a
    move/from16 v5, p4

    .line 1036
    .line 1037
    move-object v3, v7

    .line 1038
    move v4, v8

    .line 1039
    :goto_1b
    move-object v6, v9

    .line 1040
    move v8, v10

    .line 1041
    goto :goto_18

    .line 1042
    :pswitch_9
    move-object/from16 v7, p2

    .line 1043
    .line 1044
    move-object/from16 v9, p6

    .line 1045
    .line 1046
    move v10, v3

    .line 1047
    move/from16 v3, v18

    .line 1048
    .line 1049
    move-wide/from16 v4, v20

    .line 1050
    .line 1051
    const/16 v19, -0x1

    .line 1052
    .line 1053
    move/from16 v18, v13

    .line 1054
    .line 1055
    move/from16 v20, v14

    .line 1056
    .line 1057
    if-nez v8, :cond_20

    .line 1058
    .line 1059
    or-int v14, v20, v17

    .line 1060
    .line 1061
    invoke-static {v7, v3, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1062
    .line 1063
    .line 1064
    move-result v3

    .line 1065
    iget v6, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1066
    .line 1067
    invoke-virtual {v1, v2, v4, v5, v6}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 1068
    .line 1069
    .line 1070
    move/from16 v5, p4

    .line 1071
    .line 1072
    move v4, v3

    .line 1073
    move-object v3, v7

    .line 1074
    goto :goto_1b

    .line 1075
    :cond_20
    move-object v13, v1

    .line 1076
    :cond_21
    move-object v11, v2

    .line 1077
    goto/16 :goto_1d

    .line 1078
    .line 1079
    :pswitch_a
    move-object/from16 v7, p2

    .line 1080
    .line 1081
    move-object/from16 v9, p6

    .line 1082
    .line 1083
    move v10, v3

    .line 1084
    move/from16 v3, v18

    .line 1085
    .line 1086
    move-wide/from16 v4, v20

    .line 1087
    .line 1088
    const/16 v19, -0x1

    .line 1089
    .line 1090
    move/from16 v18, v13

    .line 1091
    .line 1092
    move/from16 v20, v14

    .line 1093
    .line 1094
    if-nez v8, :cond_20

    .line 1095
    .line 1096
    or-int v14, v20, v17

    .line 1097
    .line 1098
    invoke-static {v7, v3, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1099
    .line 1100
    .line 1101
    move-result v8

    .line 1102
    move-wide v3, v4

    .line 1103
    iget-wide v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 1104
    .line 1105
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 1106
    .line 1107
    .line 1108
    goto :goto_1a

    .line 1109
    :pswitch_b
    move-object/from16 v7, p2

    .line 1110
    .line 1111
    move-object/from16 v9, p6

    .line 1112
    .line 1113
    move v10, v3

    .line 1114
    move/from16 v3, v18

    .line 1115
    .line 1116
    move-wide/from16 v4, v20

    .line 1117
    .line 1118
    const/16 v19, -0x1

    .line 1119
    .line 1120
    move/from16 v18, v13

    .line 1121
    .line 1122
    move/from16 v20, v14

    .line 1123
    .line 1124
    move-object v13, v1

    .line 1125
    const/4 v1, 0x5

    .line 1126
    if-ne v8, v1, :cond_21

    .line 1127
    .line 1128
    add-int/lit8 v1, v3, 0x4

    .line 1129
    .line 1130
    or-int v14, v20, v17

    .line 1131
    .line 1132
    invoke-static {v3, v7}, Ljp/ce;->c(I[B)I

    .line 1133
    .line 1134
    .line 1135
    move-result v3

    .line 1136
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1137
    .line 1138
    .line 1139
    move-result v3

    .line 1140
    sget-object v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 1141
    .line 1142
    invoke-virtual {v6, v2, v4, v5, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->f(Ljava/lang/Object;JF)V

    .line 1143
    .line 1144
    .line 1145
    move/from16 v5, p4

    .line 1146
    .line 1147
    move v4, v1

    .line 1148
    move-object v3, v7

    .line 1149
    :goto_1c
    move-object v6, v9

    .line 1150
    move v8, v10

    .line 1151
    goto/16 :goto_17

    .line 1152
    .line 1153
    :pswitch_c
    move-object/from16 v7, p2

    .line 1154
    .line 1155
    move-object/from16 v9, p6

    .line 1156
    .line 1157
    move v10, v3

    .line 1158
    move/from16 v3, v18

    .line 1159
    .line 1160
    move-wide/from16 v4, v20

    .line 1161
    .line 1162
    const/16 v19, -0x1

    .line 1163
    .line 1164
    move/from16 v18, v13

    .line 1165
    .line 1166
    move/from16 v20, v14

    .line 1167
    .line 1168
    move-object v13, v1

    .line 1169
    move/from16 v1, v30

    .line 1170
    .line 1171
    if-ne v8, v1, :cond_21

    .line 1172
    .line 1173
    add-int/lit8 v8, v3, 0x8

    .line 1174
    .line 1175
    or-int v14, v20, v17

    .line 1176
    .line 1177
    invoke-static {v3, v7}, Ljp/ce;->n(I[B)J

    .line 1178
    .line 1179
    .line 1180
    move-result-wide v11

    .line 1181
    invoke-static {v11, v12}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 1182
    .line 1183
    .line 1184
    move-result-wide v11

    .line 1185
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;

    .line 1186
    .line 1187
    move-wide v3, v4

    .line 1188
    move-wide v5, v11

    .line 1189
    invoke-virtual/range {v1 .. v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u2;->e(Ljava/lang/Object;JD)V

    .line 1190
    .line 1191
    .line 1192
    move/from16 v5, p4

    .line 1193
    .line 1194
    move-object v3, v7

    .line 1195
    move v4, v8

    .line 1196
    goto :goto_1c

    .line 1197
    :cond_22
    :goto_1d
    move v8, v10

    .line 1198
    move-object/from16 v32, v13

    .line 1199
    .line 1200
    move/from16 v31, v18

    .line 1201
    .line 1202
    move/from16 v14, v27

    .line 1203
    .line 1204
    :goto_1e
    move/from16 v10, p5

    .line 1205
    .line 1206
    goto/16 :goto_52

    .line 1207
    .line 1208
    :cond_23
    move-object v13, v1

    .line 1209
    move v10, v3

    .line 1210
    move/from16 v27, v11

    .line 1211
    .line 1212
    const/16 v19, -0x1

    .line 1213
    .line 1214
    move-object v11, v2

    .line 1215
    move-wide/from16 v1, v20

    .line 1216
    .line 1217
    const/16 v3, 0x1b

    .line 1218
    .line 1219
    const/16 v20, 0xa

    .line 1220
    .line 1221
    if-ne v7, v3, :cond_27

    .line 1222
    .line 1223
    const/4 v3, 0x2

    .line 1224
    if-ne v8, v3, :cond_26

    .line 1225
    .line 1226
    invoke-virtual {v13, v11, v1, v2}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v3

    .line 1230
    check-cast v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 1231
    .line 1232
    move-object v4, v3

    .line 1233
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;

    .line 1234
    .line 1235
    iget-boolean v4, v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;->d:Z

    .line 1236
    .line 1237
    if-nez v4, :cond_25

    .line 1238
    .line 1239
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1240
    .line 1241
    .line 1242
    move-result v4

    .line 1243
    if-nez v4, :cond_24

    .line 1244
    .line 1245
    :goto_1f
    move/from16 v4, v20

    .line 1246
    .line 1247
    goto :goto_20

    .line 1248
    :cond_24
    add-int v20, v4, v4

    .line 1249
    .line 1250
    goto :goto_1f

    .line 1251
    :goto_20
    invoke-interface {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;->d(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 1252
    .line 1253
    .line 1254
    move-result-object v3

    .line 1255
    invoke-virtual {v13, v11, v1, v2, v3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1256
    .line 1257
    .line 1258
    :cond_25
    move-object v6, v3

    .line 1259
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1260
    .line 1261
    .line 1262
    move-result-object v1

    .line 1263
    move-object/from16 v3, p2

    .line 1264
    .line 1265
    move/from16 v5, p4

    .line 1266
    .line 1267
    move-object/from16 v7, p6

    .line 1268
    .line 1269
    move v2, v15

    .line 1270
    move/from16 v4, v18

    .line 1271
    .line 1272
    invoke-static/range {v1 .. v7}, Ljp/ce;->d(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1273
    .line 1274
    .line 1275
    move-result v4

    .line 1276
    move-object/from16 v6, p6

    .line 1277
    .line 1278
    move v8, v10

    .line 1279
    move-object v2, v11

    .line 1280
    move-object v1, v13

    .line 1281
    goto/16 :goto_7

    .line 1282
    .line 1283
    :cond_26
    move-object/from16 v3, p2

    .line 1284
    .line 1285
    move/from16 v5, p4

    .line 1286
    .line 1287
    move/from16 v31, v9

    .line 1288
    .line 1289
    move-object/from16 v32, v13

    .line 1290
    .line 1291
    move/from16 v20, v14

    .line 1292
    .line 1293
    move/from16 v13, v18

    .line 1294
    .line 1295
    move/from16 v14, v27

    .line 1296
    .line 1297
    move-object/from16 v9, p6

    .line 1298
    .line 1299
    goto/16 :goto_43

    .line 1300
    .line 1301
    :cond_27
    const/16 v3, 0x31

    .line 1302
    .line 1303
    if-gt v7, v3, :cond_78

    .line 1304
    .line 1305
    int-to-long v3, v4

    .line 1306
    move-wide/from16 v21, v3

    .line 1307
    .line 1308
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 1309
    .line 1310
    invoke-virtual {v3, v11, v1, v2}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1311
    .line 1312
    .line 1313
    move-result-object v4

    .line 1314
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 1315
    .line 1316
    move/from16 v31, v9

    .line 1317
    .line 1318
    move-object v9, v4

    .line 1319
    check-cast v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;

    .line 1320
    .line 1321
    iget-boolean v9, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;->d:Z

    .line 1322
    .line 1323
    if-nez v9, :cond_29

    .line 1324
    .line 1325
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1326
    .line 1327
    .line 1328
    move-result v9

    .line 1329
    if-nez v9, :cond_28

    .line 1330
    .line 1331
    :goto_21
    move/from16 v9, v20

    .line 1332
    .line 1333
    goto :goto_22

    .line 1334
    :cond_28
    add-int v20, v9, v9

    .line 1335
    .line 1336
    goto :goto_21

    .line 1337
    :goto_22
    invoke-interface {v4, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;->d(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 1338
    .line 1339
    .line 1340
    move-result-object v4

    .line 1341
    invoke-virtual {v3, v11, v1, v2, v4}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1342
    .line 1343
    .line 1344
    :cond_29
    move-object v9, v4

    .line 1345
    const-string v1, "While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length."

    .line 1346
    .line 1347
    packed-switch v7, :pswitch_data_1

    .line 1348
    .line 1349
    .line 1350
    const/4 v7, 0x3

    .line 1351
    if-ne v8, v7, :cond_2b

    .line 1352
    .line 1353
    and-int/lit8 v1, v15, -0x8

    .line 1354
    .line 1355
    or-int/lit8 v6, v1, 0x4

    .line 1356
    .line 1357
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1358
    .line 1359
    .line 1360
    move-result-object v2

    .line 1361
    invoke-interface {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 1362
    .line 1363
    .line 1364
    move-result-object v1

    .line 1365
    move-object/from16 v3, p2

    .line 1366
    .line 1367
    move/from16 v5, p4

    .line 1368
    .line 1369
    move-object/from16 v7, p6

    .line 1370
    .line 1371
    move/from16 v4, v18

    .line 1372
    .line 1373
    invoke-static/range {v1 .. v7}, Ljp/ce;->k(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1374
    .line 1375
    .line 1376
    move-result v8

    .line 1377
    move v12, v4

    .line 1378
    move-object v4, v1

    .line 1379
    move v1, v6

    .line 1380
    move-object v6, v7

    .line 1381
    invoke-interface {v2, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->b(Ljava/lang/Object;)V

    .line 1382
    .line 1383
    .line 1384
    iput-object v4, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 1385
    .line 1386
    invoke-interface {v9, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1387
    .line 1388
    .line 1389
    :goto_23
    if-ge v8, v5, :cond_2a

    .line 1390
    .line 1391
    invoke-static {v3, v8, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1392
    .line 1393
    .line 1394
    move-result v4

    .line 1395
    iget v7, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1396
    .line 1397
    if-ne v15, v7, :cond_2a

    .line 1398
    .line 1399
    move v6, v1

    .line 1400
    invoke-interface {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 1401
    .line 1402
    .line 1403
    move-result-object v1

    .line 1404
    move-object/from16 v7, p6

    .line 1405
    .line 1406
    invoke-static/range {v1 .. v7}, Ljp/ce;->k(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1407
    .line 1408
    .line 1409
    move-result v8

    .line 1410
    move-object v4, v1

    .line 1411
    move v1, v6

    .line 1412
    move-object v6, v7

    .line 1413
    invoke-interface {v2, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->b(Ljava/lang/Object;)V

    .line 1414
    .line 1415
    .line 1416
    iput-object v4, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 1417
    .line 1418
    invoke-interface {v9, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1419
    .line 1420
    .line 1421
    goto :goto_23

    .line 1422
    :cond_2a
    move-object v9, v6

    .line 1423
    move v4, v8

    .line 1424
    :goto_24
    move-object/from16 v32, v13

    .line 1425
    .line 1426
    move/from16 v20, v14

    .line 1427
    .line 1428
    move/from16 v14, v27

    .line 1429
    .line 1430
    :goto_25
    move v13, v12

    .line 1431
    goto/16 :goto_41

    .line 1432
    .line 1433
    :cond_2b
    move-object/from16 v3, p2

    .line 1434
    .line 1435
    move/from16 v5, p4

    .line 1436
    .line 1437
    move-object/from16 v9, p6

    .line 1438
    .line 1439
    move-object/from16 v32, v13

    .line 1440
    .line 1441
    move/from16 v20, v14

    .line 1442
    .line 1443
    move/from16 v13, v18

    .line 1444
    .line 1445
    move/from16 v14, v27

    .line 1446
    .line 1447
    goto/16 :goto_40

    .line 1448
    .line 1449
    :pswitch_d
    move-object/from16 v3, p2

    .line 1450
    .line 1451
    move/from16 v5, p4

    .line 1452
    .line 1453
    move-object/from16 v6, p6

    .line 1454
    .line 1455
    move/from16 v12, v18

    .line 1456
    .line 1457
    const/4 v4, 0x2

    .line 1458
    if-ne v8, v4, :cond_2f

    .line 1459
    .line 1460
    if-nez v9, :cond_2e

    .line 1461
    .line 1462
    invoke-static {v3, v12, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1463
    .line 1464
    .line 1465
    move-result v2

    .line 1466
    iget v4, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1467
    .line 1468
    add-int/2addr v4, v2

    .line 1469
    if-lt v2, v4, :cond_2d

    .line 1470
    .line 1471
    if-ne v2, v4, :cond_2c

    .line 1472
    .line 1473
    :goto_26
    move v4, v2

    .line 1474
    :goto_27
    move-object v9, v6

    .line 1475
    goto :goto_24

    .line 1476
    :cond_2c
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 1477
    .line 1478
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 1479
    .line 1480
    .line 1481
    throw v0

    .line 1482
    :cond_2d
    invoke-static {v3, v2, v6}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1483
    .line 1484
    .line 1485
    throw v17

    .line 1486
    :cond_2e
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1487
    .line 1488
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1489
    .line 1490
    .line 1491
    throw v0

    .line 1492
    :cond_2f
    if-eqz v8, :cond_31

    .line 1493
    .line 1494
    :cond_30
    move-object v9, v6

    .line 1495
    move-object/from16 v32, v13

    .line 1496
    .line 1497
    move/from16 v20, v14

    .line 1498
    .line 1499
    move/from16 v14, v27

    .line 1500
    .line 1501
    :goto_28
    move v13, v12

    .line 1502
    goto/16 :goto_40

    .line 1503
    .line 1504
    :cond_31
    if-nez v9, :cond_32

    .line 1505
    .line 1506
    invoke-static {v3, v12, v6}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1507
    .line 1508
    .line 1509
    throw v17

    .line 1510
    :cond_32
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1511
    .line 1512
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1513
    .line 1514
    .line 1515
    throw v0

    .line 1516
    :pswitch_e
    move-object/from16 v3, p2

    .line 1517
    .line 1518
    move/from16 v5, p4

    .line 1519
    .line 1520
    move-object/from16 v6, p6

    .line 1521
    .line 1522
    move/from16 v12, v18

    .line 1523
    .line 1524
    const/4 v4, 0x2

    .line 1525
    if-ne v8, v4, :cond_35

    .line 1526
    .line 1527
    check-cast v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 1528
    .line 1529
    invoke-static {v3, v12, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1530
    .line 1531
    .line 1532
    move-result v2

    .line 1533
    iget v4, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1534
    .line 1535
    add-int/2addr v4, v2

    .line 1536
    :goto_29
    if-ge v2, v4, :cond_33

    .line 1537
    .line 1538
    invoke-static {v3, v2, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1539
    .line 1540
    .line 1541
    move-result v2

    .line 1542
    iget v7, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1543
    .line 1544
    invoke-static {v7}, Ljp/ee;->b(I)I

    .line 1545
    .line 1546
    .line 1547
    move-result v7

    .line 1548
    invoke-virtual {v9, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 1549
    .line 1550
    .line 1551
    goto :goto_29

    .line 1552
    :cond_33
    if-ne v2, v4, :cond_34

    .line 1553
    .line 1554
    goto :goto_26

    .line 1555
    :cond_34
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 1556
    .line 1557
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 1558
    .line 1559
    .line 1560
    throw v0

    .line 1561
    :cond_35
    if-nez v8, :cond_30

    .line 1562
    .line 1563
    check-cast v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 1564
    .line 1565
    invoke-static {v3, v12, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1566
    .line 1567
    .line 1568
    move-result v1

    .line 1569
    iget v2, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1570
    .line 1571
    invoke-static {v2}, Ljp/ee;->b(I)I

    .line 1572
    .line 1573
    .line 1574
    move-result v2

    .line 1575
    invoke-virtual {v9, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 1576
    .line 1577
    .line 1578
    :goto_2a
    if-ge v1, v5, :cond_36

    .line 1579
    .line 1580
    invoke-static {v3, v1, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1581
    .line 1582
    .line 1583
    move-result v2

    .line 1584
    iget v4, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1585
    .line 1586
    if-ne v15, v4, :cond_36

    .line 1587
    .line 1588
    invoke-static {v3, v2, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1589
    .line 1590
    .line 1591
    move-result v1

    .line 1592
    iget v2, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1593
    .line 1594
    invoke-static {v2}, Ljp/ee;->b(I)I

    .line 1595
    .line 1596
    .line 1597
    move-result v2

    .line 1598
    invoke-virtual {v9, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 1599
    .line 1600
    .line 1601
    goto :goto_2a

    .line 1602
    :cond_36
    move v4, v1

    .line 1603
    goto/16 :goto_27

    .line 1604
    .line 1605
    :pswitch_f
    move-object/from16 v3, p2

    .line 1606
    .line 1607
    move/from16 v5, p4

    .line 1608
    .line 1609
    move-object/from16 v6, p6

    .line 1610
    .line 1611
    move/from16 v12, v18

    .line 1612
    .line 1613
    const/4 v4, 0x2

    .line 1614
    if-ne v8, v4, :cond_37

    .line 1615
    .line 1616
    invoke-static {v3, v12, v9, v6}, Ljp/ce;->e([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1617
    .line 1618
    .line 1619
    move-result v1

    .line 1620
    move v4, v5

    .line 1621
    move v2, v15

    .line 1622
    goto :goto_2b

    .line 1623
    :cond_37
    if-nez v8, :cond_3f

    .line 1624
    .line 1625
    move-object v2, v3

    .line 1626
    move v4, v5

    .line 1627
    move-object v5, v9

    .line 1628
    move v3, v12

    .line 1629
    move v1, v15

    .line 1630
    invoke-static/range {v1 .. v6}, Ljp/ce;->i(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1631
    .line 1632
    .line 1633
    move-result v7

    .line 1634
    move-object v3, v2

    .line 1635
    move v2, v1

    .line 1636
    move v1, v7

    .line 1637
    :goto_2b
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->B(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;

    .line 1638
    .line 1639
    .line 1640
    move-result-object v5

    .line 1641
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 1642
    .line 1643
    if-eqz v5, :cond_3d

    .line 1644
    .line 1645
    if-eqz v9, :cond_3b

    .line 1646
    .line 1647
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 1648
    .line 1649
    .line 1650
    move-result v7

    .line 1651
    move/from16 v18, v1

    .line 1652
    .line 1653
    move-object/from16 v8, v17

    .line 1654
    .line 1655
    const/4 v1, 0x0

    .line 1656
    const/4 v15, 0x0

    .line 1657
    :goto_2c
    if-ge v15, v7, :cond_3a

    .line 1658
    .line 1659
    invoke-interface {v9, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1660
    .line 1661
    .line 1662
    move-result-object v17

    .line 1663
    move/from16 v20, v14

    .line 1664
    .line 1665
    move-object/from16 v14, v17

    .line 1666
    .line 1667
    check-cast v14, Ljava/lang/Integer;

    .line 1668
    .line 1669
    move-object/from16 v32, v13

    .line 1670
    .line 1671
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 1672
    .line 1673
    .line 1674
    move-result v13

    .line 1675
    invoke-interface {v5, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;->a(I)Z

    .line 1676
    .line 1677
    .line 1678
    move-result v17

    .line 1679
    if-eqz v17, :cond_39

    .line 1680
    .line 1681
    if-eq v15, v1, :cond_38

    .line 1682
    .line 1683
    invoke-interface {v9, v1, v14}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 1684
    .line 1685
    .line 1686
    :cond_38
    add-int/lit8 v1, v1, 0x1

    .line 1687
    .line 1688
    move/from16 v14, v27

    .line 1689
    .line 1690
    goto :goto_2d

    .line 1691
    :cond_39
    move/from16 v14, v27

    .line 1692
    .line 1693
    invoke-static {v14, v13, v11, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->o(IILjava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1694
    .line 1695
    .line 1696
    move-result-object v8

    .line 1697
    :goto_2d
    add-int/lit8 v15, v15, 0x1

    .line 1698
    .line 1699
    move/from16 v27, v14

    .line 1700
    .line 1701
    move/from16 v14, v20

    .line 1702
    .line 1703
    move-object/from16 v13, v32

    .line 1704
    .line 1705
    goto :goto_2c

    .line 1706
    :cond_3a
    move-object/from16 v32, v13

    .line 1707
    .line 1708
    move/from16 v20, v14

    .line 1709
    .line 1710
    move/from16 v14, v27

    .line 1711
    .line 1712
    if-eq v1, v7, :cond_3e

    .line 1713
    .line 1714
    invoke-interface {v9, v1, v7}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 1715
    .line 1716
    .line 1717
    move-result-object v1

    .line 1718
    invoke-interface {v1}, Ljava/util/List;->clear()V

    .line 1719
    .line 1720
    .line 1721
    goto :goto_2f

    .line 1722
    :cond_3b
    move/from16 v18, v1

    .line 1723
    .line 1724
    move-object/from16 v32, v13

    .line 1725
    .line 1726
    move/from16 v20, v14

    .line 1727
    .line 1728
    move/from16 v14, v27

    .line 1729
    .line 1730
    invoke-interface {v9}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1731
    .line 1732
    .line 1733
    move-result-object v1

    .line 1734
    move-object/from16 v7, v17

    .line 1735
    .line 1736
    :cond_3c
    :goto_2e
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1737
    .line 1738
    .line 1739
    move-result v8

    .line 1740
    if-eqz v8, :cond_3e

    .line 1741
    .line 1742
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1743
    .line 1744
    .line 1745
    move-result-object v8

    .line 1746
    check-cast v8, Ljava/lang/Integer;

    .line 1747
    .line 1748
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 1749
    .line 1750
    .line 1751
    move-result v8

    .line 1752
    invoke-interface {v5, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;->a(I)Z

    .line 1753
    .line 1754
    .line 1755
    move-result v9

    .line 1756
    if-nez v9, :cond_3c

    .line 1757
    .line 1758
    invoke-static {v14, v8, v11, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->o(IILjava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1759
    .line 1760
    .line 1761
    move-result-object v7

    .line 1762
    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    .line 1763
    .line 1764
    .line 1765
    goto :goto_2e

    .line 1766
    :cond_3d
    move/from16 v18, v1

    .line 1767
    .line 1768
    move-object/from16 v32, v13

    .line 1769
    .line 1770
    move/from16 v20, v14

    .line 1771
    .line 1772
    move/from16 v14, v27

    .line 1773
    .line 1774
    :cond_3e
    :goto_2f
    move v15, v2

    .line 1775
    move v5, v4

    .line 1776
    move-object v9, v6

    .line 1777
    move v13, v12

    .line 1778
    move/from16 v4, v18

    .line 1779
    .line 1780
    goto/16 :goto_41

    .line 1781
    .line 1782
    :cond_3f
    move-object/from16 v32, v13

    .line 1783
    .line 1784
    move/from16 v20, v14

    .line 1785
    .line 1786
    move/from16 v14, v27

    .line 1787
    .line 1788
    :goto_30
    move-object v9, v6

    .line 1789
    goto/16 :goto_28

    .line 1790
    .line 1791
    :pswitch_10
    move-object/from16 v3, p2

    .line 1792
    .line 1793
    move/from16 v4, p4

    .line 1794
    .line 1795
    move-object/from16 v6, p6

    .line 1796
    .line 1797
    move-object/from16 v32, v13

    .line 1798
    .line 1799
    move/from16 v20, v14

    .line 1800
    .line 1801
    move v2, v15

    .line 1802
    move/from16 v12, v18

    .line 1803
    .line 1804
    move/from16 v14, v27

    .line 1805
    .line 1806
    const/4 v7, 0x2

    .line 1807
    if-ne v8, v7, :cond_47

    .line 1808
    .line 1809
    invoke-static {v3, v12, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1810
    .line 1811
    .line 1812
    move-result v7

    .line 1813
    iget v8, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1814
    .line 1815
    if-ltz v8, :cond_46

    .line 1816
    .line 1817
    array-length v13, v3

    .line 1818
    sub-int/2addr v13, v7

    .line 1819
    if-gt v8, v13, :cond_45

    .line 1820
    .line 1821
    if-nez v8, :cond_40

    .line 1822
    .line 1823
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 1824
    .line 1825
    invoke-interface {v9, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1826
    .line 1827
    .line 1828
    goto :goto_32

    .line 1829
    :cond_40
    invoke-static {v3, v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->x([BII)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 1830
    .line 1831
    .line 1832
    move-result-object v13

    .line 1833
    invoke-interface {v9, v13}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1834
    .line 1835
    .line 1836
    :goto_31
    add-int/2addr v7, v8

    .line 1837
    :goto_32
    if-ge v7, v4, :cond_44

    .line 1838
    .line 1839
    invoke-static {v3, v7, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1840
    .line 1841
    .line 1842
    move-result v8

    .line 1843
    iget v13, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1844
    .line 1845
    if-ne v2, v13, :cond_44

    .line 1846
    .line 1847
    invoke-static {v3, v8, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1848
    .line 1849
    .line 1850
    move-result v7

    .line 1851
    iget v8, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1852
    .line 1853
    if-ltz v8, :cond_43

    .line 1854
    .line 1855
    array-length v13, v3

    .line 1856
    sub-int/2addr v13, v7

    .line 1857
    if-gt v8, v13, :cond_42

    .line 1858
    .line 1859
    if-nez v8, :cond_41

    .line 1860
    .line 1861
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 1862
    .line 1863
    invoke-interface {v9, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1864
    .line 1865
    .line 1866
    goto :goto_32

    .line 1867
    :cond_41
    invoke-static {v3, v7, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->x([BII)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 1868
    .line 1869
    .line 1870
    move-result-object v13

    .line 1871
    invoke-interface {v9, v13}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1872
    .line 1873
    .line 1874
    goto :goto_31

    .line 1875
    :cond_42
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 1876
    .line 1877
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 1878
    .line 1879
    .line 1880
    throw v0

    .line 1881
    :cond_43
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 1882
    .line 1883
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 1884
    .line 1885
    .line 1886
    throw v0

    .line 1887
    :cond_44
    move v15, v2

    .line 1888
    move v5, v4

    .line 1889
    move-object v9, v6

    .line 1890
    move v4, v7

    .line 1891
    goto/16 :goto_25

    .line 1892
    .line 1893
    :cond_45
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 1894
    .line 1895
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 1896
    .line 1897
    .line 1898
    throw v0

    .line 1899
    :cond_46
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 1900
    .line 1901
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 1902
    .line 1903
    .line 1904
    throw v0

    .line 1905
    :cond_47
    move v15, v2

    .line 1906
    move v5, v4

    .line 1907
    goto :goto_30

    .line 1908
    :pswitch_11
    move-object/from16 v3, p2

    .line 1909
    .line 1910
    move/from16 v4, p4

    .line 1911
    .line 1912
    move-object/from16 v6, p6

    .line 1913
    .line 1914
    move-object/from16 v32, v13

    .line 1915
    .line 1916
    move/from16 v20, v14

    .line 1917
    .line 1918
    move v2, v15

    .line 1919
    move/from16 v12, v18

    .line 1920
    .line 1921
    move/from16 v14, v27

    .line 1922
    .line 1923
    const/4 v7, 0x2

    .line 1924
    if-ne v8, v7, :cond_47

    .line 1925
    .line 1926
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 1927
    .line 1928
    .line 1929
    move-result-object v1

    .line 1930
    move v5, v4

    .line 1931
    move-object v7, v6

    .line 1932
    move-object v6, v9

    .line 1933
    move v4, v12

    .line 1934
    invoke-static/range {v1 .. v7}, Ljp/ce;->d(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1935
    .line 1936
    .line 1937
    move-result v1

    .line 1938
    move v15, v2

    .line 1939
    move v13, v4

    .line 1940
    move-object v9, v7

    .line 1941
    move v4, v1

    .line 1942
    goto/16 :goto_41

    .line 1943
    .line 1944
    :pswitch_12
    move-object/from16 v3, p2

    .line 1945
    .line 1946
    move/from16 v4, p4

    .line 1947
    .line 1948
    move-object/from16 v32, v13

    .line 1949
    .line 1950
    move/from16 v20, v14

    .line 1951
    .line 1952
    move v2, v15

    .line 1953
    move/from16 v15, v18

    .line 1954
    .line 1955
    move/from16 v14, v27

    .line 1956
    .line 1957
    const/4 v7, 0x2

    .line 1958
    move-object v13, v9

    .line 1959
    move-object/from16 v9, p6

    .line 1960
    .line 1961
    if-ne v8, v7, :cond_54

    .line 1962
    .line 1963
    const-wide/32 v7, 0x20000000

    .line 1964
    .line 1965
    .line 1966
    and-long v7, v21, v7

    .line 1967
    .line 1968
    cmp-long v1, v7, v24

    .line 1969
    .line 1970
    if-nez v1, :cond_4d

    .line 1971
    .line 1972
    invoke-static {v3, v15, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 1973
    .line 1974
    .line 1975
    move-result v1

    .line 1976
    iget v7, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 1977
    .line 1978
    if-ltz v7, :cond_4c

    .line 1979
    .line 1980
    if-nez v7, :cond_48

    .line 1981
    .line 1982
    invoke-interface {v13, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1983
    .line 1984
    .line 1985
    goto :goto_34

    .line 1986
    :cond_48
    new-instance v8, Ljava/lang/String;

    .line 1987
    .line 1988
    sget-object v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 1989
    .line 1990
    invoke-direct {v8, v3, v1, v7, v12}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 1991
    .line 1992
    .line 1993
    invoke-interface {v13, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1994
    .line 1995
    .line 1996
    :goto_33
    add-int/2addr v1, v7

    .line 1997
    :goto_34
    if-ge v1, v4, :cond_4b

    .line 1998
    .line 1999
    invoke-static {v3, v1, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2000
    .line 2001
    .line 2002
    move-result v7

    .line 2003
    iget v8, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2004
    .line 2005
    if-ne v2, v8, :cond_4b

    .line 2006
    .line 2007
    invoke-static {v3, v7, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2008
    .line 2009
    .line 2010
    move-result v1

    .line 2011
    iget v7, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2012
    .line 2013
    if-ltz v7, :cond_4a

    .line 2014
    .line 2015
    if-nez v7, :cond_49

    .line 2016
    .line 2017
    invoke-interface {v13, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2018
    .line 2019
    .line 2020
    goto :goto_34

    .line 2021
    :cond_49
    new-instance v8, Ljava/lang/String;

    .line 2022
    .line 2023
    sget-object v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 2024
    .line 2025
    invoke-direct {v8, v3, v1, v7, v12}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 2026
    .line 2027
    .line 2028
    invoke-interface {v13, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2029
    .line 2030
    .line 2031
    goto :goto_33

    .line 2032
    :cond_4a
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2033
    .line 2034
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2035
    .line 2036
    .line 2037
    throw v0

    .line 2038
    :cond_4b
    move v5, v4

    .line 2039
    move v13, v15

    .line 2040
    move v4, v1

    .line 2041
    :goto_35
    move v15, v2

    .line 2042
    goto/16 :goto_41

    .line 2043
    .line 2044
    :cond_4c
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2045
    .line 2046
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2047
    .line 2048
    .line 2049
    throw v0

    .line 2050
    :cond_4d
    invoke-static {v3, v15, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2051
    .line 2052
    .line 2053
    move-result v1

    .line 2054
    iget v7, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2055
    .line 2056
    if-ltz v7, :cond_53

    .line 2057
    .line 2058
    if-nez v7, :cond_4e

    .line 2059
    .line 2060
    invoke-interface {v13, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2061
    .line 2062
    .line 2063
    goto :goto_37

    .line 2064
    :cond_4e
    add-int v8, v1, v7

    .line 2065
    .line 2066
    sget-object v17, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 2067
    .line 2068
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2069
    .line 2070
    .line 2071
    const/4 v0, 0x0

    .line 2072
    invoke-static {v0, v3, v1, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->c(I[BII)I

    .line 2073
    .line 2074
    .line 2075
    move-result v17

    .line 2076
    if-nez v17, :cond_52

    .line 2077
    .line 2078
    new-instance v0, Ljava/lang/String;

    .line 2079
    .line 2080
    move/from16 v17, v8

    .line 2081
    .line 2082
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 2083
    .line 2084
    invoke-direct {v0, v3, v1, v7, v8}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 2085
    .line 2086
    .line 2087
    invoke-interface {v13, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2088
    .line 2089
    .line 2090
    :goto_36
    move/from16 v1, v17

    .line 2091
    .line 2092
    :goto_37
    if-ge v1, v4, :cond_4b

    .line 2093
    .line 2094
    invoke-static {v3, v1, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2095
    .line 2096
    .line 2097
    move-result v0

    .line 2098
    iget v7, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2099
    .line 2100
    if-ne v2, v7, :cond_4b

    .line 2101
    .line 2102
    invoke-static {v3, v0, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2103
    .line 2104
    .line 2105
    move-result v1

    .line 2106
    iget v0, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2107
    .line 2108
    if-ltz v0, :cond_51

    .line 2109
    .line 2110
    if-nez v0, :cond_4f

    .line 2111
    .line 2112
    invoke-interface {v13, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2113
    .line 2114
    .line 2115
    goto :goto_37

    .line 2116
    :cond_4f
    add-int v7, v1, v0

    .line 2117
    .line 2118
    sget-object v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 2119
    .line 2120
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2121
    .line 2122
    .line 2123
    const/4 v8, 0x0

    .line 2124
    invoke-static {v8, v3, v1, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->c(I[BII)I

    .line 2125
    .line 2126
    .line 2127
    move-result v17

    .line 2128
    if-nez v17, :cond_50

    .line 2129
    .line 2130
    new-instance v8, Ljava/lang/String;

    .line 2131
    .line 2132
    move/from16 v17, v7

    .line 2133
    .line 2134
    sget-object v7, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 2135
    .line 2136
    invoke-direct {v8, v3, v1, v0, v7}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 2137
    .line 2138
    .line 2139
    invoke-interface {v13, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2140
    .line 2141
    .line 2142
    goto :goto_36

    .line 2143
    :cond_50
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2144
    .line 2145
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2146
    .line 2147
    .line 2148
    throw v0

    .line 2149
    :cond_51
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2150
    .line 2151
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2152
    .line 2153
    .line 2154
    throw v0

    .line 2155
    :cond_52
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2156
    .line 2157
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2158
    .line 2159
    .line 2160
    throw v0

    .line 2161
    :cond_53
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2162
    .line 2163
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2164
    .line 2165
    .line 2166
    throw v0

    .line 2167
    :cond_54
    :goto_38
    move v5, v4

    .line 2168
    move v13, v15

    .line 2169
    move v15, v2

    .line 2170
    goto/16 :goto_40

    .line 2171
    .line 2172
    :pswitch_13
    move-object/from16 v3, p2

    .line 2173
    .line 2174
    move/from16 v4, p4

    .line 2175
    .line 2176
    move-object/from16 v32, v13

    .line 2177
    .line 2178
    move/from16 v20, v14

    .line 2179
    .line 2180
    move v2, v15

    .line 2181
    move/from16 v15, v18

    .line 2182
    .line 2183
    move/from16 v14, v27

    .line 2184
    .line 2185
    const/4 v7, 0x2

    .line 2186
    move-object v13, v9

    .line 2187
    move-object/from16 v9, p6

    .line 2188
    .line 2189
    if-ne v8, v7, :cond_59

    .line 2190
    .line 2191
    if-nez v13, :cond_58

    .line 2192
    .line 2193
    invoke-static {v3, v15, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2194
    .line 2195
    .line 2196
    move-result v0

    .line 2197
    iget v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2198
    .line 2199
    add-int/2addr v5, v0

    .line 2200
    if-lt v0, v5, :cond_57

    .line 2201
    .line 2202
    if-ne v0, v5, :cond_56

    .line 2203
    .line 2204
    :cond_55
    :goto_39
    move v5, v4

    .line 2205
    move v13, v15

    .line 2206
    move v4, v0

    .line 2207
    goto/16 :goto_35

    .line 2208
    .line 2209
    :cond_56
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2210
    .line 2211
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2212
    .line 2213
    .line 2214
    throw v0

    .line 2215
    :cond_57
    invoke-static {v3, v0, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2216
    .line 2217
    .line 2218
    throw v17

    .line 2219
    :cond_58
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2220
    .line 2221
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2222
    .line 2223
    .line 2224
    throw v0

    .line 2225
    :cond_59
    if-eqz v8, :cond_5a

    .line 2226
    .line 2227
    goto :goto_38

    .line 2228
    :cond_5a
    if-nez v13, :cond_5b

    .line 2229
    .line 2230
    invoke-static {v3, v15, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2231
    .line 2232
    .line 2233
    throw v17

    .line 2234
    :cond_5b
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2235
    .line 2236
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2237
    .line 2238
    .line 2239
    throw v0

    .line 2240
    :pswitch_14
    move-object/from16 v3, p2

    .line 2241
    .line 2242
    move/from16 v4, p4

    .line 2243
    .line 2244
    move-object/from16 v32, v13

    .line 2245
    .line 2246
    move/from16 v20, v14

    .line 2247
    .line 2248
    move v2, v15

    .line 2249
    move/from16 v15, v18

    .line 2250
    .line 2251
    move/from16 v14, v27

    .line 2252
    .line 2253
    const/4 v7, 0x2

    .line 2254
    move-object v13, v9

    .line 2255
    move-object/from16 v9, p6

    .line 2256
    .line 2257
    if-ne v8, v7, :cond_5e

    .line 2258
    .line 2259
    move-object v0, v13

    .line 2260
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 2261
    .line 2262
    invoke-static {v3, v15, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2263
    .line 2264
    .line 2265
    move-result v5

    .line 2266
    iget v6, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2267
    .line 2268
    add-int/2addr v6, v5

    .line 2269
    :goto_3a
    if-ge v5, v6, :cond_5c

    .line 2270
    .line 2271
    invoke-static {v5, v3}, Ljp/ce;->c(I[B)I

    .line 2272
    .line 2273
    .line 2274
    move-result v7

    .line 2275
    invoke-virtual {v0, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 2276
    .line 2277
    .line 2278
    add-int/lit8 v5, v5, 0x4

    .line 2279
    .line 2280
    goto :goto_3a

    .line 2281
    :cond_5c
    if-ne v5, v6, :cond_5d

    .line 2282
    .line 2283
    move v13, v5

    .line 2284
    move v5, v4

    .line 2285
    move v4, v13

    .line 2286
    move v13, v15

    .line 2287
    goto/16 :goto_35

    .line 2288
    .line 2289
    :cond_5d
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2290
    .line 2291
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2292
    .line 2293
    .line 2294
    throw v0

    .line 2295
    :cond_5e
    const/4 v1, 0x5

    .line 2296
    if-ne v8, v1, :cond_54

    .line 2297
    .line 2298
    add-int/lit8 v0, v15, 0x4

    .line 2299
    .line 2300
    move-object v1, v13

    .line 2301
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 2302
    .line 2303
    invoke-static {v15, v3}, Ljp/ce;->c(I[B)I

    .line 2304
    .line 2305
    .line 2306
    move-result v5

    .line 2307
    invoke-virtual {v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 2308
    .line 2309
    .line 2310
    :goto_3b
    if-ge v0, v4, :cond_55

    .line 2311
    .line 2312
    invoke-static {v3, v0, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2313
    .line 2314
    .line 2315
    move-result v5

    .line 2316
    iget v6, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2317
    .line 2318
    if-ne v2, v6, :cond_55

    .line 2319
    .line 2320
    invoke-static {v5, v3}, Ljp/ce;->c(I[B)I

    .line 2321
    .line 2322
    .line 2323
    move-result v0

    .line 2324
    invoke-virtual {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 2325
    .line 2326
    .line 2327
    add-int/lit8 v0, v5, 0x4

    .line 2328
    .line 2329
    goto :goto_3b

    .line 2330
    :pswitch_15
    move-object/from16 v3, p2

    .line 2331
    .line 2332
    move/from16 v4, p4

    .line 2333
    .line 2334
    move-object/from16 v32, v13

    .line 2335
    .line 2336
    move/from16 v20, v14

    .line 2337
    .line 2338
    move v2, v15

    .line 2339
    move/from16 v15, v18

    .line 2340
    .line 2341
    move/from16 v14, v27

    .line 2342
    .line 2343
    const/4 v7, 0x2

    .line 2344
    move-object v13, v9

    .line 2345
    move-object/from16 v9, p6

    .line 2346
    .line 2347
    if-ne v8, v7, :cond_62

    .line 2348
    .line 2349
    if-nez v13, :cond_61

    .line 2350
    .line 2351
    invoke-static {v3, v15, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2352
    .line 2353
    .line 2354
    move-result v0

    .line 2355
    iget v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2356
    .line 2357
    add-int/2addr v5, v0

    .line 2358
    if-lt v0, v5, :cond_60

    .line 2359
    .line 2360
    if-ne v0, v5, :cond_5f

    .line 2361
    .line 2362
    goto/16 :goto_39

    .line 2363
    .line 2364
    :cond_5f
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2365
    .line 2366
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2367
    .line 2368
    .line 2369
    throw v0

    .line 2370
    :cond_60
    invoke-static {v0, v3}, Ljp/ce;->n(I[B)J

    .line 2371
    .line 2372
    .line 2373
    throw v17

    .line 2374
    :cond_61
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2375
    .line 2376
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2377
    .line 2378
    .line 2379
    throw v0

    .line 2380
    :cond_62
    const/4 v1, 0x1

    .line 2381
    if-eq v8, v1, :cond_63

    .line 2382
    .line 2383
    goto/16 :goto_38

    .line 2384
    .line 2385
    :cond_63
    if-nez v13, :cond_64

    .line 2386
    .line 2387
    invoke-static {v15, v3}, Ljp/ce;->n(I[B)J

    .line 2388
    .line 2389
    .line 2390
    throw v17

    .line 2391
    :cond_64
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2392
    .line 2393
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2394
    .line 2395
    .line 2396
    throw v0

    .line 2397
    :pswitch_16
    move-object/from16 v3, p2

    .line 2398
    .line 2399
    move/from16 v4, p4

    .line 2400
    .line 2401
    move-object/from16 v32, v13

    .line 2402
    .line 2403
    move/from16 v20, v14

    .line 2404
    .line 2405
    move v2, v15

    .line 2406
    move/from16 v15, v18

    .line 2407
    .line 2408
    move/from16 v14, v27

    .line 2409
    .line 2410
    const/4 v7, 0x2

    .line 2411
    move-object v13, v9

    .line 2412
    move-object/from16 v9, p6

    .line 2413
    .line 2414
    if-ne v8, v7, :cond_65

    .line 2415
    .line 2416
    invoke-static {v3, v15, v13, v9}, Ljp/ce;->e([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2417
    .line 2418
    .line 2419
    move-result v0

    .line 2420
    goto/16 :goto_39

    .line 2421
    .line 2422
    :cond_65
    if-nez v8, :cond_54

    .line 2423
    .line 2424
    move v1, v2

    .line 2425
    move-object v2, v3

    .line 2426
    move-object v6, v9

    .line 2427
    move-object v5, v13

    .line 2428
    move v3, v15

    .line 2429
    invoke-static/range {v1 .. v6}, Ljp/ce;->i(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2430
    .line 2431
    .line 2432
    move-result v0

    .line 2433
    move v15, v1

    .line 2434
    move v13, v3

    .line 2435
    move v5, v4

    .line 2436
    move-object v3, v2

    .line 2437
    :goto_3c
    move v4, v0

    .line 2438
    goto/16 :goto_41

    .line 2439
    .line 2440
    :pswitch_17
    move-object/from16 v3, p2

    .line 2441
    .line 2442
    move/from16 v5, p4

    .line 2443
    .line 2444
    move-object v6, v9

    .line 2445
    move-object/from16 v32, v13

    .line 2446
    .line 2447
    move/from16 v20, v14

    .line 2448
    .line 2449
    move/from16 v13, v18

    .line 2450
    .line 2451
    move/from16 v14, v27

    .line 2452
    .line 2453
    const/4 v7, 0x2

    .line 2454
    move-object/from16 v9, p6

    .line 2455
    .line 2456
    if-ne v8, v7, :cond_69

    .line 2457
    .line 2458
    if-nez v6, :cond_68

    .line 2459
    .line 2460
    invoke-static {v3, v13, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2461
    .line 2462
    .line 2463
    move-result v0

    .line 2464
    iget v2, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2465
    .line 2466
    add-int/2addr v2, v0

    .line 2467
    if-lt v0, v2, :cond_67

    .line 2468
    .line 2469
    if-ne v0, v2, :cond_66

    .line 2470
    .line 2471
    :goto_3d
    goto :goto_3c

    .line 2472
    :cond_66
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2473
    .line 2474
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2475
    .line 2476
    .line 2477
    throw v0

    .line 2478
    :cond_67
    invoke-static {v3, v0, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2479
    .line 2480
    .line 2481
    throw v17

    .line 2482
    :cond_68
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2483
    .line 2484
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2485
    .line 2486
    .line 2487
    throw v0

    .line 2488
    :cond_69
    if-eqz v8, :cond_6a

    .line 2489
    .line 2490
    goto/16 :goto_40

    .line 2491
    .line 2492
    :cond_6a
    if-nez v6, :cond_6b

    .line 2493
    .line 2494
    invoke-static {v3, v13, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2495
    .line 2496
    .line 2497
    throw v17

    .line 2498
    :cond_6b
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2499
    .line 2500
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2501
    .line 2502
    .line 2503
    throw v0

    .line 2504
    :pswitch_18
    move-object/from16 v3, p2

    .line 2505
    .line 2506
    move/from16 v5, p4

    .line 2507
    .line 2508
    move-object v6, v9

    .line 2509
    move-object/from16 v32, v13

    .line 2510
    .line 2511
    move/from16 v20, v14

    .line 2512
    .line 2513
    move/from16 v13, v18

    .line 2514
    .line 2515
    move/from16 v14, v27

    .line 2516
    .line 2517
    const/4 v7, 0x2

    .line 2518
    move-object/from16 v9, p6

    .line 2519
    .line 2520
    if-ne v8, v7, :cond_6e

    .line 2521
    .line 2522
    move-object v0, v6

    .line 2523
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 2524
    .line 2525
    invoke-static {v3, v13, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2526
    .line 2527
    .line 2528
    move-result v2

    .line 2529
    iget v4, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2530
    .line 2531
    add-int/2addr v4, v2

    .line 2532
    :goto_3e
    if-ge v2, v4, :cond_6c

    .line 2533
    .line 2534
    invoke-static {v2, v3}, Ljp/ce;->c(I[B)I

    .line 2535
    .line 2536
    .line 2537
    move-result v6

    .line 2538
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 2539
    .line 2540
    .line 2541
    move-result v6

    .line 2542
    invoke-virtual {v0, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e(F)V

    .line 2543
    .line 2544
    .line 2545
    add-int/lit8 v2, v2, 0x4

    .line 2546
    .line 2547
    goto :goto_3e

    .line 2548
    :cond_6c
    if-ne v2, v4, :cond_6d

    .line 2549
    .line 2550
    move v4, v2

    .line 2551
    goto/16 :goto_41

    .line 2552
    .line 2553
    :cond_6d
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2554
    .line 2555
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2556
    .line 2557
    .line 2558
    throw v0

    .line 2559
    :cond_6e
    const/4 v1, 0x5

    .line 2560
    if-ne v8, v1, :cond_73

    .line 2561
    .line 2562
    add-int/lit8 v4, v13, 0x4

    .line 2563
    .line 2564
    move-object v0, v6

    .line 2565
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 2566
    .line 2567
    invoke-static {v13, v3}, Ljp/ce;->c(I[B)I

    .line 2568
    .line 2569
    .line 2570
    move-result v1

    .line 2571
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 2572
    .line 2573
    .line 2574
    move-result v1

    .line 2575
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e(F)V

    .line 2576
    .line 2577
    .line 2578
    :goto_3f
    if-ge v4, v5, :cond_74

    .line 2579
    .line 2580
    invoke-static {v3, v4, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2581
    .line 2582
    .line 2583
    move-result v1

    .line 2584
    iget v2, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2585
    .line 2586
    if-ne v15, v2, :cond_74

    .line 2587
    .line 2588
    invoke-static {v1, v3}, Ljp/ce;->c(I[B)I

    .line 2589
    .line 2590
    .line 2591
    move-result v2

    .line 2592
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 2593
    .line 2594
    .line 2595
    move-result v2

    .line 2596
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e(F)V

    .line 2597
    .line 2598
    .line 2599
    add-int/lit8 v4, v1, 0x4

    .line 2600
    .line 2601
    goto :goto_3f

    .line 2602
    :pswitch_19
    move-object/from16 v3, p2

    .line 2603
    .line 2604
    move/from16 v5, p4

    .line 2605
    .line 2606
    move-object v6, v9

    .line 2607
    move-object/from16 v32, v13

    .line 2608
    .line 2609
    move/from16 v20, v14

    .line 2610
    .line 2611
    move/from16 v13, v18

    .line 2612
    .line 2613
    move/from16 v14, v27

    .line 2614
    .line 2615
    const/4 v7, 0x2

    .line 2616
    move-object/from16 v9, p6

    .line 2617
    .line 2618
    if-ne v8, v7, :cond_72

    .line 2619
    .line 2620
    if-nez v6, :cond_71

    .line 2621
    .line 2622
    invoke-static {v3, v13, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2623
    .line 2624
    .line 2625
    move-result v0

    .line 2626
    iget v2, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2627
    .line 2628
    add-int/2addr v2, v0

    .line 2629
    if-lt v0, v2, :cond_70

    .line 2630
    .line 2631
    if-ne v0, v2, :cond_6f

    .line 2632
    .line 2633
    goto/16 :goto_3d

    .line 2634
    .line 2635
    :cond_6f
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 2636
    .line 2637
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 2638
    .line 2639
    .line 2640
    throw v0

    .line 2641
    :cond_70
    invoke-static {v0, v3}, Ljp/ce;->n(I[B)J

    .line 2642
    .line 2643
    .line 2644
    move-result-wide v0

    .line 2645
    invoke-static {v0, v1}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 2646
    .line 2647
    .line 2648
    throw v17

    .line 2649
    :cond_71
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2650
    .line 2651
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2652
    .line 2653
    .line 2654
    throw v0

    .line 2655
    :cond_72
    const/4 v1, 0x1

    .line 2656
    if-eq v8, v1, :cond_76

    .line 2657
    .line 2658
    :cond_73
    :goto_40
    move v4, v13

    .line 2659
    :cond_74
    :goto_41
    if-eq v4, v13, :cond_75

    .line 2660
    .line 2661
    const v16, 0xfffff

    .line 2662
    .line 2663
    .line 2664
    move-object/from16 v0, p0

    .line 2665
    .line 2666
    move-object v6, v9

    .line 2667
    move v8, v10

    .line 2668
    move-object v2, v11

    .line 2669
    move v7, v14

    .line 2670
    move/from16 v14, v20

    .line 2671
    .line 2672
    move/from16 v9, v31

    .line 2673
    .line 2674
    move-object/from16 v1, v32

    .line 2675
    .line 2676
    goto/16 :goto_1

    .line 2677
    .line 2678
    :cond_75
    move-object v7, v3

    .line 2679
    move v3, v4

    .line 2680
    move v8, v10

    .line 2681
    goto/16 :goto_1e

    .line 2682
    .line 2683
    :cond_76
    if-nez v6, :cond_77

    .line 2684
    .line 2685
    invoke-static {v13, v3}, Ljp/ce;->n(I[B)J

    .line 2686
    .line 2687
    .line 2688
    move-result-wide v0

    .line 2689
    invoke-static {v0, v1}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 2690
    .line 2691
    .line 2692
    throw v17

    .line 2693
    :cond_77
    new-instance v0, Ljava/lang/ClassCastException;

    .line 2694
    .line 2695
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 2696
    .line 2697
    .line 2698
    throw v0

    .line 2699
    :cond_78
    move-object/from16 v3, p2

    .line 2700
    .line 2701
    move/from16 v5, p4

    .line 2702
    .line 2703
    move/from16 v31, v9

    .line 2704
    .line 2705
    move-object/from16 v32, v13

    .line 2706
    .line 2707
    move/from16 v20, v14

    .line 2708
    .line 2709
    move/from16 v13, v18

    .line 2710
    .line 2711
    move/from16 v14, v27

    .line 2712
    .line 2713
    move-object/from16 v9, p6

    .line 2714
    .line 2715
    const/16 v0, 0x32

    .line 2716
    .line 2717
    if-ne v7, v0, :cond_7c

    .line 2718
    .line 2719
    const/4 v0, 0x2

    .line 2720
    if-ne v8, v0, :cond_7b

    .line 2721
    .line 2722
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 2723
    .line 2724
    const/4 v7, 0x3

    .line 2725
    div-int/lit8 v3, v10, 0x3

    .line 2726
    .line 2727
    add-int/2addr v3, v3

    .line 2728
    aget-object v3, v29, v3

    .line 2729
    .line 2730
    invoke-virtual {v0, v11, v1, v2}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2731
    .line 2732
    .line 2733
    move-result-object v4

    .line 2734
    move-object v5, v4

    .line 2735
    check-cast v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 2736
    .line 2737
    iget-boolean v5, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->d:Z

    .line 2738
    .line 2739
    if-nez v5, :cond_7a

    .line 2740
    .line 2741
    sget-object v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 2742
    .line 2743
    invoke-virtual {v5}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 2744
    .line 2745
    .line 2746
    move-result v6

    .line 2747
    if-eqz v6, :cond_79

    .line 2748
    .line 2749
    new-instance v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 2750
    .line 2751
    invoke-direct {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;-><init>()V

    .line 2752
    .line 2753
    .line 2754
    goto :goto_42

    .line 2755
    :cond_79
    new-instance v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 2756
    .line 2757
    invoke-direct {v6, v5}, Ljava/util/LinkedHashMap;-><init>(Ljava/util/Map;)V

    .line 2758
    .line 2759
    .line 2760
    const/4 v5, 0x1

    .line 2761
    iput-boolean v5, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->d:Z

    .line 2762
    .line 2763
    move-object v5, v6

    .line 2764
    :goto_42
    invoke-static {v5, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->d(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 2765
    .line 2766
    .line 2767
    invoke-virtual {v0, v11, v1, v2, v5}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 2768
    .line 2769
    .line 2770
    :cond_7a
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 2771
    .line 2772
    .line 2773
    move-result-object v0

    .line 2774
    throw v0

    .line 2775
    :cond_7b
    :goto_43
    move-object v7, v3

    .line 2776
    move v8, v10

    .line 2777
    move v3, v13

    .line 2778
    goto/16 :goto_1e

    .line 2779
    .line 2780
    :cond_7c
    add-int/lit8 v0, v10, 0x2

    .line 2781
    .line 2782
    move/from16 v17, v0

    .line 2783
    .line 2784
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->m:Lsun/misc/Unsafe;

    .line 2785
    .line 2786
    aget v17, v28, v17

    .line 2787
    .line 2788
    const v16, 0xfffff

    .line 2789
    .line 2790
    .line 2791
    and-int v3, v17, v16

    .line 2792
    .line 2793
    move/from16 v17, v4

    .line 2794
    .line 2795
    int-to-long v3, v3

    .line 2796
    packed-switch v7, :pswitch_data_2

    .line 2797
    .line 2798
    .line 2799
    :goto_44
    move-object/from16 v7, p2

    .line 2800
    .line 2801
    :goto_45
    move/from16 v18, v10

    .line 2802
    .line 2803
    goto/16 :goto_4f

    .line 2804
    .line 2805
    :pswitch_1a
    const/4 v7, 0x3

    .line 2806
    if-ne v8, v7, :cond_7d

    .line 2807
    .line 2808
    and-int/lit8 v0, v15, -0x8

    .line 2809
    .line 2810
    or-int/lit8 v6, v0, 0x4

    .line 2811
    .line 2812
    move-object/from16 v12, p0

    .line 2813
    .line 2814
    invoke-virtual {v12, v14, v11, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->E(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 2815
    .line 2816
    .line 2817
    move-result-object v1

    .line 2818
    invoke-virtual {v12, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 2819
    .line 2820
    .line 2821
    move-result-object v2

    .line 2822
    move-object/from16 v3, p2

    .line 2823
    .line 2824
    move-object v7, v9

    .line 2825
    move v4, v13

    .line 2826
    invoke-static/range {v1 .. v7}, Ljp/ce;->k(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2827
    .line 2828
    .line 2829
    move-result v0

    .line 2830
    move-object v6, v7

    .line 2831
    move-object v7, v3

    .line 2832
    invoke-virtual {v12, v14, v10, v11, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->n(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 2833
    .line 2834
    .line 2835
    move v4, v0

    .line 2836
    :goto_46
    move-object v9, v6

    .line 2837
    :goto_47
    move/from16 v18, v10

    .line 2838
    .line 2839
    goto/16 :goto_50

    .line 2840
    .line 2841
    :cond_7d
    move-object/from16 v12, p0

    .line 2842
    .line 2843
    goto :goto_44

    .line 2844
    :pswitch_1b
    move-object/from16 v12, p0

    .line 2845
    .line 2846
    move-object/from16 v7, p2

    .line 2847
    .line 2848
    move-object v6, v9

    .line 2849
    if-nez v8, :cond_7e

    .line 2850
    .line 2851
    invoke-static {v7, v13, v6}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2852
    .line 2853
    .line 2854
    move-result v5

    .line 2855
    iget-wide v8, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 2856
    .line 2857
    move-wide/from16 v24, v8

    .line 2858
    .line 2859
    and-long v8, v24, v22

    .line 2860
    .line 2861
    const/16 v30, 0x1

    .line 2862
    .line 2863
    ushr-long v21, v24, v30

    .line 2864
    .line 2865
    neg-long v8, v8

    .line 2866
    xor-long v8, v21, v8

    .line 2867
    .line 2868
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2869
    .line 2870
    .line 2871
    move-result-object v8

    .line 2872
    invoke-virtual {v0, v11, v1, v2, v8}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 2873
    .line 2874
    .line 2875
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 2876
    .line 2877
    .line 2878
    :goto_48
    move v4, v5

    .line 2879
    goto :goto_46

    .line 2880
    :cond_7e
    move-object v9, v6

    .line 2881
    goto :goto_45

    .line 2882
    :pswitch_1c
    move-object/from16 v12, p0

    .line 2883
    .line 2884
    move-object/from16 v7, p2

    .line 2885
    .line 2886
    move-object v6, v9

    .line 2887
    if-nez v8, :cond_7e

    .line 2888
    .line 2889
    invoke-static {v7, v13, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2890
    .line 2891
    .line 2892
    move-result v5

    .line 2893
    iget v8, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2894
    .line 2895
    invoke-static {v8}, Ljp/ee;->b(I)I

    .line 2896
    .line 2897
    .line 2898
    move-result v8

    .line 2899
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2900
    .line 2901
    .line 2902
    move-result-object v8

    .line 2903
    invoke-virtual {v0, v11, v1, v2, v8}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 2904
    .line 2905
    .line 2906
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 2907
    .line 2908
    .line 2909
    goto :goto_48

    .line 2910
    :pswitch_1d
    move-object/from16 v12, p0

    .line 2911
    .line 2912
    move-object/from16 v7, p2

    .line 2913
    .line 2914
    move-object v6, v9

    .line 2915
    if-nez v8, :cond_7e

    .line 2916
    .line 2917
    invoke-static {v7, v13, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2918
    .line 2919
    .line 2920
    move-result v5

    .line 2921
    iget v8, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 2922
    .line 2923
    invoke-virtual {v12, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->B(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;

    .line 2924
    .line 2925
    .line 2926
    move-result-object v9

    .line 2927
    if-eqz v9, :cond_80

    .line 2928
    .line 2929
    invoke-interface {v9, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;->a(I)Z

    .line 2930
    .line 2931
    .line 2932
    move-result v9

    .line 2933
    if-eqz v9, :cond_7f

    .line 2934
    .line 2935
    goto :goto_49

    .line 2936
    :cond_7f
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->u(Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 2937
    .line 2938
    .line 2939
    move-result-object v0

    .line 2940
    int-to-long v1, v8

    .line 2941
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2942
    .line 2943
    .line 2944
    move-result-object v1

    .line 2945
    invoke-virtual {v0, v15, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 2946
    .line 2947
    .line 2948
    goto :goto_48

    .line 2949
    :cond_80
    :goto_49
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2950
    .line 2951
    .line 2952
    move-result-object v8

    .line 2953
    invoke-virtual {v0, v11, v1, v2, v8}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 2954
    .line 2955
    .line 2956
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 2957
    .line 2958
    .line 2959
    goto :goto_48

    .line 2960
    :pswitch_1e
    move-object/from16 v12, p0

    .line 2961
    .line 2962
    move-object/from16 v7, p2

    .line 2963
    .line 2964
    move-object v6, v9

    .line 2965
    const/4 v5, 0x2

    .line 2966
    if-ne v8, v5, :cond_7e

    .line 2967
    .line 2968
    invoke-static {v7, v13, v6}, Ljp/ce;->b([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2969
    .line 2970
    .line 2971
    move-result v5

    .line 2972
    iget-object v8, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 2973
    .line 2974
    invoke-virtual {v0, v11, v1, v2, v8}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 2975
    .line 2976
    .line 2977
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 2978
    .line 2979
    .line 2980
    goto :goto_48

    .line 2981
    :pswitch_1f
    move-object/from16 v12, p0

    .line 2982
    .line 2983
    move-object/from16 v7, p2

    .line 2984
    .line 2985
    move-object v6, v9

    .line 2986
    const/4 v5, 0x2

    .line 2987
    if-ne v8, v5, :cond_7e

    .line 2988
    .line 2989
    invoke-virtual {v12, v14, v11, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->E(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 2990
    .line 2991
    .line 2992
    move-result-object v1

    .line 2993
    invoke-virtual {v12, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->C(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 2994
    .line 2995
    .line 2996
    move-result-object v2

    .line 2997
    move/from16 v5, p4

    .line 2998
    .line 2999
    move-object v3, v7

    .line 3000
    move v4, v13

    .line 3001
    invoke-static/range {v1 .. v6}, Ljp/ce;->l(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 3002
    .line 3003
    .line 3004
    move-result v0

    .line 3005
    move-object v9, v6

    .line 3006
    invoke-virtual {v12, v14, v10, v11, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->n(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 3007
    .line 3008
    .line 3009
    move v4, v0

    .line 3010
    goto/16 :goto_47

    .line 3011
    .line 3012
    :pswitch_20
    move-object/from16 v7, p2

    .line 3013
    .line 3014
    move/from16 v18, v10

    .line 3015
    .line 3016
    const/4 v5, 0x2

    .line 3017
    if-ne v8, v5, :cond_85

    .line 3018
    .line 3019
    invoke-static {v7, v13, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 3020
    .line 3021
    .line 3022
    move-result v5

    .line 3023
    iget v8, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 3024
    .line 3025
    if-nez v8, :cond_81

    .line 3026
    .line 3027
    invoke-virtual {v0, v11, v1, v2, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3028
    .line 3029
    .line 3030
    goto :goto_4b

    .line 3031
    :cond_81
    and-int v6, v17, v26

    .line 3032
    .line 3033
    move/from16 v17, v6

    .line 3034
    .line 3035
    add-int v6, v5, v8

    .line 3036
    .line 3037
    if-eqz v17, :cond_83

    .line 3038
    .line 3039
    sget-object v17, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 3040
    .line 3041
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3042
    .line 3043
    .line 3044
    const/4 v10, 0x0

    .line 3045
    invoke-static {v10, v7, v5, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->c(I[BII)I

    .line 3046
    .line 3047
    .line 3048
    move-result v17

    .line 3049
    if-nez v17, :cond_82

    .line 3050
    .line 3051
    goto :goto_4a

    .line 3052
    :cond_82
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 3053
    .line 3054
    invoke-direct {v0, v12}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 3055
    .line 3056
    .line 3057
    throw v0

    .line 3058
    :cond_83
    const/4 v10, 0x0

    .line 3059
    :goto_4a
    new-instance v12, Ljava/lang/String;

    .line 3060
    .line 3061
    sget-object v10, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 3062
    .line 3063
    invoke-direct {v12, v7, v5, v8, v10}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 3064
    .line 3065
    .line 3066
    invoke-virtual {v0, v11, v1, v2, v12}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3067
    .line 3068
    .line 3069
    move v5, v6

    .line 3070
    :goto_4b
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3071
    .line 3072
    .line 3073
    :goto_4c
    move v4, v5

    .line 3074
    goto/16 :goto_50

    .line 3075
    .line 3076
    :pswitch_21
    move-object/from16 v7, p2

    .line 3077
    .line 3078
    move/from16 v18, v10

    .line 3079
    .line 3080
    if-nez v8, :cond_85

    .line 3081
    .line 3082
    invoke-static {v7, v13, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 3083
    .line 3084
    .line 3085
    move-result v5

    .line 3086
    move v8, v5

    .line 3087
    iget-wide v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 3088
    .line 3089
    cmp-long v5, v5, v24

    .line 3090
    .line 3091
    if-eqz v5, :cond_84

    .line 3092
    .line 3093
    const/16 v30, 0x1

    .line 3094
    .line 3095
    goto :goto_4d

    .line 3096
    :cond_84
    const/16 v30, 0x0

    .line 3097
    .line 3098
    :goto_4d
    invoke-static/range {v30 .. v30}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 3099
    .line 3100
    .line 3101
    move-result-object v5

    .line 3102
    invoke-virtual {v0, v11, v1, v2, v5}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3103
    .line 3104
    .line 3105
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3106
    .line 3107
    .line 3108
    :goto_4e
    move v4, v8

    .line 3109
    goto/16 :goto_50

    .line 3110
    .line 3111
    :pswitch_22
    move-object/from16 v7, p2

    .line 3112
    .line 3113
    move/from16 v18, v10

    .line 3114
    .line 3115
    const/4 v5, 0x5

    .line 3116
    if-ne v8, v5, :cond_85

    .line 3117
    .line 3118
    add-int/lit8 v5, v13, 0x4

    .line 3119
    .line 3120
    invoke-static {v13, v7}, Ljp/ce;->c(I[B)I

    .line 3121
    .line 3122
    .line 3123
    move-result v6

    .line 3124
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3125
    .line 3126
    .line 3127
    move-result-object v6

    .line 3128
    invoke-virtual {v0, v11, v1, v2, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3129
    .line 3130
    .line 3131
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3132
    .line 3133
    .line 3134
    goto :goto_4c

    .line 3135
    :pswitch_23
    move-object/from16 v7, p2

    .line 3136
    .line 3137
    move/from16 v18, v10

    .line 3138
    .line 3139
    const/4 v5, 0x1

    .line 3140
    if-ne v8, v5, :cond_85

    .line 3141
    .line 3142
    add-int/lit8 v5, v13, 0x8

    .line 3143
    .line 3144
    invoke-static {v13, v7}, Ljp/ce;->n(I[B)J

    .line 3145
    .line 3146
    .line 3147
    move-result-wide v21

    .line 3148
    invoke-static/range {v21 .. v22}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 3149
    .line 3150
    .line 3151
    move-result-object v6

    .line 3152
    invoke-virtual {v0, v11, v1, v2, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3153
    .line 3154
    .line 3155
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3156
    .line 3157
    .line 3158
    goto :goto_4c

    .line 3159
    :pswitch_24
    move-object/from16 v7, p2

    .line 3160
    .line 3161
    move/from16 v18, v10

    .line 3162
    .line 3163
    if-nez v8, :cond_85

    .line 3164
    .line 3165
    invoke-static {v7, v13, v9}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 3166
    .line 3167
    .line 3168
    move-result v5

    .line 3169
    iget v6, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 3170
    .line 3171
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3172
    .line 3173
    .line 3174
    move-result-object v6

    .line 3175
    invoke-virtual {v0, v11, v1, v2, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3176
    .line 3177
    .line 3178
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3179
    .line 3180
    .line 3181
    goto :goto_4c

    .line 3182
    :pswitch_25
    move-object/from16 v7, p2

    .line 3183
    .line 3184
    move/from16 v18, v10

    .line 3185
    .line 3186
    if-nez v8, :cond_85

    .line 3187
    .line 3188
    invoke-static {v7, v13, v9}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 3189
    .line 3190
    .line 3191
    move-result v5

    .line 3192
    move v8, v5

    .line 3193
    iget-wide v5, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 3194
    .line 3195
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 3196
    .line 3197
    .line 3198
    move-result-object v5

    .line 3199
    invoke-virtual {v0, v11, v1, v2, v5}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3200
    .line 3201
    .line 3202
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3203
    .line 3204
    .line 3205
    goto :goto_4e

    .line 3206
    :pswitch_26
    move-object/from16 v7, p2

    .line 3207
    .line 3208
    move/from16 v18, v10

    .line 3209
    .line 3210
    const/4 v5, 0x5

    .line 3211
    if-ne v8, v5, :cond_85

    .line 3212
    .line 3213
    add-int/lit8 v5, v13, 0x4

    .line 3214
    .line 3215
    invoke-static {v13, v7}, Ljp/ce;->c(I[B)I

    .line 3216
    .line 3217
    .line 3218
    move-result v6

    .line 3219
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 3220
    .line 3221
    .line 3222
    move-result v6

    .line 3223
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 3224
    .line 3225
    .line 3226
    move-result-object v6

    .line 3227
    invoke-virtual {v0, v11, v1, v2, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3228
    .line 3229
    .line 3230
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3231
    .line 3232
    .line 3233
    goto/16 :goto_4c

    .line 3234
    .line 3235
    :pswitch_27
    move-object/from16 v7, p2

    .line 3236
    .line 3237
    move/from16 v18, v10

    .line 3238
    .line 3239
    const/4 v5, 0x1

    .line 3240
    if-ne v8, v5, :cond_85

    .line 3241
    .line 3242
    add-int/lit8 v5, v13, 0x8

    .line 3243
    .line 3244
    invoke-static {v13, v7}, Ljp/ce;->n(I[B)J

    .line 3245
    .line 3246
    .line 3247
    move-result-wide v21

    .line 3248
    invoke-static/range {v21 .. v22}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 3249
    .line 3250
    .line 3251
    move-result-wide v21

    .line 3252
    invoke-static/range {v21 .. v22}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 3253
    .line 3254
    .line 3255
    move-result-object v6

    .line 3256
    invoke-virtual {v0, v11, v1, v2, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 3257
    .line 3258
    .line 3259
    invoke-virtual {v0, v11, v3, v4, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3260
    .line 3261
    .line 3262
    goto/16 :goto_4c

    .line 3263
    .line 3264
    :cond_85
    :goto_4f
    move v4, v13

    .line 3265
    :goto_50
    if-eq v4, v13, :cond_86

    .line 3266
    .line 3267
    move-object/from16 v0, p0

    .line 3268
    .line 3269
    move/from16 v5, p4

    .line 3270
    .line 3271
    move-object v3, v7

    .line 3272
    move-object v6, v9

    .line 3273
    move-object v2, v11

    .line 3274
    move v7, v14

    .line 3275
    move/from16 v8, v18

    .line 3276
    .line 3277
    :goto_51
    move/from16 v14, v20

    .line 3278
    .line 3279
    move/from16 v9, v31

    .line 3280
    .line 3281
    move-object/from16 v1, v32

    .line 3282
    .line 3283
    goto/16 :goto_0

    .line 3284
    .line 3285
    :cond_86
    move/from16 v10, p5

    .line 3286
    .line 3287
    move v3, v4

    .line 3288
    move/from16 v8, v18

    .line 3289
    .line 3290
    :goto_52
    if-ne v15, v10, :cond_87

    .line 3291
    .line 3292
    if-eqz v10, :cond_87

    .line 3293
    .line 3294
    move-object/from16 v12, p0

    .line 3295
    .line 3296
    move/from16 v5, p4

    .line 3297
    .line 3298
    move v4, v3

    .line 3299
    move/from16 v14, v20

    .line 3300
    .line 3301
    move/from16 v9, v31

    .line 3302
    .line 3303
    :goto_53
    const v0, 0xfffff

    .line 3304
    .line 3305
    .line 3306
    goto/16 :goto_56

    .line 3307
    .line 3308
    :cond_87
    move-object/from16 v12, p0

    .line 3309
    .line 3310
    iget-boolean v0, v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->f:Z

    .line 3311
    .line 3312
    if-eqz v0, :cond_88

    .line 3313
    .line 3314
    iget-object v0, v9, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->d:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w0;

    .line 3315
    .line 3316
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w0;->b:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w0;

    .line 3317
    .line 3318
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;

    .line 3319
    .line 3320
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w0;->b:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w0;

    .line 3321
    .line 3322
    if-eq v0, v1, :cond_88

    .line 3323
    .line 3324
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3325
    .line 3326
    .line 3327
    new-instance v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v0;

    .line 3328
    .line 3329
    iget-object v2, v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 3330
    .line 3331
    invoke-direct {v1, v2, v14}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v0;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;I)V

    .line 3332
    .line 3333
    .line 3334
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w0;->a:Ljava/util/Map;

    .line 3335
    .line 3336
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3337
    .line 3338
    .line 3339
    move-result-object v0

    .line 3340
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f1;

    .line 3341
    .line 3342
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->u(Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 3343
    .line 3344
    .line 3345
    move-result-object v5

    .line 3346
    move/from16 v4, p4

    .line 3347
    .line 3348
    move-object v2, v7

    .line 3349
    move-object v6, v9

    .line 3350
    move v1, v15

    .line 3351
    invoke-static/range {v1 .. v6}, Ljp/ce;->f(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 3352
    .line 3353
    .line 3354
    move-result v0

    .line 3355
    move/from16 v5, p4

    .line 3356
    .line 3357
    :goto_54
    move v4, v0

    .line 3358
    goto :goto_55

    .line 3359
    :cond_88
    move v1, v15

    .line 3360
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->u(Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 3361
    .line 3362
    .line 3363
    move-result-object v5

    .line 3364
    move-object/from16 v2, p2

    .line 3365
    .line 3366
    move/from16 v4, p4

    .line 3367
    .line 3368
    move-object/from16 v6, p6

    .line 3369
    .line 3370
    invoke-static/range {v1 .. v6}, Ljp/ce;->f(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 3371
    .line 3372
    .line 3373
    move-result v0

    .line 3374
    move v5, v4

    .line 3375
    goto :goto_54

    .line 3376
    :goto_55
    move-object/from16 v3, p2

    .line 3377
    .line 3378
    move-object/from16 v6, p6

    .line 3379
    .line 3380
    move v15, v1

    .line 3381
    move-object v2, v11

    .line 3382
    move-object v0, v12

    .line 3383
    move v7, v14

    .line 3384
    goto :goto_51

    .line 3385
    :cond_89
    move/from16 v10, p5

    .line 3386
    .line 3387
    move-object/from16 v32, v1

    .line 3388
    .line 3389
    move-object v11, v2

    .line 3390
    move/from16 v31, v9

    .line 3391
    .line 3392
    move-object/from16 v28, v12

    .line 3393
    .line 3394
    move-object/from16 v29, v13

    .line 3395
    .line 3396
    move/from16 v20, v14

    .line 3397
    .line 3398
    move-object v12, v0

    .line 3399
    goto :goto_53

    .line 3400
    :goto_56
    if-eq v9, v0, :cond_8a

    .line 3401
    .line 3402
    int-to-long v0, v9

    .line 3403
    move-object/from16 v13, v32

    .line 3404
    .line 3405
    invoke-virtual {v13, v11, v0, v1, v14}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 3406
    .line 3407
    .line 3408
    :cond_8a
    iget v0, v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->h:I

    .line 3409
    .line 3410
    :goto_57
    iget v1, v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->i:I

    .line 3411
    .line 3412
    if-ge v0, v1, :cond_8d

    .line 3413
    .line 3414
    iget-object v1, v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->g:[I

    .line 3415
    .line 3416
    aget v1, v1, v0

    .line 3417
    .line 3418
    aget v2, v28, v1

    .line 3419
    .line 3420
    invoke-virtual {v12, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->z(I)I

    .line 3421
    .line 3422
    .line 3423
    move-result v2

    .line 3424
    const v16, 0xfffff

    .line 3425
    .line 3426
    .line 3427
    and-int v2, v2, v16

    .line 3428
    .line 3429
    int-to-long v2, v2

    .line 3430
    invoke-static {v2, v3, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->h(JLjava/lang/Object;)Ljava/lang/Object;

    .line 3431
    .line 3432
    .line 3433
    move-result-object v2

    .line 3434
    if-nez v2, :cond_8b

    .line 3435
    .line 3436
    goto :goto_58

    .line 3437
    :cond_8b
    invoke-virtual {v12, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->B(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;

    .line 3438
    .line 3439
    .line 3440
    move-result-object v3

    .line 3441
    if-nez v3, :cond_8c

    .line 3442
    .line 3443
    :goto_58
    add-int/lit8 v0, v0, 0x1

    .line 3444
    .line 3445
    goto :goto_57

    .line 3446
    :cond_8c
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 3447
    .line 3448
    const/4 v7, 0x3

    .line 3449
    div-int/2addr v1, v7

    .line 3450
    add-int/2addr v1, v1

    .line 3451
    aget-object v0, v29, v1

    .line 3452
    .line 3453
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 3454
    .line 3455
    .line 3456
    move-result-object v0

    .line 3457
    throw v0

    .line 3458
    :cond_8d
    const-string v0, "Failed to parse the message."

    .line 3459
    .line 3460
    if-nez v10, :cond_8f

    .line 3461
    .line 3462
    if-ne v4, v5, :cond_8e

    .line 3463
    .line 3464
    goto :goto_59

    .line 3465
    :cond_8e
    new-instance v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 3466
    .line 3467
    invoke-direct {v1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 3468
    .line 3469
    .line 3470
    throw v1

    .line 3471
    :cond_8f
    if-gt v4, v5, :cond_90

    .line 3472
    .line 3473
    if-ne v15, v10, :cond_90

    .line 3474
    .line 3475
    :goto_59
    return v4

    .line 3476
    :cond_90
    new-instance v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 3477
    .line 3478
    invoke-direct {v1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 3479
    .line 3480
    .line 3481
    throw v1

    .line 3482
    :cond_91
    move-object v11, v2

    .line 3483
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 3484
    .line 3485
    invoke-static {v11}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 3486
    .line 3487
    .line 3488
    move-result-object v1

    .line 3489
    const-string v2, "Mutating immutable message: "

    .line 3490
    .line 3491
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 3492
    .line 3493
    .line 3494
    move-result-object v1

    .line 3495
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 3496
    .line 3497
    .line 3498
    throw v0

    .line 3499
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_9
        :pswitch_2
        :pswitch_7
        :pswitch_8
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 3500
    .line 3501
    .line 3502
    .line 3503
    .line 3504
    .line 3505
    .line 3506
    .line 3507
    .line 3508
    .line 3509
    .line 3510
    .line 3511
    .line 3512
    .line 3513
    .line 3514
    .line 3515
    .line 3516
    .line 3517
    .line 3518
    .line 3519
    .line 3520
    .line 3521
    .line 3522
    .line 3523
    .line 3524
    .line 3525
    .line 3526
    .line 3527
    .line 3528
    .line 3529
    .line 3530
    .line 3531
    .line 3532
    .line 3533
    .line 3534
    .line 3535
    .line 3536
    .line 3537
    :pswitch_data_1
    .packed-switch 0x12
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_16
        :pswitch_f
        :pswitch_14
        :pswitch_15
        :pswitch_e
        :pswitch_d
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_16
        :pswitch_f
        :pswitch_14
        :pswitch_15
        :pswitch_e
        :pswitch_d
    .end packed-switch

    .line 3538
    .line 3539
    .line 3540
    .line 3541
    .line 3542
    .line 3543
    .line 3544
    .line 3545
    .line 3546
    .line 3547
    .line 3548
    .line 3549
    .line 3550
    .line 3551
    .line 3552
    .line 3553
    .line 3554
    .line 3555
    .line 3556
    .line 3557
    .line 3558
    .line 3559
    .line 3560
    .line 3561
    .line 3562
    .line 3563
    .line 3564
    .line 3565
    .line 3566
    .line 3567
    .line 3568
    .line 3569
    .line 3570
    .line 3571
    .line 3572
    .line 3573
    .line 3574
    .line 3575
    .line 3576
    .line 3577
    .line 3578
    .line 3579
    .line 3580
    .line 3581
    .line 3582
    .line 3583
    .line 3584
    .line 3585
    .line 3586
    .line 3587
    .line 3588
    .line 3589
    .line 3590
    .line 3591
    .line 3592
    .line 3593
    .line 3594
    .line 3595
    .line 3596
    .line 3597
    .line 3598
    .line 3599
    .line 3600
    .line 3601
    .line 3602
    .line 3603
    :pswitch_data_2
    .packed-switch 0x33
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_24
        :pswitch_1d
        :pswitch_22
        :pswitch_23
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
    .end packed-switch
.end method

.method public final x(II)I
    .locals 5

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    div-int/lit8 v0, v0, 0x3

    .line 5
    .line 6
    const/4 v1, -0x1

    .line 7
    add-int/2addr v0, v1

    .line 8
    :goto_0
    if-gt p2, v0, :cond_2

    .line 9
    .line 10
    add-int v2, v0, p2

    .line 11
    .line 12
    ushr-int/lit8 v2, v2, 0x1

    .line 13
    .line 14
    mul-int/lit8 v3, v2, 0x3

    .line 15
    .line 16
    aget v4, p0, v3

    .line 17
    .line 18
    if-ne p1, v4, :cond_0

    .line 19
    .line 20
    return v3

    .line 21
    :cond_0
    if-ge p1, v4, :cond_1

    .line 22
    .line 23
    add-int/lit8 v0, v2, -0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    add-int/lit8 p2, v2, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_2
    return v1
.end method

.method public final z(I)I
    .locals 0

    .line 1
    add-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->a:[I

    .line 4
    .line 5
    aget p0, p0, p1

    .line 6
    .line 7
    return p0
.end method
