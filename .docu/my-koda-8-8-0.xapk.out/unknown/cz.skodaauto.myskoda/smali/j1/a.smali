.class public final Lj1/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvl/a;
.implements Lju/b;
.implements Ly4/i;
.implements Ll/w;
.implements Ll/j;
.implements Laq/i;
.implements Lvw0/k;
.implements Lkx0/a;
.implements Ltn/b;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lj1/a;->d:I

    packed-switch p1, :pswitch_data_0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    new-instance p1, Let/d;

    const/16 v0, 0x8

    .line 5
    invoke-direct {p1, v0}, Let/d;-><init>(I)V

    .line 6
    iput-object p1, p0, Lj1/a;->e:Ljava/lang/Object;

    return-void

    .line 7
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    new-instance p1, Lww0/a;

    invoke-direct {p1}, Lww0/a;-><init>()V

    iput-object p1, p0, Lj1/a;->e:Ljava/lang/Object;

    return-void

    .line 9
    :pswitch_1
    :try_start_0
    const-string p1, "AndroidKeyStore"

    invoke-static {p1}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    move-result-object p1

    const/4 v0, 0x0

    .line 10
    invoke-virtual {p1, v0}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    iput-object p1, p0, Lj1/a;->e:Ljava/lang/Object;

    return-void

    :catch_0
    move-exception p0

    .line 13
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    throw p1

    :pswitch_data_0
    .packed-switch 0x15
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lj1/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Leb/j0;Ljava/lang/Class;)V
    .locals 2

    const/16 v0, 0x10

    iput v0, p0, Lj1/a;->d:I

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    iget-object v0, p1, Leb/j0;->f:Ljava/lang/Object;

    check-cast v0, Ljava/util/Map;

    .line 16
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v0

    .line 17
    invoke-interface {v0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    const-class v0, Ljava/lang/Void;

    .line 18
    invoke-virtual {v0, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 20
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    .line 21
    const-string v0, "Given internalKeyMananger "

    .line 22
    const-string v1, " does not support primitive class "

    .line 23
    invoke-static {v0, p1, v1, p2}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 25
    :cond_1
    :goto_0
    iput-object p1, p0, Lj1/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lj1/a;->d:I

    iput-object p1, p0, Lj1/a;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static c(Ljava/lang/Object;)Lj1/a;
    .locals 2

    .line 1
    new-instance v0, Lj1/a;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x4

    .line 6
    invoke-direct {v0, p0, v1}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 11
    .line 12
    const-string v0, "instance cannot be null"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public static n(Ljava/lang/String;)V
    .locals 3

    .line 1
    new-instance v0, Lj1/a;

    .line 2
    .line 3
    const/16 v1, 0x15

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lj1/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lj1/a;->r(Ljava/lang/String;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    invoke-static {p0}, Lrr/f;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string v0, "AES"

    .line 19
    .line 20
    const-string v1, "AndroidKeyStore"

    .line 21
    .line 22
    invoke-static {v0, v1}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    new-instance v1, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v1, p0, v2}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    .line 30
    .line 31
    .line 32
    const/16 p0, 0x100

    .line 33
    .line 34
    invoke-virtual {v1, p0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setKeySize(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    const-string v1, "GCM"

    .line 39
    .line 40
    filled-new-array {v1}, [Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {p0, v1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setBlockModes([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    const-string v1, "NoPadding"

    .line 49
    .line 50
    filled-new-array {v1}, [Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-virtual {p0, v1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setEncryptionPaddings([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {p0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {v0, p0}, Ljavax/crypto/KeyGenerator;->init(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 70
    .line 71
    const-string v1, "cannot generate a new key "

    .line 72
    .line 73
    const-string v2, " because it already exists; please delete it with deleteKey() and try again"

    .line 74
    .line 75
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw v0
.end method

.method public static v(Lj1/a;Ljava/lang/String;)Ljava/util/ArrayList;
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    new-instance v2, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    const/4 v5, 0x0

    .line 15
    :goto_0
    const/16 v6, 0x20

    .line 16
    .line 17
    if-ge v5, v3, :cond_0

    .line 18
    .line 19
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v7

    .line 23
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->g(II)I

    .line 24
    .line 25
    .line 26
    move-result v7

    .line 27
    if-gtz v7, :cond_0

    .line 28
    .line 29
    add-int/lit8 v5, v5, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    :goto_1
    if-le v3, v5, :cond_1

    .line 33
    .line 34
    add-int/lit8 v7, v3, -0x1

    .line 35
    .line 36
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->g(II)I

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    if-gtz v7, :cond_1

    .line 45
    .line 46
    add-int/lit8 v3, v3, -0x1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    const/4 v7, 0x0

    .line 50
    :goto_2
    if-ge v5, v3, :cond_43

    .line 51
    .line 52
    :goto_3
    add-int/lit8 v8, v5, 0x1

    .line 53
    .line 54
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    or-int/lit8 v9, v5, 0x20

    .line 59
    .line 60
    add-int/lit8 v10, v9, -0x61

    .line 61
    .line 62
    add-int/lit8 v11, v9, -0x7a

    .line 63
    .line 64
    mul-int/2addr v11, v10

    .line 65
    const/16 v10, 0x65

    .line 66
    .line 67
    if-gtz v11, :cond_2

    .line 68
    .line 69
    if-eq v9, v10, :cond_2

    .line 70
    .line 71
    goto :goto_4

    .line 72
    :cond_2
    if-lt v8, v3, :cond_42

    .line 73
    .line 74
    const/4 v5, 0x0

    .line 75
    :goto_4
    if-eqz v5, :cond_41

    .line 76
    .line 77
    or-int/lit8 v9, v5, 0x20

    .line 78
    .line 79
    const/16 v12, 0x7a

    .line 80
    .line 81
    if-eq v9, v12, :cond_3a

    .line 82
    .line 83
    const/4 v7, 0x0

    .line 84
    :goto_5
    if-ge v8, v3, :cond_3

    .line 85
    .line 86
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 87
    .line 88
    .line 89
    move-result v9

    .line 90
    invoke-static {v9, v6}, Lkotlin/jvm/internal/m;->g(II)I

    .line 91
    .line 92
    .line 93
    move-result v9

    .line 94
    if-gtz v9, :cond_3

    .line 95
    .line 96
    add-int/lit8 v8, v8, 0x1

    .line 97
    .line 98
    goto :goto_5

    .line 99
    :cond_3
    const-wide v14, 0xffffffffL

    .line 100
    .line 101
    .line 102
    .line 103
    .line 104
    const/high16 v9, 0x7fc00000    # Float.NaN

    .line 105
    .line 106
    if-ne v8, v3, :cond_4

    .line 107
    .line 108
    move v12, v6

    .line 109
    move/from16 v16, v7

    .line 110
    .line 111
    int-to-long v6, v8

    .line 112
    shl-long/2addr v6, v12

    .line 113
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 114
    .line 115
    .line 116
    move-result v8

    .line 117
    int-to-long v8, v8

    .line 118
    and-long/2addr v8, v14

    .line 119
    or-long/2addr v6, v8

    .line 120
    move/from16 v32, v5

    .line 121
    .line 122
    move/from16 v19, v12

    .line 123
    .line 124
    :goto_6
    move-wide/from16 v21, v14

    .line 125
    .line 126
    const/16 v20, 0x1

    .line 127
    .line 128
    goto/16 :goto_27

    .line 129
    .line 130
    :cond_4
    move v12, v6

    .line 131
    move/from16 v16, v7

    .line 132
    .line 133
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 134
    .line 135
    .line 136
    move-result v6

    .line 137
    const/16 v7, 0x2d

    .line 138
    .line 139
    if-ne v6, v7, :cond_5

    .line 140
    .line 141
    const/16 v17, 0x1

    .line 142
    .line 143
    :goto_7
    move/from16 v18, v9

    .line 144
    .line 145
    goto :goto_8

    .line 146
    :cond_5
    const/16 v17, 0x0

    .line 147
    .line 148
    goto :goto_7

    .line 149
    :goto_8
    const/16 v9, 0x2e

    .line 150
    .line 151
    move/from16 v19, v12

    .line 152
    .line 153
    const/16 v12, 0xa

    .line 154
    .line 155
    if-eqz v17, :cond_8

    .line 156
    .line 157
    add-int/lit8 v6, v8, 0x1

    .line 158
    .line 159
    if-ne v6, v3, :cond_6

    .line 160
    .line 161
    int-to-long v6, v6

    .line 162
    shl-long v6, v6, v19

    .line 163
    .line 164
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    int-to-long v8, v8

    .line 169
    and-long/2addr v8, v14

    .line 170
    or-long/2addr v6, v8

    .line 171
    move/from16 v32, v5

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_6
    const/16 v20, 0x1

    .line 175
    .line 176
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 177
    .line 178
    .line 179
    move-result v13

    .line 180
    move-wide/from16 v21, v14

    .line 181
    .line 182
    add-int/lit8 v14, v13, -0x30

    .line 183
    .line 184
    int-to-char v14, v14

    .line 185
    if-ge v14, v12, :cond_7

    .line 186
    .line 187
    goto :goto_a

    .line 188
    :cond_7
    if-eq v13, v9, :cond_9

    .line 189
    .line 190
    int-to-long v6, v6

    .line 191
    shl-long v6, v6, v19

    .line 192
    .line 193
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 194
    .line 195
    .line 196
    move-result v8

    .line 197
    int-to-long v8, v8

    .line 198
    :goto_9
    and-long v8, v8, v21

    .line 199
    .line 200
    or-long/2addr v6, v8

    .line 201
    move/from16 v32, v5

    .line 202
    .line 203
    goto/16 :goto_27

    .line 204
    .line 205
    :cond_8
    move-wide/from16 v21, v14

    .line 206
    .line 207
    const/16 v20, 0x1

    .line 208
    .line 209
    move v13, v6

    .line 210
    move v6, v8

    .line 211
    :cond_9
    :goto_a
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 212
    .line 213
    .line 214
    move-result v14

    .line 215
    const-wide/16 v23, 0x0

    .line 216
    .line 217
    move v15, v6

    .line 218
    move-wide/from16 v25, v23

    .line 219
    .line 220
    :goto_b
    const-wide/16 v27, 0xa

    .line 221
    .line 222
    if-eq v15, v3, :cond_b

    .line 223
    .line 224
    add-int/lit8 v11, v13, -0x30

    .line 225
    .line 226
    int-to-char v4, v11

    .line 227
    if-ge v4, v12, :cond_b

    .line 228
    .line 229
    mul-long v25, v25, v27

    .line 230
    .line 231
    move v4, v8

    .line 232
    int-to-long v7, v11

    .line 233
    add-long v25, v25, v7

    .line 234
    .line 235
    add-int/lit8 v15, v15, 0x1

    .line 236
    .line 237
    if-ge v15, v14, :cond_a

    .line 238
    .line 239
    invoke-virtual {v1, v15}, Ljava/lang/String;->charAt(I)C

    .line 240
    .line 241
    .line 242
    move-result v7

    .line 243
    move v13, v7

    .line 244
    goto :goto_c

    .line 245
    :cond_a
    const/4 v13, 0x0

    .line 246
    :goto_c
    move v8, v4

    .line 247
    const/16 v7, 0x2d

    .line 248
    .line 249
    goto :goto_b

    .line 250
    :cond_b
    move v4, v8

    .line 251
    sub-int v7, v15, v6

    .line 252
    .line 253
    if-eq v15, v3, :cond_12

    .line 254
    .line 255
    if-ne v13, v9, :cond_12

    .line 256
    .line 257
    add-int/lit8 v13, v15, 0x1

    .line 258
    .line 259
    move v8, v13

    .line 260
    const/16 v31, 0x10

    .line 261
    .line 262
    :goto_d
    sub-int v9, v3, v8

    .line 263
    .line 264
    const/16 v33, 0x30

    .line 265
    .line 266
    const/4 v11, 0x4

    .line 267
    if-lt v9, v11, :cond_d

    .line 268
    .line 269
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 270
    .line 271
    .line 272
    move-result v9

    .line 273
    int-to-long v10, v9

    .line 274
    add-int/lit8 v9, v8, 0x1

    .line 275
    .line 276
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 277
    .line 278
    .line 279
    move-result v9

    .line 280
    move/from16 v35, v13

    .line 281
    .line 282
    int-to-long v12, v9

    .line 283
    shl-long v12, v12, v31

    .line 284
    .line 285
    or-long v9, v10, v12

    .line 286
    .line 287
    add-int/lit8 v11, v8, 0x2

    .line 288
    .line 289
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 290
    .line 291
    .line 292
    move-result v11

    .line 293
    int-to-long v11, v11

    .line 294
    shl-long v11, v11, v19

    .line 295
    .line 296
    or-long/2addr v9, v11

    .line 297
    add-int/lit8 v11, v8, 0x3

    .line 298
    .line 299
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 300
    .line 301
    .line 302
    move-result v11

    .line 303
    int-to-long v11, v11

    .line 304
    shl-long v11, v11, v33

    .line 305
    .line 306
    or-long/2addr v9, v11

    .line 307
    const-wide v11, 0x30003000300030L

    .line 308
    .line 309
    .line 310
    .line 311
    .line 312
    sub-long v11, v9, v11

    .line 313
    .line 314
    const-wide v36, 0x46004600460046L    # 2.447700077935472E-307

    .line 315
    .line 316
    .line 317
    .line 318
    .line 319
    add-long v9, v9, v36

    .line 320
    .line 321
    or-long/2addr v9, v11

    .line 322
    const-wide v36, -0x7f007f007f0080L

    .line 323
    .line 324
    .line 325
    .line 326
    .line 327
    and-long v9, v9, v36

    .line 328
    .line 329
    cmp-long v9, v9, v23

    .line 330
    .line 331
    if-eqz v9, :cond_c

    .line 332
    .line 333
    const/4 v9, -0x1

    .line 334
    goto :goto_e

    .line 335
    :cond_c
    const-wide v9, 0x3e80064000a0001L

    .line 336
    .line 337
    .line 338
    .line 339
    .line 340
    mul-long/2addr v11, v9

    .line 341
    ushr-long v9, v11, v33

    .line 342
    .line 343
    long-to-int v9, v9

    .line 344
    :goto_e
    if-ltz v9, :cond_e

    .line 345
    .line 346
    const-wide/16 v10, 0x2710

    .line 347
    .line 348
    mul-long v25, v25, v10

    .line 349
    .line 350
    int-to-long v9, v9

    .line 351
    add-long v25, v25, v9

    .line 352
    .line 353
    add-int/lit8 v8, v8, 0x4

    .line 354
    .line 355
    move/from16 v13, v35

    .line 356
    .line 357
    const/16 v10, 0x65

    .line 358
    .line 359
    const/16 v12, 0xa

    .line 360
    .line 361
    goto :goto_d

    .line 362
    :cond_d
    move/from16 v35, v13

    .line 363
    .line 364
    :cond_e
    if-ge v8, v14, :cond_f

    .line 365
    .line 366
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 367
    .line 368
    .line 369
    move-result v9

    .line 370
    goto :goto_f

    .line 371
    :cond_f
    const/4 v9, 0x0

    .line 372
    :goto_f
    move v13, v9

    .line 373
    :goto_10
    if-eq v8, v3, :cond_11

    .line 374
    .line 375
    add-int/lit8 v9, v13, -0x30

    .line 376
    .line 377
    int-to-char v10, v9

    .line 378
    const/16 v11, 0xa

    .line 379
    .line 380
    if-ge v10, v11, :cond_11

    .line 381
    .line 382
    mul-long v25, v25, v27

    .line 383
    .line 384
    int-to-long v9, v9

    .line 385
    add-long v25, v25, v9

    .line 386
    .line 387
    add-int/lit8 v8, v8, 0x1

    .line 388
    .line 389
    if-ge v8, v14, :cond_10

    .line 390
    .line 391
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 392
    .line 393
    .line 394
    move-result v9

    .line 395
    goto :goto_f

    .line 396
    :cond_10
    const/4 v13, 0x0

    .line 397
    goto :goto_10

    .line 398
    :cond_11
    sub-int v9, v35, v8

    .line 399
    .line 400
    sub-int/2addr v7, v9

    .line 401
    move v10, v9

    .line 402
    move/from16 v9, v35

    .line 403
    .line 404
    goto :goto_11

    .line 405
    :cond_12
    const/16 v31, 0x10

    .line 406
    .line 407
    const/16 v33, 0x30

    .line 408
    .line 409
    move v8, v15

    .line 410
    move v9, v8

    .line 411
    const/4 v10, 0x0

    .line 412
    :goto_11
    if-nez v7, :cond_13

    .line 413
    .line 414
    int-to-long v6, v8

    .line 415
    shl-long v6, v6, v19

    .line 416
    .line 417
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 418
    .line 419
    .line 420
    move-result v4

    .line 421
    int-to-long v8, v4

    .line 422
    goto/16 :goto_9

    .line 423
    .line 424
    :cond_13
    or-int/lit8 v11, v13, 0x20

    .line 425
    .line 426
    const/16 v13, 0x65

    .line 427
    .line 428
    if-ne v11, v13, :cond_1d

    .line 429
    .line 430
    add-int/lit8 v11, v8, 0x1

    .line 431
    .line 432
    if-ge v11, v14, :cond_14

    .line 433
    .line 434
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 435
    .line 436
    .line 437
    move-result v18

    .line 438
    move/from16 v13, v18

    .line 439
    .line 440
    :goto_12
    const/16 v12, 0x2d

    .line 441
    .line 442
    goto :goto_13

    .line 443
    :cond_14
    const/4 v13, 0x0

    .line 444
    goto :goto_12

    .line 445
    :goto_13
    if-ne v13, v12, :cond_15

    .line 446
    .line 447
    move/from16 v12, v20

    .line 448
    .line 449
    goto :goto_14

    .line 450
    :cond_15
    const/4 v12, 0x0

    .line 451
    :goto_14
    move/from16 v30, v4

    .line 452
    .line 453
    if-nez v12, :cond_16

    .line 454
    .line 455
    const/16 v4, 0x2b

    .line 456
    .line 457
    if-ne v13, v4, :cond_17

    .line 458
    .line 459
    :cond_16
    add-int/lit8 v11, v8, 0x2

    .line 460
    .line 461
    :cond_17
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 462
    .line 463
    .line 464
    move-result v4

    .line 465
    const/4 v13, 0x0

    .line 466
    :goto_15
    if-eq v11, v3, :cond_1a

    .line 467
    .line 468
    add-int/lit8 v4, v4, -0x30

    .line 469
    .line 470
    move/from16 v35, v10

    .line 471
    .line 472
    int-to-char v10, v4

    .line 473
    move/from16 v36, v4

    .line 474
    .line 475
    const/16 v4, 0xa

    .line 476
    .line 477
    if-ge v10, v4, :cond_1b

    .line 478
    .line 479
    const/16 v10, 0x400

    .line 480
    .line 481
    if-ge v13, v10, :cond_18

    .line 482
    .line 483
    mul-int/lit8 v13, v13, 0xa

    .line 484
    .line 485
    add-int v13, v13, v36

    .line 486
    .line 487
    :cond_18
    add-int/lit8 v11, v11, 0x1

    .line 488
    .line 489
    if-ge v11, v14, :cond_19

    .line 490
    .line 491
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 492
    .line 493
    .line 494
    move-result v10

    .line 495
    goto :goto_16

    .line 496
    :cond_19
    const/4 v10, 0x0

    .line 497
    :goto_16
    move v4, v10

    .line 498
    move/from16 v10, v35

    .line 499
    .line 500
    goto :goto_15

    .line 501
    :cond_1a
    move/from16 v35, v10

    .line 502
    .line 503
    :cond_1b
    if-eqz v12, :cond_1c

    .line 504
    .line 505
    neg-int v4, v13

    .line 506
    goto :goto_17

    .line 507
    :cond_1c
    move v4, v13

    .line 508
    :goto_17
    add-int v10, v35, v4

    .line 509
    .line 510
    goto :goto_18

    .line 511
    :cond_1d
    move/from16 v30, v4

    .line 512
    .line 513
    move/from16 v35, v10

    .line 514
    .line 515
    move v11, v8

    .line 516
    const/4 v4, 0x0

    .line 517
    :goto_18
    const/16 v12, 0x13

    .line 518
    .line 519
    if-le v7, v12, :cond_28

    .line 520
    .line 521
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 522
    .line 523
    .line 524
    move-result v13

    .line 525
    move/from16 v34, v6

    .line 526
    .line 527
    :goto_19
    if-eq v11, v3, :cond_22

    .line 528
    .line 529
    move/from16 v12, v33

    .line 530
    .line 531
    if-eq v13, v12, :cond_1e

    .line 532
    .line 533
    const/16 v12, 0x2e

    .line 534
    .line 535
    if-ne v13, v12, :cond_1f

    .line 536
    .line 537
    :cond_1e
    const/16 v12, 0x30

    .line 538
    .line 539
    goto :goto_1a

    .line 540
    :cond_1f
    const/16 v12, 0x13

    .line 541
    .line 542
    goto :goto_1c

    .line 543
    :goto_1a
    if-ne v13, v12, :cond_20

    .line 544
    .line 545
    add-int/lit8 v7, v7, -0x1

    .line 546
    .line 547
    :cond_20
    add-int/lit8 v12, v34, 0x1

    .line 548
    .line 549
    if-ge v12, v14, :cond_21

    .line 550
    .line 551
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 552
    .line 553
    .line 554
    move-result v13

    .line 555
    goto :goto_1b

    .line 556
    :cond_21
    const/4 v13, 0x0

    .line 557
    :goto_1b
    move/from16 v34, v12

    .line 558
    .line 559
    const/16 v12, 0x13

    .line 560
    .line 561
    const/16 v33, 0x30

    .line 562
    .line 563
    goto :goto_19

    .line 564
    :cond_22
    :goto_1c
    if-le v7, v12, :cond_28

    .line 565
    .line 566
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 567
    .line 568
    .line 569
    move-result v7

    .line 570
    move/from16 v34, v4

    .line 571
    .line 572
    move/from16 v32, v5

    .line 573
    .line 574
    move-wide/from16 v12, v23

    .line 575
    .line 576
    :goto_1d
    const-wide v4, 0xde0b6b3a7640000L

    .line 577
    .line 578
    .line 579
    .line 580
    .line 581
    if-eq v6, v15, :cond_24

    .line 582
    .line 583
    invoke-static {v12, v13, v4, v5}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 584
    .line 585
    .line 586
    move-result v10

    .line 587
    if-gez v10, :cond_24

    .line 588
    .line 589
    mul-long v12, v12, v27

    .line 590
    .line 591
    const/16 v33, 0x30

    .line 592
    .line 593
    add-int/lit8 v7, v7, -0x30

    .line 594
    .line 595
    int-to-long v4, v7

    .line 596
    add-long/2addr v12, v4

    .line 597
    add-int/lit8 v6, v6, 0x1

    .line 598
    .line 599
    if-ge v6, v14, :cond_23

    .line 600
    .line 601
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 602
    .line 603
    .line 604
    move-result v4

    .line 605
    move v7, v4

    .line 606
    goto :goto_1d

    .line 607
    :cond_23
    const/4 v7, 0x0

    .line 608
    goto :goto_1d

    .line 609
    :cond_24
    invoke-static {v12, v13, v4, v5}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 610
    .line 611
    .line 612
    move-result v7

    .line 613
    if-ltz v7, :cond_25

    .line 614
    .line 615
    sub-int/2addr v15, v6

    .line 616
    add-int v10, v15, v34

    .line 617
    .line 618
    :goto_1e
    move/from16 v4, v20

    .line 619
    .line 620
    goto :goto_21

    .line 621
    :cond_25
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 622
    .line 623
    .line 624
    move-result v6

    .line 625
    move v7, v9

    .line 626
    :goto_1f
    if-eq v7, v8, :cond_27

    .line 627
    .line 628
    invoke-static {v12, v13, v4, v5}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 629
    .line 630
    .line 631
    move-result v10

    .line 632
    if-gez v10, :cond_27

    .line 633
    .line 634
    mul-long v12, v12, v27

    .line 635
    .line 636
    const/16 v33, 0x30

    .line 637
    .line 638
    add-int/lit8 v6, v6, -0x30

    .line 639
    .line 640
    int-to-long v4, v6

    .line 641
    add-long/2addr v12, v4

    .line 642
    add-int/lit8 v7, v7, 0x1

    .line 643
    .line 644
    if-ge v7, v14, :cond_26

    .line 645
    .line 646
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 647
    .line 648
    .line 649
    move-result v4

    .line 650
    move v6, v4

    .line 651
    goto :goto_20

    .line 652
    :cond_26
    const/4 v6, 0x0

    .line 653
    :goto_20
    const-wide v4, 0xde0b6b3a7640000L

    .line 654
    .line 655
    .line 656
    .line 657
    .line 658
    goto :goto_1f

    .line 659
    :cond_27
    sub-int/2addr v9, v7

    .line 660
    add-int v10, v9, v34

    .line 661
    .line 662
    goto :goto_1e

    .line 663
    :cond_28
    move/from16 v32, v5

    .line 664
    .line 665
    move-wide/from16 v12, v25

    .line 666
    .line 667
    const/4 v4, 0x0

    .line 668
    :goto_21
    const/16 v5, -0xa

    .line 669
    .line 670
    if-gt v5, v10, :cond_2b

    .line 671
    .line 672
    const/16 v5, 0xb

    .line 673
    .line 674
    if-ge v10, v5, :cond_2b

    .line 675
    .line 676
    if-nez v4, :cond_2b

    .line 677
    .line 678
    const-wide/32 v4, 0x1000000

    .line 679
    .line 680
    .line 681
    invoke-static {v12, v13, v4, v5}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 682
    .line 683
    .line 684
    move-result v4

    .line 685
    if-gtz v4, :cond_2b

    .line 686
    .line 687
    long-to-float v4, v12

    .line 688
    sget-object v5, Lj3/b;->a:[F

    .line 689
    .line 690
    if-gez v10, :cond_29

    .line 691
    .line 692
    neg-int v6, v10

    .line 693
    aget v5, v5, v6

    .line 694
    .line 695
    div-float/2addr v4, v5

    .line 696
    goto :goto_22

    .line 697
    :cond_29
    aget v5, v5, v10

    .line 698
    .line 699
    mul-float/2addr v4, v5

    .line 700
    :goto_22
    if-eqz v17, :cond_2a

    .line 701
    .line 702
    neg-float v4, v4

    .line 703
    :cond_2a
    int-to-long v5, v11

    .line 704
    shl-long v5, v5, v19

    .line 705
    .line 706
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 707
    .line 708
    .line 709
    move-result v4

    .line 710
    :goto_23
    int-to-long v7, v4

    .line 711
    and-long v7, v7, v21

    .line 712
    .line 713
    or-long v6, v5, v7

    .line 714
    .line 715
    goto/16 :goto_27

    .line 716
    .line 717
    :cond_2b
    cmp-long v4, v12, v23

    .line 718
    .line 719
    if-nez v4, :cond_2d

    .line 720
    .line 721
    if-eqz v17, :cond_2c

    .line 722
    .line 723
    const/high16 v4, -0x80000000

    .line 724
    .line 725
    goto :goto_24

    .line 726
    :cond_2c
    const/4 v4, 0x0

    .line 727
    :goto_24
    int-to-long v5, v11

    .line 728
    shl-long v5, v5, v19

    .line 729
    .line 730
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 731
    .line 732
    .line 733
    move-result v4

    .line 734
    goto :goto_23

    .line 735
    :cond_2d
    const/16 v4, -0x7e

    .line 736
    .line 737
    const-string v5, "substring(...)"

    .line 738
    .line 739
    if-gt v4, v10, :cond_34

    .line 740
    .line 741
    const/16 v4, 0x80

    .line 742
    .line 743
    if-ge v10, v4, :cond_34

    .line 744
    .line 745
    add-int/lit16 v4, v10, 0x145

    .line 746
    .line 747
    sget-object v6, Lj3/b;->b:[J

    .line 748
    .line 749
    aget-wide v6, v6, v4

    .line 750
    .line 751
    invoke-static {v12, v13}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    .line 752
    .line 753
    .line 754
    move-result v4

    .line 755
    shl-long v8, v12, v4

    .line 756
    .line 757
    and-long v12, v8, v21

    .line 758
    .line 759
    ushr-long v8, v8, v19

    .line 760
    .line 761
    and-long v14, v6, v21

    .line 762
    .line 763
    ushr-long v6, v6, v19

    .line 764
    .line 765
    mul-long v25, v8, v6

    .line 766
    .line 767
    mul-long/2addr v6, v12

    .line 768
    mul-long/2addr v8, v14

    .line 769
    mul-long/2addr v12, v14

    .line 770
    ushr-long v12, v12, v19

    .line 771
    .line 772
    add-long/2addr v8, v12

    .line 773
    and-long v12, v6, v21

    .line 774
    .line 775
    add-long/2addr v8, v12

    .line 776
    ushr-long v8, v8, v19

    .line 777
    .line 778
    add-long v25, v25, v8

    .line 779
    .line 780
    ushr-long v6, v6, v19

    .line 781
    .line 782
    add-long v25, v25, v6

    .line 783
    .line 784
    const/16 v6, 0x3f

    .line 785
    .line 786
    ushr-long v7, v25, v6

    .line 787
    .line 788
    long-to-int v7, v7

    .line 789
    add-int/lit8 v8, v7, 0x9

    .line 790
    .line 791
    ushr-long v8, v25, v8

    .line 792
    .line 793
    xor-int/lit8 v7, v7, 0x1

    .line 794
    .line 795
    add-int/2addr v4, v7

    .line 796
    const-wide/16 v12, 0x1ff

    .line 797
    .line 798
    and-long v14, v25, v12

    .line 799
    .line 800
    cmp-long v7, v14, v12

    .line 801
    .line 802
    if-eqz v7, :cond_2e

    .line 803
    .line 804
    cmp-long v7, v14, v23

    .line 805
    .line 806
    const-wide/16 v12, 0x1

    .line 807
    .line 808
    if-nez v7, :cond_2f

    .line 809
    .line 810
    const-wide/16 v14, 0x3

    .line 811
    .line 812
    and-long/2addr v14, v8

    .line 813
    cmp-long v7, v14, v12

    .line 814
    .line 815
    if-nez v7, :cond_2f

    .line 816
    .line 817
    :cond_2e
    move/from16 v4, v30

    .line 818
    .line 819
    goto :goto_26

    .line 820
    :cond_2f
    add-long/2addr v8, v12

    .line 821
    ushr-long v7, v8, v20

    .line 822
    .line 823
    const-wide/high16 v14, 0x20000000000000L

    .line 824
    .line 825
    cmp-long v9, v7, v14

    .line 826
    .line 827
    if-ltz v9, :cond_30

    .line 828
    .line 829
    add-int/lit8 v4, v4, -0x1

    .line 830
    .line 831
    const-wide/high16 v7, 0x10000000000000L

    .line 832
    .line 833
    :cond_30
    const-wide v14, -0x10000000000001L

    .line 834
    .line 835
    .line 836
    .line 837
    .line 838
    and-long/2addr v7, v14

    .line 839
    const-wide/32 v14, 0x3526a

    .line 840
    .line 841
    .line 842
    int-to-long v9, v10

    .line 843
    mul-long/2addr v9, v14

    .line 844
    shr-long v9, v9, v31

    .line 845
    .line 846
    const/16 v14, 0x400

    .line 847
    .line 848
    int-to-long v14, v14

    .line 849
    add-long/2addr v9, v14

    .line 850
    int-to-long v14, v6

    .line 851
    add-long/2addr v9, v14

    .line 852
    int-to-long v14, v4

    .line 853
    sub-long/2addr v9, v14

    .line 854
    cmp-long v4, v9, v12

    .line 855
    .line 856
    if-ltz v4, :cond_31

    .line 857
    .line 858
    const-wide/16 v12, 0x7fe

    .line 859
    .line 860
    cmp-long v4, v9, v12

    .line 861
    .line 862
    if-lez v4, :cond_32

    .line 863
    .line 864
    :cond_31
    move/from16 v4, v30

    .line 865
    .line 866
    goto :goto_25

    .line 867
    :cond_32
    const/16 v4, 0x34

    .line 868
    .line 869
    shl-long v4, v9, v4

    .line 870
    .line 871
    or-long/2addr v4, v7

    .line 872
    if-eqz v17, :cond_33

    .line 873
    .line 874
    const-wide/high16 v23, -0x8000000000000000L

    .line 875
    .line 876
    :cond_33
    or-long v4, v4, v23

    .line 877
    .line 878
    invoke-static {v4, v5}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 879
    .line 880
    .line 881
    move-result-wide v4

    .line 882
    double-to-float v4, v4

    .line 883
    int-to-long v5, v11

    .line 884
    shl-long v5, v5, v19

    .line 885
    .line 886
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 887
    .line 888
    .line 889
    move-result v4

    .line 890
    goto/16 :goto_23

    .line 891
    .line 892
    :goto_25
    invoke-virtual {v1, v4, v11}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 893
    .line 894
    .line 895
    move-result-object v4

    .line 896
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 897
    .line 898
    .line 899
    invoke-static {v4}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 900
    .line 901
    .line 902
    move-result v4

    .line 903
    int-to-long v5, v11

    .line 904
    shl-long v5, v5, v19

    .line 905
    .line 906
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 907
    .line 908
    .line 909
    move-result v4

    .line 910
    goto/16 :goto_23

    .line 911
    .line 912
    :goto_26
    invoke-virtual {v1, v4, v11}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 913
    .line 914
    .line 915
    move-result-object v4

    .line 916
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 917
    .line 918
    .line 919
    invoke-static {v4}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 920
    .line 921
    .line 922
    move-result v4

    .line 923
    int-to-long v5, v11

    .line 924
    shl-long v5, v5, v19

    .line 925
    .line 926
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 927
    .line 928
    .line 929
    move-result v4

    .line 930
    goto/16 :goto_23

    .line 931
    .line 932
    :cond_34
    move/from16 v4, v30

    .line 933
    .line 934
    invoke-virtual {v1, v4, v11}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 935
    .line 936
    .line 937
    move-result-object v4

    .line 938
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 939
    .line 940
    .line 941
    invoke-static {v4}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 942
    .line 943
    .line 944
    move-result v4

    .line 945
    int-to-long v5, v11

    .line 946
    shl-long v5, v5, v19

    .line 947
    .line 948
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 949
    .line 950
    .line 951
    move-result v4

    .line 952
    goto/16 :goto_23

    .line 953
    .line 954
    :goto_27
    ushr-long v4, v6, v19

    .line 955
    .line 956
    long-to-int v4, v4

    .line 957
    and-long v5, v6, v21

    .line 958
    .line 959
    long-to-int v5, v5

    .line 960
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 961
    .line 962
    .line 963
    move-result v5

    .line 964
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 965
    .line 966
    .line 967
    move-result v6

    .line 968
    if-nez v6, :cond_36

    .line 969
    .line 970
    iget-object v6, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 971
    .line 972
    check-cast v6, [F

    .line 973
    .line 974
    add-int/lit8 v7, v16, 0x1

    .line 975
    .line 976
    aput v5, v6, v16

    .line 977
    .line 978
    array-length v8, v6

    .line 979
    if-lt v7, v8, :cond_35

    .line 980
    .line 981
    mul-int/lit8 v8, v7, 0x2

    .line 982
    .line 983
    new-array v8, v8, [F

    .line 984
    .line 985
    iput-object v8, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 986
    .line 987
    array-length v9, v6

    .line 988
    const/4 v10, 0x0

    .line 989
    invoke-static {v6, v10, v8, v10, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 990
    .line 991
    .line 992
    :cond_35
    move v8, v4

    .line 993
    goto :goto_28

    .line 994
    :cond_36
    move v8, v4

    .line 995
    move/from16 v7, v16

    .line 996
    .line 997
    :goto_28
    if-ge v8, v3, :cond_37

    .line 998
    .line 999
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 1000
    .line 1001
    .line 1002
    move-result v4

    .line 1003
    const/16 v6, 0x2c

    .line 1004
    .line 1005
    if-ne v4, v6, :cond_37

    .line 1006
    .line 1007
    add-int/lit8 v8, v8, 0x1

    .line 1008
    .line 1009
    goto :goto_28

    .line 1010
    :cond_37
    if-ge v8, v3, :cond_39

    .line 1011
    .line 1012
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 1013
    .line 1014
    .line 1015
    move-result v4

    .line 1016
    if-eqz v4, :cond_38

    .line 1017
    .line 1018
    goto :goto_29

    .line 1019
    :cond_38
    move/from16 v6, v19

    .line 1020
    .line 1021
    move/from16 v5, v32

    .line 1022
    .line 1023
    const/16 v10, 0x65

    .line 1024
    .line 1025
    goto/16 :goto_5

    .line 1026
    .line 1027
    :cond_39
    :goto_29
    move v5, v8

    .line 1028
    goto :goto_2a

    .line 1029
    :cond_3a
    move/from16 v32, v5

    .line 1030
    .line 1031
    move/from16 v19, v6

    .line 1032
    .line 1033
    const/16 v20, 0x1

    .line 1034
    .line 1035
    goto :goto_29

    .line 1036
    :goto_2a
    iget-object v4, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 1037
    .line 1038
    check-cast v4, [F

    .line 1039
    .line 1040
    const/4 v6, 0x2

    .line 1041
    sparse-switch v32, :sswitch_data_0

    .line 1042
    .line 1043
    .line 1044
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1045
    .line 1046
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1047
    .line 1048
    const-string v2, "Unknown command for: "

    .line 1049
    .line 1050
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1051
    .line 1052
    .line 1053
    move/from16 v4, v32

    .line 1054
    .line 1055
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 1056
    .line 1057
    .line 1058
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v1

    .line 1062
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1063
    .line 1064
    .line 1065
    throw v0

    .line 1066
    :sswitch_0
    add-int/lit8 v6, v7, -0x1

    .line 1067
    .line 1068
    const/4 v8, 0x0

    .line 1069
    :goto_2b
    if-gt v8, v6, :cond_3d

    .line 1070
    .line 1071
    new-instance v9, Lj3/z;

    .line 1072
    .line 1073
    aget v10, v4, v8

    .line 1074
    .line 1075
    invoke-direct {v9, v10}, Lj3/z;-><init>(F)V

    .line 1076
    .line 1077
    .line 1078
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1079
    .line 1080
    .line 1081
    add-int/lit8 v8, v8, 0x1

    .line 1082
    .line 1083
    goto :goto_2b

    .line 1084
    :sswitch_1
    add-int/lit8 v6, v7, -0x2

    .line 1085
    .line 1086
    const/4 v8, 0x0

    .line 1087
    :goto_2c
    if-gt v8, v6, :cond_3d

    .line 1088
    .line 1089
    new-instance v9, Lj3/y;

    .line 1090
    .line 1091
    aget v10, v4, v8

    .line 1092
    .line 1093
    add-int/lit8 v11, v8, 0x1

    .line 1094
    .line 1095
    aget v11, v4, v11

    .line 1096
    .line 1097
    invoke-direct {v9, v10, v11}, Lj3/y;-><init>(FF)V

    .line 1098
    .line 1099
    .line 1100
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1101
    .line 1102
    .line 1103
    add-int/lit8 v8, v8, 0x2

    .line 1104
    .line 1105
    goto :goto_2c

    .line 1106
    :sswitch_2
    add-int/lit8 v6, v7, -0x4

    .line 1107
    .line 1108
    const/4 v8, 0x0

    .line 1109
    :goto_2d
    if-gt v8, v6, :cond_3d

    .line 1110
    .line 1111
    new-instance v9, Lj3/x;

    .line 1112
    .line 1113
    aget v10, v4, v8

    .line 1114
    .line 1115
    add-int/lit8 v11, v8, 0x1

    .line 1116
    .line 1117
    aget v11, v4, v11

    .line 1118
    .line 1119
    add-int/lit8 v12, v8, 0x2

    .line 1120
    .line 1121
    aget v12, v4, v12

    .line 1122
    .line 1123
    add-int/lit8 v13, v8, 0x3

    .line 1124
    .line 1125
    aget v13, v4, v13

    .line 1126
    .line 1127
    invoke-direct {v9, v10, v11, v12, v13}, Lj3/x;-><init>(FFFF)V

    .line 1128
    .line 1129
    .line 1130
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1131
    .line 1132
    .line 1133
    add-int/lit8 v8, v8, 0x4

    .line 1134
    .line 1135
    goto :goto_2d

    .line 1136
    :sswitch_3
    add-int/lit8 v6, v7, -0x4

    .line 1137
    .line 1138
    const/4 v8, 0x0

    .line 1139
    :goto_2e
    if-gt v8, v6, :cond_3d

    .line 1140
    .line 1141
    new-instance v9, Lj3/w;

    .line 1142
    .line 1143
    aget v10, v4, v8

    .line 1144
    .line 1145
    add-int/lit8 v11, v8, 0x1

    .line 1146
    .line 1147
    aget v11, v4, v11

    .line 1148
    .line 1149
    add-int/lit8 v12, v8, 0x2

    .line 1150
    .line 1151
    aget v12, v4, v12

    .line 1152
    .line 1153
    add-int/lit8 v13, v8, 0x3

    .line 1154
    .line 1155
    aget v13, v4, v13

    .line 1156
    .line 1157
    invoke-direct {v9, v10, v11, v12, v13}, Lj3/w;-><init>(FFFF)V

    .line 1158
    .line 1159
    .line 1160
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1161
    .line 1162
    .line 1163
    add-int/lit8 v8, v8, 0x4

    .line 1164
    .line 1165
    goto :goto_2e

    .line 1166
    :sswitch_4
    add-int/lit8 v8, v7, -0x2

    .line 1167
    .line 1168
    if-ltz v8, :cond_3d

    .line 1169
    .line 1170
    new-instance v9, Lj3/v;

    .line 1171
    .line 1172
    const/16 v29, 0x0

    .line 1173
    .line 1174
    aget v10, v4, v29

    .line 1175
    .line 1176
    aget v11, v4, v20

    .line 1177
    .line 1178
    invoke-direct {v9, v10, v11}, Lj3/v;-><init>(FF)V

    .line 1179
    .line 1180
    .line 1181
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1182
    .line 1183
    .line 1184
    :goto_2f
    if-gt v6, v8, :cond_3d

    .line 1185
    .line 1186
    new-instance v9, Lj3/u;

    .line 1187
    .line 1188
    aget v10, v4, v6

    .line 1189
    .line 1190
    add-int/lit8 v11, v6, 0x1

    .line 1191
    .line 1192
    aget v11, v4, v11

    .line 1193
    .line 1194
    invoke-direct {v9, v10, v11}, Lj3/u;-><init>(FF)V

    .line 1195
    .line 1196
    .line 1197
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1198
    .line 1199
    .line 1200
    add-int/lit8 v6, v6, 0x2

    .line 1201
    .line 1202
    goto :goto_2f

    .line 1203
    :sswitch_5
    add-int/lit8 v6, v7, -0x2

    .line 1204
    .line 1205
    const/4 v10, 0x0

    .line 1206
    :goto_30
    if-gt v10, v6, :cond_3d

    .line 1207
    .line 1208
    new-instance v8, Lj3/u;

    .line 1209
    .line 1210
    aget v9, v4, v10

    .line 1211
    .line 1212
    add-int/lit8 v11, v10, 0x1

    .line 1213
    .line 1214
    aget v11, v4, v11

    .line 1215
    .line 1216
    invoke-direct {v8, v9, v11}, Lj3/u;-><init>(FF)V

    .line 1217
    .line 1218
    .line 1219
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1220
    .line 1221
    .line 1222
    add-int/lit8 v10, v10, 0x2

    .line 1223
    .line 1224
    goto :goto_30

    .line 1225
    :sswitch_6
    add-int/lit8 v6, v7, -0x1

    .line 1226
    .line 1227
    const/4 v10, 0x0

    .line 1228
    :goto_31
    if-gt v10, v6, :cond_3d

    .line 1229
    .line 1230
    new-instance v8, Lj3/t;

    .line 1231
    .line 1232
    aget v9, v4, v10

    .line 1233
    .line 1234
    invoke-direct {v8, v9}, Lj3/t;-><init>(F)V

    .line 1235
    .line 1236
    .line 1237
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1238
    .line 1239
    .line 1240
    add-int/lit8 v10, v10, 0x1

    .line 1241
    .line 1242
    goto :goto_31

    .line 1243
    :sswitch_7
    add-int/lit8 v6, v7, -0x6

    .line 1244
    .line 1245
    const/4 v10, 0x0

    .line 1246
    :goto_32
    if-gt v10, v6, :cond_3d

    .line 1247
    .line 1248
    new-instance v11, Lj3/s;

    .line 1249
    .line 1250
    aget v12, v4, v10

    .line 1251
    .line 1252
    add-int/lit8 v8, v10, 0x1

    .line 1253
    .line 1254
    aget v13, v4, v8

    .line 1255
    .line 1256
    add-int/lit8 v8, v10, 0x2

    .line 1257
    .line 1258
    aget v14, v4, v8

    .line 1259
    .line 1260
    add-int/lit8 v8, v10, 0x3

    .line 1261
    .line 1262
    aget v15, v4, v8

    .line 1263
    .line 1264
    add-int/lit8 v8, v10, 0x4

    .line 1265
    .line 1266
    aget v16, v4, v8

    .line 1267
    .line 1268
    add-int/lit8 v8, v10, 0x5

    .line 1269
    .line 1270
    aget v17, v4, v8

    .line 1271
    .line 1272
    invoke-direct/range {v11 .. v17}, Lj3/s;-><init>(FFFFFF)V

    .line 1273
    .line 1274
    .line 1275
    invoke-interface {v2, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1276
    .line 1277
    .line 1278
    add-int/lit8 v10, v10, 0x6

    .line 1279
    .line 1280
    goto :goto_32

    .line 1281
    :sswitch_8
    add-int/lit8 v6, v7, -0x7

    .line 1282
    .line 1283
    const/4 v10, 0x0

    .line 1284
    :goto_33
    if-gt v10, v6, :cond_3d

    .line 1285
    .line 1286
    new-instance v11, Lj3/r;

    .line 1287
    .line 1288
    aget v12, v4, v10

    .line 1289
    .line 1290
    add-int/lit8 v8, v10, 0x1

    .line 1291
    .line 1292
    aget v13, v4, v8

    .line 1293
    .line 1294
    add-int/lit8 v8, v10, 0x2

    .line 1295
    .line 1296
    aget v14, v4, v8

    .line 1297
    .line 1298
    add-int/lit8 v8, v10, 0x3

    .line 1299
    .line 1300
    aget v8, v4, v8

    .line 1301
    .line 1302
    const/4 v9, 0x0

    .line 1303
    invoke-static {v8, v9}, Ljava/lang/Float;->compare(FF)I

    .line 1304
    .line 1305
    .line 1306
    move-result v8

    .line 1307
    if-eqz v8, :cond_3b

    .line 1308
    .line 1309
    move/from16 v15, v20

    .line 1310
    .line 1311
    goto :goto_34

    .line 1312
    :cond_3b
    const/4 v15, 0x0

    .line 1313
    :goto_34
    add-int/lit8 v8, v10, 0x4

    .line 1314
    .line 1315
    aget v8, v4, v8

    .line 1316
    .line 1317
    invoke-static {v8, v9}, Ljava/lang/Float;->compare(FF)I

    .line 1318
    .line 1319
    .line 1320
    move-result v8

    .line 1321
    if-eqz v8, :cond_3c

    .line 1322
    .line 1323
    move/from16 v16, v20

    .line 1324
    .line 1325
    goto :goto_35

    .line 1326
    :cond_3c
    const/16 v16, 0x0

    .line 1327
    .line 1328
    :goto_35
    add-int/lit8 v8, v10, 0x5

    .line 1329
    .line 1330
    aget v17, v4, v8

    .line 1331
    .line 1332
    add-int/lit8 v8, v10, 0x6

    .line 1333
    .line 1334
    aget v18, v4, v8

    .line 1335
    .line 1336
    invoke-direct/range {v11 .. v18}, Lj3/r;-><init>(FFFZZFF)V

    .line 1337
    .line 1338
    .line 1339
    invoke-interface {v2, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1340
    .line 1341
    .line 1342
    add-int/lit8 v10, v10, 0x7

    .line 1343
    .line 1344
    goto :goto_33

    .line 1345
    :sswitch_9
    sget-object v4, Lj3/j;->c:Lj3/j;

    .line 1346
    .line 1347
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1348
    .line 1349
    .line 1350
    :cond_3d
    const/16 v29, 0x0

    .line 1351
    .line 1352
    goto/16 :goto_41

    .line 1353
    .line 1354
    :sswitch_a
    add-int/lit8 v6, v7, -0x1

    .line 1355
    .line 1356
    const/4 v10, 0x0

    .line 1357
    :goto_36
    if-gt v10, v6, :cond_3d

    .line 1358
    .line 1359
    new-instance v8, Lj3/a0;

    .line 1360
    .line 1361
    aget v9, v4, v10

    .line 1362
    .line 1363
    invoke-direct {v8, v9}, Lj3/a0;-><init>(F)V

    .line 1364
    .line 1365
    .line 1366
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1367
    .line 1368
    .line 1369
    add-int/lit8 v10, v10, 0x1

    .line 1370
    .line 1371
    goto :goto_36

    .line 1372
    :sswitch_b
    add-int/lit8 v6, v7, -0x2

    .line 1373
    .line 1374
    const/4 v10, 0x0

    .line 1375
    :goto_37
    if-gt v10, v6, :cond_3d

    .line 1376
    .line 1377
    new-instance v8, Lj3/q;

    .line 1378
    .line 1379
    aget v9, v4, v10

    .line 1380
    .line 1381
    add-int/lit8 v11, v10, 0x1

    .line 1382
    .line 1383
    aget v11, v4, v11

    .line 1384
    .line 1385
    invoke-direct {v8, v9, v11}, Lj3/q;-><init>(FF)V

    .line 1386
    .line 1387
    .line 1388
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1389
    .line 1390
    .line 1391
    add-int/lit8 v10, v10, 0x2

    .line 1392
    .line 1393
    goto :goto_37

    .line 1394
    :sswitch_c
    add-int/lit8 v6, v7, -0x4

    .line 1395
    .line 1396
    const/4 v10, 0x0

    .line 1397
    :goto_38
    if-gt v10, v6, :cond_3d

    .line 1398
    .line 1399
    new-instance v8, Lj3/p;

    .line 1400
    .line 1401
    aget v9, v4, v10

    .line 1402
    .line 1403
    add-int/lit8 v11, v10, 0x1

    .line 1404
    .line 1405
    aget v11, v4, v11

    .line 1406
    .line 1407
    add-int/lit8 v12, v10, 0x2

    .line 1408
    .line 1409
    aget v12, v4, v12

    .line 1410
    .line 1411
    add-int/lit8 v13, v10, 0x3

    .line 1412
    .line 1413
    aget v13, v4, v13

    .line 1414
    .line 1415
    invoke-direct {v8, v9, v11, v12, v13}, Lj3/p;-><init>(FFFF)V

    .line 1416
    .line 1417
    .line 1418
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1419
    .line 1420
    .line 1421
    add-int/lit8 v10, v10, 0x4

    .line 1422
    .line 1423
    goto :goto_38

    .line 1424
    :sswitch_d
    add-int/lit8 v6, v7, -0x4

    .line 1425
    .line 1426
    const/4 v10, 0x0

    .line 1427
    :goto_39
    if-gt v10, v6, :cond_3d

    .line 1428
    .line 1429
    new-instance v8, Lj3/o;

    .line 1430
    .line 1431
    aget v9, v4, v10

    .line 1432
    .line 1433
    add-int/lit8 v11, v10, 0x1

    .line 1434
    .line 1435
    aget v11, v4, v11

    .line 1436
    .line 1437
    add-int/lit8 v12, v10, 0x2

    .line 1438
    .line 1439
    aget v12, v4, v12

    .line 1440
    .line 1441
    add-int/lit8 v13, v10, 0x3

    .line 1442
    .line 1443
    aget v13, v4, v13

    .line 1444
    .line 1445
    invoke-direct {v8, v9, v11, v12, v13}, Lj3/o;-><init>(FFFF)V

    .line 1446
    .line 1447
    .line 1448
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1449
    .line 1450
    .line 1451
    add-int/lit8 v10, v10, 0x4

    .line 1452
    .line 1453
    goto :goto_39

    .line 1454
    :sswitch_e
    add-int/lit8 v8, v7, -0x2

    .line 1455
    .line 1456
    if-ltz v8, :cond_3d

    .line 1457
    .line 1458
    new-instance v9, Lj3/n;

    .line 1459
    .line 1460
    const/16 v29, 0x0

    .line 1461
    .line 1462
    aget v10, v4, v29

    .line 1463
    .line 1464
    aget v11, v4, v20

    .line 1465
    .line 1466
    invoke-direct {v9, v10, v11}, Lj3/n;-><init>(FF)V

    .line 1467
    .line 1468
    .line 1469
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1470
    .line 1471
    .line 1472
    :goto_3a
    if-gt v6, v8, :cond_40

    .line 1473
    .line 1474
    new-instance v9, Lj3/m;

    .line 1475
    .line 1476
    aget v10, v4, v6

    .line 1477
    .line 1478
    add-int/lit8 v11, v6, 0x1

    .line 1479
    .line 1480
    aget v11, v4, v11

    .line 1481
    .line 1482
    invoke-direct {v9, v10, v11}, Lj3/m;-><init>(FF)V

    .line 1483
    .line 1484
    .line 1485
    invoke-interface {v2, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1486
    .line 1487
    .line 1488
    add-int/lit8 v6, v6, 0x2

    .line 1489
    .line 1490
    goto :goto_3a

    .line 1491
    :sswitch_f
    const/16 v29, 0x0

    .line 1492
    .line 1493
    add-int/lit8 v6, v7, -0x2

    .line 1494
    .line 1495
    move/from16 v10, v29

    .line 1496
    .line 1497
    :goto_3b
    if-gt v10, v6, :cond_40

    .line 1498
    .line 1499
    new-instance v8, Lj3/m;

    .line 1500
    .line 1501
    aget v9, v4, v10

    .line 1502
    .line 1503
    add-int/lit8 v11, v10, 0x1

    .line 1504
    .line 1505
    aget v11, v4, v11

    .line 1506
    .line 1507
    invoke-direct {v8, v9, v11}, Lj3/m;-><init>(FF)V

    .line 1508
    .line 1509
    .line 1510
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1511
    .line 1512
    .line 1513
    add-int/lit8 v10, v10, 0x2

    .line 1514
    .line 1515
    goto :goto_3b

    .line 1516
    :sswitch_10
    const/16 v29, 0x0

    .line 1517
    .line 1518
    add-int/lit8 v6, v7, -0x1

    .line 1519
    .line 1520
    move/from16 v10, v29

    .line 1521
    .line 1522
    :goto_3c
    if-gt v10, v6, :cond_40

    .line 1523
    .line 1524
    new-instance v8, Lj3/l;

    .line 1525
    .line 1526
    aget v9, v4, v10

    .line 1527
    .line 1528
    invoke-direct {v8, v9}, Lj3/l;-><init>(F)V

    .line 1529
    .line 1530
    .line 1531
    invoke-interface {v2, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1532
    .line 1533
    .line 1534
    add-int/lit8 v10, v10, 0x1

    .line 1535
    .line 1536
    goto :goto_3c

    .line 1537
    :sswitch_11
    const/16 v29, 0x0

    .line 1538
    .line 1539
    add-int/lit8 v6, v7, -0x6

    .line 1540
    .line 1541
    move/from16 v10, v29

    .line 1542
    .line 1543
    :goto_3d
    if-gt v10, v6, :cond_40

    .line 1544
    .line 1545
    new-instance v11, Lj3/k;

    .line 1546
    .line 1547
    aget v12, v4, v10

    .line 1548
    .line 1549
    add-int/lit8 v8, v10, 0x1

    .line 1550
    .line 1551
    aget v13, v4, v8

    .line 1552
    .line 1553
    add-int/lit8 v8, v10, 0x2

    .line 1554
    .line 1555
    aget v14, v4, v8

    .line 1556
    .line 1557
    add-int/lit8 v8, v10, 0x3

    .line 1558
    .line 1559
    aget v15, v4, v8

    .line 1560
    .line 1561
    add-int/lit8 v8, v10, 0x4

    .line 1562
    .line 1563
    aget v16, v4, v8

    .line 1564
    .line 1565
    add-int/lit8 v8, v10, 0x5

    .line 1566
    .line 1567
    aget v17, v4, v8

    .line 1568
    .line 1569
    invoke-direct/range {v11 .. v17}, Lj3/k;-><init>(FFFFFF)V

    .line 1570
    .line 1571
    .line 1572
    invoke-interface {v2, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1573
    .line 1574
    .line 1575
    add-int/lit8 v10, v10, 0x6

    .line 1576
    .line 1577
    goto :goto_3d

    .line 1578
    :sswitch_12
    const/16 v29, 0x0

    .line 1579
    .line 1580
    add-int/lit8 v6, v7, -0x7

    .line 1581
    .line 1582
    move/from16 v10, v29

    .line 1583
    .line 1584
    :goto_3e
    if-gt v10, v6, :cond_40

    .line 1585
    .line 1586
    new-instance v11, Lj3/i;

    .line 1587
    .line 1588
    aget v12, v4, v10

    .line 1589
    .line 1590
    add-int/lit8 v8, v10, 0x1

    .line 1591
    .line 1592
    aget v13, v4, v8

    .line 1593
    .line 1594
    add-int/lit8 v8, v10, 0x2

    .line 1595
    .line 1596
    aget v14, v4, v8

    .line 1597
    .line 1598
    add-int/lit8 v8, v10, 0x3

    .line 1599
    .line 1600
    aget v8, v4, v8

    .line 1601
    .line 1602
    const/4 v9, 0x0

    .line 1603
    invoke-static {v8, v9}, Ljava/lang/Float;->compare(FF)I

    .line 1604
    .line 1605
    .line 1606
    move-result v8

    .line 1607
    if-eqz v8, :cond_3e

    .line 1608
    .line 1609
    move/from16 v15, v20

    .line 1610
    .line 1611
    goto :goto_3f

    .line 1612
    :cond_3e
    move/from16 v15, v29

    .line 1613
    .line 1614
    :goto_3f
    add-int/lit8 v8, v10, 0x4

    .line 1615
    .line 1616
    aget v8, v4, v8

    .line 1617
    .line 1618
    invoke-static {v8, v9}, Ljava/lang/Float;->compare(FF)I

    .line 1619
    .line 1620
    .line 1621
    move-result v8

    .line 1622
    if-eqz v8, :cond_3f

    .line 1623
    .line 1624
    move/from16 v16, v20

    .line 1625
    .line 1626
    goto :goto_40

    .line 1627
    :cond_3f
    move/from16 v16, v29

    .line 1628
    .line 1629
    :goto_40
    add-int/lit8 v8, v10, 0x5

    .line 1630
    .line 1631
    aget v17, v4, v8

    .line 1632
    .line 1633
    add-int/lit8 v8, v10, 0x6

    .line 1634
    .line 1635
    aget v18, v4, v8

    .line 1636
    .line 1637
    invoke-direct/range {v11 .. v18}, Lj3/i;-><init>(FFFZZFF)V

    .line 1638
    .line 1639
    .line 1640
    invoke-interface {v2, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1641
    .line 1642
    .line 1643
    add-int/lit8 v10, v10, 0x7

    .line 1644
    .line 1645
    goto :goto_3e

    .line 1646
    :cond_40
    :goto_41
    move/from16 v6, v19

    .line 1647
    .line 1648
    goto/16 :goto_2

    .line 1649
    .line 1650
    :cond_41
    move v5, v8

    .line 1651
    goto/16 :goto_2

    .line 1652
    .line 1653
    :cond_42
    move v5, v8

    .line 1654
    goto/16 :goto_3

    .line 1655
    .line 1656
    :cond_43
    return-object v2

    .line 1657
    :sswitch_data_0
    .sparse-switch
        0x41 -> :sswitch_12
        0x43 -> :sswitch_11
        0x48 -> :sswitch_10
        0x4c -> :sswitch_f
        0x4d -> :sswitch_e
        0x51 -> :sswitch_d
        0x53 -> :sswitch_c
        0x54 -> :sswitch_b
        0x56 -> :sswitch_a
        0x5a -> :sswitch_9
        0x61 -> :sswitch_8
        0x63 -> :sswitch_7
        0x68 -> :sswitch_6
        0x6c -> :sswitch_5
        0x6d -> :sswitch_4
        0x71 -> :sswitch_3
        0x73 -> :sswitch_2
        0x74 -> :sswitch_1
        0x76 -> :sswitch_0
        0x7a -> :sswitch_9
    .end sparse-switch
.end method

.method public static x()I
    .locals 5

    .line 1
    new-instance v0, Ljava/security/SecureRandom;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/security/SecureRandom;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x4

    .line 7
    new-array v1, v1, [B

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    move v3, v2

    .line 11
    :goto_0
    if-nez v3, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 14
    .line 15
    .line 16
    aget-byte v3, v1, v2

    .line 17
    .line 18
    and-int/lit8 v3, v3, 0x7f

    .line 19
    .line 20
    shl-int/lit8 v3, v3, 0x18

    .line 21
    .line 22
    const/4 v4, 0x1

    .line 23
    aget-byte v4, v1, v4

    .line 24
    .line 25
    and-int/lit16 v4, v4, 0xff

    .line 26
    .line 27
    shl-int/lit8 v4, v4, 0x10

    .line 28
    .line 29
    or-int/2addr v3, v4

    .line 30
    const/4 v4, 0x2

    .line 31
    aget-byte v4, v1, v4

    .line 32
    .line 33
    and-int/lit16 v4, v4, 0xff

    .line 34
    .line 35
    shl-int/lit8 v4, v4, 0x8

    .line 36
    .line 37
    or-int/2addr v3, v4

    .line 38
    const/4 v4, 0x3

    .line 39
    aget-byte v4, v1, v4

    .line 40
    .line 41
    and-int/lit16 v4, v4, 0xff

    .line 42
    .line 43
    or-int/2addr v3, v4

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    return v3
.end method


# virtual methods
.method public a()Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Low0/n;

    .line 4
    .line 5
    invoke-static {p0}, Ljp/tc;->b(Low0/n;)Low0/x;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lvw0/l;

    .line 10
    .line 11
    invoke-virtual {p0}, Lvw0/l;->a()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public b(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljl/h;

    .line 4
    .line 5
    new-instance v0, Ljl/d;

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ljl/h;->j(Landroid/graphics/drawable/Drawable;)Li3/c;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p1, 0x0

    .line 15
    :goto_0
    invoke-direct {v0, p1}, Ljl/d;-><init>(Li3/c;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ljl/h;->k(Ljl/f;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public d(Ll/l;Z)V
    .locals 2

    .line 1
    instance-of v0, p1, Ll/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ll/d0;

    .line 7
    .line 8
    iget-object v0, v0, Ll/d0;->z:Ll/l;

    .line 9
    .line 10
    invoke-virtual {v0}, Ll/l;->k()Ll/l;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-virtual {v0, v1}, Ll/l;->c(Z)V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lm/j;

    .line 21
    .line 22
    iget-object p0, p0, Lm/j;->h:Ll/w;

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    invoke-interface {p0, p1, p2}, Ll/w;->d(Ll/l;Z)V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public e(B)V
    .locals 0

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Parcel;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeByte(B)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public f(Ll/l;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lm/j;

    .line 4
    .line 5
    iget-object v0, p0, Lm/j;->f:Ll/l;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-ne p1, v0, :cond_0

    .line 9
    .line 10
    return v1

    .line 11
    :cond_0
    move-object v0, p1

    .line 12
    check-cast v0, Ll/d0;

    .line 13
    .line 14
    iget-object v0, v0, Ll/d0;->A:Ll/n;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lm/j;->h:Ll/w;

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    invoke-interface {p0, p1}, Ll/w;->f(Ll/l;)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0

    .line 31
    :cond_1
    return v1
.end method

.method public g(Ljava/lang/Object;)Laq/t;
    .locals 2

    .line 1
    check-cast p1, Lus/a;

    .line 2
    .line 3
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lb81/b;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    const-string p0, "Received null app settings at app startup. Cannot send cached reports"

    .line 11
    .line 12
    const-string p1, "FirebaseCrashlytics"

    .line 13
    .line 14
    invoke-static {p1, p0, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 15
    .line 16
    .line 17
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    iget-object p0, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lms/l;

    .line 25
    .line 26
    invoke-static {p0}, Lms/l;->a(Lms/l;)Laq/t;

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lms/l;->m:Lss/b;

    .line 30
    .line 31
    iget-object v1, p0, Lms/l;->e:Lns/d;

    .line 32
    .line 33
    iget-object v1, v1, Lns/d;->a:Lns/b;

    .line 34
    .line 35
    invoke-virtual {p1, v1, v0}, Lss/b;->n(Ljava/util/concurrent/Executor;Ljava/lang/String;)Laq/t;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lms/l;->q:Laq/k;

    .line 39
    .line 40
    invoke-virtual {p0, v0}, Laq/k;->d(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method

.method public get()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lj1/a;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ld8/c;

    .line 9
    .line 10
    iget-object p0, p0, Ld8/c;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/content/Context;

    .line 13
    .line 14
    new-instance v0, La61/a;

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Lwq/f;

    .line 21
    .line 22
    const/4 v2, 0x1

    .line 23
    invoke-direct {v1, v2}, Lwq/f;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Lrn/i;

    .line 27
    .line 28
    const/4 v3, 0x7

    .line 29
    invoke-direct {v2, p0, v0, v1, v3}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    return-object v2

    .line 33
    :sswitch_0
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 36
    .line 37
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Lgt/b;

    .line 40
    .line 41
    invoke-static {p0}, Lkp/s6;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :sswitch_1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Lj1/a;

    .line 48
    .line 49
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Landroid/content/Context;

    .line 52
    .line 53
    new-instance v0, Lku/a;

    .line 54
    .line 55
    invoke-direct {v0, p0}, Lku/a;-><init>(Landroid/content/Context;)V

    .line 56
    .line 57
    .line 58
    return-object v0

    .line 59
    :sswitch_2
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 60
    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :sswitch_data_0
    .sparse-switch
        0x4 -> :sswitch_2
        0x8 -> :sswitch_1
        0x1b -> :sswitch_0
    .end sparse-switch
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lj1/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lk0/k;

    .line 9
    .line 10
    iget-object v1, v0, Lk0/k;->i:Ly4/h;

    .line 11
    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v1, 0x0

    .line 17
    :goto_0
    const-string v2, "The result can only set once!"

    .line 18
    .line 19
    invoke-static {v2, v1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Lk0/k;->i:Ly4/h;

    .line 23
    .line 24
    new-instance p1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v0, "ListFuture["

    .line 27
    .line 28
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string p0, "]"

    .line 35
    .line 36
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_0
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lk0/d;

    .line 47
    .line 48
    iget-object v0, p0, Lk0/d;->e:Ly4/h;

    .line 49
    .line 50
    if-nez v0, :cond_1

    .line 51
    .line 52
    const/4 v0, 0x1

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    const/4 v0, 0x0

    .line 55
    :goto_1
    const-string v1, "The result can only set once!"

    .line 56
    .line 57
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 58
    .line 59
    .line 60
    iput-object p1, p0, Lk0/d;->e:Ly4/h;

    .line 61
    .line 62
    new-instance p1, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string v0, "FutureChain["

    .line 65
    .line 66
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string p0, "]"

    .line 73
    .line 74
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_0
    .end packed-switch
.end method

.method public i(Ljava/lang/String;Ljava/lang/Iterable;)V
    .locals 3

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "values"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Low0/n;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    invoke-static {p1, v0}, Low0/a;->e(Ljava/lang/String;Z)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance v0, Ljava/util/ArrayList;

    .line 21
    .line 22
    const/16 v1, 0xa

    .line 23
    .line 24
    invoke-static {p2, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 29
    .line 30
    .line 31
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_0

    .line 40
    .line 41
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    check-cast v1, Ljava/lang/String;

    .line 46
    .line 47
    const-string v2, "<this>"

    .line 48
    .line 49
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const/4 v2, 0x1

    .line 53
    invoke-static {v1, v2}, Low0/a;->e(Ljava/lang/String;Z)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-virtual {p0, p1, v0}, Lap0/o;->i(Ljava/lang/String;Ljava/lang/Iterable;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public j(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Parcel;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeFloat(F)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public k(J)V
    .locals 8

    .line 1
    invoke-static {p1, p2}, Lt4/o;->b(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    invoke-static {v0, v1, v2, v3}, Lt4/p;->a(JJ)Z

    .line 8
    .line 9
    .line 10
    move-result v4

    .line 11
    const/4 v5, 0x0

    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-wide v6, 0x100000000L

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    invoke-static {v0, v1, v6, v7}, Lt4/p;->a(JJ)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_1

    .line 25
    .line 26
    const/4 v5, 0x1

    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const-wide v6, 0x200000000L

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    invoke-static {v0, v1, v6, v7}, Lt4/p;->a(JJ)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    const/4 v5, 0x2

    .line 40
    :cond_2
    :goto_0
    invoke-virtual {p0, v5}, Lj1/a;->e(B)V

    .line 41
    .line 42
    .line 43
    invoke-static {p1, p2}, Lt4/o;->b(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    invoke-static {v0, v1, v2, v3}, Lt4/p;->a(JJ)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_3

    .line 52
    .line 53
    invoke-static {p1, p2}, Lt4/o;->c(J)F

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    invoke-virtual {p0, p1}, Lj1/a;->j(F)V

    .line 58
    .line 59
    .line 60
    :cond_3
    return-void
.end method

.method public l(Ll/l;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/appcompat/widget/Toolbar;

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 6
    .line 7
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Lm/j;->k()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object p0, p0, Landroidx/appcompat/widget/Toolbar;->J:Ld6/n;

    .line 19
    .line 20
    iget-object p0, p0, Ld6/n;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Ld6/o;

    .line 37
    .line 38
    check-cast v0, Landroidx/fragment/app/a1;

    .line 39
    .line 40
    iget-object v0, v0, Landroidx/fragment/app/a1;->a:Landroidx/fragment/app/j1;

    .line 41
    .line 42
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j1;->t(Landroid/view/Menu;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    return-void
.end method

.method public m(Ll/l;Landroid/view/MenuItem;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/appcompat/widget/Toolbar;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public declared-synchronized o(Ljava/lang/String;)Lhu/q;
    .locals 6

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v0, Lhu/q;

    .line 3
    .line 4
    invoke-static {p1}, Lrr/f;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iget-object v1, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/security/KeyStore;

    .line 11
    .line 12
    invoke-direct {v0, p1, v1}, Lhu/q;-><init>(Ljava/lang/String;Ljava/security/KeyStore;)V

    .line 13
    .line 14
    .line 15
    const/16 p1, 0xa

    .line 16
    .line 17
    new-array p1, p1, [B

    .line 18
    .line 19
    sget-object v1, Lrr/e;->a:Ley0/b;

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Ljava/security/SecureRandom;

    .line 26
    .line 27
    invoke-virtual {v1, p1}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 28
    .line 29
    .line 30
    const/4 v1, 0x0

    .line 31
    new-array v1, v1, [B
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    :try_start_1
    invoke-virtual {v0, p1, v1}, Lhu/q;->z([B[B)[B

    .line 34
    .line 35
    .line 36
    move-result-object v2
    :try_end_1
    .catch Ljava/security/ProviderException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    goto :goto_0

    .line 38
    :catch_0
    move-exception v2

    .line 39
    :try_start_2
    const-string v3, "q"

    .line 40
    .line 41
    const-string v4, "encountered a potentially transient KeyStore error, will wait and retry"

    .line 42
    .line 43
    invoke-static {v3, v4, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 44
    .line 45
    .line 46
    invoke-static {}, Ljava/lang/Math;->random()D

    .line 47
    .line 48
    .line 49
    move-result-wide v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 50
    const-wide/high16 v4, 0x4059000000000000L    # 100.0

    .line 51
    .line 52
    mul-double/2addr v2, v4

    .line 53
    double-to-int v2, v2

    .line 54
    int-to-long v2, v2

    .line 55
    :try_start_3
    invoke-static {v2, v3}, Ljava/lang/Thread;->sleep(J)V
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 56
    .line 57
    .line 58
    :catch_1
    :try_start_4
    invoke-virtual {v0, p1, v1}, Lhu/q;->z([B[B)[B

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    :goto_0
    invoke-virtual {v0, v2, v1}, Lhu/q;->w([B[B)[B

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-static {p1, v1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 67
    .line 68
    .line 69
    move-result p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 70
    if-eqz p1, :cond_0

    .line 71
    .line 72
    monitor-exit p0

    .line 73
    return-object v0

    .line 74
    :cond_0
    :try_start_5
    new-instance p1, Ljava/security/KeyStoreException;

    .line 75
    .line 76
    const-string v0, "cannot use Android Keystore: encryption/decryption of non-empty message and empty aad returns an incorrect result"

    .line 77
    .line 78
    invoke-direct {p1, v0}, Ljava/security/KeyStoreException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p1

    .line 82
    :catchall_0
    move-exception p1

    .line 83
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 84
    throw p1
.end method

.method public declared-synchronized p()Lhu/q;
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Lqr/v;

    .line 5
    .line 6
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lqr/y;

    .line 11
    .line 12
    invoke-virtual {v0}, Lqr/y;->p()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-lez v1, :cond_0

    .line 17
    .line 18
    new-instance v1, Lhu/q;

    .line 19
    .line 20
    const/16 v2, 0x15

    .line 21
    .line 22
    invoke-direct {v1, v0, v2}, Lhu/q;-><init>(Ljava/lang/Object;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    .line 25
    monitor-exit p0

    .line 26
    return-object v1

    .line 27
    :cond_0
    :try_start_1
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 28
    .line 29
    const-string v1, "empty keyset"

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :catchall_0
    move-exception v0

    .line 36
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    throw v0
.end method

.method public q()Lsp/v;
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lrp/b;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x3

    .line 10
    invoke-virtual {p0, v0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object v0, Lsp/v;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    invoke-static {p0, v0}, Lhp/j;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lsp/v;

    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :catch_0
    move-exception p0

    .line 27
    new-instance v0, La8/r0;

    .line 28
    .line 29
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 30
    .line 31
    .line 32
    throw v0
.end method

.method public declared-synchronized r(Ljava/lang/String;)Z
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-static {p1}, Lrr/f;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    :try_start_1
    iget-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/security/KeyStore;

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Ljava/security/KeyStore;->containsAlias(Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result p1
    :try_end_1
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 14
    monitor-exit p0

    .line 15
    return p1

    .line 16
    :catchall_0
    move-exception p1

    .line 17
    goto :goto_2

    .line 18
    :catch_0
    :try_start_2
    const-string v0, "a"

    .line 19
    .line 20
    const-string v1, "Keystore is temporarily unavailable, wait 20ms, reinitialize Keystore and try again."

    .line 21
    .line 22
    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 23
    .line 24
    .line 25
    const-wide/16 v0, 0x14

    .line 26
    .line 27
    :try_start_3
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V

    .line 28
    .line 29
    .line 30
    const-string v0, "AndroidKeyStore"

    .line 31
    .line 32
    invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    iput-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    invoke-virtual {v0, v1}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catch_1
    move-exception p1

    .line 44
    goto :goto_1

    .line 45
    :catch_2
    :goto_0
    :try_start_4
    iget-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v0, Ljava/security/KeyStore;

    .line 48
    .line 49
    invoke-virtual {v0, p1}, Ljava/security/KeyStore;->containsAlias(Ljava/lang/String;)Z

    .line 50
    .line 51
    .line 52
    move-result p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 53
    monitor-exit p0

    .line 54
    return p1

    .line 55
    :goto_1
    :try_start_5
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 56
    .line 57
    invoke-direct {v0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :goto_2
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 62
    throw p1
.end method

.method public declared-synchronized s(I)Z
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Lqr/v;

    .line 5
    .line 6
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 7
    .line 8
    check-cast v0, Lqr/y;

    .line 9
    .line 10
    invoke-virtual {v0}, Lqr/y;->q()Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lqr/x;

    .line 33
    .line 34
    invoke-virtual {v1}, Lqr/x;->r()I

    .line 35
    .line 36
    .line 37
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    if-ne v1, p1, :cond_0

    .line 39
    .line 40
    monitor-exit p0

    .line 41
    const/4 p0, 0x1

    .line 42
    return p0

    .line 43
    :catchall_0
    move-exception p1

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    monitor-exit p0

    .line 46
    const/4 p0, 0x0

    .line 47
    return p0

    .line 48
    :goto_0
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 49
    throw p1
.end method

.method public declared-synchronized t(Lqr/t;)Lqr/x;
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-static {p1}, Lmr/g;->c(Lqr/t;)Lqr/q;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    monitor-enter p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 7
    :try_start_1
    invoke-static {}, Lj1/a;->x()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    :goto_0
    invoke-virtual {p0, v1}, Lj1/a;->s(I)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-static {}, Lj1/a;->x()I

    .line 18
    .line 19
    .line 20
    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p1

    .line 23
    goto :goto_2

    .line 24
    :cond_0
    :try_start_2
    monitor-exit p0

    .line 25
    invoke-virtual {p1}, Lqr/t;->p()Lqr/d0;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    sget-object v2, Lqr/d0;->e:Lqr/d0;

    .line 30
    .line 31
    if-ne p1, v2, :cond_1

    .line 32
    .line 33
    sget-object p1, Lqr/d0;->f:Lqr/d0;

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :catchall_1
    move-exception p1

    .line 37
    goto :goto_3

    .line 38
    :cond_1
    :goto_1
    invoke-static {}, Lqr/x;->v()Lqr/w;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 43
    .line 44
    .line 45
    iget-object v3, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 46
    .line 47
    check-cast v3, Lqr/x;

    .line 48
    .line 49
    invoke-static {v3, v0}, Lqr/x;->m(Lqr/x;Lqr/q;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 53
    .line 54
    .line 55
    iget-object v0, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 56
    .line 57
    check-cast v0, Lqr/x;

    .line 58
    .line 59
    invoke-static {v0, v1}, Lqr/x;->p(Lqr/x;I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 63
    .line 64
    .line 65
    iget-object v0, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 66
    .line 67
    check-cast v0, Lqr/x;

    .line 68
    .line 69
    invoke-static {v0}, Lqr/x;->o(Lqr/x;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 73
    .line 74
    .line 75
    iget-object v0, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 76
    .line 77
    check-cast v0, Lqr/x;

    .line 78
    .line 79
    invoke-static {v0, p1}, Lqr/x;->n(Lqr/x;Lqr/d0;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    check-cast p1, Lqr/x;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 87
    .line 88
    monitor-exit p0

    .line 89
    return-object p1

    .line 90
    :goto_2
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 91
    :try_start_4
    throw p1

    .line 92
    :goto_3
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 93
    throw p1
.end method

.method public u(Lcom/google/crypto/tink/shaded/protobuf/i;)Lqr/q;
    .locals 3

    .line 1
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Leb/j0;

    .line 4
    .line 5
    :try_start_0
    invoke-virtual {p0}, Leb/j0;->w()Lmr/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0, p1}, Lmr/a;->b(Lcom/google/crypto/tink/shaded/protobuf/i;)Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {v0, p1}, Lmr/a;->c(Lcom/google/crypto/tink/shaded/protobuf/a;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Lmr/a;->a(Lcom/google/crypto/tink/shaded/protobuf/a;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 21
    .line 22
    invoke-static {}, Lqr/q;->t()Lqr/o;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {p0}, Leb/j0;->t()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 31
    .line 32
    .line 33
    iget-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 34
    .line 35
    check-cast v1, Lqr/q;

    .line 36
    .line 37
    invoke-static {v1, p0}, Lqr/q;->m(Lqr/q;Ljava/lang/String;)V
    :try_end_0
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_0 .. :try_end_0} :catch_1

    .line 38
    .line 39
    .line 40
    :try_start_1
    invoke-virtual {p1}, Lcom/google/crypto/tink/shaded/protobuf/a;->a()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    new-array v1, p0, [B

    .line 45
    .line 46
    new-instance v2, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 47
    .line 48
    invoke-direct {v2, p0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k;-><init>(I[B)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/a;->d(Lcom/google/crypto/tink/shaded/protobuf/k;)V

    .line 52
    .line 53
    .line 54
    iget p0, v2, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 55
    .line 56
    iget v2, v2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 57
    .line 58
    sub-int/2addr p0, v2

    .line 59
    if-nez p0, :cond_0

    .line 60
    .line 61
    new-instance p0, Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 62
    .line 63
    invoke-direct {p0, v1}, Lcom/google/crypto/tink/shaded/protobuf/h;-><init>([B)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 64
    .line 65
    .line 66
    :try_start_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 67
    .line 68
    .line 69
    iget-object p1, v0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 70
    .line 71
    check-cast p1, Lqr/q;

    .line 72
    .line 73
    invoke-static {p1, p0}, Lqr/q;->n(Lqr/q;Lcom/google/crypto/tink/shaded/protobuf/h;)V

    .line 74
    .line 75
    .line 76
    sget-object p0, Lqr/p;->f:Lqr/p;

    .line 77
    .line 78
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 79
    .line 80
    .line 81
    iget-object p1, v0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 82
    .line 83
    check-cast p1, Lqr/q;

    .line 84
    .line 85
    invoke-static {p1, p0}, Lqr/q;->o(Lqr/q;Lqr/p;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Lqr/q;
    :try_end_2
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_2 .. :try_end_2} :catch_1

    .line 93
    .line 94
    return-object p0

    .line 95
    :cond_0
    :try_start_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 96
    .line 97
    const-string v0, "Did not write as much data as expected."

    .line 98
    .line 99
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0

    .line 103
    :catch_0
    move-exception p0

    .line 104
    :try_start_4
    new-instance v0, Ljava/lang/RuntimeException;

    .line 105
    .line 106
    const-string v1, "ByteString"

    .line 107
    .line 108
    invoke-virtual {p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/a;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-direct {v0, p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 113
    .line 114
    .line 115
    throw v0
    :try_end_4
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_4 .. :try_end_4} :catch_1

    .line 116
    :catch_1
    move-exception p0

    .line 117
    new-instance p1, Ljava/security/GeneralSecurityException;

    .line 118
    .line 119
    const-string v0, "Unexpected proto"

    .line 120
    .line 121
    invoke-direct {p1, v0, p0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 122
    .line 123
    .line 124
    throw p1
.end method

.method public w(Lgv/a;)V
    .locals 1

    .line 1
    const-string v0, "definition"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lww0/a;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lww0/a;->a(Lgv/a;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p0}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public y(I)Ljava/util/ArrayList;
    .locals 19

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    move-object/from16 v1, p0

    .line 7
    .line 8
    iget-object v1, v1, Lj1/a;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ln1/v;

    .line 11
    .line 12
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {v2}, Lv2/f;->e()Lay0/k;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    move-object v9, v3

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v9, 0x0

    .line 25
    :goto_0
    invoke-static {v2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 26
    .line 27
    .line 28
    move-result-object v10

    .line 29
    :try_start_0
    iget-boolean v3, v1, Ln1/v;->b:Z

    .line 30
    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    iget-object v3, v1, Ln1/v;->c:Ln1/n;

    .line 34
    .line 35
    :goto_1
    move-object v8, v3

    .line 36
    goto :goto_2

    .line 37
    :catchall_0
    move-exception v0

    .line 38
    goto :goto_4

    .line 39
    :cond_1
    iget-object v3, v1, Ln1/v;->e:Ll2/j1;

    .line 40
    .line 41
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    check-cast v3, Ln1/n;

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :goto_2
    if-eqz v8, :cond_2

    .line 49
    .line 50
    new-instance v5, Lkotlin/jvm/internal/d0;

    .line 51
    .line 52
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 53
    .line 54
    .line 55
    const/4 v3, 0x1

    .line 56
    iput v3, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 57
    .line 58
    iget-object v3, v8, Ln1/n;->k:Lay0/k;

    .line 59
    .line 60
    invoke-static/range {p1 .. p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 61
    .line 62
    .line 63
    move-result-object v6

    .line 64
    invoke-interface {v3, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    move-object v6, v3

    .line 69
    check-cast v6, Ljava/util/List;

    .line 70
    .line 71
    move-object v3, v6

    .line 72
    check-cast v3, Ljava/util/Collection;

    .line 73
    .line 74
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 75
    .line 76
    .line 77
    move-result v11

    .line 78
    const/4 v3, 0x0

    .line 79
    move v12, v3

    .line 80
    :goto_3
    if-ge v12, v11, :cond_2

    .line 81
    .line 82
    invoke-interface {v6, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    check-cast v3, Llx0/l;

    .line 87
    .line 88
    iget-object v13, v1, Ln1/v;->o:Lo1/l0;

    .line 89
    .line 90
    iget-object v7, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v7, Ljava/lang/Number;

    .line 93
    .line 94
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v14

    .line 98
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v3, Lt4/a;

    .line 101
    .line 102
    move-object v7, v5

    .line 103
    iget-wide v4, v3, Lt4/a;->a:J

    .line 104
    .line 105
    sget-object v3, Ln1/v;->w:Lu2/l;

    .line 106
    .line 107
    new-instance v18, Lbg/a;

    .line 108
    .line 109
    move-wide v15, v4

    .line 110
    move-object v5, v7

    .line 111
    move-object/from16 v3, v18

    .line 112
    .line 113
    const/4 v4, 0x0

    .line 114
    move/from16 v7, p1

    .line 115
    .line 116
    invoke-direct/range {v3 .. v8}, Lbg/a;-><init>(Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Ljava/util/List;ILn1/n;)V

    .line 117
    .line 118
    .line 119
    move-object/from16 v18, v3

    .line 120
    .line 121
    const/16 v17, 0x0

    .line 122
    .line 123
    invoke-virtual/range {v13 .. v18}, Lo1/l0;->a(IJZLay0/k;)Lo1/k0;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 128
    .line 129
    .line 130
    add-int/lit8 v12, v12, 0x1

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_2
    invoke-static {v2, v10, v9}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 134
    .line 135
    .line 136
    return-object v0

    .line 137
    :goto_4
    invoke-static {v2, v10, v9}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 138
    .line 139
    .line 140
    throw v0
.end method
