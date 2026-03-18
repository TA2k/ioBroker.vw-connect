.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y1;


# static fields
.field public static final b:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;


# instance fields
.field public final synthetic a:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->b:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 8
    .line 9
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static c(I[BII)I
    .locals 11

    .line 1
    const/16 v0, -0x13

    .line 2
    .line 3
    const/16 v1, -0x10

    .line 4
    .line 5
    const/16 v2, -0x3e

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/16 v4, -0x60

    .line 9
    .line 10
    const/16 v5, -0x20

    .line 11
    .line 12
    const/16 v6, -0x41

    .line 13
    .line 14
    const/4 v7, -0x1

    .line 15
    if-eqz p0, :cond_d

    .line 16
    .line 17
    if-lt p2, p3, :cond_0

    .line 18
    .line 19
    return p0

    .line 20
    :cond_0
    int-to-byte v8, p0

    .line 21
    if-ge v8, v5, :cond_1

    .line 22
    .line 23
    if-lt v8, v2, :cond_18

    .line 24
    .line 25
    add-int/lit8 p0, p2, 0x1

    .line 26
    .line 27
    aget-byte p2, p1, p2

    .line 28
    .line 29
    if-gt p2, v6, :cond_18

    .line 30
    .line 31
    :goto_0
    move p2, p0

    .line 32
    goto/16 :goto_5

    .line 33
    .line 34
    :cond_1
    shr-int/lit8 v9, p0, 0x8

    .line 35
    .line 36
    not-int v9, v9

    .line 37
    if-ge v8, v1, :cond_6

    .line 38
    .line 39
    int-to-byte p0, v9

    .line 40
    if-nez p0, :cond_3

    .line 41
    .line 42
    add-int/lit8 p0, p2, 0x1

    .line 43
    .line 44
    aget-byte p2, p1, p2

    .line 45
    .line 46
    if-ge p0, p3, :cond_2

    .line 47
    .line 48
    move v10, p2

    .line 49
    move p2, p0

    .line 50
    move p0, v10

    .line 51
    goto :goto_1

    .line 52
    :cond_2
    invoke-static {v8, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->d(II)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    return p0

    .line 57
    :cond_3
    :goto_1
    if-gt p0, v6, :cond_18

    .line 58
    .line 59
    if-ne v8, v5, :cond_4

    .line 60
    .line 61
    if-lt p0, v4, :cond_18

    .line 62
    .line 63
    :cond_4
    if-ne v8, v0, :cond_5

    .line 64
    .line 65
    if-ge p0, v4, :cond_18

    .line 66
    .line 67
    :cond_5
    add-int/lit8 p0, p2, 0x1

    .line 68
    .line 69
    aget-byte p2, p1, p2

    .line 70
    .line 71
    if-gt p2, v6, :cond_18

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_6
    int-to-byte v9, v9

    .line 75
    if-nez v9, :cond_8

    .line 76
    .line 77
    add-int/lit8 p0, p2, 0x1

    .line 78
    .line 79
    aget-byte v9, p1, p2

    .line 80
    .line 81
    if-ge p0, p3, :cond_7

    .line 82
    .line 83
    move p2, p0

    .line 84
    move p0, v3

    .line 85
    goto :goto_2

    .line 86
    :cond_7
    invoke-static {v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->d(II)I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    return p0

    .line 91
    :cond_8
    shr-int/lit8 p0, p0, 0x10

    .line 92
    .line 93
    :goto_2
    if-nez p0, :cond_c

    .line 94
    .line 95
    add-int/lit8 p0, p2, 0x1

    .line 96
    .line 97
    aget-byte p2, p1, p2

    .line 98
    .line 99
    if-ge p0, p3, :cond_9

    .line 100
    .line 101
    move v10, p2

    .line 102
    move p2, p0

    .line 103
    move p0, v10

    .line 104
    goto :goto_4

    .line 105
    :cond_9
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 106
    .line 107
    const/16 p0, -0xc

    .line 108
    .line 109
    if-gt v8, p0, :cond_b

    .line 110
    .line 111
    if-gt v9, v6, :cond_b

    .line 112
    .line 113
    if-le p2, v6, :cond_a

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_a
    shl-int/lit8 p0, v9, 0x8

    .line 117
    .line 118
    shl-int/lit8 p1, p2, 0x10

    .line 119
    .line 120
    xor-int/2addr p0, v8

    .line 121
    xor-int/2addr p0, p1

    .line 122
    return p0

    .line 123
    :cond_b
    :goto_3
    return v7

    .line 124
    :cond_c
    :goto_4
    if-gt v9, v6, :cond_18

    .line 125
    .line 126
    shl-int/lit8 v8, v8, 0x1c

    .line 127
    .line 128
    add-int/lit8 v9, v9, 0x70

    .line 129
    .line 130
    add-int/2addr v9, v8

    .line 131
    shr-int/lit8 v8, v9, 0x1e

    .line 132
    .line 133
    if-nez v8, :cond_18

    .line 134
    .line 135
    if-gt p0, v6, :cond_18

    .line 136
    .line 137
    add-int/lit8 p0, p2, 0x1

    .line 138
    .line 139
    aget-byte p2, p1, p2

    .line 140
    .line 141
    if-gt p2, v6, :cond_18

    .line 142
    .line 143
    goto :goto_0

    .line 144
    :cond_d
    :goto_5
    if-ge p2, p3, :cond_e

    .line 145
    .line 146
    aget-byte p0, p1, p2

    .line 147
    .line 148
    if-ltz p0, :cond_e

    .line 149
    .line 150
    add-int/lit8 p2, p2, 0x1

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_e
    if-lt p2, p3, :cond_f

    .line 154
    .line 155
    goto :goto_7

    .line 156
    :cond_f
    :goto_6
    if-lt p2, p3, :cond_10

    .line 157
    .line 158
    :goto_7
    return v3

    .line 159
    :cond_10
    add-int/lit8 p0, p2, 0x1

    .line 160
    .line 161
    aget-byte v8, p1, p2

    .line 162
    .line 163
    if-gez v8, :cond_19

    .line 164
    .line 165
    if-ge v8, v5, :cond_12

    .line 166
    .line 167
    if-lt p0, p3, :cond_11

    .line 168
    .line 169
    return v8

    .line 170
    :cond_11
    if-lt v8, v2, :cond_18

    .line 171
    .line 172
    add-int/lit8 p2, p2, 0x2

    .line 173
    .line 174
    aget-byte p0, p1, p0

    .line 175
    .line 176
    if-le p0, v6, :cond_f

    .line 177
    .line 178
    goto :goto_8

    .line 179
    :cond_12
    if-ge v8, v1, :cond_16

    .line 180
    .line 181
    add-int/lit8 v9, p3, -0x1

    .line 182
    .line 183
    if-lt p0, v9, :cond_13

    .line 184
    .line 185
    invoke-static {p1, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a([BII)I

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    return p0

    .line 190
    :cond_13
    add-int/lit8 v9, p2, 0x2

    .line 191
    .line 192
    aget-byte p0, p1, p0

    .line 193
    .line 194
    if-gt p0, v6, :cond_18

    .line 195
    .line 196
    if-ne v8, v5, :cond_14

    .line 197
    .line 198
    if-lt p0, v4, :cond_18

    .line 199
    .line 200
    :cond_14
    if-ne v8, v0, :cond_15

    .line 201
    .line 202
    if-ge p0, v4, :cond_18

    .line 203
    .line 204
    :cond_15
    add-int/lit8 p2, p2, 0x3

    .line 205
    .line 206
    aget-byte p0, p1, v9

    .line 207
    .line 208
    if-le p0, v6, :cond_f

    .line 209
    .line 210
    goto :goto_8

    .line 211
    :cond_16
    add-int/lit8 v9, p3, -0x2

    .line 212
    .line 213
    if-lt p0, v9, :cond_17

    .line 214
    .line 215
    invoke-static {p1, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a([BII)I

    .line 216
    .line 217
    .line 218
    move-result p0

    .line 219
    return p0

    .line 220
    :cond_17
    add-int/lit8 v9, p2, 0x2

    .line 221
    .line 222
    aget-byte p0, p1, p0

    .line 223
    .line 224
    if-gt p0, v6, :cond_18

    .line 225
    .line 226
    shl-int/lit8 v8, v8, 0x1c

    .line 227
    .line 228
    add-int/lit8 p0, p0, 0x70

    .line 229
    .line 230
    add-int/2addr p0, v8

    .line 231
    shr-int/lit8 p0, p0, 0x1e

    .line 232
    .line 233
    if-nez p0, :cond_18

    .line 234
    .line 235
    add-int/lit8 p0, p2, 0x3

    .line 236
    .line 237
    aget-byte v8, p1, v9

    .line 238
    .line 239
    if-gt v8, v6, :cond_18

    .line 240
    .line 241
    add-int/lit8 p2, p2, 0x4

    .line 242
    .line 243
    aget-byte p0, p1, p0

    .line 244
    .line 245
    if-le p0, v6, :cond_f

    .line 246
    .line 247
    :cond_18
    :goto_8
    return v7

    .line 248
    :cond_19
    move p2, p0

    .line 249
    goto :goto_6
.end method

.method public static final d(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;
    .locals 1

    .line 1
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 2
    .line 3
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_2

    .line 10
    .line 11
    iget-boolean v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->d:Z

    .line 12
    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 22
    .line 23
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;-><init>()V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;

    .line 28
    .line 29
    invoke-direct {v0, p0}, Ljava/util/LinkedHashMap;-><init>(Ljava/util/Map;)V

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x1

    .line 33
    iput-boolean p0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->d:Z

    .line 34
    .line 35
    move-object p0, v0

    .line 36
    :cond_1
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->b()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w1;->putAll(Ljava/util/Map;)V

    .line 46
    .line 47
    .line 48
    :cond_2
    return-object p0
.end method

.method public static e(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Ljava/util/Map$Entry;)V
    .locals 0

    .line 1
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 6
    .line 7
    sget-object p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    throw p0
.end method


# virtual methods
.method public a(Ljava/lang/Class;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;
    .locals 2

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string p1, "This should never be called."

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    const-class p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    :try_start_0
    invoke-virtual {p1, p0}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->e(Ljava/lang/Class;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const/4 v0, 0x3

    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-virtual {p0, v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    return-object p0

    .line 39
    :catch_0
    move-exception p0

    .line 40
    new-instance v0, Ljava/lang/RuntimeException;

    .line 41
    .line 42
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    const-string v1, "Unable to get message info for "

    .line 47
    .line 48
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-direct {v0, p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 53
    .line 54
    .line 55
    throw v0

    .line 56
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    const-string v0, "Unsupported message type: "

    .line 63
    .line 64
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public b(Ljava/lang/Class;)Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :pswitch_0
    const-class p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
