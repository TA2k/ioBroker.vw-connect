.class public final Lw9/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw9/b;


# static fields
.field public static final m:[I

.field public static final n:[I


# instance fields
.field public final a:Lo8/q;

.field public final b:Lo8/i0;

.field public final c:Lcom/google/android/material/datepicker/w;

.field public final d:I

.field public final e:[B

.field public final f:Lw7/p;

.field public final g:I

.field public final h:Lt7/o;

.field public i:I

.field public j:J

.field public k:I

.field public l:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Lw9/a;->m:[I

    .line 9
    .line 10
    const/16 v0, 0x59

    .line 11
    .line 12
    new-array v0, v0, [I

    .line 13
    .line 14
    fill-array-data v0, :array_1

    .line 15
    .line 16
    .line 17
    sput-object v0, Lw9/a;->n:[I

    .line 18
    .line 19
    return-void

    .line 20
    nop

    .line 21
    :array_0
    .array-data 4
        -0x1
        -0x1
        -0x1
        -0x1
        0x2
        0x4
        0x6
        0x8
        -0x1
        -0x1
        -0x1
        -0x1
        0x2
        0x4
        0x6
        0x8
    .end array-data

    .line 22
    .line 23
    :array_1
    .array-data 4
        0x7
        0x8
        0x9
        0xa
        0xb
        0xc
        0xd
        0xe
        0x10
        0x11
        0x13
        0x15
        0x17
        0x19
        0x1c
        0x1f
        0x22
        0x25
        0x29
        0x2d
        0x32
        0x37
        0x3c
        0x42
        0x49
        0x50
        0x58
        0x61
        0x6b
        0x76
        0x82
        0x8f
        0x9d
        0xad
        0xbe
        0xd1
        0xe6
        0xfd
        0x117
        0x133
        0x151
        0x173
        0x198
        0x1c1
        0x1ee
        0x220
        0x256
        0x292
        0x2d4
        0x31c
        0x36c
        0x3c3
        0x424
        0x48e
        0x502
        0x583
        0x610
        0x6ab
        0x756
        0x812
        0x8e0
        0x9c3
        0xabd
        0xbd0
        0xcff
        0xe4c
        0xfba
        0x114c
        0x1307
        0x14ee
        0x1706
        0x1954
        0x1bdc
        0x1ea5
        0x21b6
        0x2515
        0x28ca
        0x2cdf
        0x315b
        0x364b
        0x3bb9
        0x41b2
        0x4844
        0x4f7e
        0x5771
        0x602f
        0x69ce
        0x7462
        0x7fff
    .end array-data
.end method

.method public constructor <init>(Lo8/q;Lo8/i0;Lcom/google/android/material/datepicker/w;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw9/a;->a:Lo8/q;

    .line 5
    .line 6
    iput-object p2, p0, Lw9/a;->b:Lo8/i0;

    .line 7
    .line 8
    iput-object p3, p0, Lw9/a;->c:Lcom/google/android/material/datepicker/w;

    .line 9
    .line 10
    iget p1, p3, Lcom/google/android/material/datepicker/w;->f:I

    .line 11
    .line 12
    div-int/lit8 p2, p1, 0xa

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-static {v0, p2}, Ljava/lang/Math;->max(II)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iput p2, p0, Lw9/a;->g:I

    .line 20
    .line 21
    new-instance v1, Lw7/p;

    .line 22
    .line 23
    iget-object v2, p3, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v2, [B

    .line 26
    .line 27
    invoke-direct {v1, v2}, Lw7/p;-><init>([B)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Lw7/p;->p()I

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Lw7/p;->p()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iput v1, p0, Lw9/a;->d:I

    .line 38
    .line 39
    iget v2, p3, Lcom/google/android/material/datepicker/w;->e:I

    .line 40
    .line 41
    iget v3, p3, Lcom/google/android/material/datepicker/w;->g:I

    .line 42
    .line 43
    mul-int/lit8 v4, v2, 0x4

    .line 44
    .line 45
    sub-int v4, v3, v4

    .line 46
    .line 47
    mul-int/lit8 v4, v4, 0x8

    .line 48
    .line 49
    iget p3, p3, Lcom/google/android/material/datepicker/w;->h:I

    .line 50
    .line 51
    mul-int/2addr p3, v2

    .line 52
    div-int/2addr v4, p3

    .line 53
    add-int/2addr v4, v0

    .line 54
    if-ne v1, v4, :cond_0

    .line 55
    .line 56
    invoke-static {p2, v1}, Lw7/w;->e(II)I

    .line 57
    .line 58
    .line 59
    move-result p3

    .line 60
    mul-int v0, p3, v3

    .line 61
    .line 62
    new-array v0, v0, [B

    .line 63
    .line 64
    iput-object v0, p0, Lw9/a;->e:[B

    .line 65
    .line 66
    new-instance v0, Lw7/p;

    .line 67
    .line 68
    mul-int/lit8 v4, v1, 0x2

    .line 69
    .line 70
    mul-int/2addr v4, v2

    .line 71
    mul-int/2addr v4, p3

    .line 72
    invoke-direct {v0, v4}, Lw7/p;-><init>(I)V

    .line 73
    .line 74
    .line 75
    iput-object v0, p0, Lw9/a;->f:Lw7/p;

    .line 76
    .line 77
    mul-int/2addr v3, p1

    .line 78
    mul-int/lit8 v3, v3, 0x8

    .line 79
    .line 80
    div-int/2addr v3, v1

    .line 81
    new-instance p3, Lt7/n;

    .line 82
    .line 83
    invoke-direct {p3}, Lt7/n;-><init>()V

    .line 84
    .line 85
    .line 86
    const-string v0, "audio/raw"

    .line 87
    .line 88
    invoke-static {v0}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    iput-object v0, p3, Lt7/n;->m:Ljava/lang/String;

    .line 93
    .line 94
    iput v3, p3, Lt7/n;->h:I

    .line 95
    .line 96
    iput v3, p3, Lt7/n;->i:I

    .line 97
    .line 98
    const/4 v0, 0x2

    .line 99
    mul-int/2addr p2, v0

    .line 100
    mul-int/2addr p2, v2

    .line 101
    iput p2, p3, Lt7/n;->n:I

    .line 102
    .line 103
    iput v2, p3, Lt7/n;->E:I

    .line 104
    .line 105
    iput p1, p3, Lt7/n;->F:I

    .line 106
    .line 107
    iput v0, p3, Lt7/n;->G:I

    .line 108
    .line 109
    new-instance p1, Lt7/o;

    .line 110
    .line 111
    invoke-direct {p1, p3}, Lt7/o;-><init>(Lt7/n;)V

    .line 112
    .line 113
    .line 114
    iput-object p1, p0, Lw9/a;->h:Lt7/o;

    .line 115
    .line 116
    return-void

    .line 117
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 118
    .line 119
    const-string p1, "Expected frames per block: "

    .line 120
    .line 121
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string p1, "; got: "

    .line 128
    .line 129
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    const/4 p1, 0x0

    .line 140
    invoke-static {p1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    throw p0
.end method


# virtual methods
.method public final a(IJ)V
    .locals 7

    .line 1
    new-instance v0, Lw9/f;

    .line 2
    .line 3
    iget v2, p0, Lw9/a;->d:I

    .line 4
    .line 5
    int-to-long v3, p1

    .line 6
    iget-object v1, p0, Lw9/a;->c:Lcom/google/android/material/datepicker/w;

    .line 7
    .line 8
    move-wide v5, p2

    .line 9
    invoke-direct/range {v0 .. v6}, Lw9/f;-><init>(Lcom/google/android/material/datepicker/w;IJJ)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lw9/a;->a:Lo8/q;

    .line 13
    .line 14
    invoke-interface {p1, v0}, Lo8/q;->c(Lo8/c0;)V

    .line 15
    .line 16
    .line 17
    iget-object p1, p0, Lw9/a;->h:Lt7/o;

    .line 18
    .line 19
    iget-object p0, p0, Lw9/a;->b:Lo8/i0;

    .line 20
    .line 21
    invoke-interface {p0, p1}, Lo8/i0;->c(Lt7/o;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final b(Lo8/p;J)Z
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p2

    .line 4
    .line 5
    iget v3, v0, Lw9/a;->k:I

    .line 6
    .line 7
    iget-object v4, v0, Lw9/a;->c:Lcom/google/android/material/datepicker/w;

    .line 8
    .line 9
    iget v5, v4, Lcom/google/android/material/datepicker/w;->e:I

    .line 10
    .line 11
    mul-int/lit8 v5, v5, 0x2

    .line 12
    .line 13
    div-int/2addr v3, v5

    .line 14
    iget v5, v0, Lw9/a;->g:I

    .line 15
    .line 16
    sub-int v3, v5, v3

    .line 17
    .line 18
    iget v6, v0, Lw9/a;->d:I

    .line 19
    .line 20
    invoke-static {v3, v6}, Lw7/w;->e(II)I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    iget v7, v4, Lcom/google/android/material/datepicker/w;->g:I

    .line 25
    .line 26
    mul-int/2addr v3, v7

    .line 27
    const-wide/16 v8, 0x0

    .line 28
    .line 29
    cmp-long v8, v1, v8

    .line 30
    .line 31
    if-nez v8, :cond_0

    .line 32
    .line 33
    :goto_0
    const/4 v8, 0x1

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    const/4 v8, 0x0

    .line 36
    :goto_1
    iget-object v11, v0, Lw9/a;->e:[B

    .line 37
    .line 38
    if-nez v8, :cond_2

    .line 39
    .line 40
    iget v12, v0, Lw9/a;->i:I

    .line 41
    .line 42
    if-ge v12, v3, :cond_2

    .line 43
    .line 44
    sub-int v12, v3, v12

    .line 45
    .line 46
    int-to-long v12, v12

    .line 47
    invoke-static {v12, v13, v1, v2}, Ljava/lang/Math;->min(JJ)J

    .line 48
    .line 49
    .line 50
    move-result-wide v12

    .line 51
    long-to-int v12, v12

    .line 52
    iget v13, v0, Lw9/a;->i:I

    .line 53
    .line 54
    move-object/from16 v14, p1

    .line 55
    .line 56
    invoke-interface {v14, v11, v13, v12}, Lt7/g;->read([BII)I

    .line 57
    .line 58
    .line 59
    move-result v11

    .line 60
    const/4 v12, -0x1

    .line 61
    if-ne v11, v12, :cond_1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    iget v12, v0, Lw9/a;->i:I

    .line 65
    .line 66
    add-int/2addr v12, v11

    .line 67
    iput v12, v0, Lw9/a;->i:I

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    iget v1, v0, Lw9/a;->i:I

    .line 71
    .line 72
    div-int/2addr v1, v7

    .line 73
    if-lez v1, :cond_8

    .line 74
    .line 75
    const/4 v2, 0x0

    .line 76
    :goto_2
    iget-object v3, v0, Lw9/a;->f:Lw7/p;

    .line 77
    .line 78
    if-ge v2, v1, :cond_7

    .line 79
    .line 80
    const/4 v12, 0x0

    .line 81
    :goto_3
    iget v13, v4, Lcom/google/android/material/datepicker/w;->e:I

    .line 82
    .line 83
    if-ge v12, v13, :cond_6

    .line 84
    .line 85
    iget-object v14, v3, Lw7/p;->a:[B

    .line 86
    .line 87
    mul-int v15, v2, v7

    .line 88
    .line 89
    mul-int/lit8 v16, v12, 0x4

    .line 90
    .line 91
    add-int v16, v16, v15

    .line 92
    .line 93
    mul-int/lit8 v15, v13, 0x4

    .line 94
    .line 95
    add-int v15, v15, v16

    .line 96
    .line 97
    div-int v17, v7, v13

    .line 98
    .line 99
    add-int/lit8 v17, v17, -0x4

    .line 100
    .line 101
    add-int/lit8 v18, v16, 0x1

    .line 102
    .line 103
    const/16 v19, 0x1

    .line 104
    .line 105
    aget-byte v10, v11, v18

    .line 106
    .line 107
    and-int/lit16 v10, v10, 0xff

    .line 108
    .line 109
    shl-int/lit8 v10, v10, 0x8

    .line 110
    .line 111
    aget-byte v9, v11, v16

    .line 112
    .line 113
    and-int/lit16 v9, v9, 0xff

    .line 114
    .line 115
    or-int/2addr v9, v10

    .line 116
    int-to-short v9, v9

    .line 117
    add-int/lit8 v16, v16, 0x2

    .line 118
    .line 119
    aget-byte v10, v11, v16

    .line 120
    .line 121
    and-int/lit16 v10, v10, 0xff

    .line 122
    .line 123
    move/from16 p1, v1

    .line 124
    .line 125
    const/16 v1, 0x58

    .line 126
    .line 127
    invoke-static {v10, v1}, Ljava/lang/Math;->min(II)I

    .line 128
    .line 129
    .line 130
    move-result v10

    .line 131
    sget-object v16, Lw9/a;->n:[I

    .line 132
    .line 133
    aget v20, v16, v10

    .line 134
    .line 135
    mul-int v21, v2, v6

    .line 136
    .line 137
    mul-int v21, v21, v13

    .line 138
    .line 139
    add-int v21, v21, v12

    .line 140
    .line 141
    mul-int/lit8 v21, v21, 0x2

    .line 142
    .line 143
    and-int/lit16 v1, v9, 0xff

    .line 144
    .line 145
    int-to-byte v1, v1

    .line 146
    aput-byte v1, v14, v21

    .line 147
    .line 148
    add-int/lit8 v1, v21, 0x1

    .line 149
    .line 150
    move/from16 p3, v1

    .line 151
    .line 152
    shr-int/lit8 v1, v9, 0x8

    .line 153
    .line 154
    int-to-byte v1, v1

    .line 155
    aput-byte v1, v14, p3

    .line 156
    .line 157
    move/from16 p3, v2

    .line 158
    .line 159
    const/4 v1, 0x0

    .line 160
    :goto_4
    mul-int/lit8 v2, v17, 0x2

    .line 161
    .line 162
    if-ge v1, v2, :cond_5

    .line 163
    .line 164
    div-int/lit8 v2, v1, 0x8

    .line 165
    .line 166
    div-int/lit8 v22, v1, 0x2

    .line 167
    .line 168
    rem-int/lit8 v22, v22, 0x4

    .line 169
    .line 170
    mul-int/2addr v2, v13

    .line 171
    mul-int/lit8 v2, v2, 0x4

    .line 172
    .line 173
    add-int/2addr v2, v15

    .line 174
    add-int v2, v2, v22

    .line 175
    .line 176
    aget-byte v2, v11, v2

    .line 177
    .line 178
    move/from16 v22, v1

    .line 179
    .line 180
    and-int/lit16 v1, v2, 0xff

    .line 181
    .line 182
    rem-int/lit8 v23, v22, 0x2

    .line 183
    .line 184
    if-nez v23, :cond_3

    .line 185
    .line 186
    and-int/lit8 v1, v2, 0xf

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_3
    shr-int/lit8 v1, v1, 0x4

    .line 190
    .line 191
    :goto_5
    and-int/lit8 v2, v1, 0x7

    .line 192
    .line 193
    mul-int/lit8 v2, v2, 0x2

    .line 194
    .line 195
    add-int/lit8 v2, v2, 0x1

    .line 196
    .line 197
    mul-int v2, v2, v20

    .line 198
    .line 199
    shr-int/lit8 v2, v2, 0x3

    .line 200
    .line 201
    and-int/lit8 v20, v1, 0x8

    .line 202
    .line 203
    if-eqz v20, :cond_4

    .line 204
    .line 205
    neg-int v2, v2

    .line 206
    :cond_4
    add-int/2addr v9, v2

    .line 207
    const/16 v2, -0x8000

    .line 208
    .line 209
    move/from16 v20, v1

    .line 210
    .line 211
    const/16 v1, 0x7fff

    .line 212
    .line 213
    invoke-static {v9, v2, v1}, Lw7/w;->g(III)I

    .line 214
    .line 215
    .line 216
    move-result v9

    .line 217
    mul-int/lit8 v1, v13, 0x2

    .line 218
    .line 219
    add-int v21, v1, v21

    .line 220
    .line 221
    and-int/lit16 v1, v9, 0xff

    .line 222
    .line 223
    int-to-byte v1, v1

    .line 224
    aput-byte v1, v14, v21

    .line 225
    .line 226
    add-int/lit8 v1, v21, 0x1

    .line 227
    .line 228
    shr-int/lit8 v2, v9, 0x8

    .line 229
    .line 230
    int-to-byte v2, v2

    .line 231
    aput-byte v2, v14, v1

    .line 232
    .line 233
    sget-object v1, Lw9/a;->m:[I

    .line 234
    .line 235
    aget v1, v1, v20

    .line 236
    .line 237
    add-int/2addr v10, v1

    .line 238
    const/4 v1, 0x0

    .line 239
    const/16 v2, 0x58

    .line 240
    .line 241
    invoke-static {v10, v1, v2}, Lw7/w;->g(III)I

    .line 242
    .line 243
    .line 244
    move-result v10

    .line 245
    aget v20, v16, v10

    .line 246
    .line 247
    add-int/lit8 v1, v22, 0x1

    .line 248
    .line 249
    goto :goto_4

    .line 250
    :cond_5
    add-int/lit8 v12, v12, 0x1

    .line 251
    .line 252
    move/from16 v1, p1

    .line 253
    .line 254
    move/from16 v2, p3

    .line 255
    .line 256
    goto/16 :goto_3

    .line 257
    .line 258
    :cond_6
    move/from16 p1, v1

    .line 259
    .line 260
    move/from16 p3, v2

    .line 261
    .line 262
    const/16 v19, 0x1

    .line 263
    .line 264
    add-int/lit8 v2, p3, 0x1

    .line 265
    .line 266
    goto/16 :goto_2

    .line 267
    .line 268
    :cond_7
    move/from16 p1, v1

    .line 269
    .line 270
    mul-int v6, v6, p1

    .line 271
    .line 272
    iget v1, v4, Lcom/google/android/material/datepicker/w;->e:I

    .line 273
    .line 274
    mul-int/lit8 v6, v6, 0x2

    .line 275
    .line 276
    mul-int/2addr v6, v1

    .line 277
    const/4 v1, 0x0

    .line 278
    invoke-virtual {v3, v1}, Lw7/p;->I(I)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v3, v6}, Lw7/p;->H(I)V

    .line 282
    .line 283
    .line 284
    iget v2, v0, Lw9/a;->i:I

    .line 285
    .line 286
    mul-int v6, p1, v7

    .line 287
    .line 288
    sub-int/2addr v2, v6

    .line 289
    iput v2, v0, Lw9/a;->i:I

    .line 290
    .line 291
    iget v2, v3, Lw7/p;->c:I

    .line 292
    .line 293
    iget-object v6, v0, Lw9/a;->b:Lo8/i0;

    .line 294
    .line 295
    invoke-interface {v6, v3, v2, v1}, Lo8/i0;->a(Lw7/p;II)V

    .line 296
    .line 297
    .line 298
    iget v1, v0, Lw9/a;->k:I

    .line 299
    .line 300
    add-int/2addr v1, v2

    .line 301
    iput v1, v0, Lw9/a;->k:I

    .line 302
    .line 303
    iget v2, v4, Lcom/google/android/material/datepicker/w;->e:I

    .line 304
    .line 305
    mul-int/lit8 v2, v2, 0x2

    .line 306
    .line 307
    div-int/2addr v1, v2

    .line 308
    if-lt v1, v5, :cond_8

    .line 309
    .line 310
    invoke-virtual {v0, v5}, Lw9/a;->d(I)V

    .line 311
    .line 312
    .line 313
    :cond_8
    if-eqz v8, :cond_9

    .line 314
    .line 315
    iget v1, v0, Lw9/a;->k:I

    .line 316
    .line 317
    iget v2, v4, Lcom/google/android/material/datepicker/w;->e:I

    .line 318
    .line 319
    mul-int/lit8 v2, v2, 0x2

    .line 320
    .line 321
    div-int/2addr v1, v2

    .line 322
    if-lez v1, :cond_9

    .line 323
    .line 324
    invoke-virtual {v0, v1}, Lw9/a;->d(I)V

    .line 325
    .line 326
    .line 327
    :cond_9
    return v8
.end method

.method public final c(J)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lw9/a;->i:I

    .line 3
    .line 4
    iput-wide p1, p0, Lw9/a;->j:J

    .line 5
    .line 6
    iput v0, p0, Lw9/a;->k:I

    .line 7
    .line 8
    const-wide/16 p1, 0x0

    .line 9
    .line 10
    iput-wide p1, p0, Lw9/a;->l:J

    .line 11
    .line 12
    return-void
.end method

.method public final d(I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget-wide v2, v0, Lw9/a;->j:J

    .line 6
    .line 7
    iget-wide v4, v0, Lw9/a;->l:J

    .line 8
    .line 9
    iget-object v11, v0, Lw9/a;->c:Lcom/google/android/material/datepicker/w;

    .line 10
    .line 11
    iget v6, v11, Lcom/google/android/material/datepicker/w;->f:I

    .line 12
    .line 13
    int-to-long v8, v6

    .line 14
    sget-object v6, Lw7/w;->a:Ljava/lang/String;

    .line 15
    .line 16
    sget-object v10, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 17
    .line 18
    const-wide/32 v6, 0xf4240

    .line 19
    .line 20
    .line 21
    invoke-static/range {v4 .. v10}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v4

    .line 25
    add-long v13, v2, v4

    .line 26
    .line 27
    iget v2, v11, Lcom/google/android/material/datepicker/w;->e:I

    .line 28
    .line 29
    mul-int/lit8 v3, v1, 0x2

    .line 30
    .line 31
    mul-int v16, v3, v2

    .line 32
    .line 33
    iget v2, v0, Lw9/a;->k:I

    .line 34
    .line 35
    sub-int v17, v2, v16

    .line 36
    .line 37
    const/4 v15, 0x1

    .line 38
    const/16 v18, 0x0

    .line 39
    .line 40
    iget-object v12, v0, Lw9/a;->b:Lo8/i0;

    .line 41
    .line 42
    invoke-interface/range {v12 .. v18}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 43
    .line 44
    .line 45
    iget-wide v2, v0, Lw9/a;->l:J

    .line 46
    .line 47
    int-to-long v4, v1

    .line 48
    add-long/2addr v2, v4

    .line 49
    iput-wide v2, v0, Lw9/a;->l:J

    .line 50
    .line 51
    iget v1, v0, Lw9/a;->k:I

    .line 52
    .line 53
    sub-int v1, v1, v16

    .line 54
    .line 55
    iput v1, v0, Lw9/a;->k:I

    .line 56
    .line 57
    return-void
.end method
