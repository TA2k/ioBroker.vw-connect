.class public final Lh/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static e:Lh/e0;


# instance fields
.field public final synthetic a:I

.field public b:I

.field public c:J

.field public d:J


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lh/e0;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh/e0;->a:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Lh/e0;->b:I

    return-void
.end method

.method public static c(Lh/e0;JJI)V
    .locals 3

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move-wide p1, v1

    .line 8
    :cond_0
    and-int/lit8 p5, p5, 0x2

    .line 9
    .line 10
    if-eqz p5, :cond_1

    .line 11
    .line 12
    move-wide p3, v1

    .line 13
    :cond_1
    monitor-enter p0

    .line 14
    cmp-long p5, p1, v1

    .line 15
    .line 16
    if-ltz p5, :cond_4

    .line 17
    .line 18
    cmp-long p5, p3, v1

    .line 19
    .line 20
    if-ltz p5, :cond_3

    .line 21
    .line 22
    :try_start_0
    iget-wide v0, p0, Lh/e0;->c:J

    .line 23
    .line 24
    add-long/2addr v0, p1

    .line 25
    iput-wide v0, p0, Lh/e0;->c:J

    .line 26
    .line 27
    iget-wide p1, p0, Lh/e0;->d:J

    .line 28
    .line 29
    add-long/2addr p1, p3

    .line 30
    iput-wide p1, p0, Lh/e0;->d:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    .line 32
    cmp-long p1, p1, v0

    .line 33
    .line 34
    if-gtz p1, :cond_2

    .line 35
    .line 36
    monitor-exit p0

    .line 37
    return-void

    .line 38
    :cond_2
    :try_start_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p2, "Check failed."

    .line 41
    .line 42
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p1

    .line 46
    :catchall_0
    move-exception p1

    .line 47
    goto :goto_0

    .line 48
    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p2, "Check failed."

    .line 51
    .line 52
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p1

    .line 56
    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string p2, "Check failed."

    .line 59
    .line 60
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p1

    .line 64
    :goto_0
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 65
    throw p1
.end method


# virtual methods
.method public a(JDD)V
    .locals 14

    .line 1
    const-wide v0, 0xdc6d62da00L

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    sub-long v2, p1, v0

    .line 7
    .line 8
    long-to-float v2, v2

    .line 9
    const v3, 0x4ca4cb80    # 8.64E7f

    .line 10
    .line 11
    .line 12
    div-float/2addr v2, v3

    .line 13
    const v3, 0x3c8ceb25

    .line 14
    .line 15
    .line 16
    mul-float/2addr v3, v2

    .line 17
    const v4, 0x40c7ae92

    .line 18
    .line 19
    .line 20
    add-float/2addr v3, v4

    .line 21
    float-to-double v4, v3

    .line 22
    const-wide v6, 0x3fa11c5fc0000000L    # 0.03341960161924362

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    invoke-static {v4, v5}, Ljava/lang/Math;->sin(D)D

    .line 28
    .line 29
    .line 30
    move-result-wide v8

    .line 31
    mul-double/2addr v8, v6

    .line 32
    add-double/2addr v8, v4

    .line 33
    const/high16 v6, 0x40000000    # 2.0f

    .line 34
    .line 35
    mul-float/2addr v6, v3

    .line 36
    float-to-double v6, v6

    .line 37
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 38
    .line 39
    .line 40
    move-result-wide v6

    .line 41
    const-wide v10, 0x3f36e05b00000000L    # 3.4906598739326E-4

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    mul-double/2addr v6, v10

    .line 47
    add-double/2addr v6, v8

    .line 48
    const/high16 v8, 0x40400000    # 3.0f

    .line 49
    .line 50
    mul-float/2addr v3, v8

    .line 51
    float-to-double v8, v3

    .line 52
    invoke-static {v8, v9}, Ljava/lang/Math;->sin(D)D

    .line 53
    .line 54
    .line 55
    move-result-wide v8

    .line 56
    const-wide v10, 0x3ed5f61cc0000000L    # 5.236000106378924E-6

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    mul-double/2addr v8, v10

    .line 62
    add-double/2addr v8, v6

    .line 63
    const-wide v6, 0x3ffcbed85e1ce332L    # 1.796593063

    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    add-double/2addr v8, v6

    .line 69
    const-wide v6, 0x400921fb54442d18L    # Math.PI

    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    add-double/2addr v8, v6

    .line 75
    move-wide/from16 v6, p5

    .line 76
    .line 77
    neg-double v6, v6

    .line 78
    const-wide v10, 0x4076800000000000L    # 360.0

    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    div-double/2addr v6, v10

    .line 84
    const v3, 0x3a6bedfa    # 9.0E-4f

    .line 85
    .line 86
    .line 87
    sub-float/2addr v2, v3

    .line 88
    float-to-double v10, v2

    .line 89
    sub-double/2addr v10, v6

    .line 90
    invoke-static {v10, v11}, Ljava/lang/Math;->round(D)J

    .line 91
    .line 92
    .line 93
    move-result-wide v10

    .line 94
    long-to-float v2, v10

    .line 95
    add-float/2addr v2, v3

    .line 96
    float-to-double v2, v2

    .line 97
    add-double/2addr v2, v6

    .line 98
    const-wide v6, 0x3f75b573eab367a1L    # 0.0053

    .line 99
    .line 100
    .line 101
    .line 102
    .line 103
    invoke-static {v4, v5}, Ljava/lang/Math;->sin(D)D

    .line 104
    .line 105
    .line 106
    move-result-wide v4

    .line 107
    mul-double/2addr v4, v6

    .line 108
    add-double/2addr v4, v2

    .line 109
    const-wide/high16 v2, 0x4000000000000000L    # 2.0

    .line 110
    .line 111
    mul-double/2addr v2, v8

    .line 112
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 113
    .line 114
    .line 115
    move-result-wide v2

    .line 116
    const-wide v6, -0x4083bcd35a858794L    # -0.0069

    .line 117
    .line 118
    .line 119
    .line 120
    .line 121
    mul-double/2addr v2, v6

    .line 122
    add-double/2addr v2, v4

    .line 123
    invoke-static {v8, v9}, Ljava/lang/Math;->sin(D)D

    .line 124
    .line 125
    .line 126
    move-result-wide v4

    .line 127
    const-wide v6, 0x3fda31a380000000L    # 0.4092797040939331

    .line 128
    .line 129
    .line 130
    .line 131
    .line 132
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 133
    .line 134
    .line 135
    move-result-wide v6

    .line 136
    mul-double/2addr v6, v4

    .line 137
    invoke-static {v6, v7}, Ljava/lang/Math;->asin(D)D

    .line 138
    .line 139
    .line 140
    move-result-wide v4

    .line 141
    const-wide v6, 0x3f91df46a0000000L    # 0.01745329238474369

    .line 142
    .line 143
    .line 144
    .line 145
    .line 146
    mul-double v6, v6, p3

    .line 147
    .line 148
    const-wide v8, -0x4045311600000000L    # -0.10471975803375244

    .line 149
    .line 150
    .line 151
    .line 152
    .line 153
    invoke-static {v8, v9}, Ljava/lang/Math;->sin(D)D

    .line 154
    .line 155
    .line 156
    move-result-wide v8

    .line 157
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 158
    .line 159
    .line 160
    move-result-wide v10

    .line 161
    invoke-static {v4, v5}, Ljava/lang/Math;->sin(D)D

    .line 162
    .line 163
    .line 164
    move-result-wide v12

    .line 165
    mul-double/2addr v12, v10

    .line 166
    sub-double/2addr v8, v12

    .line 167
    invoke-static {v6, v7}, Ljava/lang/Math;->cos(D)D

    .line 168
    .line 169
    .line 170
    move-result-wide v6

    .line 171
    invoke-static {v4, v5}, Ljava/lang/Math;->cos(D)D

    .line 172
    .line 173
    .line 174
    move-result-wide v4

    .line 175
    mul-double/2addr v4, v6

    .line 176
    div-double/2addr v8, v4

    .line 177
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 178
    .line 179
    cmpl-double v4, v8, v4

    .line 180
    .line 181
    const/4 v5, 0x1

    .line 182
    const-wide/16 v6, -0x1

    .line 183
    .line 184
    if-ltz v4, :cond_0

    .line 185
    .line 186
    iput v5, p0, Lh/e0;->b:I

    .line 187
    .line 188
    iput-wide v6, p0, Lh/e0;->c:J

    .line 189
    .line 190
    iput-wide v6, p0, Lh/e0;->d:J

    .line 191
    .line 192
    return-void

    .line 193
    :cond_0
    const-wide/high16 v10, -0x4010000000000000L    # -1.0

    .line 194
    .line 195
    cmpg-double v4, v8, v10

    .line 196
    .line 197
    const/4 v10, 0x0

    .line 198
    if-gtz v4, :cond_1

    .line 199
    .line 200
    iput v10, p0, Lh/e0;->b:I

    .line 201
    .line 202
    iput-wide v6, p0, Lh/e0;->c:J

    .line 203
    .line 204
    iput-wide v6, p0, Lh/e0;->d:J

    .line 205
    .line 206
    return-void

    .line 207
    :cond_1
    invoke-static {v8, v9}, Ljava/lang/Math;->acos(D)D

    .line 208
    .line 209
    .line 210
    move-result-wide v6

    .line 211
    const-wide v8, 0x401921fb54442d18L    # 6.283185307179586

    .line 212
    .line 213
    .line 214
    .line 215
    .line 216
    div-double/2addr v6, v8

    .line 217
    double-to-float v4, v6

    .line 218
    float-to-double v6, v4

    .line 219
    add-double v8, v2, v6

    .line 220
    .line 221
    const-wide v11, 0x4194997000000000L    # 8.64E7

    .line 222
    .line 223
    .line 224
    .line 225
    .line 226
    mul-double/2addr v8, v11

    .line 227
    invoke-static {v8, v9}, Ljava/lang/Math;->round(D)J

    .line 228
    .line 229
    .line 230
    move-result-wide v8

    .line 231
    add-long/2addr v8, v0

    .line 232
    iput-wide v8, p0, Lh/e0;->c:J

    .line 233
    .line 234
    sub-double/2addr v2, v6

    .line 235
    mul-double/2addr v2, v11

    .line 236
    invoke-static {v2, v3}, Ljava/lang/Math;->round(D)J

    .line 237
    .line 238
    .line 239
    move-result-wide v2

    .line 240
    add-long/2addr v2, v0

    .line 241
    iput-wide v2, p0, Lh/e0;->d:J

    .line 242
    .line 243
    cmp-long v0, v2, p1

    .line 244
    .line 245
    if-gez v0, :cond_2

    .line 246
    .line 247
    iget-wide v0, p0, Lh/e0;->c:J

    .line 248
    .line 249
    cmp-long v0, v0, p1

    .line 250
    .line 251
    if-lez v0, :cond_2

    .line 252
    .line 253
    iput v10, p0, Lh/e0;->b:I

    .line 254
    .line 255
    return-void

    .line 256
    :cond_2
    iput v5, p0, Lh/e0;->b:I

    .line 257
    .line 258
    return-void
.end method

.method public declared-synchronized b()J
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-wide v0, p0, Lh/e0;->c:J

    .line 3
    .line 4
    iget-wide v2, p0, Lh/e0;->d:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    sub-long/2addr v0, v2

    .line 7
    monitor-exit p0

    .line 8
    return-wide v0

    .line 9
    :catchall_0
    move-exception v0

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lh/e0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "WindowCounter(streamId="

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lh/e0;->b:I

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", total="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-wide v1, p0, Lh/e0;->c:J

    .line 29
    .line 30
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", acknowledged="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lh/e0;->d:J

    .line 39
    .line 40
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", unacknowledged="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Lh/e0;->b()J

    .line 49
    .line 50
    .line 51
    move-result-wide v1

    .line 52
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const/16 p0, 0x29

    .line 56
    .line 57
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
