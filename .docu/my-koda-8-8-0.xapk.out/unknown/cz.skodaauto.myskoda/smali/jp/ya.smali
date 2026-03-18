.class public abstract Ljp/ya;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lmv/a;)Ljava/nio/ByteBuffer;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lmv/a;->f:I

    .line 4
    .line 5
    const/4 v2, -0x1

    .line 6
    if-eq v1, v2, :cond_3

    .line 7
    .line 8
    const/16 v2, 0x11

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-eq v1, v2, :cond_2

    .line 12
    .line 13
    const/16 v2, 0x23

    .line 14
    .line 15
    if-eq v1, v2, :cond_1

    .line 16
    .line 17
    const v0, 0x32315659

    .line 18
    .line 19
    .line 20
    if-eq v1, v0, :cond_0

    .line 21
    .line 22
    new-instance v0, Lbv/a;

    .line 23
    .line 24
    const-string v1, "Unsupported image format"

    .line 25
    .line 26
    const/16 v2, 0xd

    .line 27
    .line 28
    invoke-direct {v0, v1, v2}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 29
    .line 30
    .line 31
    throw v0

    .line 32
    :cond_0
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    throw v3

    .line 36
    :cond_1
    invoke-virtual {v0}, Lmv/a;->b()[Landroid/media/Image$Plane;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    iget v2, v0, Lmv/a;->c:I

    .line 44
    .line 45
    iget v0, v0, Lmv/a;->d:I

    .line 46
    .line 47
    invoke-static {v1, v2, v0}, Ljp/ya;->c([Landroid/media/Image$Plane;II)Ljava/nio/ByteBuffer;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    return-object v0

    .line 52
    :cond_2
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    throw v3

    .line 56
    :cond_3
    iget-object v0, v0, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 57
    .line 58
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    sget-object v2, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 66
    .line 67
    if-ne v1, v2, :cond_4

    .line 68
    .line 69
    sget-object v1, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 70
    .line 71
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->isMutable()Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    invoke-virtual {v0, v1, v2}, Landroid/graphics/Bitmap;->copy(Landroid/graphics/Bitmap$Config;Z)Landroid/graphics/Bitmap;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    :cond_4
    move-object v1, v0

    .line 80
    invoke-virtual {v1}, Landroid/graphics/Bitmap;->getWidth()I

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    invoke-virtual {v1}, Landroid/graphics/Bitmap;->getHeight()I

    .line 85
    .line 86
    .line 87
    move-result v8

    .line 88
    mul-int v0, v4, v8

    .line 89
    .line 90
    new-array v2, v0, [I

    .line 91
    .line 92
    const/4 v5, 0x0

    .line 93
    const/4 v6, 0x0

    .line 94
    const/4 v3, 0x0

    .line 95
    move v7, v4

    .line 96
    invoke-virtual/range {v1 .. v8}, Landroid/graphics/Bitmap;->getPixels([IIIIIII)V

    .line 97
    .line 98
    .line 99
    int-to-double v5, v8

    .line 100
    const-wide/high16 v9, 0x4000000000000000L    # 2.0

    .line 101
    .line 102
    div-double/2addr v5, v9

    .line 103
    invoke-static {v5, v6}, Ljava/lang/Math;->ceil(D)D

    .line 104
    .line 105
    .line 106
    move-result-wide v5

    .line 107
    double-to-int v1, v5

    .line 108
    int-to-double v5, v4

    .line 109
    div-double/2addr v5, v9

    .line 110
    invoke-static {v5, v6}, Ljava/lang/Math;->ceil(D)D

    .line 111
    .line 112
    .line 113
    move-result-wide v5

    .line 114
    double-to-int v3, v5

    .line 115
    add-int/2addr v1, v1

    .line 116
    mul-int/2addr v1, v3

    .line 117
    add-int/2addr v1, v0

    .line 118
    invoke-static {v1}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    const/4 v5, 0x0

    .line 123
    const/4 v6, 0x0

    .line 124
    const/4 v7, 0x0

    .line 125
    :goto_0
    if-ge v5, v8, :cond_7

    .line 126
    .line 127
    const/4 v9, 0x0

    .line 128
    :goto_1
    if-ge v9, v4, :cond_6

    .line 129
    .line 130
    aget v10, v2, v7

    .line 131
    .line 132
    shr-int/lit8 v11, v10, 0x10

    .line 133
    .line 134
    shr-int/lit8 v12, v10, 0x8

    .line 135
    .line 136
    const/16 v13, 0xff

    .line 137
    .line 138
    and-int/2addr v10, v13

    .line 139
    add-int/lit8 v14, v6, 0x1

    .line 140
    .line 141
    and-int/2addr v11, v13

    .line 142
    and-int/2addr v12, v13

    .line 143
    mul-int/lit8 v15, v11, 0x42

    .line 144
    .line 145
    mul-int/lit16 v3, v12, 0x81

    .line 146
    .line 147
    add-int/2addr v3, v15

    .line 148
    mul-int/lit8 v15, v10, 0x19

    .line 149
    .line 150
    add-int/2addr v15, v3

    .line 151
    add-int/lit16 v15, v15, 0x80

    .line 152
    .line 153
    shr-int/lit8 v3, v15, 0x8

    .line 154
    .line 155
    add-int/lit8 v3, v3, 0x10

    .line 156
    .line 157
    invoke-static {v13, v3}, Ljava/lang/Math;->min(II)I

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    int-to-byte v3, v3

    .line 162
    invoke-virtual {v1, v6, v3}, Ljava/nio/ByteBuffer;->put(IB)Ljava/nio/ByteBuffer;

    .line 163
    .line 164
    .line 165
    rem-int/lit8 v3, v5, 0x2

    .line 166
    .line 167
    if-nez v3, :cond_5

    .line 168
    .line 169
    rem-int/lit8 v3, v7, 0x2

    .line 170
    .line 171
    if-nez v3, :cond_5

    .line 172
    .line 173
    mul-int/lit8 v3, v12, 0x5e

    .line 174
    .line 175
    mul-int/lit8 v6, v11, 0x70

    .line 176
    .line 177
    mul-int/lit8 v12, v12, 0x4a

    .line 178
    .line 179
    mul-int/lit8 v11, v11, -0x26

    .line 180
    .line 181
    sub-int/2addr v6, v3

    .line 182
    mul-int/lit8 v3, v10, 0x12

    .line 183
    .line 184
    sub-int/2addr v11, v12

    .line 185
    mul-int/lit8 v10, v10, 0x70

    .line 186
    .line 187
    sub-int/2addr v6, v3

    .line 188
    add-int/lit16 v6, v6, 0x80

    .line 189
    .line 190
    add-int/2addr v11, v10

    .line 191
    add-int/lit16 v11, v11, 0x80

    .line 192
    .line 193
    shr-int/lit8 v3, v6, 0x8

    .line 194
    .line 195
    shr-int/lit8 v6, v11, 0x8

    .line 196
    .line 197
    add-int/lit16 v3, v3, 0x80

    .line 198
    .line 199
    add-int/lit16 v6, v6, 0x80

    .line 200
    .line 201
    add-int/lit8 v10, v0, 0x1

    .line 202
    .line 203
    invoke-static {v13, v3}, Ljava/lang/Math;->min(II)I

    .line 204
    .line 205
    .line 206
    move-result v3

    .line 207
    int-to-byte v3, v3

    .line 208
    invoke-virtual {v1, v0, v3}, Ljava/nio/ByteBuffer;->put(IB)Ljava/nio/ByteBuffer;

    .line 209
    .line 210
    .line 211
    add-int/lit8 v0, v0, 0x2

    .line 212
    .line 213
    invoke-static {v13, v6}, Ljava/lang/Math;->min(II)I

    .line 214
    .line 215
    .line 216
    move-result v3

    .line 217
    int-to-byte v3, v3

    .line 218
    invoke-virtual {v1, v10, v3}, Ljava/nio/ByteBuffer;->put(IB)Ljava/nio/ByteBuffer;

    .line 219
    .line 220
    .line 221
    :cond_5
    add-int/lit8 v7, v7, 0x1

    .line 222
    .line 223
    add-int/lit8 v9, v9, 0x1

    .line 224
    .line 225
    move v6, v14

    .line 226
    goto :goto_1

    .line 227
    :cond_6
    add-int/lit8 v5, v5, 0x1

    .line 228
    .line 229
    goto :goto_0

    .line 230
    :cond_7
    return-object v1
.end method

.method public static final b(Lbo0/i;Ljava/util/List;Ljava/util/List;Lij0/a;Z)Lbo0/i;
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "timers"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "stringResource"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    move-object v0, p2

    .line 17
    check-cast v0, Ljava/lang/Iterable;

    .line 18
    .line 19
    new-instance v1, Ljava/util/ArrayList;

    .line 20
    .line 21
    const/16 v2, 0xa

    .line 22
    .line 23
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 28
    .line 29
    .line 30
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    const/4 v3, 0x0

    .line 39
    if-eqz v2, :cond_4

    .line 40
    .line 41
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Lao0/c;

    .line 46
    .line 47
    new-instance v4, Lbo0/h;

    .line 48
    .line 49
    iget-wide v5, v2, Lao0/c;->a:J

    .line 50
    .line 51
    const-wide/16 v7, 0x1

    .line 52
    .line 53
    invoke-static {v5, v6, v7, v8}, Lao0/d;->a(JJ)Z

    .line 54
    .line 55
    .line 56
    move-result v7

    .line 57
    if-eqz v7, :cond_0

    .line 58
    .line 59
    new-array v3, v3, [Ljava/lang/Object;

    .line 60
    .line 61
    move-object v7, p3

    .line 62
    check-cast v7, Ljj0/f;

    .line 63
    .line 64
    const v8, 0x7f120141

    .line 65
    .line 66
    .line 67
    invoke-virtual {v7, v8, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    :goto_1
    move-object v7, v3

    .line 72
    goto :goto_2

    .line 73
    :cond_0
    const-wide/16 v7, 0x2

    .line 74
    .line 75
    invoke-static {v5, v6, v7, v8}, Lao0/d;->a(JJ)Z

    .line 76
    .line 77
    .line 78
    move-result v7

    .line 79
    if-eqz v7, :cond_1

    .line 80
    .line 81
    new-array v3, v3, [Ljava/lang/Object;

    .line 82
    .line 83
    move-object v7, p3

    .line 84
    check-cast v7, Ljj0/f;

    .line 85
    .line 86
    const v8, 0x7f120142

    .line 87
    .line 88
    .line 89
    invoke-virtual {v7, v8, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    goto :goto_1

    .line 94
    :cond_1
    const-wide/16 v7, 0x3

    .line 95
    .line 96
    invoke-static {v5, v6, v7, v8}, Lao0/d;->a(JJ)Z

    .line 97
    .line 98
    .line 99
    move-result v7

    .line 100
    if-eqz v7, :cond_2

    .line 101
    .line 102
    new-array v3, v3, [Ljava/lang/Object;

    .line 103
    .line 104
    move-object v7, p3

    .line 105
    check-cast v7, Ljj0/f;

    .line 106
    .line 107
    const v8, 0x7f120143

    .line 108
    .line 109
    .line 110
    invoke-virtual {v7, v8, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    goto :goto_1

    .line 115
    :cond_2
    const-string v3, ""

    .line 116
    .line 117
    goto :goto_1

    .line 118
    :goto_2
    iget-object v3, v2, Lao0/c;->c:Ljava/time/LocalTime;

    .line 119
    .line 120
    invoke-static {v3}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    iget-object v3, v2, Lao0/c;->d:Lao0/f;

    .line 125
    .line 126
    sget-object v9, Lao0/f;->d:Lao0/f;

    .line 127
    .line 128
    if-ne v3, v9, :cond_3

    .line 129
    .line 130
    invoke-static {v2}, Ljp/ab;->a(Lao0/c;)Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    :goto_3
    move-object v9, v3

    .line 135
    goto :goto_4

    .line 136
    :cond_3
    const/4 v3, 0x0

    .line 137
    goto :goto_3

    .line 138
    :goto_4
    iget-boolean v10, v2, Lao0/c;->b:Z

    .line 139
    .line 140
    invoke-direct/range {v4 .. v10}, Lbo0/h;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    goto :goto_0

    .line 147
    :cond_4
    new-instance p3, La5/f;

    .line 148
    .line 149
    const/4 v0, 0x3

    .line 150
    invoke-direct {p3, v0}, La5/f;-><init>(I)V

    .line 151
    .line 152
    .line 153
    invoke-static {v1, p3}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 154
    .line 155
    .line 156
    move-result-object p3

    .line 157
    if-eqz p1, :cond_5

    .line 158
    .line 159
    invoke-static {p1, p2}, Landroidx/glance/appwidget/protobuf/f1;->e(Ljava/util/List;Ljava/util/List;)Z

    .line 160
    .line 161
    .line 162
    move-result p1

    .line 163
    if-nez p1, :cond_6

    .line 164
    .line 165
    :cond_5
    if-nez p4, :cond_6

    .line 166
    .line 167
    const/4 p1, 0x1

    .line 168
    goto :goto_5

    .line 169
    :cond_6
    move p1, v3

    .line 170
    :goto_5
    const/4 p2, 0x4

    .line 171
    invoke-static {p0, p3, p1, v3, p2}, Lbo0/i;->a(Lbo0/i;Ljava/util/List;ZZI)Lbo0/i;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    return-object p0
.end method

.method public static c([Landroid/media/Image$Plane;II)Ljava/nio/ByteBuffer;
    .locals 12

    .line 1
    mul-int v4, p1, p2

    .line 2
    .line 3
    div-int/lit8 v0, v4, 0x4

    .line 4
    .line 5
    add-int/2addr v0, v0

    .line 6
    add-int/2addr v0, v4

    .line 7
    new-array v8, v0, [B

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    aget-object v1, p0, v0

    .line 11
    .line 12
    invoke-virtual {v1}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const/4 v2, 0x2

    .line 17
    aget-object v3, p0, v2

    .line 18
    .line 19
    invoke-virtual {v3}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    invoke-virtual {v1}, Ljava/nio/Buffer;->limit()I

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    add-int/lit8 v7, v5, 0x1

    .line 32
    .line 33
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 34
    .line 35
    .line 36
    add-int/lit8 v7, v6, -0x1

    .line 37
    .line 38
    invoke-virtual {v1, v7}, Ljava/nio/ByteBuffer;->limit(I)Ljava/nio/Buffer;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/nio/Buffer;->remaining()I

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    add-int v9, v4, v4

    .line 46
    .line 47
    div-int/lit8 v9, v9, 0x4

    .line 48
    .line 49
    add-int/lit8 v10, v9, -0x2

    .line 50
    .line 51
    const/4 v11, 0x0

    .line 52
    if-ne v7, v10, :cond_0

    .line 53
    .line 54
    invoke-virtual {v3, v1}, Ljava/nio/ByteBuffer;->compareTo(Ljava/nio/ByteBuffer;)I

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    if-nez v7, :cond_0

    .line 59
    .line 60
    move v7, v0

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    move v7, v11

    .line 63
    :goto_0
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v1, v6}, Ljava/nio/ByteBuffer;->limit(I)Ljava/nio/Buffer;

    .line 67
    .line 68
    .line 69
    if-eqz v7, :cond_1

    .line 70
    .line 71
    aget-object p1, p0, v11

    .line 72
    .line 73
    invoke-virtual {p1}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-virtual {p1, v8, v11, v4}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 78
    .line 79
    .line 80
    aget-object p1, p0, v0

    .line 81
    .line 82
    invoke-virtual {p1}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    aget-object p0, p0, v2

    .line 87
    .line 88
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-virtual {p0, v8, v4, v0}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 93
    .line 94
    .line 95
    add-int/2addr v4, v0

    .line 96
    add-int/lit8 v9, v9, -0x1

    .line 97
    .line 98
    invoke-virtual {p1, v8, v4, v9}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_1
    aget-object v5, p0, v11

    .line 103
    .line 104
    const/4 v9, 0x0

    .line 105
    const/4 v10, 0x1

    .line 106
    move v6, p1

    .line 107
    move v7, p2

    .line 108
    invoke-static/range {v5 .. v10}, Ljp/ya;->e(Landroid/media/Image$Plane;II[BII)V

    .line 109
    .line 110
    .line 111
    aget-object v5, p0, v0

    .line 112
    .line 113
    add-int/lit8 v9, v4, 0x1

    .line 114
    .line 115
    const/4 v10, 0x2

    .line 116
    invoke-static/range {v5 .. v10}, Ljp/ya;->e(Landroid/media/Image$Plane;II[BII)V

    .line 117
    .line 118
    .line 119
    aget-object v0, p0, v2

    .line 120
    .line 121
    const/4 v5, 0x2

    .line 122
    move v1, v6

    .line 123
    move v2, v7

    .line 124
    move-object v3, v8

    .line 125
    invoke-static/range {v0 .. v5}, Ljp/ya;->e(Landroid/media/Image$Plane;II[BII)V

    .line 126
    .line 127
    .line 128
    :goto_1
    invoke-static {v8}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0
.end method

.method public static d(Landroid/graphics/Bitmap;III)Landroid/graphics/Bitmap;
    .locals 7

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-static {p0, p1, p1, p2, p3}, Landroid/graphics/Bitmap;->createBitmap(Landroid/graphics/Bitmap;IIII)Landroid/graphics/Bitmap;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance v5, Landroid/graphics/Matrix;

    .line 10
    .line 11
    invoke-direct {v5}, Landroid/graphics/Matrix;-><init>()V

    .line 12
    .line 13
    .line 14
    int-to-float p1, p1

    .line 15
    invoke-virtual {v5, p1}, Landroid/graphics/Matrix;->postRotate(F)Z

    .line 16
    .line 17
    .line 18
    const/4 v6, 0x1

    .line 19
    const/4 v1, 0x0

    .line 20
    const/4 v2, 0x0

    .line 21
    move-object v0, p0

    .line 22
    move v3, p2

    .line 23
    move v4, p3

    .line 24
    invoke-static/range {v0 .. v6}, Landroid/graphics/Bitmap;->createBitmap(Landroid/graphics/Bitmap;IIIILandroid/graphics/Matrix;Z)Landroid/graphics/Bitmap;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public static final e(Landroid/media/Image$Plane;II[BII)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/nio/Buffer;->limit()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getRowStride()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v1

    .line 17
    add-int/lit8 v2, v2, -0x1

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getRowStride()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    div-int/2addr v2, v1

    .line 24
    if-nez v2, :cond_0

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_0
    div-int/2addr p2, v2

    .line 28
    div-int/2addr p1, p2

    .line 29
    const/4 p2, 0x0

    .line 30
    move v1, p2

    .line 31
    move v3, v1

    .line 32
    :goto_0
    if-ge v1, v2, :cond_2

    .line 33
    .line 34
    move v4, p2

    .line 35
    move v5, v3

    .line 36
    :goto_1
    if-ge v4, p1, :cond_1

    .line 37
    .line 38
    invoke-virtual {v0, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    aput-byte v6, p3, p4

    .line 43
    .line 44
    add-int/2addr p4, p5

    .line 45
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getPixelStride()I

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    add-int/2addr v5, v6

    .line 50
    add-int/lit8 v4, v4, 0x1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getRowStride()I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    add-int/2addr v3, v4

    .line 58
    add-int/lit8 v1, v1, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    :goto_2
    return-void
.end method
