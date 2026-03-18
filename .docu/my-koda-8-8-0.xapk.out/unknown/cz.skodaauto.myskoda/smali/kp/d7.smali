.class public abstract Lkp/d7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;JFFLl2/o;II)V
    .locals 18

    .line 1
    move-object/from16 v0, p5

    .line 2
    .line 3
    check-cast v0, Ll2/t;

    .line 4
    .line 5
    const v1, -0x4a783646

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    and-int/lit8 v1, p7, 0x1

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    or-int/lit8 v2, p6, 0x6

    .line 16
    .line 17
    move v3, v2

    .line 18
    move-object/from16 v2, p0

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_0
    and-int/lit8 v2, p6, 0x6

    .line 22
    .line 23
    if-nez v2, :cond_2

    .line 24
    .line 25
    move-object/from16 v2, p0

    .line 26
    .line 27
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    const/4 v3, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_1
    const/4 v3, 0x2

    .line 36
    :goto_0
    or-int v3, p6, v3

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    move-object/from16 v2, p0

    .line 40
    .line 41
    move/from16 v3, p6

    .line 42
    .line 43
    :goto_1
    and-int/lit8 v4, p7, 0x2

    .line 44
    .line 45
    if-nez v4, :cond_3

    .line 46
    .line 47
    move-wide/from16 v4, p1

    .line 48
    .line 49
    invoke-virtual {v0, v4, v5}, Ll2/t;->f(J)Z

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-eqz v6, :cond_4

    .line 54
    .line 55
    const/16 v6, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_3
    move-wide/from16 v4, p1

    .line 59
    .line 60
    :cond_4
    const/16 v6, 0x10

    .line 61
    .line 62
    :goto_2
    or-int/2addr v3, v6

    .line 63
    or-int/lit16 v3, v3, 0xd80

    .line 64
    .line 65
    and-int/lit16 v6, v3, 0x493

    .line 66
    .line 67
    const/16 v7, 0x492

    .line 68
    .line 69
    const/4 v8, 0x0

    .line 70
    const/4 v9, 0x1

    .line 71
    if-eq v6, v7, :cond_5

    .line 72
    .line 73
    move v6, v9

    .line 74
    goto :goto_3

    .line 75
    :cond_5
    move v6, v8

    .line 76
    :goto_3
    and-int/2addr v3, v9

    .line 77
    invoke-virtual {v0, v3, v6}, Ll2/t;->O(IZ)Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-eqz v3, :cond_c

    .line 82
    .line 83
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 84
    .line 85
    .line 86
    and-int/lit8 v3, p6, 0x1

    .line 87
    .line 88
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 89
    .line 90
    if-eqz v3, :cond_7

    .line 91
    .line 92
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    if-eqz v3, :cond_6

    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_6
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 100
    .line 101
    .line 102
    move/from16 v1, p3

    .line 103
    .line 104
    move-wide v3, v4

    .line 105
    move/from16 v5, p4

    .line 106
    .line 107
    goto :goto_6

    .line 108
    :cond_7
    :goto_4
    if-eqz v1, :cond_8

    .line 109
    .line 110
    move-object v2, v6

    .line 111
    :cond_8
    and-int/lit8 v1, p7, 0x2

    .line 112
    .line 113
    if-eqz v1, :cond_9

    .line 114
    .line 115
    sget-object v1, Lf2/h;->a:Ll2/u2;

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    check-cast v1, Lf2/g;

    .line 122
    .line 123
    invoke-virtual {v1}, Lf2/g;->a()J

    .line 124
    .line 125
    .line 126
    move-result-wide v3

    .line 127
    const v1, 0x3df5c28f    # 0.12f

    .line 128
    .line 129
    .line 130
    invoke-static {v3, v4, v1}, Le3/s;->b(JF)J

    .line 131
    .line 132
    .line 133
    move-result-wide v3

    .line 134
    goto :goto_5

    .line 135
    :cond_9
    move-wide v3, v4

    .line 136
    :goto_5
    int-to-float v1, v9

    .line 137
    int-to-float v5, v8

    .line 138
    :goto_6
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 139
    .line 140
    .line 141
    const/4 v7, 0x0

    .line 142
    cmpg-float v9, v5, v7

    .line 143
    .line 144
    if-nez v9, :cond_a

    .line 145
    .line 146
    goto :goto_7

    .line 147
    :cond_a
    const/4 v9, 0x0

    .line 148
    const/16 v10, 0xe

    .line 149
    .line 150
    const/4 v11, 0x0

    .line 151
    const/4 v12, 0x0

    .line 152
    move/from16 p1, v5

    .line 153
    .line 154
    move-object/from16 p0, v6

    .line 155
    .line 156
    move/from16 p4, v9

    .line 157
    .line 158
    move/from16 p5, v10

    .line 159
    .line 160
    move/from16 p2, v11

    .line 161
    .line 162
    move/from16 p3, v12

    .line 163
    .line 164
    invoke-static/range {p0 .. p5}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object v6

    .line 168
    :goto_7
    invoke-static {v1, v7}, Lt4/f;->a(FF)Z

    .line 169
    .line 170
    .line 171
    move-result v7

    .line 172
    const/high16 v9, 0x3f800000    # 1.0f

    .line 173
    .line 174
    if-eqz v7, :cond_b

    .line 175
    .line 176
    const v7, -0x1b2d8496

    .line 177
    .line 178
    .line 179
    invoke-virtual {v0, v7}, Ll2/t;->Y(I)V

    .line 180
    .line 181
    .line 182
    sget-object v7, Lw3/h1;->h:Ll2/u2;

    .line 183
    .line 184
    invoke-virtual {v0, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    check-cast v7, Lt4/c;

    .line 189
    .line 190
    invoke-interface {v7}, Lt4/c;->a()F

    .line 191
    .line 192
    .line 193
    move-result v7

    .line 194
    div-float v7, v9, v7

    .line 195
    .line 196
    invoke-virtual {v0, v8}, Ll2/t;->q(Z)V

    .line 197
    .line 198
    .line 199
    goto :goto_8

    .line 200
    :cond_b
    const v7, -0x1b2c8099

    .line 201
    .line 202
    .line 203
    invoke-virtual {v0, v7}, Ll2/t;->Y(I)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v0, v8}, Ll2/t;->q(Z)V

    .line 207
    .line 208
    .line 209
    move v7, v1

    .line 210
    :goto_8
    invoke-interface {v2, v6}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v6

    .line 214
    invoke-static {v6, v9}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 215
    .line 216
    .line 217
    move-result-object v6

    .line 218
    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 219
    .line 220
    .line 221
    move-result-object v6

    .line 222
    sget-object v7, Le3/j0;->a:Le3/i0;

    .line 223
    .line 224
    invoke-static {v6, v3, v4, v7}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 225
    .line 226
    .line 227
    move-result-object v6

    .line 228
    invoke-static {v6, v0, v8}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 229
    .line 230
    .line 231
    move v13, v1

    .line 232
    move-wide v11, v3

    .line 233
    move v14, v5

    .line 234
    :goto_9
    move-object v10, v2

    .line 235
    goto :goto_a

    .line 236
    :cond_c
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 237
    .line 238
    .line 239
    move/from16 v13, p3

    .line 240
    .line 241
    move/from16 v14, p4

    .line 242
    .line 243
    move-wide v11, v4

    .line 244
    goto :goto_9

    .line 245
    :goto_a
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    if-eqz v0, :cond_d

    .line 250
    .line 251
    new-instance v9, Lf2/v;

    .line 252
    .line 253
    const/16 v17, 0x0

    .line 254
    .line 255
    move/from16 v15, p6

    .line 256
    .line 257
    move/from16 v16, p7

    .line 258
    .line 259
    invoke-direct/range {v9 .. v17}, Lf2/v;-><init>(Lx2/s;JFFIII)V

    .line 260
    .line 261
    .line 262
    iput-object v9, v0, Ll2/u1;->d:Lay0/n;

    .line 263
    .line 264
    :cond_d
    return-void
.end method

.method public static b(Landroid/content/Context;Landroid/net/Uri;)Ljava/nio/MappedByteBuffer;
    .locals 8

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v1, 0x0

    .line 6
    :try_start_0
    const-string v0, "r"

    .line 7
    .line 8
    invoke-virtual {p0, p1, v0, v1}, Landroid/content/ContentResolver;->openFileDescriptor(Landroid/net/Uri;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    .line 18
    .line 19
    return-object v1

    .line 20
    :cond_0
    :try_start_1
    new-instance p1, Ljava/io/FileInputStream;

    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->getFileDescriptor()Ljava/io/FileDescriptor;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-direct {p1, v0}, Ljava/io/FileInputStream;-><init>(Ljava/io/FileDescriptor;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 27
    .line 28
    .line 29
    :try_start_2
    invoke-virtual {p1}, Ljava/io/FileInputStream;->getChannel()Ljava/nio/channels/FileChannel;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v2}, Ljava/nio/channels/FileChannel;->size()J

    .line 34
    .line 35
    .line 36
    move-result-wide v6

    .line 37
    sget-object v3, Ljava/nio/channels/FileChannel$MapMode;->READ_ONLY:Ljava/nio/channels/FileChannel$MapMode;

    .line 38
    .line 39
    const-wide/16 v4, 0x0

    .line 40
    .line 41
    invoke-virtual/range {v2 .. v7}, Ljava/nio/channels/FileChannel;->map(Ljava/nio/channels/FileChannel$MapMode;JJ)Ljava/nio/MappedByteBuffer;

    .line 42
    .line 43
    .line 44
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 45
    :try_start_3
    invoke-virtual {p1}, Ljava/io/FileInputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 46
    .line 47
    .line 48
    :try_start_4
    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    .line 49
    .line 50
    .line 51
    return-object v0

    .line 52
    :catchall_0
    move-exception v0

    .line 53
    move-object p1, v0

    .line 54
    goto :goto_1

    .line 55
    :catchall_1
    move-exception v0

    .line 56
    move-object v2, v0

    .line 57
    :try_start_5
    invoke-virtual {p1}, Ljava/io/FileInputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :catchall_2
    move-exception v0

    .line 62
    move-object p1, v0

    .line 63
    :try_start_6
    invoke-virtual {v2, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    :goto_0
    throw v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 67
    :goto_1
    :try_start_7
    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 68
    .line 69
    .line 70
    goto :goto_2

    .line 71
    :catchall_3
    move-exception v0

    .line 72
    move-object p0, v0

    .line 73
    :try_start_8
    invoke-virtual {p1, p0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 74
    .line 75
    .line 76
    :goto_2
    throw p1
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_0

    .line 77
    :catch_0
    :cond_1
    return-object v1
.end method
