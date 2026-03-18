.class public final Ly7/e;
.super Ly7/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Landroid/content/ContentResolver;

.field public i:Landroid/net/Uri;

.field public j:Landroid/content/res/AssetFileDescriptor;

.field public k:Ljava/io/FileInputStream;

.field public l:J

.field public m:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Ly7/c;-><init>(Z)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Ly7/e;->h:Landroid/content/ContentResolver;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Ly7/e;->i:Landroid/net/Uri;

    .line 3
    .line 4
    const/16 v1, 0x7d0

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    :try_start_0
    iget-object v3, p0, Ly7/e;->k:Ljava/io/FileInputStream;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    invoke-virtual {v3}, Ljava/io/FileInputStream;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception v3

    .line 16
    goto :goto_5

    .line 17
    :catch_0
    move-exception v3

    .line 18
    goto :goto_4

    .line 19
    :cond_0
    :goto_0
    iput-object v0, p0, Ly7/e;->k:Ljava/io/FileInputStream;

    .line 20
    .line 21
    :try_start_1
    iget-object v3, p0, Ly7/e;->j:Landroid/content/res/AssetFileDescriptor;

    .line 22
    .line 23
    if-eqz v3, :cond_1

    .line 24
    .line 25
    invoke-virtual {v3}, Landroid/content/res/AssetFileDescriptor;->close()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :catchall_1
    move-exception v1

    .line 30
    goto :goto_3

    .line 31
    :catch_1
    move-exception v3

    .line 32
    goto :goto_2

    .line 33
    :cond_1
    :goto_1
    iput-object v0, p0, Ly7/e;->j:Landroid/content/res/AssetFileDescriptor;

    .line 34
    .line 35
    iget-boolean v0, p0, Ly7/e;->m:Z

    .line 36
    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    iput-boolean v2, p0, Ly7/e;->m:Z

    .line 40
    .line 41
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 42
    .line 43
    .line 44
    :cond_2
    return-void

    .line 45
    :goto_2
    :try_start_2
    new-instance v4, Ly7/d;

    .line 46
    .line 47
    invoke-direct {v4, v1, v3}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 48
    .line 49
    .line 50
    throw v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 51
    :goto_3
    iput-object v0, p0, Ly7/e;->j:Landroid/content/res/AssetFileDescriptor;

    .line 52
    .line 53
    iget-boolean v0, p0, Ly7/e;->m:Z

    .line 54
    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    iput-boolean v2, p0, Ly7/e;->m:Z

    .line 58
    .line 59
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 60
    .line 61
    .line 62
    :cond_3
    throw v1

    .line 63
    :goto_4
    :try_start_3
    new-instance v4, Ly7/d;

    .line 64
    .line 65
    invoke-direct {v4, v1, v3}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 66
    .line 67
    .line 68
    throw v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 69
    :goto_5
    iput-object v0, p0, Ly7/e;->k:Ljava/io/FileInputStream;

    .line 70
    .line 71
    :try_start_4
    iget-object v4, p0, Ly7/e;->j:Landroid/content/res/AssetFileDescriptor;

    .line 72
    .line 73
    if-eqz v4, :cond_4

    .line 74
    .line 75
    invoke-virtual {v4}, Landroid/content/res/AssetFileDescriptor;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_2
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 76
    .line 77
    .line 78
    goto :goto_6

    .line 79
    :catchall_2
    move-exception v1

    .line 80
    goto :goto_8

    .line 81
    :catch_2
    move-exception v3

    .line 82
    goto :goto_7

    .line 83
    :cond_4
    :goto_6
    iput-object v0, p0, Ly7/e;->j:Landroid/content/res/AssetFileDescriptor;

    .line 84
    .line 85
    iget-boolean v0, p0, Ly7/e;->m:Z

    .line 86
    .line 87
    if-eqz v0, :cond_5

    .line 88
    .line 89
    iput-boolean v2, p0, Ly7/e;->m:Z

    .line 90
    .line 91
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 92
    .line 93
    .line 94
    :cond_5
    throw v3

    .line 95
    :goto_7
    :try_start_5
    new-instance v4, Ly7/d;

    .line 96
    .line 97
    invoke-direct {v4, v1, v3}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 98
    .line 99
    .line 100
    throw v4
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 101
    :goto_8
    iput-object v0, p0, Ly7/e;->j:Landroid/content/res/AssetFileDescriptor;

    .line 102
    .line 103
    iget-boolean v0, p0, Ly7/e;->m:Z

    .line 104
    .line 105
    if-eqz v0, :cond_6

    .line 106
    .line 107
    iput-boolean v2, p0, Ly7/e;->m:Z

    .line 108
    .line 109
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 110
    .line 111
    .line 112
    :cond_6
    throw v1
.end method

.method public final g(Ly7/j;)J
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "Could not open file descriptor for: "

    .line 6
    .line 7
    :try_start_0
    iget-object v4, v1, Ly7/j;->a:Landroid/net/Uri;

    .line 8
    .line 9
    iget-wide v5, v1, Ly7/j;->f:J

    .line 10
    .line 11
    iget-wide v7, v1, Ly7/j;->e:J

    .line 12
    .line 13
    invoke-virtual {v4}, Landroid/net/Uri;->normalizeScheme()Landroid/net/Uri;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    iput-object v4, v0, Ly7/e;->i:Landroid/net/Uri;

    .line 18
    .line 19
    invoke-virtual {v0}, Ly7/c;->p()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v4}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v9

    .line 26
    const-string v10, "content"

    .line 27
    .line 28
    invoke-static {v9, v10}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v9
    :try_end_0
    .catch Ly7/d; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    iget-object v10, v0, Ly7/e;->h:Landroid/content/ContentResolver;

    .line 33
    .line 34
    const/4 v11, 0x1

    .line 35
    if-eqz v9, :cond_0

    .line 36
    .line 37
    :try_start_1
    new-instance v9, Landroid/os/Bundle;

    .line 38
    .line 39
    invoke-direct {v9}, Landroid/os/Bundle;-><init>()V

    .line 40
    .line 41
    .line 42
    const-string v12, "android.provider.extra.ACCEPT_ORIGINAL_MEDIA_FORMAT"

    .line 43
    .line 44
    invoke-virtual {v9, v12, v11}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 45
    .line 46
    .line 47
    const-string v12, "*/*"

    .line 48
    .line 49
    invoke-virtual {v10, v4, v12, v9}, Landroid/content/ContentResolver;->openTypedAssetFileDescriptor(Landroid/net/Uri;Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/res/AssetFileDescriptor;

    .line 50
    .line 51
    .line 52
    move-result-object v9

    .line 53
    goto :goto_0

    .line 54
    :catch_0
    move-exception v0

    .line 55
    const/16 v2, 0x7d0

    .line 56
    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_0
    const-string v9, "r"

    .line 60
    .line 61
    invoke-virtual {v10, v4, v9}, Landroid/content/ContentResolver;->openAssetFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    :goto_0
    iput-object v9, v0, Ly7/e;->j:Landroid/content/res/AssetFileDescriptor;

    .line 66
    .line 67
    if-eqz v9, :cond_b

    .line 68
    .line 69
    invoke-virtual {v9}, Landroid/content/res/AssetFileDescriptor;->getLength()J

    .line 70
    .line 71
    .line 72
    move-result-wide v12

    .line 73
    new-instance v2, Ljava/io/FileInputStream;

    .line 74
    .line 75
    invoke-virtual {v9}, Landroid/content/res/AssetFileDescriptor;->getFileDescriptor()Ljava/io/FileDescriptor;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    invoke-direct {v2, v4}, Ljava/io/FileInputStream;-><init>(Ljava/io/FileDescriptor;)V

    .line 80
    .line 81
    .line 82
    iput-object v2, v0, Ly7/e;->k:Ljava/io/FileInputStream;

    .line 83
    .line 84
    const-wide/16 v14, -0x1

    .line 85
    .line 86
    cmp-long v4, v12, v14

    .line 87
    .line 88
    const/16 v10, 0x7d8

    .line 89
    .line 90
    const/4 v3, 0x0

    .line 91
    if-eqz v4, :cond_2

    .line 92
    .line 93
    cmp-long v16, v7, v12

    .line 94
    .line 95
    if-gtz v16, :cond_1

    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_1
    new-instance v0, Ly7/d;

    .line 99
    .line 100
    invoke-direct {v0, v10, v3}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 101
    .line 102
    .line 103
    throw v0

    .line 104
    :cond_2
    :goto_1
    invoke-virtual {v9}, Landroid/content/res/AssetFileDescriptor;->getStartOffset()J

    .line 105
    .line 106
    .line 107
    move-result-wide v16

    .line 108
    move-wide/from16 v18, v12

    .line 109
    .line 110
    add-long v11, v16, v7

    .line 111
    .line 112
    invoke-virtual {v2, v11, v12}, Ljava/io/FileInputStream;->skip(J)J

    .line 113
    .line 114
    .line 115
    move-result-wide v11

    .line 116
    sub-long v11, v11, v16

    .line 117
    .line 118
    cmp-long v7, v11, v7

    .line 119
    .line 120
    if-nez v7, :cond_a

    .line 121
    .line 122
    const-wide/16 v7, 0x0

    .line 123
    .line 124
    if-nez v4, :cond_5

    .line 125
    .line 126
    invoke-virtual {v2}, Ljava/io/FileInputStream;->getChannel()Ljava/nio/channels/FileChannel;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    invoke-virtual {v2}, Ljava/nio/channels/FileChannel;->size()J

    .line 131
    .line 132
    .line 133
    move-result-wide v11

    .line 134
    cmp-long v4, v11, v7

    .line 135
    .line 136
    if-nez v4, :cond_3

    .line 137
    .line 138
    iput-wide v14, v0, Ly7/e;->l:J

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_3
    invoke-virtual {v2}, Ljava/nio/channels/FileChannel;->position()J

    .line 142
    .line 143
    .line 144
    move-result-wide v16

    .line 145
    sub-long v11, v11, v16

    .line 146
    .line 147
    iput-wide v11, v0, Ly7/e;->l:J

    .line 148
    .line 149
    cmp-long v2, v11, v7

    .line 150
    .line 151
    if-ltz v2, :cond_4

    .line 152
    .line 153
    goto :goto_2

    .line 154
    :cond_4
    new-instance v0, Ly7/d;

    .line 155
    .line 156
    invoke-direct {v0, v10, v3}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 157
    .line 158
    .line 159
    throw v0

    .line 160
    :cond_5
    sub-long v12, v18, v11

    .line 161
    .line 162
    iput-wide v12, v0, Ly7/e;->l:J
    :try_end_1
    .catch Ly7/d; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 163
    .line 164
    cmp-long v2, v12, v7

    .line 165
    .line 166
    if-ltz v2, :cond_9

    .line 167
    .line 168
    :goto_2
    cmp-long v2, v5, v14

    .line 169
    .line 170
    if-eqz v2, :cond_7

    .line 171
    .line 172
    iget-wide v3, v0, Ly7/e;->l:J

    .line 173
    .line 174
    cmp-long v7, v3, v14

    .line 175
    .line 176
    if-nez v7, :cond_6

    .line 177
    .line 178
    move-wide v3, v5

    .line 179
    goto :goto_3

    .line 180
    :cond_6
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 181
    .line 182
    .line 183
    move-result-wide v3

    .line 184
    :goto_3
    iput-wide v3, v0, Ly7/e;->l:J

    .line 185
    .line 186
    :cond_7
    const/4 v9, 0x1

    .line 187
    iput-boolean v9, v0, Ly7/e;->m:Z

    .line 188
    .line 189
    invoke-virtual/range {p0 .. p1}, Ly7/c;->q(Ly7/j;)V

    .line 190
    .line 191
    .line 192
    if-eqz v2, :cond_8

    .line 193
    .line 194
    return-wide v5

    .line 195
    :cond_8
    iget-wide v0, v0, Ly7/e;->l:J

    .line 196
    .line 197
    return-wide v0

    .line 198
    :cond_9
    :try_start_2
    new-instance v0, Ly7/d;

    .line 199
    .line 200
    invoke-direct {v0, v10, v3}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 201
    .line 202
    .line 203
    throw v0

    .line 204
    :cond_a
    new-instance v0, Ly7/d;

    .line 205
    .line 206
    invoke-direct {v0, v10, v3}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 207
    .line 208
    .line 209
    throw v0

    .line 210
    :cond_b
    new-instance v0, Ly7/d;

    .line 211
    .line 212
    new-instance v1, Ljava/io/IOException;

    .line 213
    .line 214
    new-instance v3, Ljava/lang/StringBuilder;

    .line 215
    .line 216
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v2

    .line 226
    invoke-direct {v1, v2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V
    :try_end_2
    .catch Ly7/d; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 227
    .line 228
    .line 229
    const/16 v2, 0x7d0

    .line 230
    .line 231
    :try_start_3
    invoke-direct {v0, v2, v1}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 232
    .line 233
    .line 234
    throw v0
    :try_end_3
    .catch Ly7/d; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1

    .line 235
    :catch_1
    move-exception v0

    .line 236
    :goto_4
    new-instance v1, Ly7/d;

    .line 237
    .line 238
    instance-of v3, v0, Ljava/io/FileNotFoundException;

    .line 239
    .line 240
    if-eqz v3, :cond_c

    .line 241
    .line 242
    const/16 v3, 0x7d5

    .line 243
    .line 244
    goto :goto_5

    .line 245
    :cond_c
    move v3, v2

    .line 246
    :goto_5
    invoke-direct {v1, v3, v0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 247
    .line 248
    .line 249
    throw v1

    .line 250
    :catch_2
    move-exception v0

    .line 251
    throw v0
.end method

.method public final getUri()Landroid/net/Uri;
    .locals 0

    .line 1
    iget-object p0, p0, Ly7/e;->i:Landroid/net/Uri;

    .line 2
    .line 3
    return-object p0
.end method

.method public final read([BII)I
    .locals 8

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    iget-wide v0, p0, Ly7/e;->l:J

    .line 6
    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    cmp-long v2, v0, v2

    .line 10
    .line 11
    const/4 v3, -0x1

    .line 12
    if-nez v2, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    const-wide/16 v4, -0x1

    .line 16
    .line 17
    cmp-long v2, v0, v4

    .line 18
    .line 19
    if-nez v2, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    int-to-long v6, p3

    .line 23
    :try_start_0
    invoke-static {v0, v1, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    long-to-int p3, v0

    .line 28
    :goto_0
    iget-object v0, p0, Ly7/e;->k:Ljava/io/FileInputStream;

    .line 29
    .line 30
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v0, p1, p2, p3}, Ljava/io/FileInputStream;->read([BII)I

    .line 33
    .line 34
    .line 35
    move-result p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 36
    if-ne p1, v3, :cond_3

    .line 37
    .line 38
    :goto_1
    return v3

    .line 39
    :cond_3
    iget-wide p2, p0, Ly7/e;->l:J

    .line 40
    .line 41
    cmp-long v0, p2, v4

    .line 42
    .line 43
    if-eqz v0, :cond_4

    .line 44
    .line 45
    int-to-long v0, p1

    .line 46
    sub-long/2addr p2, v0

    .line 47
    iput-wide p2, p0, Ly7/e;->l:J

    .line 48
    .line 49
    :cond_4
    invoke-virtual {p0, p1}, Ly7/c;->c(I)V

    .line 50
    .line 51
    .line 52
    return p1

    .line 53
    :catch_0
    move-exception p0

    .line 54
    new-instance p1, Ly7/d;

    .line 55
    .line 56
    const/16 p2, 0x7d0

    .line 57
    .line 58
    invoke-direct {p1, p2, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 59
    .line 60
    .line 61
    throw p1
.end method
