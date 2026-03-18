.class public final Ly7/q;
.super Ly7/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public h:Ljava/io/RandomAccessFile;

.field public i:Landroid/net/Uri;

.field public j:J

.field public k:Z


# virtual methods
.method public final close()V
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Ly7/q;->i:Landroid/net/Uri;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    :try_start_0
    iget-object v2, p0, Ly7/q;->h:Ljava/io/RandomAccessFile;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/io/RandomAccessFile;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception v2

    .line 14
    goto :goto_2

    .line 15
    :catch_0
    move-exception v2

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    :goto_0
    iput-object v0, p0, Ly7/q;->h:Ljava/io/RandomAccessFile;

    .line 18
    .line 19
    iget-boolean v0, p0, Ly7/q;->k:Z

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    iput-boolean v1, p0, Ly7/q;->k:Z

    .line 24
    .line 25
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void

    .line 29
    :goto_1
    :try_start_1
    new-instance v3, Ly7/p;

    .line 30
    .line 31
    const/16 v4, 0x7d0

    .line 32
    .line 33
    invoke-direct {v3, v4, v2}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 34
    .line 35
    .line 36
    throw v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    :goto_2
    iput-object v0, p0, Ly7/q;->h:Ljava/io/RandomAccessFile;

    .line 38
    .line 39
    iget-boolean v0, p0, Ly7/q;->k:Z

    .line 40
    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    iput-boolean v1, p0, Ly7/q;->k:Z

    .line 44
    .line 45
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 46
    .line 47
    .line 48
    :cond_2
    throw v2
.end method

.method public final g(Ly7/j;)J
    .locals 8

    .line 1
    iget-object v0, p1, Ly7/j;->a:Landroid/net/Uri;

    .line 2
    .line 3
    iget-wide v1, p1, Ly7/j;->e:J

    .line 4
    .line 5
    iput-object v0, p0, Ly7/q;->i:Landroid/net/Uri;

    .line 6
    .line 7
    invoke-virtual {p0}, Ly7/c;->p()V

    .line 8
    .line 9
    .line 10
    const/16 v3, 0x7d0

    .line 11
    .line 12
    const/16 v4, 0x7d6

    .line 13
    .line 14
    :try_start_0
    new-instance v5, Ljava/io/RandomAccessFile;

    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    const-string v7, "r"

    .line 24
    .line 25
    invoke-direct {v5, v6, v7}, Ljava/io/RandomAccessFile;-><init>(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_1

    .line 26
    .line 27
    .line 28
    iput-object v5, p0, Ly7/q;->h:Ljava/io/RandomAccessFile;

    .line 29
    .line 30
    :try_start_1
    invoke-virtual {v5, v1, v2}, Ljava/io/RandomAccessFile;->seek(J)V

    .line 31
    .line 32
    .line 33
    iget-wide v4, p1, Ly7/j;->f:J

    .line 34
    .line 35
    const-wide/16 v6, -0x1

    .line 36
    .line 37
    cmp-long v0, v4, v6

    .line 38
    .line 39
    if-nez v0, :cond_0

    .line 40
    .line 41
    iget-object v0, p0, Ly7/q;->h:Ljava/io/RandomAccessFile;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/io/RandomAccessFile;->length()J

    .line 44
    .line 45
    .line 46
    move-result-wide v4

    .line 47
    sub-long/2addr v4, v1

    .line 48
    goto :goto_0

    .line 49
    :catch_0
    move-exception p0

    .line 50
    goto :goto_1

    .line 51
    :cond_0
    :goto_0
    iput-wide v4, p0, Ly7/q;->j:J
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 52
    .line 53
    const-wide/16 v0, 0x0

    .line 54
    .line 55
    cmp-long v0, v4, v0

    .line 56
    .line 57
    if-ltz v0, :cond_1

    .line 58
    .line 59
    const/4 v0, 0x1

    .line 60
    iput-boolean v0, p0, Ly7/q;->k:Z

    .line 61
    .line 62
    invoke-virtual {p0, p1}, Ly7/c;->q(Ly7/j;)V

    .line 63
    .line 64
    .line 65
    iget-wide p0, p0, Ly7/q;->j:J

    .line 66
    .line 67
    return-wide p0

    .line 68
    :cond_1
    new-instance p0, Ly7/p;

    .line 69
    .line 70
    const/16 p1, 0x7d8

    .line 71
    .line 72
    const/4 v0, 0x0

    .line 73
    invoke-direct {p0, v0, v0, p1}, Ly7/i;-><init>(Ljava/lang/String;Ljava/lang/Exception;I)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :goto_1
    new-instance p1, Ly7/p;

    .line 78
    .line 79
    invoke-direct {p1, v3, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 80
    .line 81
    .line 82
    throw p1

    .line 83
    :catch_1
    move-exception p0

    .line 84
    goto :goto_2

    .line 85
    :catch_2
    move-exception p0

    .line 86
    goto :goto_3

    .line 87
    :catch_3
    move-exception p0

    .line 88
    goto :goto_4

    .line 89
    :goto_2
    new-instance p1, Ly7/p;

    .line 90
    .line 91
    invoke-direct {p1, v3, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 92
    .line 93
    .line 94
    throw p1

    .line 95
    :goto_3
    new-instance p1, Ly7/p;

    .line 96
    .line 97
    invoke-direct {p1, v4, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 98
    .line 99
    .line 100
    throw p1

    .line 101
    :goto_4
    invoke-virtual {v0}, Landroid/net/Uri;->getQuery()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 106
    .line 107
    .line 108
    move-result p1

    .line 109
    if-eqz p1, :cond_3

    .line 110
    .line 111
    invoke-virtual {v0}, Landroid/net/Uri;->getFragment()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 116
    .line 117
    .line 118
    move-result p1

    .line 119
    if-eqz p1, :cond_3

    .line 120
    .line 121
    new-instance p1, Ly7/p;

    .line 122
    .line 123
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    instance-of v0, v0, Landroid/system/ErrnoException;

    .line 128
    .line 129
    if-eqz v0, :cond_2

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    check-cast v0, Landroid/system/ErrnoException;

    .line 136
    .line 137
    iget v0, v0, Landroid/system/ErrnoException;->errno:I

    .line 138
    .line 139
    sget v1, Landroid/system/OsConstants;->EACCES:I

    .line 140
    .line 141
    if-ne v0, v1, :cond_2

    .line 142
    .line 143
    goto :goto_5

    .line 144
    :cond_2
    const/16 v4, 0x7d5

    .line 145
    .line 146
    :goto_5
    invoke-direct {p1, v4, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 147
    .line 148
    .line 149
    throw p1

    .line 150
    :cond_3
    new-instance p1, Ly7/p;

    .line 151
    .line 152
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    invoke-virtual {v0}, Landroid/net/Uri;->getQuery()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    invoke-virtual {v0}, Landroid/net/Uri;->getFragment()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    const-string v3, ",query="

    .line 165
    .line 166
    const-string v4, ",fragment="

    .line 167
    .line 168
    const-string v5, "uri has query and/or fragment, which are not supported. Did you call Uri.parse() on a string containing \'?\' or \'#\'? Use Uri.fromFile(new File(path)) to avoid this. path="

    .line 169
    .line 170
    invoke-static {v5, v1, v3, v2, v4}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v0

    .line 181
    const/16 v1, 0x3ec

    .line 182
    .line 183
    invoke-direct {p1, v0, p0, v1}, Ly7/i;-><init>(Ljava/lang/String;Ljava/lang/Exception;I)V

    .line 184
    .line 185
    .line 186
    throw p1
.end method

.method public final getUri()Landroid/net/Uri;
    .locals 0

    .line 1
    iget-object p0, p0, Ly7/q;->i:Landroid/net/Uri;

    .line 2
    .line 3
    return-object p0
.end method

.method public final read([BII)I
    .locals 5

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    iget-wide v0, p0, Ly7/q;->j:J

    .line 6
    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    cmp-long v2, v0, v2

    .line 10
    .line 11
    if-nez v2, :cond_1

    .line 12
    .line 13
    const/4 p0, -0x1

    .line 14
    return p0

    .line 15
    :cond_1
    :try_start_0
    iget-object v2, p0, Ly7/q;->h:Ljava/io/RandomAccessFile;

    .line 16
    .line 17
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 18
    .line 19
    int-to-long v3, p3

    .line 20
    invoke-static {v0, v1, v3, v4}, Ljava/lang/Math;->min(JJ)J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    long-to-int p3, v0

    .line 25
    invoke-virtual {v2, p1, p2, p3}, Ljava/io/RandomAccessFile;->read([BII)I

    .line 26
    .line 27
    .line 28
    move-result p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    if-lez p1, :cond_2

    .line 30
    .line 31
    iget-wide p2, p0, Ly7/q;->j:J

    .line 32
    .line 33
    int-to-long v0, p1

    .line 34
    sub-long/2addr p2, v0

    .line 35
    iput-wide p2, p0, Ly7/q;->j:J

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Ly7/c;->c(I)V

    .line 38
    .line 39
    .line 40
    :cond_2
    return p1

    .line 41
    :catch_0
    move-exception p0

    .line 42
    new-instance p1, Ly7/p;

    .line 43
    .line 44
    const/16 p2, 0x7d0

    .line 45
    .line 46
    invoke-direct {p1, p2, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 47
    .line 48
    .line 49
    throw p1
.end method
