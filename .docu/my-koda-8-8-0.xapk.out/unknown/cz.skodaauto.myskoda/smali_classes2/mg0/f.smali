.class public final Lmg0/f;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/ref/WeakReference;


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 9

    .line 1
    const/4 p1, 0x0

    .line 2
    if-eqz p2, :cond_0

    .line 3
    .line 4
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-object v0, p1

    .line 10
    :goto_0
    const-string v1, "android.intent.action.DOWNLOAD_COMPLETE"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_b

    .line 17
    .line 18
    const-string v0, "extra_download_id"

    .line 19
    .line 20
    const-wide/16 v1, -0x1

    .line 21
    .line 22
    invoke-virtual {p2, v0, v1, v2}, Landroid/content/Intent;->getLongExtra(Ljava/lang/String;J)J

    .line 23
    .line 24
    .line 25
    move-result-wide v5

    .line 26
    cmp-long p2, v5, v1

    .line 27
    .line 28
    if-lez p2, :cond_b

    .line 29
    .line 30
    iget-object p0, p0, Lmg0/f;->a:Ljava/lang/ref/WeakReference;

    .line 31
    .line 32
    if-eqz p0, :cond_b

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lmg0/b;

    .line 39
    .line 40
    if-eqz p0, :cond_b

    .line 41
    .line 42
    iget-object p0, p0, Lmg0/b;->a:Lmg0/e;

    .line 43
    .line 44
    iget-object p2, p0, Lmg0/e;->a:Landroid/app/DownloadManager;

    .line 45
    .line 46
    new-instance v0, Landroid/app/DownloadManager$Query;

    .line 47
    .line 48
    invoke-direct {v0}, Landroid/app/DownloadManager$Query;-><init>()V

    .line 49
    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    new-array v2, v1, [J

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    aput-wide v5, v2, v3

    .line 56
    .line 57
    invoke-virtual {v0, v2}, Landroid/app/DownloadManager$Query;->setFilterById([J)Landroid/app/DownloadManager$Query;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-virtual {p2, v0}, Landroid/app/DownloadManager;->query(Landroid/app/DownloadManager$Query;)Landroid/database/Cursor;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    :try_start_0
    invoke-interface {p2}, Landroid/database/Cursor;->moveToFirst()Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-eqz v0, :cond_8

    .line 70
    .line 71
    const-string v0, "status"

    .line 72
    .line 73
    invoke-interface {p2, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    if-ltz v0, :cond_1

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_1
    move-object v2, p1

    .line 85
    :goto_1
    if-eqz v2, :cond_7

    .line 86
    .line 87
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    invoke-interface {p2, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eq v0, v1, :cond_6

    .line 96
    .line 97
    const/4 v1, 0x2

    .line 98
    if-eq v0, v1, :cond_5

    .line 99
    .line 100
    const/4 v1, 0x4

    .line 101
    if-eq v0, v1, :cond_4

    .line 102
    .line 103
    const/16 v1, 0x8

    .line 104
    .line 105
    if-eq v0, v1, :cond_3

    .line 106
    .line 107
    const/16 v1, 0x10

    .line 108
    .line 109
    if-eq v0, v1, :cond_2

    .line 110
    .line 111
    move-object v0, p1

    .line 112
    goto :goto_2

    .line 113
    :cond_2
    sget-object v0, Llg0/f;->h:Llg0/f;

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :catchall_0
    move-exception v0

    .line 117
    move-object p0, v0

    .line 118
    goto :goto_4

    .line 119
    :cond_3
    sget-object v0, Llg0/f;->j:Llg0/f;

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_4
    sget-object v0, Llg0/f;->e:Llg0/f;

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_5
    sget-object v0, Llg0/f;->g:Llg0/f;

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_6
    sget-object v0, Llg0/f;->f:Llg0/f;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_7
    invoke-interface {p2}, Ljava/io/Closeable;->close()V

    .line 132
    .line 133
    .line 134
    move-object v7, p1

    .line 135
    goto :goto_3

    .line 136
    :cond_8
    :try_start_1
    sget-object v0, Llg0/f;->i:Llg0/f;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 137
    .line 138
    :goto_2
    invoke-interface {p2}, Ljava/io/Closeable;->close()V

    .line 139
    .line 140
    .line 141
    move-object v7, v0

    .line 142
    :goto_3
    if-nez v7, :cond_9

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_9
    iget-boolean p2, v7, Llg0/f;->d:Z

    .line 146
    .line 147
    if-eqz p2, :cond_b

    .line 148
    .line 149
    iget-object p2, p0, Lmg0/e;->f:Ljava/util/concurrent/ConcurrentHashMap;

    .line 150
    .line 151
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    invoke-virtual {p2, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p2

    .line 159
    check-cast p2, Ljava/lang/Long;

    .line 160
    .line 161
    if-eqz p2, :cond_a

    .line 162
    .line 163
    invoke-virtual {p2}, Ljava/lang/Number;->longValue()J

    .line 164
    .line 165
    .line 166
    move-result-wide v0

    .line 167
    new-instance v3, Llg0/g;

    .line 168
    .line 169
    move-object v8, v7

    .line 170
    move-wide v6, v5

    .line 171
    move-wide v4, v0

    .line 172
    invoke-direct/range {v3 .. v8}, Llg0/g;-><init>(JJLlg0/f;)V

    .line 173
    .line 174
    .line 175
    move-wide v5, v6

    .line 176
    move-object v7, v8

    .line 177
    iget-object p2, p0, Lmg0/e;->b:Lig0/g;

    .line 178
    .line 179
    iget-object p2, p2, Lig0/g;->c:Lyy0/q1;

    .line 180
    .line 181
    invoke-virtual {p2, v3}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    :cond_a
    sget-object p2, Lge0/a;->d:Lge0/a;

    .line 185
    .line 186
    new-instance v3, Lmg0/a;

    .line 187
    .line 188
    const/4 v8, 0x0

    .line 189
    move-object v4, p0

    .line 190
    invoke-direct/range {v3 .. v8}, Lmg0/a;-><init>(Lmg0/e;JLlg0/f;Lkotlin/coroutines/Continuation;)V

    .line 191
    .line 192
    .line 193
    const/4 p0, 0x3

    .line 194
    invoke-static {p2, p1, p1, v3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 195
    .line 196
    .line 197
    return-void

    .line 198
    :goto_4
    :try_start_2
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 199
    :catchall_1
    move-exception v0

    .line 200
    move-object p1, v0

    .line 201
    invoke-static {p2, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 202
    .line 203
    .line 204
    throw p1

    .line 205
    :cond_b
    :goto_5
    return-void
.end method
