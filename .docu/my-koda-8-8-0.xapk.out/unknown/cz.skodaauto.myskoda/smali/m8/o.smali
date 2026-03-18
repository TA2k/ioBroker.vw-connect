.class public final synthetic Lm8/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lm8/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm8/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private final a()V
    .locals 4

    .line 1
    iget-object p0, p0, Lm8/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ls6/o;

    .line 4
    .line 5
    const-string v0, "fetchFonts result is not OK. ("

    .line 6
    .line 7
    iget-object v1, p0, Ls6/o;->g:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v1

    .line 10
    :try_start_0
    iget-object v2, p0, Ls6/o;->k:Lkp/m7;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    monitor-exit v1

    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto/16 :goto_6

    .line 18
    .line 19
    :cond_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    :try_start_1
    invoke-virtual {p0}, Ls6/o;->c()Lz5/g;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    iget v2, v1, Lz5/g;->f:I

    .line 25
    .line 26
    const/4 v3, 0x2

    .line 27
    if-ne v2, v3, :cond_1

    .line 28
    .line 29
    iget-object v3, p0, Ls6/o;->g:Ljava/lang/Object;

    .line 30
    .line 31
    monitor-enter v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 32
    :try_start_2
    monitor-exit v3

    .line 33
    goto :goto_0

    .line 34
    :catchall_1
    move-exception v0

    .line 35
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 36
    :try_start_3
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 37
    :catchall_2
    move-exception v0

    .line 38
    goto :goto_3

    .line 39
    :cond_1
    :goto_0
    if-nez v2, :cond_4

    .line 40
    .line 41
    :try_start_4
    const-string v0, "EmojiCompat.FontRequestEmojiCompatConfig.buildTypeface"

    .line 42
    .line 43
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Ls6/o;->f:Lst/b;

    .line 47
    .line 48
    iget-object v2, p0, Ls6/o;->d:Landroid/content/Context;

    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    filled-new-array {v1}, [Lz5/g;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    const/4 v3, 0x0

    .line 58
    invoke-static {v2, v0, v3}, Ls5/e;->a(Landroid/content/Context;[Lz5/g;I)Landroid/graphics/Typeface;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    iget-object v2, p0, Ls6/o;->d:Landroid/content/Context;

    .line 63
    .line 64
    iget-object v1, v1, Lz5/g;->a:Landroid/net/Uri;

    .line 65
    .line 66
    invoke-static {v2, v1}, Lkp/d7;->b(Landroid/content/Context;Landroid/net/Uri;)Ljava/nio/MappedByteBuffer;

    .line 67
    .line 68
    .line 69
    move-result-object v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_5

    .line 70
    if-eqz v1, :cond_3

    .line 71
    .line 72
    if-eqz v0, :cond_3

    .line 73
    .line 74
    :try_start_5
    const-string v2, "EmojiCompat.MetadataRepo.create"

    .line 75
    .line 76
    invoke-static {v2}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    new-instance v2, Lcom/google/firebase/messaging/w;

    .line 80
    .line 81
    invoke-static {v1}, Lkp/o7;->b(Ljava/nio/MappedByteBuffer;)Lt6/b;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-direct {v2, v0, v1}, Lcom/google/firebase/messaging/w;-><init>(Landroid/graphics/Typeface;Lt6/b;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 86
    .line 87
    .line 88
    :try_start_6
    invoke-static {}, Landroid/os/Trace;->endSection()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    .line 89
    .line 90
    .line 91
    :try_start_7
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 92
    .line 93
    .line 94
    iget-object v0, p0, Ls6/o;->g:Ljava/lang/Object;

    .line 95
    .line 96
    monitor-enter v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 97
    :try_start_8
    iget-object v1, p0, Ls6/o;->k:Lkp/m7;

    .line 98
    .line 99
    if-eqz v1, :cond_2

    .line 100
    .line 101
    invoke-virtual {v1, v2}, Lkp/m7;->c(Lcom/google/firebase/messaging/w;)V

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :catchall_3
    move-exception v1

    .line 106
    goto :goto_2

    .line 107
    :cond_2
    :goto_1
    monitor-exit v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 108
    :try_start_9
    invoke-virtual {p0}, Ls6/o;->b()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 109
    .line 110
    .line 111
    return-void

    .line 112
    :goto_2
    :try_start_a
    monitor-exit v0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 113
    :try_start_b
    throw v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_2

    .line 114
    :catchall_4
    move-exception v0

    .line 115
    :try_start_c
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 116
    .line 117
    .line 118
    throw v0

    .line 119
    :cond_3
    new-instance v0, Ljava/lang/RuntimeException;

    .line 120
    .line 121
    const-string v1, "Unable to open file."

    .line 122
    .line 123
    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_5

    .line 127
    :catchall_5
    move-exception v0

    .line 128
    :try_start_d
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 129
    .line 130
    .line 131
    throw v0

    .line 132
    :cond_4
    new-instance v1, Ljava/lang/RuntimeException;

    .line 133
    .line 134
    new-instance v3, Ljava/lang/StringBuilder;

    .line 135
    .line 136
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    const-string v0, ")"

    .line 143
    .line 144
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw v1
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_2

    .line 155
    :goto_3
    iget-object v2, p0, Ls6/o;->g:Ljava/lang/Object;

    .line 156
    .line 157
    monitor-enter v2

    .line 158
    :try_start_e
    iget-object v1, p0, Ls6/o;->k:Lkp/m7;

    .line 159
    .line 160
    if-eqz v1, :cond_5

    .line 161
    .line 162
    invoke-virtual {v1, v0}, Lkp/m7;->b(Ljava/lang/Throwable;)V

    .line 163
    .line 164
    .line 165
    goto :goto_4

    .line 166
    :catchall_6
    move-exception p0

    .line 167
    goto :goto_5

    .line 168
    :cond_5
    :goto_4
    monitor-exit v2
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_6

    .line 169
    invoke-virtual {p0}, Ls6/o;->b()V

    .line 170
    .line 171
    .line 172
    return-void

    .line 173
    :goto_5
    :try_start_f
    monitor-exit v2
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_6

    .line 174
    throw p0

    .line 175
    :goto_6
    :try_start_10
    monitor-exit v1
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_0

    .line 176
    throw p0
.end method

.method private final b()V
    .locals 4

    .line 1
    iget-object p0, p0, Lm8/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/material/datepicker/d;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/d;->h()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lv0/e;

    .line 11
    .line 12
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ljava/util/HashSet;

    .line 15
    .line 16
    iget-object v1, v0, Lv0/e;->a:Ljava/lang/Object;

    .line 17
    .line 18
    monitor-enter v1

    .line 19
    if-nez p0, :cond_0

    .line 20
    .line 21
    :try_start_0
    iget-object p0, v0, Lv0/e;->b:Ljava/util/HashMap;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    goto :goto_0

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto :goto_2

    .line 30
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    :cond_1
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    check-cast v2, Lv0/a;

    .line 45
    .line 46
    iget-object v3, v0, Lv0/e;->b:Ljava/util/HashMap;

    .line 47
    .line 48
    invoke-virtual {v3, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    if-eqz v3, :cond_1

    .line 53
    .line 54
    iget-object v3, v0, Lv0/e;->b:Ljava/util/HashMap;

    .line 55
    .line 56
    invoke-virtual {v3, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    check-cast v2, Lv0/b;

    .line 61
    .line 62
    invoke-virtual {v0, v2}, Lv0/e;->j(Lv0/b;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    monitor-exit v1

    .line 67
    return-void

    .line 68
    :goto_2
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 69
    throw p0
.end method

.method private final c()V
    .locals 9

    .line 1
    iget-object p0, p0, Lm8/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lw7/n;

    .line 4
    .line 5
    iget-object v0, p0, Lw7/n;->a:Ljava/lang/ref/WeakReference;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lk8/f;

    .line 12
    .line 13
    if-eqz v0, :cond_7

    .line 14
    .line 15
    iget-object p0, p0, Lw7/n;->c:Lw7/o;

    .line 16
    .line 17
    invoke-virtual {p0}, Lw7/o;->b()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    iget-object v1, v0, Lk8/f;->a:Lk8/g;

    .line 22
    .line 23
    monitor-enter v1

    .line 24
    :try_start_0
    iget v0, v1, Lk8/g;->n:I

    .line 25
    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    iget-boolean v2, v1, Lk8/g;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    .line 30
    if-nez v2, :cond_0

    .line 31
    .line 32
    monitor-exit v1

    .line 33
    return-void

    .line 34
    :catchall_0
    move-exception v0

    .line 35
    move-object p0, v0

    .line 36
    goto/16 :goto_3

    .line 37
    .line 38
    :cond_0
    if-ne v0, p0, :cond_1

    .line 39
    .line 40
    :try_start_1
    iget-object v0, v1, Lk8/g;->o:Ljava/lang/String;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    monitor-exit v1

    .line 45
    return-void

    .line 46
    :cond_1
    :try_start_2
    iput p0, v1, Lk8/g;->n:I

    .line 47
    .line 48
    const/4 v0, 0x1

    .line 49
    if-eq p0, v0, :cond_6

    .line 50
    .line 51
    if-eqz p0, :cond_6

    .line 52
    .line 53
    const/16 v0, 0x8

    .line 54
    .line 55
    if-ne p0, v0, :cond_2

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    iget-object v0, v1, Lk8/g;->o:Ljava/lang/String;

    .line 59
    .line 60
    if-nez v0, :cond_4

    .line 61
    .line 62
    iget-object v0, v1, Lk8/g;->a:Landroid/content/Context;

    .line 63
    .line 64
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 65
    .line 66
    if-eqz v0, :cond_3

    .line 67
    .line 68
    const-string v2, "phone"

    .line 69
    .line 70
    invoke-virtual {v0, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    check-cast v0, Landroid/telephony/TelephonyManager;

    .line 75
    .line 76
    if-eqz v0, :cond_3

    .line 77
    .line 78
    invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getNetworkCountryIso()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-nez v2, :cond_3

    .line 87
    .line 88
    invoke-static {v0}, Lkp/g9;->d(Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    goto :goto_0

    .line 93
    :cond_3
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-virtual {v0}, Ljava/util/Locale;->getCountry()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    invoke-static {v0}, Lkp/g9;->d(Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    :goto_0
    iput-object v0, v1, Lk8/g;->o:Ljava/lang/String;

    .line 106
    .line 107
    :cond_4
    invoke-virtual {v1, p0}, Lk8/g;->a(I)J

    .line 108
    .line 109
    .line 110
    move-result-wide v2

    .line 111
    iput-wide v2, v1, Lk8/g;->l:J

    .line 112
    .line 113
    iget-object p0, v1, Lk8/g;->d:Lw7/r;

    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 119
    .line 120
    .line 121
    move-result-wide v7

    .line 122
    iget p0, v1, Lk8/g;->g:I

    .line 123
    .line 124
    const/4 v0, 0x0

    .line 125
    if-lez p0, :cond_5

    .line 126
    .line 127
    iget-wide v2, v1, Lk8/g;->h:J

    .line 128
    .line 129
    sub-long v2, v7, v2

    .line 130
    .line 131
    long-to-int p0, v2

    .line 132
    move v2, p0

    .line 133
    goto :goto_1

    .line 134
    :cond_5
    move v2, v0

    .line 135
    :goto_1
    iget-wide v3, v1, Lk8/g;->i:J

    .line 136
    .line 137
    iget-wide v5, v1, Lk8/g;->l:J

    .line 138
    .line 139
    invoke-virtual/range {v1 .. v6}, Lk8/g;->b(IJJ)V

    .line 140
    .line 141
    .line 142
    iput-wide v7, v1, Lk8/g;->h:J

    .line 143
    .line 144
    const-wide/16 v2, 0x0

    .line 145
    .line 146
    iput-wide v2, v1, Lk8/g;->i:J

    .line 147
    .line 148
    iput-wide v2, v1, Lk8/g;->k:J

    .line 149
    .line 150
    iput-wide v2, v1, Lk8/g;->j:J

    .line 151
    .line 152
    iget-object p0, v1, Lk8/g;->f:Lk8/n;

    .line 153
    .line 154
    iget-object v2, p0, Lk8/n;->a:Ljava/util/ArrayList;

    .line 155
    .line 156
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 157
    .line 158
    .line 159
    const/4 v2, -0x1

    .line 160
    iput v2, p0, Lk8/n;->c:I

    .line 161
    .line 162
    iput v0, p0, Lk8/n;->d:I

    .line 163
    .line 164
    iput v0, p0, Lk8/n;->e:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 165
    .line 166
    monitor-exit v1

    .line 167
    return-void

    .line 168
    :cond_6
    :goto_2
    monitor-exit v1

    .line 169
    return-void

    .line 170
    :goto_3
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 171
    throw p0

    .line 172
    :cond_7
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lm8/o;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Landroidx/media3/ui/PlayerView;

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/view/View;->invalidate()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Ly9/r;

    .line 19
    .line 20
    invoke-virtual {v0}, Ly9/r;->s()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_1
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Ly9/d;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-virtual {v0, v1}, Ly9/d;->d(Z)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_2
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lh6/i;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    iput-boolean v1, v0, Lh6/i;->c:Z

    .line 39
    .line 40
    iget-object v1, v0, Lh6/i;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 43
    .line 44
    iget-object v2, v1, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 45
    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    invoke-virtual {v2}, Lk6/f;->f()Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_0

    .line 53
    .line 54
    iget v1, v0, Lh6/i;->b:I

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Lh6/i;->b(I)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    iget v2, v1, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 61
    .line 62
    const/4 v3, 0x2

    .line 63
    if-ne v2, v3, :cond_1

    .line 64
    .line 65
    iget v0, v0, Lh6/i;->b:I

    .line 66
    .line 67
    invoke-virtual {v1, v0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r(I)V

    .line 68
    .line 69
    .line 70
    :cond_1
    :goto_0
    return-void

    .line 71
    :pswitch_3
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Lun/a;

    .line 74
    .line 75
    iget-object v1, v0, Lun/a;->h:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v1, Lzn/c;

    .line 78
    .line 79
    new-instance v2, Lrx/b;

    .line 80
    .line 81
    const/16 v3, 0x14

    .line 82
    .line 83
    invoke-direct {v2, v0, v3}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 84
    .line 85
    .line 86
    check-cast v1, Lyn/h;

    .line 87
    .line 88
    invoke-virtual {v1, v2}, Lyn/h;->h(Lzn/b;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :pswitch_4
    invoke-direct {v0}, Lm8/o;->c()V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :pswitch_5
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lw3/z;

    .line 99
    .line 100
    const-string v1, "measureAndLayout"

    .line 101
    .line 102
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    :try_start_0
    iget-object v1, v0, Lw3/z;->d:Lw3/t;

    .line 106
    .line 107
    const/4 v2, 0x1

    .line 108
    invoke-virtual {v1, v2}, Lw3/t;->r(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 109
    .line 110
    .line 111
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 112
    .line 113
    .line 114
    const-string v1, "checkForSemanticsChanges"

    .line 115
    .line 116
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    :try_start_1
    invoke-virtual {v0}, Lw3/z;->n()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 120
    .line 121
    .line 122
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 123
    .line 124
    .line 125
    const/4 v1, 0x0

    .line 126
    iput-boolean v1, v0, Lw3/z;->L:Z

    .line 127
    .line 128
    return-void

    .line 129
    :catchall_0
    move-exception v0

    .line 130
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 131
    .line 132
    .line 133
    throw v0

    .line 134
    :catchall_1
    move-exception v0

    .line 135
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 136
    .line 137
    .line 138
    throw v0

    .line 139
    :pswitch_6
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v0, La7/j;

    .line 142
    .line 143
    const-string v1, "AndroidOwner:outOfFrameExecutor"

    .line 144
    .line 145
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    :try_start_2
    invoke-virtual {v0}, La7/j;->invoke()Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 149
    .line 150
    .line 151
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 152
    .line 153
    .line 154
    return-void

    .line 155
    :catchall_2
    move-exception v0

    .line 156
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 157
    .line 158
    .line 159
    throw v0

    .line 160
    :pswitch_7
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v0, Lw3/t;

    .line 163
    .line 164
    const/4 v1, 0x0

    .line 165
    iput-boolean v1, v0, Lw3/t;->M1:Z

    .line 166
    .line 167
    iget-object v1, v0, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 168
    .line 169
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 173
    .line 174
    .line 175
    move-result v2

    .line 176
    const/16 v3, 0xa

    .line 177
    .line 178
    if-ne v2, v3, :cond_2

    .line 179
    .line 180
    invoke-virtual {v0, v1}, Lw3/t;->E(Landroid/view/MotionEvent;)I

    .line 181
    .line 182
    .line 183
    return-void

    .line 184
    :cond_2
    const-string v0, "The ACTION_HOVER_EXIT event was not cleared."

    .line 185
    .line 186
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 187
    .line 188
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    throw v1

    .line 192
    :pswitch_8
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v0, Lbb/i;

    .line 195
    .line 196
    invoke-virtual {v0}, Lbb/i;->a()V

    .line 197
    .line 198
    .line 199
    return-void

    .line 200
    :pswitch_9
    invoke-direct {v0}, Lm8/o;->b()V

    .line 201
    .line 202
    .line 203
    return-void

    .line 204
    :pswitch_a
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v0, Lum/p;

    .line 207
    .line 208
    invoke-virtual {v0}, Lum/p;->c()V

    .line 209
    .line 210
    .line 211
    return-void

    .line 212
    :pswitch_b
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v0, Lum/j;

    .line 215
    .line 216
    iget-object v1, v0, Lum/j;->D:Ljava/util/concurrent/Semaphore;

    .line 217
    .line 218
    iget-object v2, v0, Lum/j;->l:Ldn/c;

    .line 219
    .line 220
    if-nez v2, :cond_3

    .line 221
    .line 222
    goto :goto_1

    .line 223
    :cond_3
    :try_start_3
    invoke-virtual {v1}, Ljava/util/concurrent/Semaphore;->acquire()V

    .line 224
    .line 225
    .line 226
    iget-object v0, v0, Lum/j;->e:Lgn/e;

    .line 227
    .line 228
    invoke-virtual {v0}, Lgn/e;->a()F

    .line 229
    .line 230
    .line 231
    move-result v0

    .line 232
    invoke-virtual {v2, v0}, Ldn/c;->l(F)V
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 233
    .line 234
    .line 235
    :catch_0
    invoke-virtual {v1}, Ljava/util/concurrent/Semaphore;->release()V

    .line 236
    .line 237
    .line 238
    goto :goto_1

    .line 239
    :catchall_3
    move-exception v0

    .line 240
    invoke-virtual {v1}, Ljava/util/concurrent/Semaphore;->release()V

    .line 241
    .line 242
    .line 243
    throw v0

    .line 244
    :goto_1
    return-void

    .line 245
    :pswitch_c
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 246
    .line 247
    check-cast v0, Ljava/util/LinkedHashSet;

    .line 248
    .line 249
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 254
    .line 255
    .line 256
    move-result v1

    .line 257
    if-eqz v1, :cond_4

    .line 258
    .line 259
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    check-cast v1, Lu/g1;

    .line 264
    .line 265
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 266
    .line 267
    .line 268
    invoke-virtual {v1, v1}, Lu/g1;->c(Lu/g1;)V

    .line 269
    .line 270
    .line 271
    goto :goto_2

    .line 272
    :cond_4
    return-void

    .line 273
    :pswitch_d
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 274
    .line 275
    move-object v1, v0

    .line 276
    check-cast v1, Lu/p0;

    .line 277
    .line 278
    iget-object v2, v1, Lu/p0;->a:Ljava/lang/Object;

    .line 279
    .line 280
    monitor-enter v2

    .line 281
    :try_start_4
    iget-object v0, v1, Lu/p0;->b:Ljava/util/ArrayList;

    .line 282
    .line 283
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 284
    .line 285
    .line 286
    move-result v0

    .line 287
    if-eqz v0, :cond_5

    .line 288
    .line 289
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 290
    goto :goto_3

    .line 291
    :catchall_4
    move-exception v0

    .line 292
    goto :goto_4

    .line 293
    :cond_5
    :try_start_5
    iget-object v0, v1, Lu/p0;->b:Ljava/util/ArrayList;

    .line 294
    .line 295
    invoke-virtual {v1, v0}, Lu/p0;->j(Ljava/util/ArrayList;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 296
    .line 297
    .line 298
    :try_start_6
    iget-object v0, v1, Lu/p0;->b:Ljava/util/ArrayList;

    .line 299
    .line 300
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 301
    .line 302
    .line 303
    monitor-exit v2

    .line 304
    :goto_3
    return-void

    .line 305
    :catchall_5
    move-exception v0

    .line 306
    iget-object v1, v1, Lu/p0;->b:Ljava/util/ArrayList;

    .line 307
    .line 308
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 309
    .line 310
    .line 311
    throw v0

    .line 312
    :goto_4
    monitor-exit v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 313
    throw v0

    .line 314
    :pswitch_e
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 315
    .line 316
    check-cast v0, Landroidx/lifecycle/a1;

    .line 317
    .line 318
    iget-boolean v1, v0, Landroidx/lifecycle/a1;->e:Z

    .line 319
    .line 320
    if-nez v1, :cond_9

    .line 321
    .line 322
    iget-object v1, v0, Landroidx/lifecycle/a1;->g:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast v1, Lu/x;

    .line 325
    .line 326
    iget-object v1, v1, Lu/x;->f:Lu/y;

    .line 327
    .line 328
    iget v1, v1, Lu/y;->O:I

    .line 329
    .line 330
    const/16 v2, 0x8

    .line 331
    .line 332
    const/4 v3, 0x1

    .line 333
    if-eq v1, v2, :cond_7

    .line 334
    .line 335
    iget-object v1, v0, Landroidx/lifecycle/a1;->g:Ljava/lang/Object;

    .line 336
    .line 337
    check-cast v1, Lu/x;

    .line 338
    .line 339
    iget-object v1, v1, Lu/x;->f:Lu/y;

    .line 340
    .line 341
    iget v1, v1, Lu/y;->O:I

    .line 342
    .line 343
    const/4 v2, 0x7

    .line 344
    if-ne v1, v2, :cond_6

    .line 345
    .line 346
    goto :goto_5

    .line 347
    :cond_6
    const/4 v1, 0x0

    .line 348
    goto :goto_6

    .line 349
    :cond_7
    :goto_5
    move v1, v3

    .line 350
    :goto_6
    const/4 v2, 0x0

    .line 351
    invoke-static {v2, v1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 352
    .line 353
    .line 354
    iget-object v1, v0, Landroidx/lifecycle/a1;->g:Ljava/lang/Object;

    .line 355
    .line 356
    check-cast v1, Lu/x;

    .line 357
    .line 358
    invoke-virtual {v1}, Lu/x;->c()Z

    .line 359
    .line 360
    .line 361
    move-result v1

    .line 362
    if-eqz v1, :cond_8

    .line 363
    .line 364
    iget-object v0, v0, Landroidx/lifecycle/a1;->g:Ljava/lang/Object;

    .line 365
    .line 366
    check-cast v0, Lu/x;

    .line 367
    .line 368
    iget-object v0, v0, Lu/x;->f:Lu/y;

    .line 369
    .line 370
    invoke-virtual {v0, v3}, Lu/y;->K(Z)V

    .line 371
    .line 372
    .line 373
    goto :goto_7

    .line 374
    :cond_8
    iget-object v0, v0, Landroidx/lifecycle/a1;->g:Ljava/lang/Object;

    .line 375
    .line 376
    check-cast v0, Lu/x;

    .line 377
    .line 378
    iget-object v0, v0, Lu/x;->f:Lu/y;

    .line 379
    .line 380
    invoke-virtual {v0, v3}, Lu/y;->L(Z)V

    .line 381
    .line 382
    .line 383
    :cond_9
    :goto_7
    return-void

    .line 384
    :pswitch_f
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 385
    .line 386
    check-cast v0, Landroid/hardware/camera2/CameraDevice;

    .line 387
    .line 388
    invoke-virtual {v0}, Landroid/hardware/camera2/CameraDevice;->close()V

    .line 389
    .line 390
    .line 391
    return-void

    .line 392
    :pswitch_10
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast v0, Lsu/h;

    .line 395
    .line 396
    const/4 v1, 0x1

    .line 397
    invoke-virtual {v0, v1}, Landroid/os/Handler;->sendEmptyMessage(I)Z

    .line 398
    .line 399
    .line 400
    return-void

    .line 401
    :pswitch_11
    invoke-direct {v0}, Lm8/o;->a()V

    .line 402
    .line 403
    .line 404
    return-void

    .line 405
    :pswitch_12
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 406
    .line 407
    check-cast v0, Lr6/b;

    .line 408
    .line 409
    iget-object v0, v0, Lr6/b;->c:Lpv/g;

    .line 410
    .line 411
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 412
    .line 413
    check-cast v0, Lr6/b;

    .line 414
    .line 415
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 416
    .line 417
    .line 418
    move-result-wide v1

    .line 419
    iget-object v3, v0, Lr6/b;->b:Ljava/util/ArrayList;

    .line 420
    .line 421
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 422
    .line 423
    .line 424
    move-result-wide v4

    .line 425
    const/4 v6, 0x0

    .line 426
    move v7, v6

    .line 427
    :goto_8
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 428
    .line 429
    .line 430
    move-result v8

    .line 431
    if-ge v7, v8, :cond_1c

    .line 432
    .line 433
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    move-result-object v8

    .line 437
    check-cast v8, Lr6/e;

    .line 438
    .line 439
    if-nez v8, :cond_b

    .line 440
    .line 441
    :cond_a
    :goto_9
    move-wide/from16 v16, v1

    .line 442
    .line 443
    move-wide/from16 v19, v4

    .line 444
    .line 445
    move v12, v7

    .line 446
    goto/16 :goto_13

    .line 447
    .line 448
    :cond_b
    iget-object v11, v0, Lr6/b;->a:Landroidx/collection/a1;

    .line 449
    .line 450
    invoke-virtual {v11, v8}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    move-result-object v12

    .line 454
    check-cast v12, Ljava/lang/Long;

    .line 455
    .line 456
    if-nez v12, :cond_c

    .line 457
    .line 458
    goto :goto_a

    .line 459
    :cond_c
    invoke-virtual {v12}, Ljava/lang/Long;->longValue()J

    .line 460
    .line 461
    .line 462
    move-result-wide v12

    .line 463
    cmp-long v12, v12, v4

    .line 464
    .line 465
    if-gez v12, :cond_a

    .line 466
    .line 467
    invoke-virtual {v11, v8}, Landroidx/collection/a1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    :goto_a
    iget-wide v11, v8, Lr6/e;->i:J

    .line 471
    .line 472
    const-wide/16 v13, 0x0

    .line 473
    .line 474
    cmp-long v15, v11, v13

    .line 475
    .line 476
    if-nez v15, :cond_d

    .line 477
    .line 478
    iput-wide v1, v8, Lr6/e;->i:J

    .line 479
    .line 480
    iget v9, v8, Lr6/e;->b:F

    .line 481
    .line 482
    invoke-virtual {v8, v9}, Lr6/e;->c(F)V

    .line 483
    .line 484
    .line 485
    goto :goto_9

    .line 486
    :cond_d
    sub-long v11, v1, v11

    .line 487
    .line 488
    iput-wide v1, v8, Lr6/e;->i:J

    .line 489
    .line 490
    invoke-static {}, Lr6/e;->b()Lr6/b;

    .line 491
    .line 492
    .line 493
    move-result-object v15

    .line 494
    iget v15, v15, Lr6/b;->g:F

    .line 495
    .line 496
    const/4 v13, 0x0

    .line 497
    cmpl-float v14, v15, v13

    .line 498
    .line 499
    if-nez v14, :cond_e

    .line 500
    .line 501
    const-wide/32 v11, 0x7fffffff

    .line 502
    .line 503
    .line 504
    :goto_b
    move-wide/from16 v19, v11

    .line 505
    .line 506
    goto :goto_c

    .line 507
    :cond_e
    long-to-float v11, v11

    .line 508
    div-float/2addr v11, v15

    .line 509
    float-to-long v11, v11

    .line 510
    goto :goto_b

    .line 511
    :goto_c
    iget-boolean v11, v8, Lr6/e;->o:Z

    .line 512
    .line 513
    const v12, 0x7f7fffff    # Float.MAX_VALUE

    .line 514
    .line 515
    .line 516
    if-eqz v11, :cond_10

    .line 517
    .line 518
    iget v11, v8, Lr6/e;->n:F

    .line 519
    .line 520
    cmpl-float v14, v11, v12

    .line 521
    .line 522
    if-eqz v14, :cond_f

    .line 523
    .line 524
    iget-object v14, v8, Lr6/e;->m:Lr6/f;

    .line 525
    .line 526
    float-to-double v10, v11

    .line 527
    iput-wide v10, v14, Lr6/f;->i:D

    .line 528
    .line 529
    iput v12, v8, Lr6/e;->n:F

    .line 530
    .line 531
    :cond_f
    iget-object v10, v8, Lr6/e;->m:Lr6/f;

    .line 532
    .line 533
    iget-wide v10, v10, Lr6/f;->i:D

    .line 534
    .line 535
    double-to-float v10, v10

    .line 536
    iput v10, v8, Lr6/e;->b:F

    .line 537
    .line 538
    iput v13, v8, Lr6/e;->a:F

    .line 539
    .line 540
    iput-boolean v6, v8, Lr6/e;->o:Z

    .line 541
    .line 542
    move v12, v7

    .line 543
    :goto_d
    const/4 v6, 0x1

    .line 544
    goto/16 :goto_f

    .line 545
    .line 546
    :cond_10
    iget v10, v8, Lr6/e;->n:F

    .line 547
    .line 548
    cmpl-float v10, v10, v12

    .line 549
    .line 550
    if-eqz v10, :cond_11

    .line 551
    .line 552
    iget-object v10, v8, Lr6/e;->m:Lr6/f;

    .line 553
    .line 554
    iget v11, v8, Lr6/e;->b:F

    .line 555
    .line 556
    float-to-double v14, v11

    .line 557
    iget v11, v8, Lr6/e;->a:F

    .line 558
    .line 559
    move-object/from16 v21, v10

    .line 560
    .line 561
    float-to-double v9, v11

    .line 562
    const-wide/16 v22, 0x2

    .line 563
    .line 564
    div-long v22, v19, v22

    .line 565
    .line 566
    move-wide/from16 v26, v9

    .line 567
    .line 568
    move-wide/from16 v24, v14

    .line 569
    .line 570
    invoke-virtual/range {v21 .. v27}, Lr6/f;->c(JDD)Lb1/x0;

    .line 571
    .line 572
    .line 573
    move-result-object v9

    .line 574
    iget-object v10, v8, Lr6/e;->m:Lr6/f;

    .line 575
    .line 576
    iget v11, v8, Lr6/e;->n:F

    .line 577
    .line 578
    float-to-double v14, v11

    .line 579
    iput-wide v14, v10, Lr6/f;->i:D

    .line 580
    .line 581
    iput v12, v8, Lr6/e;->n:F

    .line 582
    .line 583
    iget v11, v9, Lb1/x0;->d:F

    .line 584
    .line 585
    float-to-double v11, v11

    .line 586
    iget v9, v9, Lb1/x0;->e:F

    .line 587
    .line 588
    float-to-double v14, v9

    .line 589
    move-object/from16 v28, v10

    .line 590
    .line 591
    move-wide/from16 v31, v11

    .line 592
    .line 593
    move-wide/from16 v33, v14

    .line 594
    .line 595
    move-wide/from16 v29, v22

    .line 596
    .line 597
    invoke-virtual/range {v28 .. v34}, Lr6/f;->c(JDD)Lb1/x0;

    .line 598
    .line 599
    .line 600
    move-result-object v9

    .line 601
    iget v10, v9, Lb1/x0;->d:F

    .line 602
    .line 603
    iput v10, v8, Lr6/e;->b:F

    .line 604
    .line 605
    iget v9, v9, Lb1/x0;->e:F

    .line 606
    .line 607
    iput v9, v8, Lr6/e;->a:F

    .line 608
    .line 609
    goto :goto_e

    .line 610
    :cond_11
    iget-object v9, v8, Lr6/e;->m:Lr6/f;

    .line 611
    .line 612
    iget v10, v8, Lr6/e;->b:F

    .line 613
    .line 614
    float-to-double v10, v10

    .line 615
    iget v12, v8, Lr6/e;->a:F

    .line 616
    .line 617
    float-to-double v14, v12

    .line 618
    move-object/from16 v18, v9

    .line 619
    .line 620
    move-wide/from16 v21, v10

    .line 621
    .line 622
    move-wide/from16 v23, v14

    .line 623
    .line 624
    invoke-virtual/range {v18 .. v24}, Lr6/f;->c(JDD)Lb1/x0;

    .line 625
    .line 626
    .line 627
    move-result-object v9

    .line 628
    iget v10, v9, Lb1/x0;->d:F

    .line 629
    .line 630
    iput v10, v8, Lr6/e;->b:F

    .line 631
    .line 632
    iget v9, v9, Lb1/x0;->e:F

    .line 633
    .line 634
    iput v9, v8, Lr6/e;->a:F

    .line 635
    .line 636
    :goto_e
    iget v9, v8, Lr6/e;->b:F

    .line 637
    .line 638
    iget v10, v8, Lr6/e;->h:F

    .line 639
    .line 640
    invoke-static {v9, v10}, Ljava/lang/Math;->max(FF)F

    .line 641
    .line 642
    .line 643
    move-result v9

    .line 644
    iput v9, v8, Lr6/e;->b:F

    .line 645
    .line 646
    iget v10, v8, Lr6/e;->g:F

    .line 647
    .line 648
    invoke-static {v9, v10}, Ljava/lang/Math;->min(FF)F

    .line 649
    .line 650
    .line 651
    move-result v9

    .line 652
    iput v9, v8, Lr6/e;->b:F

    .line 653
    .line 654
    iget v10, v8, Lr6/e;->a:F

    .line 655
    .line 656
    iget-object v11, v8, Lr6/e;->m:Lr6/f;

    .line 657
    .line 658
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 659
    .line 660
    .line 661
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    .line 662
    .line 663
    .line 664
    move-result v10

    .line 665
    float-to-double v14, v10

    .line 666
    move v12, v7

    .line 667
    iget-wide v6, v11, Lr6/f;->e:D

    .line 668
    .line 669
    cmpg-double v6, v14, v6

    .line 670
    .line 671
    if-gez v6, :cond_12

    .line 672
    .line 673
    iget-wide v6, v11, Lr6/f;->i:D

    .line 674
    .line 675
    double-to-float v6, v6

    .line 676
    sub-float/2addr v9, v6

    .line 677
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 678
    .line 679
    .line 680
    move-result v6

    .line 681
    float-to-double v6, v6

    .line 682
    iget-wide v14, v11, Lr6/f;->d:D

    .line 683
    .line 684
    cmpg-double v6, v6, v14

    .line 685
    .line 686
    if-gez v6, :cond_12

    .line 687
    .line 688
    iget-object v6, v8, Lr6/e;->m:Lr6/f;

    .line 689
    .line 690
    iget-wide v6, v6, Lr6/f;->i:D

    .line 691
    .line 692
    double-to-float v6, v6

    .line 693
    iput v6, v8, Lr6/e;->b:F

    .line 694
    .line 695
    iput v13, v8, Lr6/e;->a:F

    .line 696
    .line 697
    goto/16 :goto_d

    .line 698
    .line 699
    :cond_12
    const/4 v6, 0x0

    .line 700
    :goto_f
    iget v7, v8, Lr6/e;->b:F

    .line 701
    .line 702
    iget v9, v8, Lr6/e;->g:F

    .line 703
    .line 704
    invoke-static {v7, v9}, Ljava/lang/Math;->min(FF)F

    .line 705
    .line 706
    .line 707
    move-result v7

    .line 708
    iput v7, v8, Lr6/e;->b:F

    .line 709
    .line 710
    iget v9, v8, Lr6/e;->h:F

    .line 711
    .line 712
    invoke-static {v7, v9}, Ljava/lang/Math;->max(FF)F

    .line 713
    .line 714
    .line 715
    move-result v7

    .line 716
    iput v7, v8, Lr6/e;->b:F

    .line 717
    .line 718
    invoke-virtual {v8, v7}, Lr6/e;->c(F)V

    .line 719
    .line 720
    .line 721
    if-eqz v6, :cond_1a

    .line 722
    .line 723
    iget-object v6, v8, Lr6/e;->k:Ljava/util/ArrayList;

    .line 724
    .line 725
    const/4 v10, 0x0

    .line 726
    iput-boolean v10, v8, Lr6/e;->f:Z

    .line 727
    .line 728
    invoke-static {}, Lr6/e;->b()Lr6/b;

    .line 729
    .line 730
    .line 731
    move-result-object v7

    .line 732
    iget-object v9, v7, Lr6/b;->a:Landroidx/collection/a1;

    .line 733
    .line 734
    invoke-virtual {v9, v8}, Landroidx/collection/a1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 735
    .line 736
    .line 737
    iget-object v9, v7, Lr6/b;->b:Ljava/util/ArrayList;

    .line 738
    .line 739
    invoke-virtual {v9, v8}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 740
    .line 741
    .line 742
    move-result v11

    .line 743
    if-ltz v11, :cond_13

    .line 744
    .line 745
    const/4 v13, 0x0

    .line 746
    invoke-virtual {v9, v11, v13}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 747
    .line 748
    .line 749
    const/4 v9, 0x1

    .line 750
    iput-boolean v9, v7, Lr6/b;->f:Z

    .line 751
    .line 752
    :cond_13
    const-wide/16 v13, 0x0

    .line 753
    .line 754
    iput-wide v13, v8, Lr6/e;->i:J

    .line 755
    .line 756
    const/4 v10, 0x0

    .line 757
    iput-boolean v10, v8, Lr6/e;->c:Z

    .line 758
    .line 759
    const/4 v7, 0x0

    .line 760
    :goto_10
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 761
    .line 762
    .line 763
    move-result v9

    .line 764
    if-ge v7, v9, :cond_18

    .line 765
    .line 766
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 767
    .line 768
    .line 769
    move-result-object v9

    .line 770
    if-eqz v9, :cond_16

    .line 771
    .line 772
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 773
    .line 774
    .line 775
    move-result-object v9

    .line 776
    check-cast v9, Lbb/t;

    .line 777
    .line 778
    iget v11, v8, Lr6/e;->b:F

    .line 779
    .line 780
    iget-object v9, v9, Lbb/t;->a:Lbb/u;

    .line 781
    .line 782
    sget-object v13, Lbb/w;->i0:Lb8/b;

    .line 783
    .line 784
    iget-object v14, v9, Lbb/u;->g:Lbb/d0;

    .line 785
    .line 786
    const/high16 v15, 0x3f800000    # 1.0f

    .line 787
    .line 788
    cmpg-float v11, v11, v15

    .line 789
    .line 790
    if-gez v11, :cond_15

    .line 791
    .line 792
    iget-wide v10, v14, Lbb/x;->A:J

    .line 793
    .line 794
    move-wide/from16 v16, v1

    .line 795
    .line 796
    const/4 v15, 0x0

    .line 797
    invoke-virtual {v14, v15}, Lbb/d0;->P(I)Lbb/x;

    .line 798
    .line 799
    .line 800
    move-result-object v1

    .line 801
    iget-object v2, v1, Lbb/x;->v:Lbb/x;

    .line 802
    .line 803
    const/4 v15, 0x0

    .line 804
    iput-object v15, v1, Lbb/x;->v:Lbb/x;

    .line 805
    .line 806
    move-wide/from16 v19, v4

    .line 807
    .line 808
    iget-wide v4, v9, Lbb/u;->a:J

    .line 809
    .line 810
    move v15, v7

    .line 811
    move-object v1, v8

    .line 812
    const-wide/16 v7, -0x1

    .line 813
    .line 814
    invoke-virtual {v14, v7, v8, v4, v5}, Lbb/d0;->F(JJ)V

    .line 815
    .line 816
    .line 817
    invoke-virtual {v14, v10, v11, v7, v8}, Lbb/d0;->F(JJ)V

    .line 818
    .line 819
    .line 820
    iput-wide v10, v9, Lbb/u;->a:J

    .line 821
    .line 822
    iget-object v4, v9, Lbb/u;->f:Landroidx/fragment/app/m;

    .line 823
    .line 824
    if-eqz v4, :cond_14

    .line 825
    .line 826
    invoke-virtual {v4}, Landroidx/fragment/app/m;->run()V

    .line 827
    .line 828
    .line 829
    :cond_14
    iget-object v4, v14, Lbb/x;->x:Ljava/util/ArrayList;

    .line 830
    .line 831
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 832
    .line 833
    .line 834
    if-eqz v2, :cond_17

    .line 835
    .line 836
    const/4 v9, 0x1

    .line 837
    invoke-virtual {v2, v2, v13, v9}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 838
    .line 839
    .line 840
    goto :goto_11

    .line 841
    :cond_15
    move-wide/from16 v16, v1

    .line 842
    .line 843
    move-wide/from16 v19, v4

    .line 844
    .line 845
    move v15, v7

    .line 846
    move-object v1, v8

    .line 847
    const/4 v9, 0x1

    .line 848
    const/4 v10, 0x0

    .line 849
    invoke-virtual {v14, v14, v13, v10}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 850
    .line 851
    .line 852
    goto :goto_11

    .line 853
    :cond_16
    move-wide/from16 v16, v1

    .line 854
    .line 855
    move-wide/from16 v19, v4

    .line 856
    .line 857
    move v15, v7

    .line 858
    move-object v1, v8

    .line 859
    :cond_17
    const/4 v9, 0x1

    .line 860
    :goto_11
    add-int/lit8 v7, v15, 0x1

    .line 861
    .line 862
    move-object v8, v1

    .line 863
    move-wide/from16 v1, v16

    .line 864
    .line 865
    move-wide/from16 v4, v19

    .line 866
    .line 867
    goto :goto_10

    .line 868
    :cond_18
    move-wide/from16 v16, v1

    .line 869
    .line 870
    move-wide/from16 v19, v4

    .line 871
    .line 872
    const/4 v9, 0x1

    .line 873
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 874
    .line 875
    .line 876
    move-result v1

    .line 877
    sub-int/2addr v1, v9

    .line 878
    :goto_12
    if-ltz v1, :cond_1b

    .line 879
    .line 880
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 881
    .line 882
    .line 883
    move-result-object v2

    .line 884
    if-nez v2, :cond_19

    .line 885
    .line 886
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 887
    .line 888
    .line 889
    :cond_19
    add-int/lit8 v1, v1, -0x1

    .line 890
    .line 891
    goto :goto_12

    .line 892
    :cond_1a
    move-wide/from16 v16, v1

    .line 893
    .line 894
    move-wide/from16 v19, v4

    .line 895
    .line 896
    :cond_1b
    :goto_13
    add-int/lit8 v7, v12, 0x1

    .line 897
    .line 898
    move-wide/from16 v1, v16

    .line 899
    .line 900
    move-wide/from16 v4, v19

    .line 901
    .line 902
    const/4 v6, 0x0

    .line 903
    goto/16 :goto_8

    .line 904
    .line 905
    :cond_1c
    iget-boolean v1, v0, Lr6/b;->f:Z

    .line 906
    .line 907
    if-eqz v1, :cond_20

    .line 908
    .line 909
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 910
    .line 911
    .line 912
    move-result v1

    .line 913
    const/4 v9, 0x1

    .line 914
    sub-int/2addr v1, v9

    .line 915
    :goto_14
    if-ltz v1, :cond_1e

    .line 916
    .line 917
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 918
    .line 919
    .line 920
    move-result-object v2

    .line 921
    if-nez v2, :cond_1d

    .line 922
    .line 923
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 924
    .line 925
    .line 926
    :cond_1d
    add-int/lit8 v1, v1, -0x1

    .line 927
    .line 928
    goto :goto_14

    .line 929
    :cond_1e
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 930
    .line 931
    .line 932
    move-result v1

    .line 933
    if-nez v1, :cond_1f

    .line 934
    .line 935
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 936
    .line 937
    const/16 v2, 0x21

    .line 938
    .line 939
    if-lt v1, v2, :cond_1f

    .line 940
    .line 941
    iget-object v1, v0, Lr6/b;->h:Lb81/a;

    .line 942
    .line 943
    iget-object v2, v1, Lb81/a;->e:Ljava/lang/Object;

    .line 944
    .line 945
    check-cast v2, Lr6/a;

    .line 946
    .line 947
    invoke-static {v2}, Li2/p0;->m(Lr6/a;)Z

    .line 948
    .line 949
    .line 950
    const/4 v15, 0x0

    .line 951
    iput-object v15, v1, Lb81/a;->e:Ljava/lang/Object;

    .line 952
    .line 953
    :cond_1f
    const/4 v10, 0x0

    .line 954
    iput-boolean v10, v0, Lr6/b;->f:Z

    .line 955
    .line 956
    :cond_20
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 957
    .line 958
    .line 959
    move-result v1

    .line 960
    if-lez v1, :cond_21

    .line 961
    .line 962
    iget-object v1, v0, Lr6/b;->e:Lb81/b;

    .line 963
    .line 964
    iget-object v0, v0, Lr6/b;->d:Lm8/o;

    .line 965
    .line 966
    iget-object v1, v1, Lb81/b;->e:Ljava/lang/Object;

    .line 967
    .line 968
    check-cast v1, Landroid/view/Choreographer;

    .line 969
    .line 970
    new-instance v2, Ll4/z;

    .line 971
    .line 972
    const/4 v3, 0x1

    .line 973
    invoke-direct {v2, v0, v3}, Ll4/z;-><init>(Ljava/lang/Runnable;I)V

    .line 974
    .line 975
    .line 976
    invoke-virtual {v1, v2}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 977
    .line 978
    .line 979
    :cond_21
    return-void

    .line 980
    :pswitch_13
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 981
    .line 982
    check-cast v0, Landroidx/lifecycle/c1;

    .line 983
    .line 984
    iget-object v0, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 985
    .line 986
    check-cast v0, Lp0/n;

    .line 987
    .line 988
    if-eqz v0, :cond_22

    .line 989
    .line 990
    invoke-virtual {v0}, Ljava/util/AbstractMap;->values()Ljava/util/Collection;

    .line 991
    .line 992
    .line 993
    move-result-object v0

    .line 994
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 995
    .line 996
    .line 997
    move-result-object v0

    .line 998
    :goto_15
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 999
    .line 1000
    .line 1001
    move-result v1

    .line 1002
    if-eqz v1, :cond_22

    .line 1003
    .line 1004
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v1

    .line 1008
    check-cast v1, Lp0/k;

    .line 1009
    .line 1010
    invoke-virtual {v1}, Lp0/k;->b()V

    .line 1011
    .line 1012
    .line 1013
    goto :goto_15

    .line 1014
    :cond_22
    return-void

    .line 1015
    :pswitch_14
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1016
    .line 1017
    check-cast v0, Lq0/e;

    .line 1018
    .line 1019
    const/4 v1, 0x1

    .line 1020
    iput-boolean v1, v0, Lq0/e;->i:Z

    .line 1021
    .line 1022
    invoke-virtual {v0}, Lq0/e;->d()V

    .line 1023
    .line 1024
    .line 1025
    return-void

    .line 1026
    :pswitch_15
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1027
    .line 1028
    check-cast v0, Lil/g;

    .line 1029
    .line 1030
    iget-object v0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 1031
    .line 1032
    check-cast v0, Lp0/n;

    .line 1033
    .line 1034
    if-eqz v0, :cond_23

    .line 1035
    .line 1036
    invoke-virtual {v0}, Ljava/util/AbstractMap;->values()Ljava/util/Collection;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v0

    .line 1040
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 1041
    .line 1042
    .line 1043
    move-result-object v0

    .line 1044
    :goto_16
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1045
    .line 1046
    .line 1047
    move-result v1

    .line 1048
    if-eqz v1, :cond_23

    .line 1049
    .line 1050
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1051
    .line 1052
    .line 1053
    move-result-object v1

    .line 1054
    check-cast v1, Lp0/k;

    .line 1055
    .line 1056
    invoke-virtual {v1}, Lp0/k;->b()V

    .line 1057
    .line 1058
    .line 1059
    goto :goto_16

    .line 1060
    :cond_23
    return-void

    .line 1061
    :pswitch_16
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1062
    .line 1063
    check-cast v0, Lp0/c;

    .line 1064
    .line 1065
    const/4 v1, 0x1

    .line 1066
    iput-boolean v1, v0, Lp0/c;->m:Z

    .line 1067
    .line 1068
    invoke-virtual {v0}, Lp0/c;->d()V

    .line 1069
    .line 1070
    .line 1071
    return-void

    .line 1072
    :pswitch_17
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1073
    .line 1074
    check-cast v0, Lp0/l;

    .line 1075
    .line 1076
    invoke-virtual {v0}, Lp0/l;->close()V

    .line 1077
    .line 1078
    .line 1079
    return-void

    .line 1080
    :pswitch_18
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1081
    .line 1082
    move-object v1, v0

    .line 1083
    check-cast v1, La8/b;

    .line 1084
    .line 1085
    iget-object v0, v1, La8/b;->g:Ljava/lang/Object;

    .line 1086
    .line 1087
    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 1088
    .line 1089
    const/4 v2, 0x0

    .line 1090
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 1091
    .line 1092
    .line 1093
    monitor-enter v1

    .line 1094
    :try_start_7
    iget-object v0, v1, La8/b;->f:Ljava/lang/Object;

    .line 1095
    .line 1096
    check-cast v0, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 1097
    .line 1098
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->isMarked()Z

    .line 1099
    .line 1100
    .line 1101
    move-result v0

    .line 1102
    if-eqz v0, :cond_24

    .line 1103
    .line 1104
    iget-object v0, v1, La8/b;->f:Ljava/lang/Object;

    .line 1105
    .line 1106
    check-cast v0, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 1107
    .line 1108
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v0

    .line 1112
    move-object v2, v0

    .line 1113
    check-cast v2, Los/e;

    .line 1114
    .line 1115
    monitor-enter v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_6

    .line 1116
    :try_start_8
    new-instance v0, Ljava/util/HashMap;

    .line 1117
    .line 1118
    iget-object v3, v2, Los/e;->a:Ljava/util/HashMap;

    .line 1119
    .line 1120
    invoke-direct {v0, v3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 1121
    .line 1122
    .line 1123
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 1124
    .line 1125
    .line 1126
    move-result-object v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_7

    .line 1127
    :try_start_9
    monitor-exit v2

    .line 1128
    iget-object v2, v1, La8/b;->f:Ljava/lang/Object;

    .line 1129
    .line 1130
    check-cast v2, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 1131
    .line 1132
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v3

    .line 1136
    check-cast v3, Los/e;

    .line 1137
    .line 1138
    const/4 v4, 0x0

    .line 1139
    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->set(Ljava/lang/Object;Z)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_6

    .line 1140
    .line 1141
    .line 1142
    move-object v2, v0

    .line 1143
    goto :goto_17

    .line 1144
    :catchall_6
    move-exception v0

    .line 1145
    goto :goto_18

    .line 1146
    :catchall_7
    move-exception v0

    .line 1147
    :try_start_a
    monitor-exit v2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_7

    .line 1148
    :try_start_b
    throw v0

    .line 1149
    :cond_24
    :goto_17
    monitor-exit v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_6

    .line 1150
    if-eqz v2, :cond_25

    .line 1151
    .line 1152
    iget-object v0, v1, La8/b;->h:Ljava/lang/Object;

    .line 1153
    .line 1154
    check-cast v0, Lss/b;

    .line 1155
    .line 1156
    iget-object v3, v0, Lss/b;->f:Ljava/lang/Object;

    .line 1157
    .line 1158
    check-cast v3, Los/h;

    .line 1159
    .line 1160
    iget-object v0, v0, Lss/b;->e:Ljava/lang/Object;

    .line 1161
    .line 1162
    check-cast v0, Ljava/lang/String;

    .line 1163
    .line 1164
    iget-boolean v1, v1, La8/b;->e:Z

    .line 1165
    .line 1166
    invoke-virtual {v3, v0, v2, v1}, Los/h;->h(Ljava/lang/String;Ljava/util/Map;Z)V

    .line 1167
    .line 1168
    .line 1169
    :cond_25
    return-void

    .line 1170
    :goto_18
    :try_start_c
    monitor-exit v1
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_6

    .line 1171
    throw v0

    .line 1172
    :pswitch_19
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1173
    .line 1174
    check-cast v0, Lss/b;

    .line 1175
    .line 1176
    iget-object v1, v0, Lss/b;->k:Ljava/lang/Object;

    .line 1177
    .line 1178
    check-cast v1, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 1179
    .line 1180
    monitor-enter v1

    .line 1181
    :try_start_d
    iget-object v2, v0, Lss/b;->k:Ljava/lang/Object;

    .line 1182
    .line 1183
    check-cast v2, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 1184
    .line 1185
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->isMarked()Z

    .line 1186
    .line 1187
    .line 1188
    move-result v2

    .line 1189
    const/4 v3, 0x0

    .line 1190
    if-eqz v2, :cond_26

    .line 1191
    .line 1192
    iget-object v2, v0, Lss/b;->k:Ljava/lang/Object;

    .line 1193
    .line 1194
    check-cast v2, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 1195
    .line 1196
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v2

    .line 1200
    check-cast v2, Ljava/lang/String;

    .line 1201
    .line 1202
    iget-object v4, v0, Lss/b;->k:Ljava/lang/Object;

    .line 1203
    .line 1204
    check-cast v4, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 1205
    .line 1206
    invoke-virtual {v4, v2, v3}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->set(Ljava/lang/Object;Z)V

    .line 1207
    .line 1208
    .line 1209
    const/4 v3, 0x1

    .line 1210
    goto :goto_19

    .line 1211
    :catchall_8
    move-exception v0

    .line 1212
    goto :goto_1a

    .line 1213
    :cond_26
    const/4 v2, 0x0

    .line 1214
    :goto_19
    monitor-exit v1
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_8

    .line 1215
    if-eqz v3, :cond_27

    .line 1216
    .line 1217
    iget-object v1, v0, Lss/b;->f:Ljava/lang/Object;

    .line 1218
    .line 1219
    check-cast v1, Los/h;

    .line 1220
    .line 1221
    iget-object v0, v0, Lss/b;->e:Ljava/lang/Object;

    .line 1222
    .line 1223
    check-cast v0, Ljava/lang/String;

    .line 1224
    .line 1225
    invoke-virtual {v1, v0, v2}, Los/h;->j(Ljava/lang/String;Ljava/lang/String;)V

    .line 1226
    .line 1227
    .line 1228
    :cond_27
    return-void

    .line 1229
    :goto_1a
    :try_start_e
    monitor-exit v1
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_8

    .line 1230
    throw v0

    .line 1231
    :pswitch_1a
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1232
    .line 1233
    check-cast v0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 1234
    .line 1235
    invoke-static {v0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->a(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)V

    .line 1236
    .line 1237
    .line 1238
    return-void

    .line 1239
    :pswitch_1b
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1240
    .line 1241
    check-cast v0, Ln8/k;

    .line 1242
    .line 1243
    iget-object v1, v0, Ln8/k;->k:Landroid/view/Surface;

    .line 1244
    .line 1245
    const/4 v2, 0x0

    .line 1246
    if-eqz v1, :cond_28

    .line 1247
    .line 1248
    iget-object v3, v0, Ln8/k;->d:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 1249
    .line 1250
    invoke-virtual {v3}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 1251
    .line 1252
    .line 1253
    move-result-object v3

    .line 1254
    :goto_1b
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1255
    .line 1256
    .line 1257
    move-result v4

    .line 1258
    if-eqz v4, :cond_28

    .line 1259
    .line 1260
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1261
    .line 1262
    .line 1263
    move-result-object v4

    .line 1264
    check-cast v4, La8/f0;

    .line 1265
    .line 1266
    iget-object v4, v4, La8/f0;->d:La8/i0;

    .line 1267
    .line 1268
    invoke-virtual {v4, v2}, La8/i0;->E0(Ljava/lang/Object;)V

    .line 1269
    .line 1270
    .line 1271
    goto :goto_1b

    .line 1272
    :cond_28
    iget-object v3, v0, Ln8/k;->j:Landroid/graphics/SurfaceTexture;

    .line 1273
    .line 1274
    if-eqz v3, :cond_29

    .line 1275
    .line 1276
    invoke-virtual {v3}, Landroid/graphics/SurfaceTexture;->release()V

    .line 1277
    .line 1278
    .line 1279
    :cond_29
    if-eqz v1, :cond_2a

    .line 1280
    .line 1281
    invoke-virtual {v1}, Landroid/view/Surface;->release()V

    .line 1282
    .line 1283
    .line 1284
    :cond_2a
    iput-object v2, v0, Ln8/k;->j:Landroid/graphics/SurfaceTexture;

    .line 1285
    .line 1286
    iput-object v2, v0, Ln8/k;->k:Landroid/view/Surface;

    .line 1287
    .line 1288
    return-void

    .line 1289
    :pswitch_1c
    iget-object v0, v0, Lm8/o;->e:Ljava/lang/Object;

    .line 1290
    .line 1291
    check-cast v0, Lm8/t;

    .line 1292
    .line 1293
    iget v1, v0, Lm8/t;->k:I

    .line 1294
    .line 1295
    add-int/lit8 v1, v1, -0x1

    .line 1296
    .line 1297
    iput v1, v0, Lm8/t;->k:I

    .line 1298
    .line 1299
    return-void

    .line 1300
    nop

    .line 1301
    :pswitch_data_0
    .packed-switch 0x0
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
