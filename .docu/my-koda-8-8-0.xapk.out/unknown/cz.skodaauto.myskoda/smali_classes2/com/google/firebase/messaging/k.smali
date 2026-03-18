.class public final Lcom/google/firebase/messaging/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Ljava/util/ArrayDeque;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Ljava/util/ArrayDeque;-><init>(I)V

    iput-object v0, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/j2;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    return-void
.end method

.method private final a(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final b(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final c(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final d(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final e(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final f(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final g(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final h(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public i(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvp/j2;

    .line 5
    .line 6
    :try_start_0
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvp/g1;

    .line 9
    .line 10
    iget-object v2, v0, Lvp/g1;->i:Lvp/p0;

    .line 11
    .line 12
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 13
    .line 14
    .line 15
    iget-object v2, v2, Lvp/p0;->r:Lvp/n0;

    .line 16
    .line 17
    const-string v3, "onActivityCreated"

    .line 18
    .line 19
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v2, p1, Lcom/google/android/gms/internal/measurement/w0;->f:Landroid/content/Intent;

    .line 23
    .line 24
    if-eqz v2, :cond_7

    .line 25
    .line 26
    invoke-virtual {v2}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    invoke-virtual {v3}, Landroid/net/Uri;->isHierarchical()Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-nez v4, :cond_0

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    :goto_0
    move-object v5, v3

    .line 40
    goto :goto_2

    .line 41
    :catchall_0
    move-exception v0

    .line 42
    move-object p0, v0

    .line 43
    goto/16 :goto_c

    .line 44
    .line 45
    :catch_0
    move-exception v0

    .line 46
    move-object p0, v0

    .line 47
    goto/16 :goto_a

    .line 48
    .line 49
    :cond_1
    :goto_1
    invoke-virtual {v2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    const/4 v4, 0x0

    .line 54
    if-eqz v3, :cond_2

    .line 55
    .line 56
    const-string v5, "com.android.vending.referral_url"

    .line 57
    .line 58
    invoke-virtual {v3, v5}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    if-nez v5, :cond_2

    .line 67
    .line 68
    invoke-static {v3}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    goto :goto_0

    .line 73
    :cond_2
    move-object v5, v4

    .line 74
    :goto_2
    if-eqz v5, :cond_7

    .line 75
    .line 76
    invoke-virtual {v5}, Landroid/net/Uri;->isHierarchical()Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-nez v3, :cond_3

    .line 81
    .line 82
    goto :goto_8

    .line 83
    :cond_3
    iget-object v3, v0, Lvp/g1;->l:Lvp/d4;

    .line 84
    .line 85
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 86
    .line 87
    .line 88
    const-string v3, "android.intent.extra.REFERRER_NAME"

    .line 89
    .line 90
    invoke-virtual {v2, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    const-string v3, "android-app://com.google.android.googlequicksearchbox/https/www.google.com"

    .line 95
    .line 96
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    if-nez v3, :cond_5

    .line 101
    .line 102
    const-string v3, "https://www.google.com"

    .line 103
    .line 104
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    if-nez v3, :cond_5

    .line 109
    .line 110
    const-string v3, "android-app://com.google.appcrawler"

    .line 111
    .line 112
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    if-eqz v2, :cond_4

    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_4
    const-string v2, "auto"

    .line 120
    .line 121
    :goto_3
    move-object v6, v2

    .line 122
    goto :goto_5

    .line 123
    :cond_5
    :goto_4
    const-string v2, "gs"

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :goto_5
    const-string v2, "referrer"

    .line 127
    .line 128
    invoke-virtual {v5, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    if-nez p2, :cond_6

    .line 133
    .line 134
    const/4 v2, 0x1

    .line 135
    :goto_6
    move v4, v2

    .line 136
    goto :goto_7

    .line 137
    :cond_6
    const/4 v2, 0x0

    .line 138
    goto :goto_6

    .line 139
    :goto_7
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 140
    .line 141
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 142
    .line 143
    .line 144
    new-instance v2, Lvp/a2;

    .line 145
    .line 146
    move-object v3, p0

    .line 147
    invoke-direct/range {v2 .. v7}, Lvp/a2;-><init>(Lcom/google/firebase/messaging/k;ZLandroid/net/Uri;Ljava/lang/String;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0, v2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 151
    .line 152
    .line 153
    goto :goto_b

    .line 154
    :cond_7
    :goto_8
    iget-object p0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast p0, Lvp/g1;

    .line 157
    .line 158
    :goto_9
    iget-object p0, p0, Lvp/g1;->o:Lvp/u2;

    .line 159
    .line 160
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p0, p1, p2}, Lvp/u2;->i0(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V

    .line 164
    .line 165
    .line 166
    return-void

    .line 167
    :goto_a
    :try_start_1
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v0, Lvp/g1;

    .line 170
    .line 171
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 172
    .line 173
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 174
    .line 175
    .line 176
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 177
    .line 178
    const-string v2, "Throwable caught in onActivityCreated"

    .line 179
    .line 180
    invoke-virtual {v0, p0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 181
    .line 182
    .line 183
    :goto_b
    iget-object p0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast p0, Lvp/g1;

    .line 186
    .line 187
    goto :goto_9

    .line 188
    :goto_c
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast v0, Lvp/g1;

    .line 191
    .line 192
    iget-object v0, v0, Lvp/g1;->o:Lvp/u2;

    .line 193
    .line 194
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v0, p1, p2}, Lvp/u2;->i0(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V

    .line 198
    .line 199
    .line 200
    throw p0
.end method

.method public j(Lcom/google/android/gms/internal/measurement/w0;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/j2;

    .line 4
    .line 5
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lvp/g1;

    .line 8
    .line 9
    iget-object p0, p0, Lvp/g1;->o:Lvp/u2;

    .line 10
    .line 11
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lvp/u2;->p:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter v0

    .line 17
    :try_start_0
    iget-object v1, p0, Lvp/u2;->k:Lcom/google/android/gms/internal/measurement/w0;

    .line 18
    .line 19
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    iput-object v1, p0, Lvp/u2;->k:Lcom/google/android/gms/internal/measurement/w0;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lvp/g1;

    .line 35
    .line 36
    iget-object v0, v0, Lvp/g1;->g:Lvp/h;

    .line 37
    .line 38
    invoke-virtual {v0}, Lvp/h;->o0()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-nez v0, :cond_1

    .line 43
    .line 44
    return-void

    .line 45
    :cond_1
    iget-object p0, p0, Lvp/u2;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 46
    .line 47
    iget p1, p1, Lcom/google/android/gms/internal/measurement/w0;->d:I

    .line 48
    .line 49
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 58
    throw p0
.end method

.method public k(Lcom/google/android/gms/internal/measurement/w0;)V
    .locals 6

    .line 1
    iget-object p0, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/j2;

    .line 4
    .line 5
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lvp/g1;

    .line 8
    .line 9
    iget-object v0, p0, Lvp/g1;->o:Lvp/u2;

    .line 10
    .line 11
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Lvp/u2;->p:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter v1

    .line 17
    const/4 v2, 0x0

    .line 18
    :try_start_0
    iput-boolean v2, v0, Lvp/u2;->o:Z

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    iput-boolean v2, v0, Lvp/u2;->l:Z

    .line 22
    .line 23
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lvp/g1;

    .line 27
    .line 28
    iget-object v2, v1, Lvp/g1;->n:Lto/a;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 34
    .line 35
    .line 36
    move-result-wide v2

    .line 37
    iget-object v4, v1, Lvp/g1;->g:Lvp/h;

    .line 38
    .line 39
    invoke-virtual {v4}, Lvp/h;->o0()Z

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    const/4 v5, 0x0

    .line 44
    if-nez v4, :cond_0

    .line 45
    .line 46
    iput-object v5, v0, Lvp/u2;->g:Lvp/r2;

    .line 47
    .line 48
    iget-object p1, v1, Lvp/g1;->j:Lvp/e1;

    .line 49
    .line 50
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 51
    .line 52
    .line 53
    new-instance v1, Lvp/v;

    .line 54
    .line 55
    invoke-direct {v1, v0, v2, v3}, Lvp/v;-><init>(Lvp/u2;J)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-virtual {v0, p1}, Lvp/u2;->f0(Lcom/google/android/gms/internal/measurement/w0;)Lvp/r2;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    iget-object v4, v0, Lvp/u2;->g:Lvp/r2;

    .line 67
    .line 68
    iput-object v4, v0, Lvp/u2;->h:Lvp/r2;

    .line 69
    .line 70
    iput-object v5, v0, Lvp/u2;->g:Lvp/r2;

    .line 71
    .line 72
    iget-object v1, v1, Lvp/g1;->j:Lvp/e1;

    .line 73
    .line 74
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 75
    .line 76
    .line 77
    new-instance v4, Lvp/a;

    .line 78
    .line 79
    invoke-direct {v4, v0, p1, v2, v3}, Lvp/a;-><init>(Lvp/u2;Lvp/r2;J)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v1, v4}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 83
    .line 84
    .line 85
    :goto_0
    iget-object p0, p0, Lvp/g1;->k:Lvp/k3;

    .line 86
    .line 87
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 88
    .line 89
    .line 90
    iget-object p1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast p1, Lvp/g1;

    .line 93
    .line 94
    iget-object v0, p1, Lvp/g1;->n:Lto/a;

    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 100
    .line 101
    .line 102
    move-result-wide v0

    .line 103
    iget-object p1, p1, Lvp/g1;->j:Lvp/e1;

    .line 104
    .line 105
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 106
    .line 107
    .line 108
    new-instance v2, Lvp/h3;

    .line 109
    .line 110
    const/4 v3, 0x1

    .line 111
    invoke-direct {v2, p0, v0, v1, v3}, Lvp/h3;-><init>(Lvp/k3;JI)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {p1, v2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :catchall_0
    move-exception p0

    .line 119
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 120
    throw p0
.end method

.method public l(Lcom/google/android/gms/internal/measurement/w0;)V
    .locals 6

    .line 1
    iget-object p0, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/j2;

    .line 4
    .line 5
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lvp/g1;

    .line 8
    .line 9
    iget-object v0, p0, Lvp/g1;->k:Lvp/k3;

    .line 10
    .line 11
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lvp/g1;

    .line 17
    .line 18
    iget-object v2, v1, Lvp/g1;->n:Lto/a;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 24
    .line 25
    .line 26
    move-result-wide v2

    .line 27
    iget-object v1, v1, Lvp/g1;->j:Lvp/e1;

    .line 28
    .line 29
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 30
    .line 31
    .line 32
    new-instance v4, Lvp/h3;

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    invoke-direct {v4, v0, v2, v3, v5}, Lvp/h3;-><init>(Lvp/k3;JI)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1, v4}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lvp/g1;->o:Lvp/u2;

    .line 42
    .line 43
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lvp/u2;->p:Ljava/lang/Object;

    .line 47
    .line 48
    monitor-enter v0

    .line 49
    const/4 v1, 0x1

    .line 50
    :try_start_0
    iput-boolean v1, p0, Lvp/u2;->o:Z

    .line 51
    .line 52
    iget-object v1, p0, Lvp/u2;->k:Lcom/google/android/gms/internal/measurement/w0;

    .line 53
    .line 54
    invoke-static {p1, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    const/4 v2, 0x0

    .line 59
    if-nez v1, :cond_0

    .line 60
    .line 61
    monitor-enter v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    :try_start_1
    iput-object p1, p0, Lvp/u2;->k:Lcom/google/android/gms/internal/measurement/w0;

    .line 63
    .line 64
    iput-boolean v2, p0, Lvp/u2;->l:Z

    .line 65
    .line 66
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 67
    :try_start_2
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v1, Lvp/g1;

    .line 70
    .line 71
    iget-object v3, v1, Lvp/g1;->g:Lvp/h;

    .line 72
    .line 73
    invoke-virtual {v3}, Lvp/h;->o0()Z

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    if-eqz v3, :cond_0

    .line 78
    .line 79
    const/4 v3, 0x0

    .line 80
    iput-object v3, p0, Lvp/u2;->m:Lvp/r2;

    .line 81
    .line 82
    iget-object v1, v1, Lvp/g1;->j:Lvp/e1;

    .line 83
    .line 84
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 85
    .line 86
    .line 87
    new-instance v3, Lvp/t2;

    .line 88
    .line 89
    const/4 v4, 0x1

    .line 90
    invoke-direct {v3, p0, v4}, Lvp/t2;-><init>(Lvp/u2;I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1, v3}, Lvp/e1;->j0(Ljava/lang/Runnable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :catchall_0
    move-exception p0

    .line 98
    goto :goto_1

    .line 99
    :catchall_1
    move-exception p0

    .line 100
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 101
    :try_start_4
    throw p0

    .line 102
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 103
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v0, Lvp/g1;

    .line 106
    .line 107
    iget-object v1, v0, Lvp/g1;->g:Lvp/h;

    .line 108
    .line 109
    invoke-virtual {v1}, Lvp/h;->o0()Z

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    if-nez v1, :cond_1

    .line 114
    .line 115
    iget-object p1, p0, Lvp/u2;->m:Lvp/r2;

    .line 116
    .line 117
    iput-object p1, p0, Lvp/u2;->g:Lvp/r2;

    .line 118
    .line 119
    iget-object p1, v0, Lvp/g1;->j:Lvp/e1;

    .line 120
    .line 121
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 122
    .line 123
    .line 124
    new-instance v0, Lvp/t2;

    .line 125
    .line 126
    const/4 v1, 0x0

    .line 127
    invoke-direct {v0, p0, v1}, Lvp/t2;-><init>(Lvp/u2;I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 131
    .line 132
    .line 133
    return-void

    .line 134
    :cond_1
    invoke-virtual {p0, p1}, Lvp/u2;->f0(Lcom/google/android/gms/internal/measurement/w0;)Lvp/r2;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/w0;->e:Ljava/lang/String;

    .line 139
    .line 140
    invoke-virtual {p0, p1, v0, v2}, Lvp/u2;->j0(Ljava/lang/String;Lvp/r2;Z)V

    .line 141
    .line 142
    .line 143
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast p0, Lvp/g1;

    .line 146
    .line 147
    iget-object p0, p0, Lvp/g1;->q:Lvp/w;

    .line 148
    .line 149
    invoke-static {p0}, Lvp/g1;->e(Lvp/x;)V

    .line 150
    .line 151
    .line 152
    iget-object p1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p1, Lvp/g1;

    .line 155
    .line 156
    iget-object v0, p1, Lvp/g1;->n:Lto/a;

    .line 157
    .line 158
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 162
    .line 163
    .line 164
    move-result-wide v0

    .line 165
    iget-object p1, p1, Lvp/g1;->j:Lvp/e1;

    .line 166
    .line 167
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 168
    .line 169
    .line 170
    new-instance v2, Lvp/v;

    .line 171
    .line 172
    invoke-direct {v2, p0, v0, v1}, Lvp/v;-><init>(Lvp/w;J)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p1, v2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 176
    .line 177
    .line 178
    return-void

    .line 179
    :goto_1
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 180
    throw p0
.end method

.method public m(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/j2;

    .line 4
    .line 5
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lvp/g1;

    .line 8
    .line 9
    iget-object p0, p0, Lvp/g1;->o:Lvp/u2;

    .line 10
    .line 11
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lvp/g1;

    .line 17
    .line 18
    iget-object v0, v0, Lvp/g1;->g:Lvp/h;

    .line 19
    .line 20
    invoke-virtual {v0}, Lvp/h;->o0()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-nez v0, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    if-eqz p2, :cond_1

    .line 28
    .line 29
    iget-object p0, p0, Lvp/u2;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 30
    .line 31
    iget p1, p1, Lcom/google/android/gms/internal/measurement/w0;->d:I

    .line 32
    .line 33
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Lvp/r2;

    .line 42
    .line 43
    if-eqz p0, :cond_1

    .line 44
    .line 45
    new-instance p1, Landroid/os/Bundle;

    .line 46
    .line 47
    invoke-direct {p1}, Landroid/os/Bundle;-><init>()V

    .line 48
    .line 49
    .line 50
    const-string v0, "id"

    .line 51
    .line 52
    iget-wide v1, p0, Lvp/r2;->c:J

    .line 53
    .line 54
    invoke-virtual {p1, v0, v1, v2}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 55
    .line 56
    .line 57
    const-string v0, "name"

    .line 58
    .line 59
    iget-object v1, p0, Lvp/r2;->a:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string v0, "referrer_name"

    .line 65
    .line 66
    iget-object p0, p0, Lvp/r2;->b:Ljava/lang/String;

    .line 67
    .line 68
    invoke-virtual {p1, v0, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const-string p0, "com.google.app_measurement.screen_service"

    .line 72
    .line 73
    invoke-virtual {p2, p0, p1}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 74
    .line 75
    .line 76
    :cond_1
    :goto_0
    return-void
.end method

.method public final onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 8

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1, p2}, Lcom/google/firebase/messaging/k;->i(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    invoke-virtual {p1}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    goto/16 :goto_6

    .line 21
    .line 22
    :cond_0
    const-string p2, "FirebaseMessaging"

    .line 23
    .line 24
    iget-object p0, p0, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Ljava/util/ArrayDeque;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    :try_start_0
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    const-string v0, "google.message_id"

    .line 36
    .line 37
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    if-nez v0, :cond_1

    .line 42
    .line 43
    const-string v0, "message_id"

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    :cond_1
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-nez v2, :cond_3

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Ljava/util/ArrayDeque;->contains(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_2

    .line 60
    .line 61
    goto/16 :goto_6

    .line 62
    .line 63
    :cond_2
    invoke-virtual {p0, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :catch_0
    move-exception v0

    .line 68
    move-object p0, v0

    .line 69
    goto :goto_1

    .line 70
    :cond_3
    :goto_0
    const-string p0, "gcm.n.analytics_data"

    .line 71
    .line 72
    invoke-virtual {p1, p0}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 73
    .line 74
    .line 75
    move-result-object v1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 76
    goto :goto_2

    .line 77
    :goto_1
    const-string p1, "Failed trying to get analytics data from Intent extras."

    .line 78
    .line 79
    invoke-static {p2, p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 80
    .line 81
    .line 82
    :cond_4
    :goto_2
    const-string p0, "1"

    .line 83
    .line 84
    if-nez v1, :cond_5

    .line 85
    .line 86
    const/4 p1, 0x0

    .line 87
    goto :goto_3

    .line 88
    :cond_5
    const-string p1, "google.c.a.e"

    .line 89
    .line 90
    invoke-virtual {v1, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    :goto_3
    if-eqz p1, :cond_d

    .line 99
    .line 100
    if-nez v1, :cond_6

    .line 101
    .line 102
    goto/16 :goto_5

    .line 103
    .line 104
    :cond_6
    const-string p1, "google.c.a.tc"

    .line 105
    .line 106
    invoke-virtual {v1, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    const/4 p1, 0x3

    .line 115
    if-eqz p0, :cond_b

    .line 116
    .line 117
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    const-class v0, Lwr/b;

    .line 122
    .line 123
    invoke-virtual {p0, v0}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    check-cast p0, Lwr/b;

    .line 128
    .line 129
    invoke-static {p2, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    if-eqz p1, :cond_7

    .line 134
    .line 135
    const-string p1, "Received event with track-conversion=true. Setting user property and reengagement event"

    .line 136
    .line 137
    invoke-static {p2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 138
    .line 139
    .line 140
    :cond_7
    if-eqz p0, :cond_a

    .line 141
    .line 142
    const-string p1, "google.c.a.c_id"

    .line 143
    .line 144
    invoke-virtual {v1, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v6

    .line 148
    check-cast p0, Lwr/c;

    .line 149
    .line 150
    const-string v4, "fcm"

    .line 151
    .line 152
    invoke-static {v4}, Lxr/a;->a(Ljava/lang/String;)Z

    .line 153
    .line 154
    .line 155
    move-result p1

    .line 156
    if-nez p1, :cond_8

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_8
    const-string v5, "_ln"

    .line 160
    .line 161
    invoke-static {v4, v5}, Lxr/a;->c(Ljava/lang/String;Ljava/lang/String;)Z

    .line 162
    .line 163
    .line 164
    move-result p1

    .line 165
    if-eqz p1, :cond_9

    .line 166
    .line 167
    iget-object p1, p0, Lwr/c;->a:Lro/f;

    .line 168
    .line 169
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 170
    .line 171
    move-object v3, p1

    .line 172
    check-cast v3, Lcom/google/android/gms/internal/measurement/k1;

    .line 173
    .line 174
    new-instance v2, Lcom/google/android/gms/internal/measurement/x0;

    .line 175
    .line 176
    const/4 v7, 0x1

    .line 177
    invoke-direct/range {v2 .. v7}, Lcom/google/android/gms/internal/measurement/x0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;Z)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v3, v2}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 181
    .line 182
    .line 183
    :cond_9
    :goto_4
    new-instance p1, Landroid/os/Bundle;

    .line 184
    .line 185
    invoke-direct {p1}, Landroid/os/Bundle;-><init>()V

    .line 186
    .line 187
    .line 188
    const-string p2, "source"

    .line 189
    .line 190
    const-string v0, "Firebase"

    .line 191
    .line 192
    invoke-virtual {p1, p2, v0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    const-string p2, "medium"

    .line 196
    .line 197
    const-string v0, "notification"

    .line 198
    .line 199
    invoke-virtual {p1, p2, v0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    const-string p2, "campaign"

    .line 203
    .line 204
    invoke-virtual {p1, p2, v6}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    const-string p2, "_cmp"

    .line 208
    .line 209
    invoke-virtual {p0, v4, p2, p1}, Lwr/c;->a(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 210
    .line 211
    .line 212
    goto :goto_5

    .line 213
    :cond_a
    const-string p0, "Unable to set user property for conversion tracking:  analytics library is missing"

    .line 214
    .line 215
    invoke-static {p2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 216
    .line 217
    .line 218
    goto :goto_5

    .line 219
    :cond_b
    invoke-static {p2, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    if-eqz p0, :cond_c

    .line 224
    .line 225
    const-string p0, "Received event with track-conversion=false. Do not set user property"

    .line 226
    .line 227
    invoke-static {p2, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 228
    .line 229
    .line 230
    :cond_c
    :goto_5
    const-string p0, "_no"

    .line 231
    .line 232
    invoke-static {p0, v1}, Ljp/je;->c(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 233
    .line 234
    .line 235
    :cond_d
    :goto_6
    return-void

    .line 236
    nop

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onActivityDestroyed(Landroid/app/Activity;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/k;->j(Lcom/google/android/gms/internal/measurement/w0;)V

    .line 11
    .line 12
    .line 13
    :pswitch_0
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onActivityPaused(Landroid/app/Activity;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/k;->k(Lcom/google/android/gms/internal/measurement/w0;)V

    .line 11
    .line 12
    .line 13
    :pswitch_0
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onActivityResumed(Landroid/app/Activity;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/k;->l(Lcom/google/android/gms/internal/measurement/w0;)V

    .line 11
    .line 12
    .line 13
    :pswitch_0
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1, p2}, Lcom/google/firebase/messaging/k;->m(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V

    .line 11
    .line 12
    .line 13
    :pswitch_0
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onActivityStarted(Landroid/app/Activity;)V
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    .line 3
    return-void
.end method

.method public final onActivityStopped(Landroid/app/Activity;)V
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/firebase/messaging/k;->d:I

    .line 2
    .line 3
    return-void
.end method
