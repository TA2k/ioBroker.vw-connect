.class public final Lht/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lht/d;


# static fields
.field public static final m:Ljava/lang/Object;


# instance fields
.field public final a:Lsr/f;

.field public final b:Lkt/c;

.field public final c:Lc2/k;

.field public final d:Lht/j;

.field public final e:Lgs/o;

.field public final f:Lht/h;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/util/concurrent/ExecutorService;

.field public final i:Lhs/k;

.field public j:Ljava/lang/String;

.field public final k:Ljava/util/HashSet;

.field public final l:Ljava/util/ArrayList;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lht/c;->m:Ljava/lang/Object;

    .line 7
    .line 8
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public constructor <init>(Lsr/f;Lgt/b;Ljava/util/concurrent/ExecutorService;Lhs/k;)V
    .locals 5

    .line 1
    new-instance v0, Lkt/c;

    .line 2
    .line 3
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p1, Lsr/f;->a:Landroid/content/Context;

    .line 7
    .line 8
    invoke-direct {v0, v1, p2}, Lkt/c;-><init>(Landroid/content/Context;Lgt/b;)V

    .line 9
    .line 10
    .line 11
    new-instance p2, Lc2/k;

    .line 12
    .line 13
    invoke-direct {p2, p1}, Lc2/k;-><init>(Lsr/f;)V

    .line 14
    .line 15
    .line 16
    sget-object v1, La61/a;->e:La61/a;

    .line 17
    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    new-instance v1, La61/a;

    .line 21
    .line 22
    const/16 v2, 0x9

    .line 23
    .line 24
    invoke-direct {v1, v2}, La61/a;-><init>(I)V

    .line 25
    .line 26
    .line 27
    sput-object v1, La61/a;->e:La61/a;

    .line 28
    .line 29
    :cond_0
    sget-object v1, La61/a;->e:La61/a;

    .line 30
    .line 31
    sget-object v2, Lht/j;->d:Lht/j;

    .line 32
    .line 33
    if-nez v2, :cond_1

    .line 34
    .line 35
    new-instance v2, Lht/j;

    .line 36
    .line 37
    invoke-direct {v2, v1}, Lht/j;-><init>(La61/a;)V

    .line 38
    .line 39
    .line 40
    sput-object v2, Lht/j;->d:Lht/j;

    .line 41
    .line 42
    :cond_1
    sget-object v1, Lht/j;->d:Lht/j;

    .line 43
    .line 44
    new-instance v2, Lgs/o;

    .line 45
    .line 46
    new-instance v3, Lgs/d;

    .line 47
    .line 48
    const/4 v4, 0x2

    .line 49
    invoke-direct {v3, p1, v4}, Lgs/d;-><init>(Ljava/lang/Object;I)V

    .line 50
    .line 51
    .line 52
    invoke-direct {v2, v3}, Lgs/o;-><init>(Lgt/b;)V

    .line 53
    .line 54
    .line 55
    new-instance v3, Lht/h;

    .line 56
    .line 57
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 58
    .line 59
    .line 60
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 61
    .line 62
    .line 63
    new-instance v4, Ljava/lang/Object;

    .line 64
    .line 65
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 66
    .line 67
    .line 68
    iput-object v4, p0, Lht/c;->g:Ljava/lang/Object;

    .line 69
    .line 70
    new-instance v4, Ljava/util/HashSet;

    .line 71
    .line 72
    invoke-direct {v4}, Ljava/util/HashSet;-><init>()V

    .line 73
    .line 74
    .line 75
    iput-object v4, p0, Lht/c;->k:Ljava/util/HashSet;

    .line 76
    .line 77
    new-instance v4, Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 80
    .line 81
    .line 82
    iput-object v4, p0, Lht/c;->l:Ljava/util/ArrayList;

    .line 83
    .line 84
    iput-object p1, p0, Lht/c;->a:Lsr/f;

    .line 85
    .line 86
    iput-object v0, p0, Lht/c;->b:Lkt/c;

    .line 87
    .line 88
    iput-object p2, p0, Lht/c;->c:Lc2/k;

    .line 89
    .line 90
    iput-object v1, p0, Lht/c;->d:Lht/j;

    .line 91
    .line 92
    iput-object v2, p0, Lht/c;->e:Lgs/o;

    .line 93
    .line 94
    iput-object v3, p0, Lht/c;->f:Lht/h;

    .line 95
    .line 96
    iput-object p3, p0, Lht/c;->h:Ljava/util/concurrent/ExecutorService;

    .line 97
    .line 98
    iput-object p4, p0, Lht/c;->i:Lhs/k;

    .line 99
    .line 100
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 6

    .line 1
    sget-object v0, Lht/c;->m:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lht/c;->a:Lsr/f;

    .line 5
    .line 6
    invoke-virtual {v1}, Lsr/f;->a()V

    .line 7
    .line 8
    .line 9
    iget-object v1, v1, Lsr/f;->a:Landroid/content/Context;

    .line 10
    .line 11
    invoke-static {v1}, Lb81/b;->h(Landroid/content/Context;)Lb81/b;

    .line 12
    .line 13
    .line 14
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 15
    :try_start_1
    iget-object v2, p0, Lht/c;->c:Lc2/k;

    .line 16
    .line 17
    invoke-virtual {v2}, Lc2/k;->z()Ljt/b;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    iget v3, v2, Ljt/b;->b:I

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    const/4 v5, 0x1

    .line 25
    if-eq v3, v4, :cond_1

    .line 26
    .line 27
    if-ne v3, v5, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v5, 0x0

    .line 31
    :cond_1
    :goto_0
    if-eqz v5, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0, v2}, Lht/c;->f(Ljt/b;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    iget-object v4, p0, Lht/c;->c:Lc2/k;

    .line 38
    .line 39
    invoke-virtual {v2}, Ljt/b;->a()Ljt/a;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    iput-object v3, v2, Ljt/a;->a:Ljava/lang/String;

    .line 44
    .line 45
    const/4 v3, 0x3

    .line 46
    iput v3, v2, Ljt/a;->b:I

    .line 47
    .line 48
    invoke-virtual {v2}, Ljt/a;->a()Ljt/b;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {v4, v2}, Lc2/k;->x(Ljt/b;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto :goto_3

    .line 58
    :cond_2
    :goto_1
    if-eqz v1, :cond_3

    .line 59
    .line 60
    :try_start_2
    invoke-virtual {v1}, Lb81/b;->u()V

    .line 61
    .line 62
    .line 63
    goto :goto_2

    .line 64
    :catchall_1
    move-exception p0

    .line 65
    goto :goto_4

    .line 66
    :cond_3
    :goto_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 67
    invoke-virtual {p0, v2}, Lht/c;->i(Ljt/b;)V

    .line 68
    .line 69
    .line 70
    iget-object v0, p0, Lht/c;->i:Lhs/k;

    .line 71
    .line 72
    new-instance v1, Lht/b;

    .line 73
    .line 74
    const/4 v2, 0x2

    .line 75
    invoke-direct {v1, p0, v2}, Lht/b;-><init>(Lht/c;I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v1}, Lhs/k;->execute(Ljava/lang/Runnable;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :goto_3
    if-eqz v1, :cond_4

    .line 83
    .line 84
    :try_start_3
    invoke-virtual {v1}, Lb81/b;->u()V

    .line 85
    .line 86
    .line 87
    :cond_4
    throw p0

    .line 88
    :goto_4
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 89
    throw p0
.end method

.method public final b(Ljt/b;)Ljt/b;
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    iget-object v2, v1, Lht/c;->b:Lkt/c;

    .line 6
    .line 7
    iget-object v3, v1, Lht/c;->a:Lsr/f;

    .line 8
    .line 9
    invoke-virtual {v3}, Lsr/f;->a()V

    .line 10
    .line 11
    .line 12
    iget-object v3, v3, Lsr/f;->c:Lsr/i;

    .line 13
    .line 14
    iget-object v3, v3, Lsr/i;->a:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v4, v0, Ljt/b;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v5, v1, Lht/c;->a:Lsr/f;

    .line 19
    .line 20
    invoke-virtual {v5}, Lsr/f;->a()V

    .line 21
    .line 22
    .line 23
    iget-object v5, v5, Lsr/f;->c:Lsr/i;

    .line 24
    .line 25
    iget-object v5, v5, Lsr/i;->g:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v6, v0, Ljt/b;->d:Ljava/lang/String;

    .line 28
    .line 29
    const-string v7, "Firebase Installations Service is unavailable. Please try again later."

    .line 30
    .line 31
    iget-object v8, v2, Lkt/c;->c:Lkt/d;

    .line 32
    .line 33
    invoke-virtual {v8}, Lkt/d;->a()Z

    .line 34
    .line 35
    .line 36
    move-result v9

    .line 37
    if-eqz v9, :cond_c

    .line 38
    .line 39
    new-instance v9, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v10, "projects/"

    .line 42
    .line 43
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v10, "/installations/"

    .line 50
    .line 51
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v4, "/authTokens:generate"

    .line 58
    .line 59
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    invoke-static {v4}, Lkt/c;->a(Ljava/lang/String;)Ljava/net/URL;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    const/4 v10, 0x0

    .line 71
    :goto_0
    const/4 v11, 0x1

    .line 72
    if-gt v10, v11, :cond_b

    .line 73
    .line 74
    const v12, 0x8003

    .line 75
    .line 76
    .line 77
    invoke-static {v12}, Landroid/net/TrafficStats;->setThreadStatsTag(I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v2, v4, v3}, Lkt/c;->c(Ljava/net/URL;Ljava/lang/String;)Ljava/net/HttpURLConnection;

    .line 81
    .line 82
    .line 83
    move-result-object v12

    .line 84
    :try_start_0
    const-string v13, "POST"

    .line 85
    .line 86
    invoke-virtual {v12, v13}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-string v13, "Authorization"

    .line 90
    .line 91
    new-instance v14, Ljava/lang/StringBuilder;

    .line 92
    .line 93
    invoke-direct {v14}, Ljava/lang/StringBuilder;-><init>()V

    .line 94
    .line 95
    .line 96
    const-string v15, "FIS_v2 "

    .line 97
    .line 98
    invoke-virtual {v14, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v14, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v14

    .line 108
    invoke-virtual {v12, v13, v14}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v12, v11}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 112
    .line 113
    .line 114
    invoke-static {v12}, Lkt/c;->h(Ljava/net/HttpURLConnection;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v12}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 118
    .line 119
    .line 120
    move-result v13

    .line 121
    invoke-virtual {v8, v13}, Lkt/d;->b(I)V

    .line 122
    .line 123
    .line 124
    const/16 v14, 0xc8

    .line 125
    .line 126
    if-lt v13, v14, :cond_0

    .line 127
    .line 128
    const/16 v14, 0x12c

    .line 129
    .line 130
    if-ge v13, v14, :cond_0

    .line 131
    .line 132
    move v14, v11

    .line 133
    goto :goto_1

    .line 134
    :cond_0
    const/4 v14, 0x0

    .line 135
    :goto_1
    const/4 v15, 0x2

    .line 136
    const/4 v9, 0x0

    .line 137
    if-eqz v14, :cond_1

    .line 138
    .line 139
    invoke-static {v12}, Lkt/c;->f(Ljava/net/HttpURLConnection;)Lkt/b;

    .line 140
    .line 141
    .line 142
    move-result-object v2
    :try_end_0
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 143
    invoke-virtual {v12}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 144
    .line 145
    .line 146
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 147
    .line 148
    .line 149
    goto :goto_5

    .line 150
    :catchall_0
    move-exception v0

    .line 151
    goto/16 :goto_6

    .line 152
    .line 153
    :catch_0
    move/from16 v16, v10

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_1
    :try_start_1
    invoke-static {v12, v9, v3, v5}, Lkt/c;->b(Ljava/net/HttpURLConnection;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/lang/AssertionError; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 157
    .line 158
    .line 159
    const/16 v14, 0x191

    .line 160
    .line 161
    move/from16 v16, v10

    .line 162
    .line 163
    const-wide/16 v9, 0x0

    .line 164
    .line 165
    if-eq v13, v14, :cond_6

    .line 166
    .line 167
    const/16 v14, 0x194

    .line 168
    .line 169
    if-ne v13, v14, :cond_2

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_2
    const/16 v14, 0x1ad

    .line 173
    .line 174
    if-eq v13, v14, :cond_5

    .line 175
    .line 176
    const/16 v14, 0x1f4

    .line 177
    .line 178
    if-lt v13, v14, :cond_3

    .line 179
    .line 180
    const/16 v14, 0x258

    .line 181
    .line 182
    if-ge v13, v14, :cond_3

    .line 183
    .line 184
    :catch_1
    :goto_2
    invoke-virtual {v12}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 185
    .line 186
    .line 187
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 188
    .line 189
    .line 190
    goto/16 :goto_7

    .line 191
    .line 192
    :cond_3
    :try_start_2
    const-string v13, "Firebase-Installations"

    .line 193
    .line 194
    const-string v14, "Firebase Installations can not communicate with Firebase server APIs due to invalid configuration. Please update your Firebase initialization process and set valid Firebase options (API key, Project ID, Application ID) when initializing Firebase."

    .line 195
    .line 196
    invoke-static {v13, v14}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 197
    .line 198
    .line 199
    const/4 v13, 0x0

    .line 200
    or-int/2addr v13, v11

    .line 201
    int-to-byte v13, v13

    .line 202
    if-ne v13, v11, :cond_4

    .line 203
    .line 204
    new-instance v13, Lkt/b;

    .line 205
    .line 206
    const/4 v14, 0x0

    .line 207
    invoke-direct {v13, v9, v10, v14, v15}, Lkt/b;-><init>(JLjava/lang/String;I)V
    :try_end_2
    .catch Ljava/lang/AssertionError; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 208
    .line 209
    .line 210
    :goto_3
    invoke-virtual {v12}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 211
    .line 212
    .line 213
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 214
    .line 215
    .line 216
    move-object v2, v13

    .line 217
    goto :goto_5

    .line 218
    :cond_4
    :try_start_3
    new-instance v9, Ljava/lang/IllegalStateException;

    .line 219
    .line 220
    const-string v10, "Missing required properties: tokenExpirationTimestamp"

    .line 221
    .line 222
    invoke-direct {v9, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    throw v9

    .line 226
    :cond_5
    new-instance v9, Lht/e;

    .line 227
    .line 228
    const-string v10, "Firebase servers have received too many requests from this client in a short period of time. Please try again later."

    .line 229
    .line 230
    invoke-direct {v9, v10}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    throw v9

    .line 234
    :cond_6
    :goto_4
    const/4 v13, 0x0

    .line 235
    or-int/2addr v13, v11

    .line 236
    int-to-byte v13, v13

    .line 237
    if-ne v13, v11, :cond_a

    .line 238
    .line 239
    new-instance v13, Lkt/b;

    .line 240
    .line 241
    const/4 v14, 0x3

    .line 242
    const/4 v15, 0x0

    .line 243
    invoke-direct {v13, v9, v10, v15, v14}, Lkt/b;-><init>(JLjava/lang/String;I)V
    :try_end_3
    .catch Ljava/lang/AssertionError; {:try_start_3 .. :try_end_3} :catch_1
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 244
    .line 245
    .line 246
    goto :goto_3

    .line 247
    :goto_5
    iget v3, v2, Lkt/b;->c:I

    .line 248
    .line 249
    invoke-static {v3}, Lu/w;->o(I)I

    .line 250
    .line 251
    .line 252
    move-result v3

    .line 253
    if-eqz v3, :cond_9

    .line 254
    .line 255
    if-eq v3, v11, :cond_8

    .line 256
    .line 257
    const/4 v2, 0x2

    .line 258
    if-ne v3, v2, :cond_7

    .line 259
    .line 260
    monitor-enter p0

    .line 261
    const/4 v14, 0x0

    .line 262
    :try_start_4
    iput-object v14, v1, Lht/c;->j:Ljava/lang/String;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 263
    .line 264
    monitor-exit p0

    .line 265
    invoke-virtual {v0}, Ljt/b;->a()Ljt/a;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    iput v2, v0, Ljt/a;->b:I

    .line 270
    .line 271
    invoke-virtual {v0}, Ljt/a;->a()Ljt/b;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    return-object v0

    .line 276
    :catchall_1
    move-exception v0

    .line 277
    :try_start_5
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 278
    throw v0

    .line 279
    :cond_7
    new-instance v0, Lht/e;

    .line 280
    .line 281
    invoke-direct {v0, v7}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    throw v0

    .line 285
    :cond_8
    const-string v1, "BAD CONFIG"

    .line 286
    .line 287
    invoke-virtual {v0}, Ljt/b;->a()Ljt/a;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    iput-object v1, v0, Ljt/a;->g:Ljava/lang/String;

    .line 292
    .line 293
    const/4 v1, 0x5

    .line 294
    iput v1, v0, Ljt/a;->b:I

    .line 295
    .line 296
    invoke-virtual {v0}, Ljt/a;->a()Ljt/b;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    return-object v0

    .line 301
    :cond_9
    iget-object v3, v2, Lkt/b;->a:Ljava/lang/String;

    .line 302
    .line 303
    iget-wide v4, v2, Lkt/b;->b:J

    .line 304
    .line 305
    iget-object v1, v1, Lht/c;->d:Lht/j;

    .line 306
    .line 307
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 308
    .line 309
    .line 310
    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 311
    .line 312
    iget-object v1, v1, Lht/j;->a:La61/a;

    .line 313
    .line 314
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 315
    .line 316
    .line 317
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 318
    .line 319
    .line 320
    move-result-wide v6

    .line 321
    invoke-virtual {v2, v6, v7}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 322
    .line 323
    .line 324
    move-result-wide v1

    .line 325
    invoke-virtual {v0}, Ljt/b;->a()Ljt/a;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    iput-object v3, v0, Ljt/a;->c:Ljava/lang/String;

    .line 330
    .line 331
    iput-wide v4, v0, Ljt/a;->e:J

    .line 332
    .line 333
    iget-byte v3, v0, Ljt/a;->h:B

    .line 334
    .line 335
    or-int/2addr v3, v11

    .line 336
    int-to-byte v3, v3

    .line 337
    iput-wide v1, v0, Ljt/a;->f:J

    .line 338
    .line 339
    const/16 v17, 0x2

    .line 340
    .line 341
    or-int/lit8 v1, v3, 0x2

    .line 342
    .line 343
    int-to-byte v1, v1

    .line 344
    iput-byte v1, v0, Ljt/a;->h:B

    .line 345
    .line 346
    invoke-virtual {v0}, Ljt/a;->a()Ljt/b;

    .line 347
    .line 348
    .line 349
    move-result-object v0

    .line 350
    return-object v0

    .line 351
    :cond_a
    :try_start_6
    new-instance v9, Ljava/lang/IllegalStateException;

    .line 352
    .line 353
    const-string v10, "Missing required properties: tokenExpirationTimestamp"

    .line 354
    .line 355
    invoke-direct {v9, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    throw v9
    :try_end_6
    .catch Ljava/lang/AssertionError; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 359
    :goto_6
    invoke-virtual {v12}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 360
    .line 361
    .line 362
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 363
    .line 364
    .line 365
    throw v0

    .line 366
    :goto_7
    add-int/lit8 v10, v16, 0x1

    .line 367
    .line 368
    goto/16 :goto_0

    .line 369
    .line 370
    :cond_b
    new-instance v0, Lht/e;

    .line 371
    .line 372
    invoke-direct {v0, v7}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    throw v0

    .line 376
    :cond_c
    new-instance v0, Lht/e;

    .line 377
    .line 378
    invoke-direct {v0, v7}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 379
    .line 380
    .line 381
    throw v0
.end method

.method public final c()Laq/t;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lht/c;->e()V

    .line 2
    .line 3
    .line 4
    monitor-enter p0

    .line 5
    :try_start_0
    iget-object v0, p0, Lht/c;->j:Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 6
    .line 7
    monitor-exit p0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_0
    new-instance v0, Laq/k;

    .line 16
    .line 17
    invoke-direct {v0}, Laq/k;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance v1, Lht/g;

    .line 21
    .line 22
    invoke-direct {v1, v0}, Lht/g;-><init>(Laq/k;)V

    .line 23
    .line 24
    .line 25
    iget-object v2, p0, Lht/c;->g:Ljava/lang/Object;

    .line 26
    .line 27
    monitor-enter v2

    .line 28
    :try_start_1
    iget-object v3, p0, Lht/c;->l:Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 34
    iget-object v0, v0, Laq/k;->a:Laq/t;

    .line 35
    .line 36
    iget-object v1, p0, Lht/c;->h:Ljava/util/concurrent/ExecutorService;

    .line 37
    .line 38
    new-instance v2, Lht/b;

    .line 39
    .line 40
    const/4 v3, 0x0

    .line 41
    invoke-direct {v2, p0, v3}, Lht/b;-><init>(Lht/c;I)V

    .line 42
    .line 43
    .line 44
    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    :catchall_0
    move-exception p0

    .line 49
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 50
    throw p0

    .line 51
    :catchall_1
    move-exception v0

    .line 52
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 53
    throw v0
.end method

.method public final d()Laq/t;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lht/c;->e()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Laq/k;

    .line 5
    .line 6
    invoke-direct {v0}, Laq/k;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lht/f;

    .line 10
    .line 11
    iget-object v2, p0, Lht/c;->d:Lht/j;

    .line 12
    .line 13
    invoke-direct {v1, v2, v0}, Lht/f;-><init>(Lht/j;Laq/k;)V

    .line 14
    .line 15
    .line 16
    iget-object v2, p0, Lht/c;->g:Ljava/lang/Object;

    .line 17
    .line 18
    monitor-enter v2

    .line 19
    :try_start_0
    iget-object v3, p0, Lht/c;->l:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    iget-object v0, v0, Laq/k;->a:Laq/t;

    .line 26
    .line 27
    iget-object v1, p0, Lht/c;->h:Ljava/util/concurrent/ExecutorService;

    .line 28
    .line 29
    new-instance v2, Lht/b;

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    invoke-direct {v2, p0, v3}, Lht/b;-><init>(Lht/c;I)V

    .line 33
    .line 34
    .line 35
    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    throw p0
.end method

.method public final e()V
    .locals 4

    .line 1
    iget-object p0, p0, Lht/c;->a:Lsr/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lsr/f;->c:Lsr/i;

    .line 7
    .line 8
    iget-object v0, v0, Lsr/i;->b:Ljava/lang/String;

    .line 9
    .line 10
    const-string v1, "Please set your Application ID. A valid Firebase App ID is required to communicate with Firebase server APIs: It identifies your application with Firebase.Please refer to https://firebase.google.com/support/privacy/init-options."

    .line 11
    .line 12
    invoke-static {v0, v1}, Lno/c0;->f(Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lsr/f;->c:Lsr/i;

    .line 19
    .line 20
    iget-object v0, v0, Lsr/i;->g:Ljava/lang/String;

    .line 21
    .line 22
    const-string v2, "Please set your Project ID. A valid Firebase Project ID is required to communicate with Firebase server APIs: It identifies your application with Firebase.Please refer to https://firebase.google.com/support/privacy/init-options."

    .line 23
    .line 24
    invoke-static {v0, v2}, Lno/c0;->f(Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Lsr/f;->c:Lsr/i;

    .line 31
    .line 32
    iget-object v0, v0, Lsr/i;->a:Ljava/lang/String;

    .line 33
    .line 34
    const-string v2, "Please set a valid API key. A Firebase API key is required to communicate with Firebase server APIs: It authenticates your project with Google.Please refer to https://firebase.google.com/support/privacy/init-options."

    .line 35
    .line 36
    invoke-static {v0, v2}, Lno/c0;->f(Ljava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lsr/f;->c:Lsr/i;

    .line 43
    .line 44
    iget-object v0, v0, Lsr/i;->b:Ljava/lang/String;

    .line 45
    .line 46
    sget-object v3, Lht/j;->c:Ljava/util/regex/Pattern;

    .line 47
    .line 48
    const-string v3, ":"

    .line 49
    .line 50
    invoke-virtual {v0, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    invoke-static {v0, v1}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 58
    .line 59
    .line 60
    iget-object p0, p0, Lsr/f;->c:Lsr/i;

    .line 61
    .line 62
    iget-object p0, p0, Lsr/i;->a:Ljava/lang/String;

    .line 63
    .line 64
    sget-object v0, Lht/j;->c:Ljava/util/regex/Pattern;

    .line 65
    .line 66
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    invoke-static {p0, v2}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public final f(Ljt/b;)Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lht/c;->a:Lsr/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Lsr/f;->a()V

    .line 4
    .line 5
    .line 6
    iget-object v0, v0, Lsr/f;->b:Ljava/lang/String;

    .line 7
    .line 8
    const-string v1, "CHIME_ANDROID_SDK"

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lht/c;->a:Lsr/f;

    .line 17
    .line 18
    const-string v1, "[DEFAULT]"

    .line 19
    .line 20
    invoke-virtual {v0}, Lsr/f;->a()V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Lsr/f;->b:Ljava/lang/String;

    .line 24
    .line 25
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_3

    .line 30
    .line 31
    :cond_0
    iget p1, p1, Ljt/b;->b:I

    .line 32
    .line 33
    const/4 v0, 0x1

    .line 34
    if-ne p1, v0, :cond_3

    .line 35
    .line 36
    iget-object p1, p0, Lht/c;->e:Lgs/o;

    .line 37
    .line 38
    invoke-virtual {p1}, Lgs/o;->get()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    check-cast p1, Ljt/c;

    .line 43
    .line 44
    iget-object v0, p1, Ljt/c;->a:Landroid/content/SharedPreferences;

    .line 45
    .line 46
    monitor-enter v0

    .line 47
    :try_start_0
    iget-object v1, p1, Ljt/c;->a:Landroid/content/SharedPreferences;

    .line 48
    .line 49
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    :try_start_1
    iget-object v2, p1, Ljt/c;->a:Landroid/content/SharedPreferences;

    .line 51
    .line 52
    const-string v3, "|S|id"

    .line 53
    .line 54
    const/4 v4, 0x0

    .line 55
    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 60
    if-eqz v2, :cond_1

    .line 61
    .line 62
    :try_start_2
    monitor-exit v0

    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    invoke-virtual {p1}, Ljt/c;->a()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 71
    :goto_0
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    if-eqz p1, :cond_2

    .line 76
    .line 77
    iget-object p0, p0, Lht/c;->f:Lht/h;

    .line 78
    .line 79
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    invoke-static {}, Lht/h;->a()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0

    .line 87
    :cond_2
    return-object v2

    .line 88
    :catchall_1
    move-exception p0

    .line 89
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 90
    :try_start_4
    throw p0

    .line 91
    :goto_1
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 92
    throw p0

    .line 93
    :cond_3
    iget-object p0, p0, Lht/c;->f:Lht/h;

    .line 94
    .line 95
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    invoke-static {}, Lht/h;->a()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0
.end method

.method public final g(Ljt/b;)Ljt/b;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Ljt/b;->a:Ljava/lang/String;

    .line 6
    .line 7
    const/4 v3, 0x4

    .line 8
    const/4 v5, 0x0

    .line 9
    if-eqz v2, :cond_3

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const/16 v6, 0xb

    .line 16
    .line 17
    if-ne v2, v6, :cond_3

    .line 18
    .line 19
    iget-object v2, v0, Lht/c;->e:Lgs/o;

    .line 20
    .line 21
    invoke-virtual {v2}, Lgs/o;->get()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Ljt/c;

    .line 26
    .line 27
    iget-object v6, v2, Ljt/c;->a:Landroid/content/SharedPreferences;

    .line 28
    .line 29
    monitor-enter v6

    .line 30
    :try_start_0
    sget-object v7, Ljt/c;->c:[Ljava/lang/String;

    .line 31
    .line 32
    const/4 v8, 0x0

    .line 33
    :goto_0
    if-ge v8, v3, :cond_2

    .line 34
    .line 35
    aget-object v9, v7, v8

    .line 36
    .line 37
    iget-object v10, v2, Ljt/c;->b:Ljava/lang/String;

    .line 38
    .line 39
    new-instance v11, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v12, "|T|"

    .line 42
    .line 43
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v11, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v10, "|"

    .line 50
    .line 51
    invoke-virtual {v11, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v11, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v9

    .line 61
    iget-object v10, v2, Ljt/c;->a:Landroid/content/SharedPreferences;

    .line 62
    .line 63
    invoke-interface {v10, v9, v5}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v9

    .line 67
    if-eqz v9, :cond_1

    .line 68
    .line 69
    invoke-virtual {v9}, Ljava/lang/String;->isEmpty()Z

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    if-nez v10, :cond_1

    .line 74
    .line 75
    const-string v2, "{"

    .line 76
    .line 77
    invoke-virtual {v9, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 78
    .line 79
    .line 80
    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 81
    if-eqz v2, :cond_0

    .line 82
    .line 83
    :try_start_1
    new-instance v2, Lorg/json/JSONObject;

    .line 84
    .line 85
    invoke-direct {v2, v9}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    const-string v7, "token"

    .line 89
    .line 90
    invoke-virtual {v2, v7}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v5
    :try_end_1
    .catch Lorg/json/JSONException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 94
    goto :goto_1

    .line 95
    :cond_0
    move-object v5, v9

    .line 96
    :catch_0
    :goto_1
    :try_start_2
    monitor-exit v6

    .line 97
    goto :goto_3

    .line 98
    :catchall_0
    move-exception v0

    .line 99
    goto :goto_2

    .line 100
    :cond_1
    add-int/lit8 v8, v8, 0x1

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_2
    monitor-exit v6

    .line 104
    goto :goto_3

    .line 105
    :goto_2
    monitor-exit v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 106
    throw v0

    .line 107
    :cond_3
    :goto_3
    iget-object v2, v0, Lht/c;->b:Lkt/c;

    .line 108
    .line 109
    iget-object v6, v0, Lht/c;->a:Lsr/f;

    .line 110
    .line 111
    invoke-virtual {v6}, Lsr/f;->a()V

    .line 112
    .line 113
    .line 114
    iget-object v6, v6, Lsr/f;->c:Lsr/i;

    .line 115
    .line 116
    iget-object v6, v6, Lsr/i;->a:Ljava/lang/String;

    .line 117
    .line 118
    iget-object v7, v1, Ljt/b;->a:Ljava/lang/String;

    .line 119
    .line 120
    iget-object v8, v0, Lht/c;->a:Lsr/f;

    .line 121
    .line 122
    invoke-virtual {v8}, Lsr/f;->a()V

    .line 123
    .line 124
    .line 125
    iget-object v8, v8, Lsr/f;->c:Lsr/i;

    .line 126
    .line 127
    iget-object v8, v8, Lsr/i;->g:Ljava/lang/String;

    .line 128
    .line 129
    iget-object v9, v0, Lht/c;->a:Lsr/f;

    .line 130
    .line 131
    invoke-virtual {v9}, Lsr/f;->a()V

    .line 132
    .line 133
    .line 134
    iget-object v9, v9, Lsr/f;->c:Lsr/i;

    .line 135
    .line 136
    iget-object v9, v9, Lsr/i;->b:Ljava/lang/String;

    .line 137
    .line 138
    const-string v10, "Firebase Installations Service is unavailable. Please try again later."

    .line 139
    .line 140
    iget-object v11, v2, Lkt/c;->c:Lkt/d;

    .line 141
    .line 142
    invoke-virtual {v11}, Lkt/d;->a()Z

    .line 143
    .line 144
    .line 145
    move-result v12

    .line 146
    if-eqz v12, :cond_c

    .line 147
    .line 148
    new-instance v12, Ljava/lang/StringBuilder;

    .line 149
    .line 150
    const-string v13, "projects/"

    .line 151
    .line 152
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v12, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    const-string v13, "/installations"

    .line 159
    .line 160
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v12

    .line 167
    invoke-static {v12}, Lkt/c;->a(Ljava/lang/String;)Ljava/net/URL;

    .line 168
    .line 169
    .line 170
    move-result-object v12

    .line 171
    const/4 v13, 0x0

    .line 172
    :goto_4
    const/4 v14, 0x1

    .line 173
    if-gt v13, v14, :cond_b

    .line 174
    .line 175
    const v15, 0x8001

    .line 176
    .line 177
    .line 178
    invoke-static {v15}, Landroid/net/TrafficStats;->setThreadStatsTag(I)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v2, v12, v6}, Lkt/c;->c(Ljava/net/URL;Ljava/lang/String;)Ljava/net/HttpURLConnection;

    .line 182
    .line 183
    .line 184
    move-result-object v15

    .line 185
    :try_start_3
    const-string v4, "POST"

    .line 186
    .line 187
    invoke-virtual {v15, v4}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v15, v14}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 191
    .line 192
    .line 193
    if-eqz v5, :cond_4

    .line 194
    .line 195
    const-string v4, "x-goog-fis-android-iid-migration-auth"

    .line 196
    .line 197
    invoke-virtual {v15, v4, v5}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    goto :goto_5

    .line 201
    :catchall_1
    move-exception v0

    .line 202
    goto/16 :goto_8

    .line 203
    .line 204
    :cond_4
    :goto_5
    invoke-static {v15, v7, v9}, Lkt/c;->g(Ljava/net/HttpURLConnection;Ljava/lang/String;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v15}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    invoke-virtual {v11, v4}, Lkt/d;->b(I)V
    :try_end_3
    .catch Ljava/lang/AssertionError; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 212
    .line 213
    .line 214
    const/16 v3, 0xc8

    .line 215
    .line 216
    if-lt v4, v3, :cond_5

    .line 217
    .line 218
    const/16 v3, 0x12c

    .line 219
    .line 220
    if-ge v4, v3, :cond_5

    .line 221
    .line 222
    move v3, v14

    .line 223
    goto :goto_6

    .line 224
    :cond_5
    const/4 v3, 0x0

    .line 225
    :goto_6
    if-eqz v3, :cond_6

    .line 226
    .line 227
    :try_start_4
    invoke-static {v15}, Lkt/c;->e(Ljava/net/HttpURLConnection;)Lkt/a;

    .line 228
    .line 229
    .line 230
    move-result-object v2
    :try_end_4
    .catch Ljava/lang/AssertionError; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 231
    invoke-virtual {v15}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 232
    .line 233
    .line 234
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 235
    .line 236
    .line 237
    goto :goto_7

    .line 238
    :catch_1
    const/4 v3, 0x4

    .line 239
    goto/16 :goto_9

    .line 240
    .line 241
    :cond_6
    :try_start_5
    invoke-static {v15, v9, v6, v8}, Lkt/c;->b(Ljava/net/HttpURLConnection;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_5
    .catch Ljava/lang/AssertionError; {:try_start_5 .. :try_end_5} :catch_1
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 242
    .line 243
    .line 244
    const/16 v3, 0x1ad

    .line 245
    .line 246
    if-eq v4, v3, :cond_a

    .line 247
    .line 248
    const/16 v3, 0x1f4

    .line 249
    .line 250
    if-lt v4, v3, :cond_7

    .line 251
    .line 252
    const/16 v3, 0x258

    .line 253
    .line 254
    if-ge v4, v3, :cond_7

    .line 255
    .line 256
    invoke-virtual {v15}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 257
    .line 258
    .line 259
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 260
    .line 261
    .line 262
    const/4 v3, 0x4

    .line 263
    goto/16 :goto_a

    .line 264
    .line 265
    :cond_7
    :try_start_6
    const-string v3, "Firebase-Installations"

    .line 266
    .line 267
    const-string v4, "Firebase Installations can not communicate with Firebase server APIs due to invalid configuration. Please update your Firebase initialization process and set valid Firebase options (API key, Project ID, Application ID) when initializing Firebase."

    .line 268
    .line 269
    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 270
    .line 271
    .line 272
    new-instance v16, Lkt/a;

    .line 273
    .line 274
    const/16 v20, 0x0

    .line 275
    .line 276
    const/16 v19, 0x0

    .line 277
    .line 278
    const/16 v18, 0x0

    .line 279
    .line 280
    const/16 v17, 0x0

    .line 281
    .line 282
    const/16 v21, 0x2

    .line 283
    .line 284
    invoke-direct/range {v16 .. v21}, Lkt/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkt/b;I)V
    :try_end_6
    .catch Ljava/lang/AssertionError; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 285
    .line 286
    .line 287
    invoke-virtual {v15}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 288
    .line 289
    .line 290
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 291
    .line 292
    .line 293
    move-object/from16 v2, v16

    .line 294
    .line 295
    :goto_7
    iget v3, v2, Lkt/a;->e:I

    .line 296
    .line 297
    invoke-static {v3}, Lu/w;->o(I)I

    .line 298
    .line 299
    .line 300
    move-result v3

    .line 301
    if-eqz v3, :cond_9

    .line 302
    .line 303
    if-ne v3, v14, :cond_8

    .line 304
    .line 305
    const-string v0, "BAD CONFIG"

    .line 306
    .line 307
    invoke-virtual {v1}, Ljt/b;->a()Ljt/a;

    .line 308
    .line 309
    .line 310
    move-result-object v1

    .line 311
    iput-object v0, v1, Ljt/a;->g:Ljava/lang/String;

    .line 312
    .line 313
    const/4 v0, 0x5

    .line 314
    iput v0, v1, Ljt/a;->b:I

    .line 315
    .line 316
    invoke-virtual {v1}, Ljt/a;->a()Ljt/b;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    return-object v0

    .line 321
    :cond_8
    new-instance v0, Lht/e;

    .line 322
    .line 323
    const-string v1, "Firebase Installations Service is unavailable. Please try again later."

    .line 324
    .line 325
    invoke-direct {v0, v1}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    throw v0

    .line 329
    :cond_9
    iget-object v3, v2, Lkt/a;->b:Ljava/lang/String;

    .line 330
    .line 331
    iget-object v4, v2, Lkt/a;->c:Ljava/lang/String;

    .line 332
    .line 333
    iget-object v0, v0, Lht/c;->d:Lht/j;

    .line 334
    .line 335
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 336
    .line 337
    .line 338
    sget-object v5, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 339
    .line 340
    iget-object v0, v0, Lht/j;->a:La61/a;

    .line 341
    .line 342
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 343
    .line 344
    .line 345
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 346
    .line 347
    .line 348
    move-result-wide v6

    .line 349
    invoke-virtual {v5, v6, v7}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 350
    .line 351
    .line 352
    move-result-wide v5

    .line 353
    iget-object v0, v2, Lkt/a;->d:Lkt/b;

    .line 354
    .line 355
    iget-object v2, v0, Lkt/b;->a:Ljava/lang/String;

    .line 356
    .line 357
    iget-wide v7, v0, Lkt/b;->b:J

    .line 358
    .line 359
    invoke-virtual {v1}, Ljt/b;->a()Ljt/a;

    .line 360
    .line 361
    .line 362
    move-result-object v0

    .line 363
    iput-object v3, v0, Ljt/a;->a:Ljava/lang/String;

    .line 364
    .line 365
    const/4 v3, 0x4

    .line 366
    iput v3, v0, Ljt/a;->b:I

    .line 367
    .line 368
    iput-object v2, v0, Ljt/a;->c:Ljava/lang/String;

    .line 369
    .line 370
    iput-object v4, v0, Ljt/a;->d:Ljava/lang/String;

    .line 371
    .line 372
    iput-wide v7, v0, Ljt/a;->e:J

    .line 373
    .line 374
    iget-byte v1, v0, Ljt/a;->h:B

    .line 375
    .line 376
    or-int/2addr v1, v14

    .line 377
    int-to-byte v1, v1

    .line 378
    iput-wide v5, v0, Ljt/a;->f:J

    .line 379
    .line 380
    or-int/lit8 v1, v1, 0x2

    .line 381
    .line 382
    int-to-byte v1, v1

    .line 383
    iput-byte v1, v0, Ljt/a;->h:B

    .line 384
    .line 385
    invoke-virtual {v0}, Ljt/a;->a()Ljt/b;

    .line 386
    .line 387
    .line 388
    move-result-object v0

    .line 389
    return-object v0

    .line 390
    :cond_a
    const/4 v3, 0x4

    .line 391
    :try_start_7
    new-instance v4, Lht/e;

    .line 392
    .line 393
    const-string v14, "Firebase servers have received too many requests from this client in a short period of time. Please try again later."

    .line 394
    .line 395
    invoke-direct {v4, v14}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    throw v4
    :try_end_7
    .catch Ljava/lang/AssertionError; {:try_start_7 .. :try_end_7} :catch_2
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_2
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 399
    :goto_8
    invoke-virtual {v15}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 400
    .line 401
    .line 402
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 403
    .line 404
    .line 405
    throw v0

    .line 406
    :catch_2
    :goto_9
    invoke-virtual {v15}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 407
    .line 408
    .line 409
    invoke-static {}, Landroid/net/TrafficStats;->clearThreadStatsTag()V

    .line 410
    .line 411
    .line 412
    :goto_a
    add-int/lit8 v13, v13, 0x1

    .line 413
    .line 414
    goto/16 :goto_4

    .line 415
    .line 416
    :cond_b
    new-instance v0, Lht/e;

    .line 417
    .line 418
    invoke-direct {v0, v10}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    throw v0

    .line 422
    :cond_c
    new-instance v0, Lht/e;

    .line 423
    .line 424
    invoke-direct {v0, v10}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 425
    .line 426
    .line 427
    throw v0
.end method

.method public final h(Ljava/lang/Exception;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lht/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lht/c;->l:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lht/i;

    .line 21
    .line 22
    invoke-interface {v1, p1}, Lht/i;->a(Ljava/lang/Exception;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    monitor-exit v0

    .line 35
    return-void

    .line 36
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    throw p0
.end method

.method public final i(Ljt/b;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lht/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lht/c;->l:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lht/i;

    .line 21
    .line 22
    invoke-interface {v1, p1}, Lht/i;->b(Ljt/b;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    monitor-exit v0

    .line 35
    return-void

    .line 36
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    throw p0
.end method
