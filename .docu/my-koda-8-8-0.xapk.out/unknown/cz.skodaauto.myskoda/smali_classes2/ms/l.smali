.class public final Lms/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r:Lms/g;

.field public static final s:Ljava/nio/charset/Charset;


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lh8/o;

.field public final c:Lb81/c;

.field public final d:Lss/b;

.field public final e:Lns/d;

.field public final f:Lms/u;

.field public final g:Lss/b;

.field public final h:Lcom/google/android/material/datepicker/d;

.field public final i:Los/f;

.field public final j:Ljs/a;

.field public final k:Lks/a;

.field public final l:Lms/i;

.field public final m:Lss/b;

.field public n:Lms/r;

.field public final o:Laq/k;

.field public final p:Laq/k;

.field public final q:Laq/k;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lms/g;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lms/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lms/l;->r:Lms/g;

    .line 8
    .line 9
    const-string v0, "UTF-8"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lms/l;->s:Ljava/nio/charset/Charset;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lms/u;Lh8/o;Lss/b;Lb81/c;Lcom/google/android/material/datepicker/d;Lss/b;Los/f;Lss/b;Ljs/a;Lks/a;Lms/i;Lns/d;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

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
    iput-object v0, p0, Lms/l;->o:Laq/k;

    .line 10
    .line 11
    new-instance v0, Laq/k;

    .line 12
    .line 13
    invoke-direct {v0}, Laq/k;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lms/l;->p:Laq/k;

    .line 17
    .line 18
    new-instance v0, Laq/k;

    .line 19
    .line 20
    invoke-direct {v0}, Laq/k;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lms/l;->q:Laq/k;

    .line 24
    .line 25
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lms/l;->a:Landroid/content/Context;

    .line 32
    .line 33
    iput-object p2, p0, Lms/l;->f:Lms/u;

    .line 34
    .line 35
    iput-object p3, p0, Lms/l;->b:Lh8/o;

    .line 36
    .line 37
    iput-object p4, p0, Lms/l;->g:Lss/b;

    .line 38
    .line 39
    iput-object p5, p0, Lms/l;->c:Lb81/c;

    .line 40
    .line 41
    iput-object p6, p0, Lms/l;->h:Lcom/google/android/material/datepicker/d;

    .line 42
    .line 43
    iput-object p7, p0, Lms/l;->d:Lss/b;

    .line 44
    .line 45
    iput-object p8, p0, Lms/l;->i:Los/f;

    .line 46
    .line 47
    iput-object p10, p0, Lms/l;->j:Ljs/a;

    .line 48
    .line 49
    iput-object p11, p0, Lms/l;->k:Lks/a;

    .line 50
    .line 51
    iput-object p12, p0, Lms/l;->l:Lms/i;

    .line 52
    .line 53
    iput-object p9, p0, Lms/l;->m:Lss/b;

    .line 54
    .line 55
    iput-object p13, p0, Lms/l;->e:Lns/d;

    .line 56
    .line 57
    return-void
.end method

.method public static a(Lms/l;)Laq/t;
    .locals 9

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "FirebaseCrashlytics"

    .line 5
    .line 6
    new-instance v1, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, Lms/l;->g:Lss/b;

    .line 12
    .line 13
    iget-object v2, v2, Lss/b;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Ljava/io/File;

    .line 16
    .line 17
    sget-object v3, Lms/l;->r:Lms/g;

    .line 18
    .line 19
    invoke-virtual {v2, v3}, Ljava/io/File;->listFiles(Ljava/io/FilenameFilter;)[Ljava/io/File;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-static {v2}, Lss/b;->m([Ljava/lang/Object;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, Ljava/io/File;

    .line 42
    .line 43
    const/4 v4, 0x0

    .line 44
    :try_start_0
    invoke-virtual {v3}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    const/4 v6, 0x3

    .line 49
    invoke-virtual {v5, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-static {v5}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 54
    .line 55
    .line 56
    move-result-wide v7
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_1

    .line 57
    :try_start_1
    const-string v5, "com.google.firebase.crash.FirebaseCrash"

    .line 58
    .line 59
    invoke-static {v5}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 60
    .line 61
    .line 62
    :try_start_2
    const-string v5, "Skipping logging Crashlytics event to Firebase, FirebaseCrash exists"

    .line 63
    .line 64
    invoke-static {v0, v5, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 65
    .line 66
    .line 67
    invoke-static {v4}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    goto :goto_1

    .line 72
    :catch_0
    const-string v5, "Logging app exception event to Firebase Analytics"

    .line 73
    .line 74
    invoke-static {v0, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    if-eqz v6, :cond_0

    .line 79
    .line 80
    invoke-static {v0, v5, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 81
    .line 82
    .line 83
    :cond_0
    new-instance v5, Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 84
    .line 85
    const/4 v6, 0x1

    .line 86
    invoke-direct {v5, v6}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;-><init>(I)V

    .line 87
    .line 88
    .line 89
    new-instance v6, Lms/k;

    .line 90
    .line 91
    invoke-direct {v6, p0, v7, v8}, Lms/k;-><init>(Lms/l;J)V

    .line 92
    .line 93
    .line 94
    invoke-static {v5, v6}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    :goto_1
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_1

    .line 99
    .line 100
    .line 101
    goto :goto_2

    .line 102
    :catch_1
    new-instance v5, Ljava/lang/StringBuilder;

    .line 103
    .line 104
    const-string v6, "Could not parse app exception timestamp from file "

    .line 105
    .line 106
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v3}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    invoke-static {v0, v5, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 121
    .line 122
    .line 123
    :goto_2
    invoke-virtual {v3}, Ljava/io/File;->delete()Z

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_1
    invoke-static {v1}, Ljp/l1;->f(Ljava/util/List;)Laq/t;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0
.end method


# virtual methods
.method public final b(ZLqn/s;Z)V
    .locals 32

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    iget-object v3, v1, Lms/l;->j:Ljs/a;

    .line 6
    .line 7
    const-string v4, "FirebaseCrashlytics"

    .line 8
    .line 9
    invoke-static {}, Lns/d;->a()V

    .line 10
    .line 11
    .line 12
    new-instance v5, Ljava/util/ArrayList;

    .line 13
    .line 14
    iget-object v6, v1, Lms/l;->m:Lss/b;

    .line 15
    .line 16
    iget-object v0, v6, Lss/b;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lss/a;

    .line 19
    .line 20
    invoke-virtual {v0}, Lss/a;->c()Ljava/util/NavigableSet;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-direct {v5, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    const/4 v7, 0x2

    .line 32
    const/4 v8, 0x0

    .line 33
    if-gt v0, v2, :cond_0

    .line 34
    .line 35
    const-string v0, "No open sessions to be closed."

    .line 36
    .line 37
    invoke-static {v4, v7}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_37

    .line 42
    .line 43
    invoke-static {v4, v0, v8}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_0
    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    move-object v9, v0

    .line 52
    check-cast v9, Ljava/lang/String;

    .line 53
    .line 54
    const/4 v13, 0x1

    .line 55
    const/4 v14, 0x0

    .line 56
    if-eqz p3, :cond_1b

    .line 57
    .line 58
    invoke-virtual/range {p2 .. p2}, Lqn/s;->b()Lus/a;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    iget-object v0, v0, Lus/a;->b:Lc8/g;

    .line 63
    .line 64
    iget-boolean v0, v0, Lc8/g;->b:Z

    .line 65
    .line 66
    if-eqz v0, :cond_1b

    .line 67
    .line 68
    iget-object v0, v1, Lms/l;->g:Lss/b;

    .line 69
    .line 70
    sget v15, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 71
    .line 72
    const/16 v16, 0x4

    .line 73
    .line 74
    const/16 v12, 0x1e

    .line 75
    .line 76
    if-lt v15, v12, :cond_1a

    .line 77
    .line 78
    iget-object v12, v1, Lms/l;->a:Landroid/content/Context;

    .line 79
    .line 80
    const-string v15, "activity"

    .line 81
    .line 82
    invoke-virtual {v12, v15}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v12

    .line 86
    check-cast v12, Landroid/app/ActivityManager;

    .line 87
    .line 88
    invoke-static {v12}, Ln01/a;->i(Landroid/app/ActivityManager;)Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object v12

    .line 92
    invoke-interface {v12}, Ljava/util/List;->size()I

    .line 93
    .line 94
    .line 95
    move-result v15

    .line 96
    if-eqz v15, :cond_18

    .line 97
    .line 98
    new-instance v15, Los/f;

    .line 99
    .line 100
    invoke-direct {v15, v0}, Los/f;-><init>(Lss/b;)V

    .line 101
    .line 102
    .line 103
    const/16 v17, 0x8

    .line 104
    .line 105
    sget-object v10, Los/f;->f:Lgv/a;

    .line 106
    .line 107
    iput-object v10, v15, Los/f;->e:Ljava/lang/Object;

    .line 108
    .line 109
    if-nez v9, :cond_1

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_1
    const-string v10, "userlog"

    .line 113
    .line 114
    invoke-virtual {v0, v9, v10}, Lss/b;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    new-instance v7, Los/m;

    .line 119
    .line 120
    invoke-direct {v7, v10}, Los/m;-><init>(Ljava/io/File;)V

    .line 121
    .line 122
    .line 123
    iput-object v7, v15, Los/f;->e:Ljava/lang/Object;

    .line 124
    .line 125
    :goto_0
    iget-object v7, v1, Lms/l;->e:Lns/d;

    .line 126
    .line 127
    new-instance v10, Los/h;

    .line 128
    .line 129
    invoke-direct {v10, v0}, Los/h;-><init>(Lss/b;)V

    .line 130
    .line 131
    .line 132
    new-instance v8, Lss/b;

    .line 133
    .line 134
    invoke-direct {v8, v9, v0, v7}, Lss/b;-><init>(Ljava/lang/String;Lss/b;Lns/d;)V

    .line 135
    .line 136
    .line 137
    iget-object v7, v8, Lss/b;->h:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v7, La8/b;

    .line 140
    .line 141
    iget-object v7, v7, La8/b;->f:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v7, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 144
    .line 145
    invoke-virtual {v7}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v7

    .line 149
    check-cast v7, Los/e;

    .line 150
    .line 151
    invoke-virtual {v10, v9, v14}, Los/h;->c(Ljava/lang/String;Z)Ljava/util/Map;

    .line 152
    .line 153
    .line 154
    move-result-object v11

    .line 155
    invoke-virtual {v7, v11}, Los/e;->c(Ljava/util/Map;)V

    .line 156
    .line 157
    .line 158
    iget-object v7, v8, Lss/b;->i:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v7, La8/b;

    .line 161
    .line 162
    iget-object v7, v7, La8/b;->f:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v7, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 165
    .line 166
    invoke-virtual {v7}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v7

    .line 170
    check-cast v7, Los/e;

    .line 171
    .line 172
    invoke-virtual {v10, v9, v13}, Los/h;->c(Ljava/lang/String;Z)Ljava/util/Map;

    .line 173
    .line 174
    .line 175
    move-result-object v11

    .line 176
    invoke-virtual {v7, v11}, Los/e;->c(Ljava/util/Map;)V

    .line 177
    .line 178
    .line 179
    iget-object v7, v8, Lss/b;->k:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast v7, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 182
    .line 183
    invoke-virtual {v10, v9}, Los/h;->d(Ljava/lang/String;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v10

    .line 187
    invoke-virtual {v7, v10, v14}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->set(Ljava/lang/Object;Z)V

    .line 188
    .line 189
    .line 190
    iget-object v7, v8, Lss/b;->j:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast v7, Lh01/v;

    .line 193
    .line 194
    const-string v10, "Failed to close rollouts state file."

    .line 195
    .line 196
    const-string v11, "Loaded rollouts state:\n"

    .line 197
    .line 198
    move/from16 v20, v13

    .line 199
    .line 200
    const-string v13, "rollouts-state"

    .line 201
    .line 202
    invoke-virtual {v0, v9, v13}, Lss/b;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    .line 203
    .line 204
    .line 205
    move-result-object v13

    .line 206
    invoke-virtual {v13}, Ljava/io/File;->exists()Z

    .line 207
    .line 208
    .line 209
    move-result v0

    .line 210
    if-eqz v0, :cond_4

    .line 211
    .line 212
    invoke-virtual {v13}, Ljava/io/File;->length()J

    .line 213
    .line 214
    .line 215
    move-result-wide v21

    .line 216
    const-wide/16 v23, 0x0

    .line 217
    .line 218
    cmp-long v0, v21, v23

    .line 219
    .line 220
    if-nez v0, :cond_2

    .line 221
    .line 222
    goto :goto_4

    .line 223
    :cond_2
    :try_start_0
    new-instance v14, Ljava/io/FileInputStream;

    .line 224
    .line 225
    invoke-direct {v14, v13}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 226
    .line 227
    .line 228
    :try_start_1
    invoke-static {v14}, Lms/f;->i(Ljava/io/FileInputStream;)Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    invoke-static {v0}, Los/h;->b(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    new-instance v2, Ljava/lang/StringBuilder;

    .line 237
    .line 238
    invoke-direct {v2, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    const-string v11, "\nfor session "

    .line 245
    .line 246
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 247
    .line 248
    .line 249
    invoke-virtual {v2, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v2

    .line 256
    const/4 v11, 0x3

    .line 257
    invoke-static {v4, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 258
    .line 259
    .line 260
    move-result v22

    .line 261
    if-eqz v22, :cond_3

    .line 262
    .line 263
    const/4 v11, 0x0

    .line 264
    invoke-static {v4, v2, v11}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 265
    .line 266
    .line 267
    :cond_3
    invoke-static {v14, v10}, Lms/f;->b(Ljava/io/Closeable;Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    goto :goto_5

    .line 271
    :goto_1
    move-object v8, v14

    .line 272
    goto :goto_3

    .line 273
    :catchall_0
    move-exception v0

    .line 274
    goto :goto_1

    .line 275
    :catch_0
    move-exception v0

    .line 276
    goto :goto_2

    .line 277
    :catchall_1
    move-exception v0

    .line 278
    const/4 v8, 0x0

    .line 279
    goto :goto_3

    .line 280
    :catch_1
    move-exception v0

    .line 281
    const/4 v14, 0x0

    .line 282
    :goto_2
    :try_start_2
    const-string v2, "Error deserializing rollouts state."

    .line 283
    .line 284
    invoke-static {v4, v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 285
    .line 286
    .line 287
    invoke-static {v13}, Los/h;->f(Ljava/io/File;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 288
    .line 289
    .line 290
    invoke-static {v14, v10}, Lms/f;->b(Ljava/io/Closeable;Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 294
    .line 295
    goto :goto_5

    .line 296
    :goto_3
    invoke-static {v8, v10}, Lms/f;->b(Ljava/io/Closeable;Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    throw v0

    .line 300
    :cond_4
    :goto_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 301
    .line 302
    const-string v2, "The file has a length of zero for session: "

    .line 303
    .line 304
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 305
    .line 306
    .line 307
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 308
    .line 309
    .line 310
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    invoke-static {v13, v0}, Los/h;->g(Ljava/io/File;Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 318
    .line 319
    :goto_5
    invoke-virtual {v7, v0}, Lh01/v;->b(Ljava/util/List;)Z

    .line 320
    .line 321
    .line 322
    iget-object v0, v6, Lss/b;->f:Ljava/lang/Object;

    .line 323
    .line 324
    move-object v2, v0

    .line 325
    check-cast v2, Lss/a;

    .line 326
    .line 327
    iget-object v0, v2, Lss/a;->b:Lss/b;

    .line 328
    .line 329
    const-string v7, "start-time"

    .line 330
    .line 331
    invoke-virtual {v0, v9, v7}, Lss/b;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    invoke-virtual {v0}, Ljava/io/File;->lastModified()J

    .line 336
    .line 337
    .line 338
    move-result-wide v10

    .line 339
    invoke-interface {v12}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 340
    .line 341
    .line 342
    move-result-object v0

    .line 343
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 344
    .line 345
    .line 346
    move-result v7

    .line 347
    if-eqz v7, :cond_5

    .line 348
    .line 349
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v7

    .line 353
    invoke-static {v7}, Ln01/a;->e(Ljava/lang/Object;)Landroid/app/ApplicationExitInfo;

    .line 354
    .line 355
    .line 356
    move-result-object v7

    .line 357
    invoke-static {v7}, Ln01/a;->d(Landroid/app/ApplicationExitInfo;)J

    .line 358
    .line 359
    .line 360
    move-result-wide v12

    .line 361
    cmp-long v12, v12, v10

    .line 362
    .line 363
    if-gez v12, :cond_6

    .line 364
    .line 365
    :cond_5
    const/4 v7, 0x0

    .line 366
    goto :goto_7

    .line 367
    :cond_6
    invoke-static {v7}, Ln01/a;->b(Landroid/app/ApplicationExitInfo;)I

    .line 368
    .line 369
    .line 370
    move-result v12

    .line 371
    const/4 v13, 0x6

    .line 372
    if-eq v12, v13, :cond_7

    .line 373
    .line 374
    goto :goto_6

    .line 375
    :cond_7
    :goto_7
    if-nez v7, :cond_9

    .line 376
    .line 377
    const-string v0, "No relevant ApplicationExitInfo occurred during session: "

    .line 378
    .line 379
    invoke-static {v0, v9}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v0

    .line 383
    const/4 v2, 0x2

    .line 384
    invoke-static {v4, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 385
    .line 386
    .line 387
    move-result v7

    .line 388
    if-eqz v7, :cond_8

    .line 389
    .line 390
    const/4 v11, 0x0

    .line 391
    invoke-static {v4, v0, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 392
    .line 393
    .line 394
    :cond_8
    move-object/from16 v31, v5

    .line 395
    .line 396
    move-object/from16 v30, v6

    .line 397
    .line 398
    move/from16 v6, v20

    .line 399
    .line 400
    goto/16 :goto_c

    .line 401
    .line 402
    :cond_9
    iget-object v0, v6, Lss/b;->e:Ljava/lang/Object;

    .line 403
    .line 404
    move-object v10, v0

    .line 405
    check-cast v10, Lms/q;

    .line 406
    .line 407
    :try_start_3
    invoke-static {v7}, Ld6/t1;->g(Landroid/app/ApplicationExitInfo;)Ljava/io/InputStream;

    .line 408
    .line 409
    .line 410
    move-result-object v0

    .line 411
    if-eqz v0, :cond_a

    .line 412
    .line 413
    invoke-static {v0}, Lss/b;->e(Ljava/io/InputStream;)Ljava/lang/String;

    .line 414
    .line 415
    .line 416
    move-result-object v0
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_2

    .line 417
    goto :goto_8

    .line 418
    :catch_2
    move-exception v0

    .line 419
    new-instance v11, Ljava/lang/StringBuilder;

    .line 420
    .line 421
    const-string v12, "Could not get input trace in application exit info: "

    .line 422
    .line 423
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 424
    .line 425
    .line 426
    invoke-static {v7}, Ld6/t1;->h(Landroid/app/ApplicationExitInfo;)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v12

    .line 430
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 431
    .line 432
    .line 433
    const-string v12, " Error: "

    .line 434
    .line 435
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 436
    .line 437
    .line 438
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 439
    .line 440
    .line 441
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 442
    .line 443
    .line 444
    move-result-object v0

    .line 445
    const/4 v11, 0x0

    .line 446
    invoke-static {v4, v0, v11}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 447
    .line 448
    .line 449
    :cond_a
    const/4 v0, 0x0

    .line 450
    :goto_8
    new-instance v11, Lps/c0;

    .line 451
    .line 452
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 453
    .line 454
    .line 455
    invoke-static {v7}, Ld6/t1;->b(Landroid/app/ApplicationExitInfo;)I

    .line 456
    .line 457
    .line 458
    move-result v12

    .line 459
    iput v12, v11, Lps/c0;->d:I

    .line 460
    .line 461
    iget-byte v12, v11, Lps/c0;->j:B

    .line 462
    .line 463
    or-int/lit8 v12, v12, 0x4

    .line 464
    .line 465
    int-to-byte v12, v12

    .line 466
    iput-byte v12, v11, Lps/c0;->j:B

    .line 467
    .line 468
    invoke-static {v7}, Ld6/t1;->v(Landroid/app/ApplicationExitInfo;)Ljava/lang/String;

    .line 469
    .line 470
    .line 471
    move-result-object v12

    .line 472
    if-eqz v12, :cond_17

    .line 473
    .line 474
    iput-object v12, v11, Lps/c0;->b:Ljava/lang/String;

    .line 475
    .line 476
    invoke-static {v7}, Ln01/a;->b(Landroid/app/ApplicationExitInfo;)I

    .line 477
    .line 478
    .line 479
    move-result v12

    .line 480
    iput v12, v11, Lps/c0;->c:I

    .line 481
    .line 482
    iget-byte v12, v11, Lps/c0;->j:B

    .line 483
    .line 484
    const/16 v18, 0x2

    .line 485
    .line 486
    or-int/lit8 v12, v12, 0x2

    .line 487
    .line 488
    int-to-byte v12, v12

    .line 489
    iput-byte v12, v11, Lps/c0;->j:B

    .line 490
    .line 491
    invoke-static {v7}, Ln01/a;->d(Landroid/app/ApplicationExitInfo;)J

    .line 492
    .line 493
    .line 494
    move-result-wide v12

    .line 495
    iput-wide v12, v11, Lps/c0;->g:J

    .line 496
    .line 497
    iget-byte v12, v11, Lps/c0;->j:B

    .line 498
    .line 499
    or-int/lit8 v12, v12, 0x20

    .line 500
    .line 501
    int-to-byte v12, v12

    .line 502
    iput-byte v12, v11, Lps/c0;->j:B

    .line 503
    .line 504
    invoke-static {v7}, Ld6/t1;->s(Landroid/app/ApplicationExitInfo;)I

    .line 505
    .line 506
    .line 507
    move-result v12

    .line 508
    iput v12, v11, Lps/c0;->a:I

    .line 509
    .line 510
    iget-byte v12, v11, Lps/c0;->j:B

    .line 511
    .line 512
    or-int/lit8 v12, v12, 0x1

    .line 513
    .line 514
    int-to-byte v12, v12

    .line 515
    iput-byte v12, v11, Lps/c0;->j:B

    .line 516
    .line 517
    invoke-static {v7}, Ld6/t1;->c(Landroid/app/ApplicationExitInfo;)J

    .line 518
    .line 519
    .line 520
    move-result-wide v12

    .line 521
    iput-wide v12, v11, Lps/c0;->e:J

    .line 522
    .line 523
    iget-byte v12, v11, Lps/c0;->j:B

    .line 524
    .line 525
    or-int/lit8 v12, v12, 0x8

    .line 526
    .line 527
    int-to-byte v12, v12

    .line 528
    iput-byte v12, v11, Lps/c0;->j:B

    .line 529
    .line 530
    invoke-static {v7}, Ld6/t1;->t(Landroid/app/ApplicationExitInfo;)J

    .line 531
    .line 532
    .line 533
    move-result-wide v12

    .line 534
    iput-wide v12, v11, Lps/c0;->f:J

    .line 535
    .line 536
    iget-byte v7, v11, Lps/c0;->j:B

    .line 537
    .line 538
    or-int/lit8 v7, v7, 0x10

    .line 539
    .line 540
    int-to-byte v7, v7

    .line 541
    iput-byte v7, v11, Lps/c0;->j:B

    .line 542
    .line 543
    iput-object v0, v11, Lps/c0;->h:Ljava/lang/String;

    .line 544
    .line 545
    invoke-virtual {v11}, Lps/c0;->a()Lps/d0;

    .line 546
    .line 547
    .line 548
    move-result-object v0

    .line 549
    iget-object v7, v10, Lms/q;->a:Landroid/content/Context;

    .line 550
    .line 551
    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 552
    .line 553
    .line 554
    move-result-object v7

    .line 555
    invoke-virtual {v7}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 556
    .line 557
    .line 558
    move-result-object v7

    .line 559
    iget v7, v7, Landroid/content/res/Configuration;->orientation:I

    .line 560
    .line 561
    new-instance v11, Lps/o0;

    .line 562
    .line 563
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 564
    .line 565
    .line 566
    const-string v12, "anr"

    .line 567
    .line 568
    iput-object v12, v11, Lps/o0;->b:Ljava/lang/String;

    .line 569
    .line 570
    iget-wide v12, v0, Lps/d0;->g:J

    .line 571
    .line 572
    iput-wide v12, v11, Lps/o0;->a:J

    .line 573
    .line 574
    iget-byte v14, v11, Lps/o0;->g:B

    .line 575
    .line 576
    or-int/lit8 v14, v14, 0x1

    .line 577
    .line 578
    int-to-byte v14, v14

    .line 579
    iput-byte v14, v11, Lps/o0;->g:B

    .line 580
    .line 581
    iget-object v14, v10, Lms/q;->c:Lcom/google/android/material/datepicker/d;

    .line 582
    .line 583
    move/from16 v29, v7

    .line 584
    .line 585
    iget-object v7, v10, Lms/q;->e:Lqn/s;

    .line 586
    .line 587
    invoke-virtual {v7}, Lqn/s;->b()Lus/a;

    .line 588
    .line 589
    .line 590
    move-result-object v7

    .line 591
    iget-object v7, v7, Lus/a;->b:Lc8/g;

    .line 592
    .line 593
    iget-boolean v7, v7, Lc8/g;->c:Z

    .line 594
    .line 595
    if-eqz v7, :cond_f

    .line 596
    .line 597
    iget-object v7, v14, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast v7, Ljava/util/ArrayList;

    .line 600
    .line 601
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 602
    .line 603
    .line 604
    move-result v7

    .line 605
    if-lez v7, :cond_f

    .line 606
    .line 607
    new-instance v7, Ljava/util/ArrayList;

    .line 608
    .line 609
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 610
    .line 611
    .line 612
    iget-object v14, v14, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 613
    .line 614
    check-cast v14, Ljava/util/ArrayList;

    .line 615
    .line 616
    invoke-virtual {v14}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 617
    .line 618
    .line 619
    move-result-object v14

    .line 620
    :goto_9
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 621
    .line 622
    .line 623
    move-result v22

    .line 624
    if-eqz v22, :cond_e

    .line 625
    .line 626
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    move-result-object v22

    .line 630
    move-object/from16 p2, v14

    .line 631
    .line 632
    move-object/from16 v14, v22

    .line 633
    .line 634
    check-cast v14, Lms/c;

    .line 635
    .line 636
    move-object/from16 v30, v6

    .line 637
    .line 638
    iget-object v6, v14, Lms/c;->a:Ljava/lang/String;

    .line 639
    .line 640
    if-eqz v6, :cond_d

    .line 641
    .line 642
    iget-object v1, v14, Lms/c;->b:Ljava/lang/String;

    .line 643
    .line 644
    if-eqz v1, :cond_c

    .line 645
    .line 646
    iget-object v14, v14, Lms/c;->c:Ljava/lang/String;

    .line 647
    .line 648
    if-eqz v14, :cond_b

    .line 649
    .line 650
    move-object/from16 v31, v5

    .line 651
    .line 652
    new-instance v5, Lps/e0;

    .line 653
    .line 654
    invoke-direct {v5, v1, v6, v14}, Lps/e0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 655
    .line 656
    .line 657
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 658
    .line 659
    .line 660
    move-object/from16 v1, p0

    .line 661
    .line 662
    move-object/from16 v14, p2

    .line 663
    .line 664
    move-object/from16 v6, v30

    .line 665
    .line 666
    move-object/from16 v5, v31

    .line 667
    .line 668
    goto :goto_9

    .line 669
    :cond_b
    new-instance v0, Ljava/lang/NullPointerException;

    .line 670
    .line 671
    const-string v1, "Null buildId"

    .line 672
    .line 673
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    throw v0

    .line 677
    :cond_c
    new-instance v0, Ljava/lang/NullPointerException;

    .line 678
    .line 679
    const-string v1, "Null arch"

    .line 680
    .line 681
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 682
    .line 683
    .line 684
    throw v0

    .line 685
    :cond_d
    new-instance v0, Ljava/lang/NullPointerException;

    .line 686
    .line 687
    const-string v1, "Null libraryName"

    .line 688
    .line 689
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 690
    .line 691
    .line 692
    throw v0

    .line 693
    :cond_e
    move-object/from16 v31, v5

    .line 694
    .line 695
    move-object/from16 v30, v6

    .line 696
    .line 697
    invoke-static {v7}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 698
    .line 699
    .line 700
    move-result-object v1

    .line 701
    goto :goto_a

    .line 702
    :cond_f
    move-object/from16 v31, v5

    .line 703
    .line 704
    move-object/from16 v30, v6

    .line 705
    .line 706
    const/4 v1, 0x0

    .line 707
    :goto_a
    new-instance v5, Lps/c0;

    .line 708
    .line 709
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 710
    .line 711
    .line 712
    iget v6, v0, Lps/d0;->d:I

    .line 713
    .line 714
    iput v6, v5, Lps/c0;->d:I

    .line 715
    .line 716
    iget-byte v6, v5, Lps/c0;->j:B

    .line 717
    .line 718
    or-int/lit8 v6, v6, 0x4

    .line 719
    .line 720
    int-to-byte v6, v6

    .line 721
    iput-byte v6, v5, Lps/c0;->j:B

    .line 722
    .line 723
    iget-object v7, v0, Lps/d0;->b:Ljava/lang/String;

    .line 724
    .line 725
    if-eqz v7, :cond_16

    .line 726
    .line 727
    iput-object v7, v5, Lps/c0;->b:Ljava/lang/String;

    .line 728
    .line 729
    iget v7, v0, Lps/d0;->c:I

    .line 730
    .line 731
    iput v7, v5, Lps/c0;->c:I

    .line 732
    .line 733
    const/16 v18, 0x2

    .line 734
    .line 735
    or-int/lit8 v6, v6, 0x2

    .line 736
    .line 737
    int-to-byte v6, v6

    .line 738
    iput-wide v12, v5, Lps/c0;->g:J

    .line 739
    .line 740
    or-int/lit8 v6, v6, 0x20

    .line 741
    .line 742
    int-to-byte v6, v6

    .line 743
    iget v7, v0, Lps/d0;->a:I

    .line 744
    .line 745
    iput v7, v5, Lps/c0;->a:I

    .line 746
    .line 747
    or-int/lit8 v6, v6, 0x1

    .line 748
    .line 749
    int-to-byte v6, v6

    .line 750
    iget-wide v12, v0, Lps/d0;->e:J

    .line 751
    .line 752
    iput-wide v12, v5, Lps/c0;->e:J

    .line 753
    .line 754
    or-int/lit8 v6, v6, 0x8

    .line 755
    .line 756
    int-to-byte v6, v6

    .line 757
    iget-wide v12, v0, Lps/d0;->f:J

    .line 758
    .line 759
    iput-wide v12, v5, Lps/c0;->f:J

    .line 760
    .line 761
    or-int/lit8 v6, v6, 0x10

    .line 762
    .line 763
    int-to-byte v6, v6

    .line 764
    iput-byte v6, v5, Lps/c0;->j:B

    .line 765
    .line 766
    iget-object v0, v0, Lps/d0;->h:Ljava/lang/String;

    .line 767
    .line 768
    iput-object v0, v5, Lps/c0;->h:Ljava/lang/String;

    .line 769
    .line 770
    iput-object v1, v5, Lps/c0;->i:Ljava/util/List;

    .line 771
    .line 772
    invoke-virtual {v5}, Lps/c0;->a()Lps/d0;

    .line 773
    .line 774
    .line 775
    move-result-object v0

    .line 776
    iget v1, v0, Lps/d0;->d:I

    .line 777
    .line 778
    const/16 v5, 0x64

    .line 779
    .line 780
    if-eq v1, v5, :cond_10

    .line 781
    .line 782
    move/from16 v1, v20

    .line 783
    .line 784
    goto :goto_b

    .line 785
    :cond_10
    const/4 v1, 0x0

    .line 786
    :goto_b
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 787
    .line 788
    .line 789
    move-result-object v1

    .line 790
    iget-object v5, v0, Lps/d0;->b:Ljava/lang/String;

    .line 791
    .line 792
    iget v6, v0, Lps/d0;->a:I

    .line 793
    .line 794
    iget v7, v0, Lps/d0;->d:I

    .line 795
    .line 796
    const-string v12, "processName"

    .line 797
    .line 798
    invoke-static {v5, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 799
    .line 800
    .line 801
    const/16 v12, 0x8

    .line 802
    .line 803
    and-int/lit8 v12, v12, 0x4

    .line 804
    .line 805
    if-eqz v12, :cond_11

    .line 806
    .line 807
    const/4 v7, 0x0

    .line 808
    :cond_11
    new-instance v12, Lps/y0;

    .line 809
    .line 810
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 811
    .line 812
    .line 813
    iput-object v5, v12, Lps/y0;->a:Ljava/lang/String;

    .line 814
    .line 815
    iput v6, v12, Lps/y0;->b:I

    .line 816
    .line 817
    iget-byte v5, v12, Lps/y0;->e:B

    .line 818
    .line 819
    or-int/lit8 v5, v5, 0x1

    .line 820
    .line 821
    int-to-byte v5, v5

    .line 822
    iput v7, v12, Lps/y0;->c:I

    .line 823
    .line 824
    const/16 v18, 0x2

    .line 825
    .line 826
    or-int/lit8 v5, v5, 0x2

    .line 827
    .line 828
    int-to-byte v5, v5

    .line 829
    const/4 v6, 0x0

    .line 830
    iput-boolean v6, v12, Lps/y0;->d:Z

    .line 831
    .line 832
    or-int/lit8 v5, v5, 0x4

    .line 833
    .line 834
    int-to-byte v5, v5

    .line 835
    iput-byte v5, v12, Lps/y0;->e:B

    .line 836
    .line 837
    invoke-virtual {v12}, Lps/y0;->a()Lps/z0;

    .line 838
    .line 839
    .line 840
    move-result-object v5

    .line 841
    move/from16 v6, v20

    .line 842
    .line 843
    int-to-byte v7, v6

    .line 844
    invoke-static {}, Lms/q;->e()Lps/u0;

    .line 845
    .line 846
    .line 847
    move-result-object v26

    .line 848
    invoke-virtual {v10}, Lms/q;->a()Ljava/util/List;

    .line 849
    .line 850
    .line 851
    move-result-object v27

    .line 852
    if-eqz v27, :cond_15

    .line 853
    .line 854
    new-instance v22, Lps/r0;

    .line 855
    .line 856
    const/16 v23, 0x0

    .line 857
    .line 858
    const/16 v24, 0x0

    .line 859
    .line 860
    move-object/from16 v25, v0

    .line 861
    .line 862
    invoke-direct/range {v22 .. v27}, Lps/r0;-><init>(Ljava/util/List;Lps/t0;Lps/p1;Lps/u0;Ljava/util/List;)V

    .line 863
    .line 864
    .line 865
    if-ne v7, v6, :cond_13

    .line 866
    .line 867
    move-object/from16 v23, v22

    .line 868
    .line 869
    new-instance v22, Lps/q0;

    .line 870
    .line 871
    const/16 v24, 0x0

    .line 872
    .line 873
    const/16 v25, 0x0

    .line 874
    .line 875
    const/16 v28, 0x0

    .line 876
    .line 877
    move-object/from16 v26, v1

    .line 878
    .line 879
    move-object/from16 v27, v5

    .line 880
    .line 881
    invoke-direct/range {v22 .. v29}, Lps/q0;-><init>(Lps/r0;Ljava/util/List;Ljava/util/List;Ljava/lang/Boolean;Lps/c2;Ljava/util/List;I)V

    .line 882
    .line 883
    .line 884
    move-object/from16 v1, v22

    .line 885
    .line 886
    move/from16 v0, v29

    .line 887
    .line 888
    iput-object v1, v11, Lps/o0;->c:Lps/d2;

    .line 889
    .line 890
    invoke-virtual {v10, v0}, Lms/q;->b(I)Lps/b1;

    .line 891
    .line 892
    .line 893
    move-result-object v0

    .line 894
    iput-object v0, v11, Lps/o0;->d:Lps/e2;

    .line 895
    .line 896
    invoke-virtual {v11}, Lps/o0;->a()Lps/p0;

    .line 897
    .line 898
    .line 899
    move-result-object v0

    .line 900
    const-string v1, "Persisting anr for session "

    .line 901
    .line 902
    invoke-static {v1, v9}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 903
    .line 904
    .line 905
    move-result-object v1

    .line 906
    const/4 v11, 0x3

    .line 907
    invoke-static {v4, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 908
    .line 909
    .line 910
    move-result v5

    .line 911
    if-eqz v5, :cond_12

    .line 912
    .line 913
    const/4 v11, 0x0

    .line 914
    invoke-static {v4, v1, v11}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 915
    .line 916
    .line 917
    :cond_12
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 918
    .line 919
    invoke-static {v0, v15, v8, v1}, Lss/b;->a(Lps/p0;Los/f;Lss/b;Ljava/util/Map;)Lps/p0;

    .line 920
    .line 921
    .line 922
    move-result-object v0

    .line 923
    invoke-static {v0, v8}, Lss/b;->b(Lps/p0;Lss/b;)Lps/j2;

    .line 924
    .line 925
    .line 926
    move-result-object v0

    .line 927
    const/4 v6, 0x1

    .line 928
    invoke-virtual {v2, v0, v9, v6}, Lss/a;->d(Lps/j2;Ljava/lang/String;Z)V

    .line 929
    .line 930
    .line 931
    :goto_c
    const/4 v2, 0x2

    .line 932
    goto :goto_d

    .line 933
    :cond_13
    new-instance v0, Ljava/lang/StringBuilder;

    .line 934
    .line 935
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 936
    .line 937
    .line 938
    if-nez v7, :cond_14

    .line 939
    .line 940
    const-string v1, " uiOrientation"

    .line 941
    .line 942
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 943
    .line 944
    .line 945
    :cond_14
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 946
    .line 947
    const-string v2, "Missing required properties:"

    .line 948
    .line 949
    invoke-static {v2, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 950
    .line 951
    .line 952
    move-result-object v0

    .line 953
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 954
    .line 955
    .line 956
    throw v1

    .line 957
    :cond_15
    new-instance v0, Ljava/lang/NullPointerException;

    .line 958
    .line 959
    const-string v1, "Null binaries"

    .line 960
    .line 961
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 962
    .line 963
    .line 964
    throw v0

    .line 965
    :cond_16
    new-instance v0, Ljava/lang/NullPointerException;

    .line 966
    .line 967
    const-string v1, "Null processName"

    .line 968
    .line 969
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 970
    .line 971
    .line 972
    throw v0

    .line 973
    :cond_17
    new-instance v0, Ljava/lang/NullPointerException;

    .line 974
    .line 975
    const-string v1, "Null processName"

    .line 976
    .line 977
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 978
    .line 979
    .line 980
    throw v0

    .line 981
    :cond_18
    move-object/from16 v31, v5

    .line 982
    .line 983
    move-object/from16 v30, v6

    .line 984
    .line 985
    move v6, v13

    .line 986
    const/16 v17, 0x8

    .line 987
    .line 988
    const-string v0, "No ApplicationExitInfo available. Session: "

    .line 989
    .line 990
    invoke-static {v0, v9}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 991
    .line 992
    .line 993
    move-result-object v0

    .line 994
    const/4 v2, 0x2

    .line 995
    invoke-static {v4, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 996
    .line 997
    .line 998
    move-result v1

    .line 999
    if-eqz v1, :cond_19

    .line 1000
    .line 1001
    const/4 v11, 0x0

    .line 1002
    invoke-static {v4, v0, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1003
    .line 1004
    .line 1005
    goto :goto_e

    .line 1006
    :cond_19
    :goto_d
    const/4 v11, 0x0

    .line 1007
    goto :goto_e

    .line 1008
    :cond_1a
    move-object/from16 v31, v5

    .line 1009
    .line 1010
    move-object/from16 v30, v6

    .line 1011
    .line 1012
    move v2, v7

    .line 1013
    move-object v11, v8

    .line 1014
    move v6, v13

    .line 1015
    const/16 v17, 0x8

    .line 1016
    .line 1017
    const-string v0, "ANR feature enabled, but device is API "

    .line 1018
    .line 1019
    invoke-static {v15, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 1020
    .line 1021
    .line 1022
    move-result-object v0

    .line 1023
    invoke-static {v4, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1024
    .line 1025
    .line 1026
    move-result v1

    .line 1027
    if-eqz v1, :cond_1c

    .line 1028
    .line 1029
    invoke-static {v4, v0, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1030
    .line 1031
    .line 1032
    goto :goto_e

    .line 1033
    :cond_1b
    move-object/from16 v31, v5

    .line 1034
    .line 1035
    move-object/from16 v30, v6

    .line 1036
    .line 1037
    move v2, v7

    .line 1038
    move-object v11, v8

    .line 1039
    move v6, v13

    .line 1040
    const/16 v16, 0x4

    .line 1041
    .line 1042
    const/16 v17, 0x8

    .line 1043
    .line 1044
    const-string v0, "ANR feature disabled."

    .line 1045
    .line 1046
    invoke-static {v4, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1047
    .line 1048
    .line 1049
    move-result v1

    .line 1050
    if-eqz v1, :cond_1c

    .line 1051
    .line 1052
    invoke-static {v4, v0, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1053
    .line 1054
    .line 1055
    :cond_1c
    :goto_e
    if-eqz p3, :cond_1e

    .line 1056
    .line 1057
    invoke-virtual {v3, v9}, Ljs/a;->c(Ljava/lang/String;)Z

    .line 1058
    .line 1059
    .line 1060
    move-result v0

    .line 1061
    if-eqz v0, :cond_1e

    .line 1062
    .line 1063
    const-string v0, "Finalizing native report for session "

    .line 1064
    .line 1065
    invoke-static {v0, v9}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1066
    .line 1067
    .line 1068
    move-result-object v0

    .line 1069
    invoke-static {v4, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1070
    .line 1071
    .line 1072
    move-result v1

    .line 1073
    if-eqz v1, :cond_1d

    .line 1074
    .line 1075
    invoke-static {v4, v0, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1076
    .line 1077
    .line 1078
    :cond_1d
    invoke-virtual {v3, v9}, Ljs/a;->a(Ljava/lang/String;)Ljs/c;

    .line 1079
    .line 1080
    .line 1081
    move-result-object v0

    .line 1082
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1083
    .line 1084
    .line 1085
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1086
    .line 1087
    const-string v1, "No minidump data found for session "

    .line 1088
    .line 1089
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1090
    .line 1091
    .line 1092
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1093
    .line 1094
    .line 1095
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v0

    .line 1099
    invoke-static {v4, v0, v11}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1100
    .line 1101
    .line 1102
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1103
    .line 1104
    const-string v1, "No Tombstones data found for session "

    .line 1105
    .line 1106
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1107
    .line 1108
    .line 1109
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1110
    .line 1111
    .line 1112
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v0

    .line 1116
    invoke-static {v4, v0, v11}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1117
    .line 1118
    .line 1119
    const-string v0, "No native core present"

    .line 1120
    .line 1121
    invoke-static {v4, v0, v11}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1122
    .line 1123
    .line 1124
    :cond_1e
    if-eqz p1, :cond_1f

    .line 1125
    .line 1126
    move-object/from16 v2, v31

    .line 1127
    .line 1128
    const/4 v1, 0x0

    .line 1129
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v0

    .line 1133
    move-object/from16 v19, v0

    .line 1134
    .line 1135
    check-cast v19, Ljava/lang/String;

    .line 1136
    .line 1137
    move-object/from16 v0, v19

    .line 1138
    .line 1139
    goto :goto_f

    .line 1140
    :cond_1f
    move-object/from16 v2, p0

    .line 1141
    .line 1142
    const/4 v1, 0x0

    .line 1143
    iget-object v0, v2, Lms/l;->l:Lms/i;

    .line 1144
    .line 1145
    invoke-virtual {v0, v11}, Lms/i;->a(Ljava/lang/String;)V

    .line 1146
    .line 1147
    .line 1148
    const/4 v0, 0x0

    .line 1149
    :goto_f
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1150
    .line 1151
    .line 1152
    move-result-wide v2

    .line 1153
    const-wide/16 v7, 0x3e8

    .line 1154
    .line 1155
    div-long/2addr v2, v7

    .line 1156
    move-object/from16 v5, v30

    .line 1157
    .line 1158
    iget-object v5, v5, Lss/b;->f:Ljava/lang/Object;

    .line 1159
    .line 1160
    check-cast v5, Lss/a;

    .line 1161
    .line 1162
    iget-object v7, v5, Lss/a;->b:Lss/b;

    .line 1163
    .line 1164
    const-string v8, ".com.google.firebase.crashlytics"

    .line 1165
    .line 1166
    invoke-virtual {v7, v8}, Lss/b;->d(Ljava/lang/String;)V

    .line 1167
    .line 1168
    .line 1169
    const-string v8, ".com.google.firebase.crashlytics-ndk"

    .line 1170
    .line 1171
    invoke-virtual {v7, v8}, Lss/b;->d(Ljava/lang/String;)V

    .line 1172
    .line 1173
    .line 1174
    iget-object v8, v7, Lss/b;->e:Ljava/lang/Object;

    .line 1175
    .line 1176
    check-cast v8, Ljava/lang/String;

    .line 1177
    .line 1178
    invoke-virtual {v8}, Ljava/lang/String;->isEmpty()Z

    .line 1179
    .line 1180
    .line 1181
    move-result v8

    .line 1182
    if-nez v8, :cond_20

    .line 1183
    .line 1184
    const-string v8, ".com.google.firebase.crashlytics.files.v1"

    .line 1185
    .line 1186
    invoke-virtual {v7, v8}, Lss/b;->d(Ljava/lang/String;)V

    .line 1187
    .line 1188
    .line 1189
    new-instance v8, Ljava/lang/StringBuilder;

    .line 1190
    .line 1191
    const-string v9, ".com.google.firebase.crashlytics.files.v2"

    .line 1192
    .line 1193
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1194
    .line 1195
    .line 1196
    sget-object v9, Ljava/io/File;->pathSeparator:Ljava/lang/String;

    .line 1197
    .line 1198
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1199
    .line 1200
    .line 1201
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1202
    .line 1203
    .line 1204
    move-result-object v8

    .line 1205
    iget-object v9, v7, Lss/b;->f:Ljava/lang/Object;

    .line 1206
    .line 1207
    check-cast v9, Ljava/io/File;

    .line 1208
    .line 1209
    invoke-virtual {v9}, Ljava/io/File;->exists()Z

    .line 1210
    .line 1211
    .line 1212
    move-result v10

    .line 1213
    if-eqz v10, :cond_20

    .line 1214
    .line 1215
    new-instance v10, Lcom/salesforce/marketingcloud/sfmcsdk/util/a;

    .line 1216
    .line 1217
    const/4 v11, 0x2

    .line 1218
    invoke-direct {v10, v8, v11}, Lcom/salesforce/marketingcloud/sfmcsdk/util/a;-><init>(Ljava/lang/String;I)V

    .line 1219
    .line 1220
    .line 1221
    invoke-virtual {v9, v10}, Ljava/io/File;->list(Ljava/io/FilenameFilter;)[Ljava/lang/String;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v8

    .line 1225
    if-eqz v8, :cond_20

    .line 1226
    .line 1227
    array-length v9, v8

    .line 1228
    move v10, v1

    .line 1229
    :goto_10
    if-ge v10, v9, :cond_20

    .line 1230
    .line 1231
    aget-object v11, v8, v10

    .line 1232
    .line 1233
    invoke-virtual {v7, v11}, Lss/b;->d(Ljava/lang/String;)V

    .line 1234
    .line 1235
    .line 1236
    add-int/lit8 v10, v10, 0x1

    .line 1237
    .line 1238
    goto :goto_10

    .line 1239
    :cond_20
    invoke-virtual {v5}, Lss/a;->c()Ljava/util/NavigableSet;

    .line 1240
    .line 1241
    .line 1242
    move-result-object v8

    .line 1243
    if-eqz v0, :cond_21

    .line 1244
    .line 1245
    invoke-interface {v8, v0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 1246
    .line 1247
    .line 1248
    :cond_21
    invoke-interface {v8}, Ljava/util/Set;->size()I

    .line 1249
    .line 1250
    .line 1251
    move-result v0

    .line 1252
    move/from16 v9, v17

    .line 1253
    .line 1254
    if-gt v0, v9, :cond_22

    .line 1255
    .line 1256
    goto :goto_12

    .line 1257
    :cond_22
    :goto_11
    invoke-interface {v8}, Ljava/util/Set;->size()I

    .line 1258
    .line 1259
    .line 1260
    move-result v0

    .line 1261
    if-le v0, v9, :cond_24

    .line 1262
    .line 1263
    invoke-interface {v8}, Ljava/util/SortedSet;->last()Ljava/lang/Object;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v0

    .line 1267
    check-cast v0, Ljava/lang/String;

    .line 1268
    .line 1269
    const-string v10, "Removing session over cap: "

    .line 1270
    .line 1271
    invoke-static {v10, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v10

    .line 1275
    const/4 v11, 0x3

    .line 1276
    invoke-static {v4, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1277
    .line 1278
    .line 1279
    move-result v12

    .line 1280
    if-eqz v12, :cond_23

    .line 1281
    .line 1282
    const/4 v11, 0x0

    .line 1283
    invoke-static {v4, v10, v11}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1284
    .line 1285
    .line 1286
    :cond_23
    new-instance v10, Ljava/io/File;

    .line 1287
    .line 1288
    iget-object v11, v7, Lss/b;->h:Ljava/lang/Object;

    .line 1289
    .line 1290
    check-cast v11, Ljava/io/File;

    .line 1291
    .line 1292
    invoke-direct {v10, v11, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 1293
    .line 1294
    .line 1295
    invoke-static {v10}, Lss/b;->l(Ljava/io/File;)Z

    .line 1296
    .line 1297
    .line 1298
    invoke-interface {v8, v0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 1299
    .line 1300
    .line 1301
    goto :goto_11

    .line 1302
    :cond_24
    :goto_12
    invoke-interface {v8}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v8

    .line 1306
    :goto_13
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 1307
    .line 1308
    .line 1309
    move-result v0

    .line 1310
    if-eqz v0, :cond_35

    .line 1311
    .line 1312
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1313
    .line 1314
    .line 1315
    move-result-object v0

    .line 1316
    move-object v9, v0

    .line 1317
    check-cast v9, Ljava/lang/String;

    .line 1318
    .line 1319
    const-string v0, "Finalizing report for session "

    .line 1320
    .line 1321
    invoke-static {v0, v9}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1322
    .line 1323
    .line 1324
    move-result-object v0

    .line 1325
    const/4 v10, 0x2

    .line 1326
    invoke-static {v4, v10}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1327
    .line 1328
    .line 1329
    move-result v11

    .line 1330
    if-eqz v11, :cond_25

    .line 1331
    .line 1332
    const/4 v11, 0x0

    .line 1333
    invoke-static {v4, v0, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1334
    .line 1335
    .line 1336
    :cond_25
    sget-object v10, Lss/a;->g:Lqs/a;

    .line 1337
    .line 1338
    sget-object v0, Lss/a;->i:Lms/g;

    .line 1339
    .line 1340
    new-instance v11, Ljava/io/File;

    .line 1341
    .line 1342
    iget-object v12, v7, Lss/b;->h:Ljava/lang/Object;

    .line 1343
    .line 1344
    check-cast v12, Ljava/io/File;

    .line 1345
    .line 1346
    invoke-direct {v11, v12, v9}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 1347
    .line 1348
    .line 1349
    invoke-virtual {v11}, Ljava/io/File;->mkdirs()Z

    .line 1350
    .line 1351
    .line 1352
    invoke-virtual {v11, v0}, Ljava/io/File;->listFiles(Ljava/io/FilenameFilter;)[Ljava/io/File;

    .line 1353
    .line 1354
    .line 1355
    move-result-object v0

    .line 1356
    invoke-static {v0}, Lss/b;->m([Ljava/lang/Object;)Ljava/util/List;

    .line 1357
    .line 1358
    .line 1359
    move-result-object v0

    .line 1360
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 1361
    .line 1362
    .line 1363
    move-result v11

    .line 1364
    if-eqz v11, :cond_27

    .line 1365
    .line 1366
    const-string v0, "Session "

    .line 1367
    .line 1368
    const-string v10, " has no events."

    .line 1369
    .line 1370
    invoke-static {v0, v9, v10}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1371
    .line 1372
    .line 1373
    move-result-object v0

    .line 1374
    const/4 v10, 0x2

    .line 1375
    invoke-static {v4, v10}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1376
    .line 1377
    .line 1378
    move-result v11

    .line 1379
    if-eqz v11, :cond_26

    .line 1380
    .line 1381
    const/4 v11, 0x0

    .line 1382
    invoke-static {v4, v0, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1383
    .line 1384
    .line 1385
    :cond_26
    const/4 v11, 0x3

    .line 1386
    const/4 v15, 0x0

    .line 1387
    :goto_14
    const/16 v18, 0x2

    .line 1388
    .line 1389
    goto/16 :goto_24

    .line 1390
    .line 1391
    :cond_27
    invoke-static {v0}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 1392
    .line 1393
    .line 1394
    new-instance v11, Ljava/util/ArrayList;

    .line 1395
    .line 1396
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 1397
    .line 1398
    .line 1399
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1400
    .line 1401
    .line 1402
    move-result-object v12

    .line 1403
    move v13, v1

    .line 1404
    :goto_15
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 1405
    .line 1406
    .line 1407
    move-result v0

    .line 1408
    if-eqz v0, :cond_2a

    .line 1409
    .line 1410
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1411
    .line 1412
    .line 1413
    move-result-object v0

    .line 1414
    move-object v14, v0

    .line 1415
    check-cast v14, Ljava/io/File;

    .line 1416
    .line 1417
    :try_start_4
    invoke-static {v14}, Lss/a;->e(Ljava/io/File;)Ljava/lang/String;

    .line 1418
    .line 1419
    .line 1420
    move-result-object v0

    .line 1421
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3

    .line 1422
    .line 1423
    .line 1424
    :try_start_5
    new-instance v15, Landroid/util/JsonReader;

    .line 1425
    .line 1426
    new-instance v1, Ljava/io/StringReader;

    .line 1427
    .line 1428
    invoke-direct {v1, v0}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    .line 1429
    .line 1430
    .line 1431
    invoke-direct {v15, v1}, Landroid/util/JsonReader;-><init>(Ljava/io/Reader;)V
    :try_end_5
    .catch Ljava/lang/IllegalStateException; {:try_start_5 .. :try_end_5} :catch_4
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_3

    .line 1432
    .line 1433
    .line 1434
    :try_start_6
    invoke-static {v15}, Lqs/a;->e(Landroid/util/JsonReader;)Lps/p0;

    .line 1435
    .line 1436
    .line 1437
    move-result-object v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 1438
    :try_start_7
    invoke-virtual {v15}, Landroid/util/JsonReader;->close()V
    :try_end_7
    .catch Ljava/lang/IllegalStateException; {:try_start_7 .. :try_end_7} :catch_4
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_3

    .line 1439
    .line 1440
    .line 1441
    :try_start_8
    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1442
    .line 1443
    .line 1444
    if-nez v13, :cond_29

    .line 1445
    .line 1446
    invoke-virtual {v14}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v0

    .line 1450
    const-string v1, "event"

    .line 1451
    .line 1452
    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1453
    .line 1454
    .line 1455
    move-result v1

    .line 1456
    if-eqz v1, :cond_28

    .line 1457
    .line 1458
    const-string v1, "_"

    .line 1459
    .line 1460
    invoke-virtual {v0, v1}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 1461
    .line 1462
    .line 1463
    move-result v0
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_3

    .line 1464
    if-eqz v0, :cond_28

    .line 1465
    .line 1466
    goto :goto_16

    .line 1467
    :cond_28
    const/4 v0, 0x0

    .line 1468
    goto :goto_17

    .line 1469
    :catch_3
    move-exception v0

    .line 1470
    goto :goto_1a

    .line 1471
    :cond_29
    :goto_16
    move v0, v6

    .line 1472
    :goto_17
    move v13, v0

    .line 1473
    goto :goto_1b

    .line 1474
    :catch_4
    move-exception v0

    .line 1475
    goto :goto_19

    .line 1476
    :catchall_2
    move-exception v0

    .line 1477
    move-object v1, v0

    .line 1478
    :try_start_9
    invoke-virtual {v15}, Landroid/util/JsonReader;->close()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 1479
    .line 1480
    .line 1481
    goto :goto_18

    .line 1482
    :catchall_3
    move-exception v0

    .line 1483
    :try_start_a
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 1484
    .line 1485
    .line 1486
    :goto_18
    throw v1
    :try_end_a
    .catch Ljava/lang/IllegalStateException; {:try_start_a .. :try_end_a} :catch_4
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_3

    .line 1487
    :goto_19
    :try_start_b
    new-instance v1, Ljava/io/IOException;

    .line 1488
    .line 1489
    invoke-direct {v1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 1490
    .line 1491
    .line 1492
    throw v1
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_3

    .line 1493
    :goto_1a
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1494
    .line 1495
    const-string v15, "Could not add event to report for "

    .line 1496
    .line 1497
    invoke-direct {v1, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1498
    .line 1499
    .line 1500
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1501
    .line 1502
    .line 1503
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1504
    .line 1505
    .line 1506
    move-result-object v1

    .line 1507
    invoke-static {v4, v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1508
    .line 1509
    .line 1510
    :goto_1b
    const/4 v1, 0x0

    .line 1511
    goto :goto_15

    .line 1512
    :cond_2a
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1513
    .line 1514
    .line 1515
    move-result v0

    .line 1516
    if-eqz v0, :cond_2b

    .line 1517
    .line 1518
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1519
    .line 1520
    const-string v1, "Could not parse event files for session "

    .line 1521
    .line 1522
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1523
    .line 1524
    .line 1525
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1526
    .line 1527
    .line 1528
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1529
    .line 1530
    .line 1531
    move-result-object v0

    .line 1532
    const/4 v11, 0x0

    .line 1533
    invoke-static {v4, v0, v11}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1534
    .line 1535
    .line 1536
    move-object v15, v11

    .line 1537
    const/4 v11, 0x3

    .line 1538
    goto/16 :goto_14

    .line 1539
    .line 1540
    :cond_2b
    new-instance v0, Los/h;

    .line 1541
    .line 1542
    invoke-direct {v0, v7}, Los/h;-><init>(Lss/b;)V

    .line 1543
    .line 1544
    .line 1545
    invoke-virtual {v0, v9}, Los/h;->d(Ljava/lang/String;)Ljava/lang/String;

    .line 1546
    .line 1547
    .line 1548
    move-result-object v0

    .line 1549
    iget-object v1, v5, Lss/a;->d:Lms/i;

    .line 1550
    .line 1551
    iget-object v1, v1, Lms/i;->b:Lms/h;

    .line 1552
    .line 1553
    monitor-enter v1

    .line 1554
    :try_start_c
    iget-object v12, v1, Lms/h;->b:Ljava/lang/String;

    .line 1555
    .line 1556
    invoke-static {v12, v9}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1557
    .line 1558
    .line 1559
    move-result v12

    .line 1560
    if-eqz v12, :cond_2c

    .line 1561
    .line 1562
    iget-object v12, v1, Lms/h;->c:Ljava/lang/String;
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_4

    .line 1563
    .line 1564
    monitor-exit v1

    .line 1565
    goto :goto_1d

    .line 1566
    :catchall_4
    move-exception v0

    .line 1567
    goto/16 :goto_25

    .line 1568
    .line 1569
    :cond_2c
    :try_start_d
    iget-object v12, v1, Lms/h;->a:Lss/b;

    .line 1570
    .line 1571
    sget-object v14, Lms/h;->d:Lms/g;

    .line 1572
    .line 1573
    new-instance v15, Ljava/io/File;

    .line 1574
    .line 1575
    iget-object v12, v12, Lss/b;->h:Ljava/lang/Object;

    .line 1576
    .line 1577
    check-cast v12, Ljava/io/File;

    .line 1578
    .line 1579
    invoke-direct {v15, v12, v9}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 1580
    .line 1581
    .line 1582
    invoke-virtual {v15}, Ljava/io/File;->mkdirs()Z

    .line 1583
    .line 1584
    .line 1585
    invoke-virtual {v15, v14}, Ljava/io/File;->listFiles(Ljava/io/FilenameFilter;)[Ljava/io/File;

    .line 1586
    .line 1587
    .line 1588
    move-result-object v12

    .line 1589
    invoke-static {v12}, Lss/b;->m([Ljava/lang/Object;)Ljava/util/List;

    .line 1590
    .line 1591
    .line 1592
    move-result-object v12

    .line 1593
    invoke-interface {v12}, Ljava/util/List;->isEmpty()Z

    .line 1594
    .line 1595
    .line 1596
    move-result v14

    .line 1597
    if-eqz v14, :cond_2d

    .line 1598
    .line 1599
    const-string v12, "Unable to read App Quality Sessions session id."

    .line 1600
    .line 1601
    const-string v14, "FirebaseCrashlytics"

    .line 1602
    .line 1603
    const/4 v15, 0x0

    .line 1604
    invoke-static {v14, v12, v15}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1605
    .line 1606
    .line 1607
    const/4 v12, 0x0

    .line 1608
    goto :goto_1c

    .line 1609
    :cond_2d
    sget-object v14, Lms/h;->e:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 1610
    .line 1611
    invoke-static {v12, v14}, Ljava/util/Collections;->min(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 1612
    .line 1613
    .line 1614
    move-result-object v12

    .line 1615
    check-cast v12, Ljava/io/File;

    .line 1616
    .line 1617
    invoke-virtual {v12}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 1618
    .line 1619
    .line 1620
    move-result-object v12

    .line 1621
    move/from16 v14, v16

    .line 1622
    .line 1623
    invoke-virtual {v12, v14}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 1624
    .line 1625
    .line 1626
    move-result-object v12
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 1627
    :goto_1c
    monitor-exit v1

    .line 1628
    :goto_1d
    const-string v1, "report"

    .line 1629
    .line 1630
    invoke-virtual {v7, v9, v1}, Lss/b;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v1

    .line 1634
    const-string v14, "appQualitySessionId: "

    .line 1635
    .line 1636
    :try_start_e
    invoke-static {v1}, Lss/a;->e(Ljava/io/File;)Ljava/lang/String;

    .line 1637
    .line 1638
    .line 1639
    move-result-object v15

    .line 1640
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1641
    .line 1642
    .line 1643
    invoke-static {v15}, Lqs/a;->i(Ljava/lang/String;)Lps/b0;

    .line 1644
    .line 1645
    .line 1646
    move-result-object v10

    .line 1647
    invoke-virtual {v10}, Lps/b0;->a()Lps/a0;

    .line 1648
    .line 1649
    .line 1650
    move-result-object v15

    .line 1651
    iget-object v10, v10, Lps/b0;->k:Lps/m2;
    :try_end_e
    .catch Ljava/io/IOException; {:try_start_e .. :try_end_e} :catch_9

    .line 1652
    .line 1653
    if-eqz v10, :cond_2f

    .line 1654
    .line 1655
    :try_start_f
    invoke-virtual {v10}, Lps/m2;->a()Lps/i0;

    .line 1656
    .line 1657
    .line 1658
    move-result-object v10

    .line 1659
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1660
    .line 1661
    .line 1662
    move-result-object v6

    .line 1663
    iput-object v6, v10, Lps/i0;->e:Ljava/lang/Long;

    .line 1664
    .line 1665
    iput-boolean v13, v10, Lps/i0;->f:Z

    .line 1666
    .line 1667
    iget-byte v6, v10, Lps/i0;->m:B
    :try_end_f
    .catch Ljava/io/IOException; {:try_start_f .. :try_end_f} :catch_5

    .line 1668
    .line 1669
    const/16 v18, 0x2

    .line 1670
    .line 1671
    or-int/lit8 v6, v6, 0x2

    .line 1672
    .line 1673
    int-to-byte v6, v6

    .line 1674
    :try_start_10
    iput-byte v6, v10, Lps/i0;->m:B

    .line 1675
    .line 1676
    if-eqz v0, :cond_2e

    .line 1677
    .line 1678
    new-instance v6, Lps/j1;

    .line 1679
    .line 1680
    invoke-direct {v6, v0}, Lps/j1;-><init>(Ljava/lang/String;)V

    .line 1681
    .line 1682
    .line 1683
    iput-object v6, v10, Lps/i0;->h:Lps/l2;

    .line 1684
    .line 1685
    :cond_2e
    invoke-virtual {v10}, Lps/i0;->a()Lps/j0;

    .line 1686
    .line 1687
    .line 1688
    move-result-object v0

    .line 1689
    iput-object v0, v15, Lps/a0;->j:Lps/m2;

    .line 1690
    .line 1691
    goto :goto_1e

    .line 1692
    :catch_5
    move-exception v0

    .line 1693
    const/16 v18, 0x2

    .line 1694
    .line 1695
    goto/16 :goto_21

    .line 1696
    .line 1697
    :cond_2f
    const/16 v18, 0x2

    .line 1698
    .line 1699
    :goto_1e
    invoke-virtual {v15}, Lps/a0;->a()Lps/b0;

    .line 1700
    .line 1701
    .line 1702
    move-result-object v0

    .line 1703
    invoke-virtual {v0}, Lps/b0;->a()Lps/a0;

    .line 1704
    .line 1705
    .line 1706
    move-result-object v6

    .line 1707
    iput-object v12, v6, Lps/a0;->g:Ljava/lang/String;

    .line 1708
    .line 1709
    iget-object v0, v0, Lps/b0;->k:Lps/m2;

    .line 1710
    .line 1711
    if-eqz v0, :cond_30

    .line 1712
    .line 1713
    invoke-virtual {v0}, Lps/m2;->a()Lps/i0;

    .line 1714
    .line 1715
    .line 1716
    move-result-object v0

    .line 1717
    iput-object v12, v0, Lps/i0;->c:Ljava/lang/String;

    .line 1718
    .line 1719
    invoke-virtual {v0}, Lps/i0;->a()Lps/j0;

    .line 1720
    .line 1721
    .line 1722
    move-result-object v0

    .line 1723
    iput-object v0, v6, Lps/a0;->j:Lps/m2;

    .line 1724
    .line 1725
    :cond_30
    invoke-virtual {v6}, Lps/a0;->a()Lps/b0;

    .line 1726
    .line 1727
    .line 1728
    move-result-object v0

    .line 1729
    iget-object v6, v0, Lps/b0;->k:Lps/m2;

    .line 1730
    .line 1731
    if-eqz v6, :cond_34

    .line 1732
    .line 1733
    invoke-virtual {v0}, Lps/b0;->a()Lps/a0;

    .line 1734
    .line 1735
    .line 1736
    move-result-object v0

    .line 1737
    invoke-virtual {v6}, Lps/m2;->a()Lps/i0;

    .line 1738
    .line 1739
    .line 1740
    move-result-object v6

    .line 1741
    iput-object v11, v6, Lps/i0;->k:Ljava/util/List;

    .line 1742
    .line 1743
    invoke-virtual {v6}, Lps/i0;->a()Lps/j0;

    .line 1744
    .line 1745
    .line 1746
    move-result-object v6

    .line 1747
    iput-object v6, v0, Lps/a0;->j:Lps/m2;

    .line 1748
    .line 1749
    invoke-virtual {v0}, Lps/a0;->a()Lps/b0;

    .line 1750
    .line 1751
    .line 1752
    move-result-object v0

    .line 1753
    iget-object v6, v0, Lps/b0;->k:Lps/m2;

    .line 1754
    .line 1755
    if-nez v6, :cond_31

    .line 1756
    .line 1757
    const/4 v11, 0x3

    .line 1758
    const/4 v15, 0x0

    .line 1759
    goto :goto_24

    .line 1760
    :cond_31
    new-instance v10, Ljava/lang/StringBuilder;

    .line 1761
    .line 1762
    invoke-direct {v10, v14}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1763
    .line 1764
    .line 1765
    invoke-virtual {v10, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1766
    .line 1767
    .line 1768
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1769
    .line 1770
    .line 1771
    move-result-object v10
    :try_end_10
    .catch Ljava/io/IOException; {:try_start_10 .. :try_end_10} :catch_8

    .line 1772
    const/4 v11, 0x3

    .line 1773
    :try_start_11
    invoke-static {v4, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1774
    .line 1775
    .line 1776
    move-result v12
    :try_end_11
    .catch Ljava/io/IOException; {:try_start_11 .. :try_end_11} :catch_7

    .line 1777
    if-eqz v12, :cond_32

    .line 1778
    .line 1779
    const/4 v15, 0x0

    .line 1780
    :try_start_12
    invoke-static {v4, v10, v15}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1781
    .line 1782
    .line 1783
    goto :goto_1f

    .line 1784
    :cond_32
    const/4 v15, 0x0

    .line 1785
    :goto_1f
    if-eqz v13, :cond_33

    .line 1786
    .line 1787
    check-cast v6, Lps/j0;

    .line 1788
    .line 1789
    iget-object v6, v6, Lps/j0;->b:Ljava/lang/String;

    .line 1790
    .line 1791
    new-instance v10, Ljava/io/File;

    .line 1792
    .line 1793
    iget-object v12, v7, Lss/b;->j:Ljava/lang/Object;

    .line 1794
    .line 1795
    check-cast v12, Ljava/io/File;

    .line 1796
    .line 1797
    invoke-direct {v10, v12, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 1798
    .line 1799
    .line 1800
    goto :goto_20

    .line 1801
    :cond_33
    check-cast v6, Lps/j0;

    .line 1802
    .line 1803
    iget-object v6, v6, Lps/j0;->b:Ljava/lang/String;

    .line 1804
    .line 1805
    new-instance v10, Ljava/io/File;

    .line 1806
    .line 1807
    iget-object v12, v7, Lss/b;->i:Ljava/lang/Object;

    .line 1808
    .line 1809
    check-cast v12, Ljava/io/File;

    .line 1810
    .line 1811
    invoke-direct {v10, v12, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 1812
    .line 1813
    .line 1814
    :goto_20
    sget-object v6, Lqs/a;->a:Lbu/c;

    .line 1815
    .line 1816
    invoke-virtual {v6, v0}, Lbu/c;->l(Ljava/lang/Object;)Ljava/lang/String;

    .line 1817
    .line 1818
    .line 1819
    move-result-object v0

    .line 1820
    invoke-static {v10, v0}, Lss/a;->f(Ljava/io/File;Ljava/lang/String;)V

    .line 1821
    .line 1822
    .line 1823
    goto :goto_24

    .line 1824
    :catch_6
    move-exception v0

    .line 1825
    goto :goto_23

    .line 1826
    :catch_7
    move-exception v0

    .line 1827
    goto :goto_22

    .line 1828
    :catch_8
    move-exception v0

    .line 1829
    :goto_21
    const/4 v11, 0x3

    .line 1830
    :goto_22
    const/4 v15, 0x0

    .line 1831
    goto :goto_23

    .line 1832
    :cond_34
    const/4 v11, 0x3

    .line 1833
    const/4 v15, 0x0

    .line 1834
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1835
    .line 1836
    const-string v6, "Reports without sessions cannot have events added to them."

    .line 1837
    .line 1838
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1839
    .line 1840
    .line 1841
    throw v0
    :try_end_12
    .catch Ljava/io/IOException; {:try_start_12 .. :try_end_12} :catch_6

    .line 1842
    :catch_9
    move-exception v0

    .line 1843
    const/4 v11, 0x3

    .line 1844
    const/4 v15, 0x0

    .line 1845
    const/16 v18, 0x2

    .line 1846
    .line 1847
    :goto_23
    new-instance v6, Ljava/lang/StringBuilder;

    .line 1848
    .line 1849
    const-string v10, "Could not synthesize final report file for "

    .line 1850
    .line 1851
    invoke-direct {v6, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1852
    .line 1853
    .line 1854
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1855
    .line 1856
    .line 1857
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1858
    .line 1859
    .line 1860
    move-result-object v1

    .line 1861
    invoke-static {v4, v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1862
    .line 1863
    .line 1864
    :goto_24
    new-instance v0, Ljava/io/File;

    .line 1865
    .line 1866
    iget-object v1, v7, Lss/b;->h:Ljava/lang/Object;

    .line 1867
    .line 1868
    check-cast v1, Ljava/io/File;

    .line 1869
    .line 1870
    invoke-direct {v0, v1, v9}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 1871
    .line 1872
    .line 1873
    invoke-static {v0}, Lss/b;->l(Ljava/io/File;)Z

    .line 1874
    .line 1875
    .line 1876
    const/4 v1, 0x0

    .line 1877
    const/4 v6, 0x1

    .line 1878
    const/16 v16, 0x4

    .line 1879
    .line 1880
    goto/16 :goto_13

    .line 1881
    .line 1882
    :goto_25
    :try_start_13
    monitor-exit v1
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_4

    .line 1883
    throw v0

    .line 1884
    :cond_35
    iget-object v0, v5, Lss/a;->c:Lqn/s;

    .line 1885
    .line 1886
    invoke-virtual {v0}, Lqn/s;->b()Lus/a;

    .line 1887
    .line 1888
    .line 1889
    move-result-object v0

    .line 1890
    iget-object v0, v0, Lus/a;->a:Lc1/l2;

    .line 1891
    .line 1892
    invoke-virtual {v5}, Lss/a;->b()Ljava/util/ArrayList;

    .line 1893
    .line 1894
    .line 1895
    move-result-object v0

    .line 1896
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 1897
    .line 1898
    .line 1899
    move-result v1

    .line 1900
    const/4 v14, 0x4

    .line 1901
    if-gt v1, v14, :cond_36

    .line 1902
    .line 1903
    goto :goto_27

    .line 1904
    :cond_36
    invoke-virtual {v0, v14, v1}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 1905
    .line 1906
    .line 1907
    move-result-object v0

    .line 1908
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1909
    .line 1910
    .line 1911
    move-result-object v0

    .line 1912
    :goto_26
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1913
    .line 1914
    .line 1915
    move-result v1

    .line 1916
    if-eqz v1, :cond_37

    .line 1917
    .line 1918
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1919
    .line 1920
    .line 1921
    move-result-object v1

    .line 1922
    check-cast v1, Ljava/io/File;

    .line 1923
    .line 1924
    invoke-virtual {v1}, Ljava/io/File;->delete()Z

    .line 1925
    .line 1926
    .line 1927
    goto :goto_26

    .line 1928
    :cond_37
    :goto_27
    return-void
.end method

.method public final c(Ljava/lang/String;Ljava/lang/Boolean;)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    const-wide/16 v7, 0x3e8

    .line 10
    .line 11
    div-long v9, v1, v7

    .line 12
    .line 13
    const-string v1, "Opening a new session with ID "

    .line 14
    .line 15
    invoke-static {v1, v3}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "FirebaseCrashlytics"

    .line 20
    .line 21
    const/4 v11, 0x3

    .line 22
    invoke-static {v2, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    const/4 v12, 0x0

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    const-string v2, "FirebaseCrashlytics"

    .line 30
    .line 31
    invoke-static {v2, v1, v12}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 32
    .line 33
    .line 34
    :cond_0
    sget-object v13, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 35
    .line 36
    iget-object v1, v0, Lms/l;->f:Lms/u;

    .line 37
    .line 38
    iget-object v2, v0, Lms/l;->h:Lcom/google/android/material/datepicker/d;

    .line 39
    .line 40
    iget-object v15, v1, Lms/u;->c:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v4, v2, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 43
    .line 44
    move-object/from16 v16, v4

    .line 45
    .line 46
    check-cast v16, Ljava/lang/String;

    .line 47
    .line 48
    iget-object v4, v2, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 49
    .line 50
    move-object/from16 v17, v4

    .line 51
    .line 52
    check-cast v17, Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {v1}, Lms/u;->c()Lms/b;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    iget-object v1, v1, Lms/b;->a:Ljava/lang/String;

    .line 59
    .line 60
    iget-object v4, v2, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v4, Ljava/lang/String;

    .line 63
    .line 64
    const/16 v21, 0x1

    .line 65
    .line 66
    if-eqz v4, :cond_1

    .line 67
    .line 68
    const/4 v4, 0x4

    .line 69
    goto :goto_0

    .line 70
    :cond_1
    move/from16 v4, v21

    .line 71
    .line 72
    :goto_0
    invoke-static {v4}, Lkx/a;->a(I)I

    .line 73
    .line 74
    .line 75
    move-result v19

    .line 76
    iget-object v2, v2, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 77
    .line 78
    move-object/from16 v20, v2

    .line 79
    .line 80
    check-cast v20, Lb81/d;

    .line 81
    .line 82
    new-instance v14, Lps/l1;

    .line 83
    .line 84
    move-object/from16 v18, v1

    .line 85
    .line 86
    invoke-direct/range {v14 .. v20}, Lps/l1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILb81/d;)V

    .line 87
    .line 88
    .line 89
    sget-object v15, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 90
    .line 91
    sget-object v1, Landroid/os/Build$VERSION;->CODENAME:Ljava/lang/String;

    .line 92
    .line 93
    invoke-static {}, Lms/f;->g()Z

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    new-instance v4, Lps/n1;

    .line 98
    .line 99
    invoke-direct {v4, v2}, Lps/n1;-><init>(Z)V

    .line 100
    .line 101
    .line 102
    iget-object v2, v0, Lms/l;->a:Landroid/content/Context;

    .line 103
    .line 104
    new-instance v6, Landroid/os/StatFs;

    .line 105
    .line 106
    invoke-static {}, Landroid/os/Environment;->getDataDirectory()Ljava/io/File;

    .line 107
    .line 108
    .line 109
    move-result-object v16

    .line 110
    invoke-virtual/range {v16 .. v16}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    invoke-direct {v6, v5}, Landroid/os/StatFs;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v6}, Landroid/os/StatFs;->getBlockCount()I

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    move-wide/from16 v18, v7

    .line 122
    .line 123
    int-to-long v7, v5

    .line 124
    invoke-virtual {v6}, Landroid/os/StatFs;->getBlockSize()I

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    int-to-long v5, v5

    .line 129
    mul-long v27, v7, v5

    .line 130
    .line 131
    sget-object v5, Lms/e;->d:Lms/e;

    .line 132
    .line 133
    const-string v6, "FirebaseCrashlytics"

    .line 134
    .line 135
    sget-object v7, Landroid/os/Build;->CPU_ABI:Ljava/lang/String;

    .line 136
    .line 137
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 138
    .line 139
    .line 140
    move-result v8

    .line 141
    const/4 v11, 0x2

    .line 142
    if-eqz v8, :cond_2

    .line 143
    .line 144
    const-string v8, "Architecture#getValue()::Build.CPU_ABI returned null or empty"

    .line 145
    .line 146
    invoke-static {v6, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 147
    .line 148
    .line 149
    move-result v20

    .line 150
    if-eqz v20, :cond_4

    .line 151
    .line 152
    invoke-static {v6, v8, v12}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 153
    .line 154
    .line 155
    goto :goto_1

    .line 156
    :cond_2
    invoke-virtual {v7, v13}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v6

    .line 160
    sget-object v8, Lms/e;->e:Ljava/util/HashMap;

    .line 161
    .line 162
    invoke-virtual {v8, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v6

    .line 166
    check-cast v6, Lms/e;

    .line 167
    .line 168
    if-nez v6, :cond_3

    .line 169
    .line 170
    goto :goto_1

    .line 171
    :cond_3
    move-object v5, v6

    .line 172
    :cond_4
    :goto_1
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 173
    .line 174
    .line 175
    move-result v23

    .line 176
    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 177
    .line 178
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 179
    .line 180
    .line 181
    move-result-object v5

    .line 182
    invoke-virtual {v5}, Ljava/lang/Runtime;->availableProcessors()I

    .line 183
    .line 184
    .line 185
    move-result v24

    .line 186
    invoke-static {v2}, Lms/f;->a(Landroid/content/Context;)J

    .line 187
    .line 188
    .line 189
    move-result-wide v25

    .line 190
    invoke-static {}, Lms/f;->f()Z

    .line 191
    .line 192
    .line 193
    move-result v29

    .line 194
    invoke-static {}, Lms/f;->c()I

    .line 195
    .line 196
    .line 197
    move-result v30

    .line 198
    sget-object v2, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 199
    .line 200
    sget-object v5, Landroid/os/Build;->PRODUCT:Ljava/lang/String;

    .line 201
    .line 202
    new-instance v22, Lps/m1;

    .line 203
    .line 204
    invoke-direct/range {v22 .. v30}, Lps/m1;-><init>(IIJJZI)V

    .line 205
    .line 206
    .line 207
    move/from16 v20, v11

    .line 208
    .line 209
    move-object/from16 v6, v22

    .line 210
    .line 211
    iget-object v11, v0, Lms/l;->j:Ljs/a;

    .line 212
    .line 213
    new-instance v12, Lps/k1;

    .line 214
    .line 215
    invoke-direct {v12, v14, v4, v6}, Lps/k1;-><init>(Lps/l1;Lps/n1;Lps/m1;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v11, v3, v9, v10, v12}, Ljs/a;->d(Ljava/lang/String;JLps/k1;)V

    .line 219
    .line 220
    .line 221
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 222
    .line 223
    .line 224
    move-result v4

    .line 225
    if-eqz v4, :cond_5

    .line 226
    .line 227
    if-eqz v3, :cond_5

    .line 228
    .line 229
    move-object v4, v2

    .line 230
    iget-object v2, v0, Lms/l;->d:Lss/b;

    .line 231
    .line 232
    iget-object v6, v2, Lss/b;->e:Ljava/lang/Object;

    .line 233
    .line 234
    move-object v11, v6

    .line 235
    check-cast v11, Ljava/lang/String;

    .line 236
    .line 237
    monitor-enter v11

    .line 238
    :try_start_0
    iput-object v3, v2, Lss/b;->e:Ljava/lang/Object;

    .line 239
    .line 240
    iget-object v6, v2, Lss/b;->h:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast v6, La8/b;

    .line 243
    .line 244
    iget-object v6, v6, La8/b;->f:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast v6, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 247
    .line 248
    invoke-virtual {v6}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v6

    .line 252
    check-cast v6, Los/e;

    .line 253
    .line 254
    monitor-enter v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 255
    :try_start_1
    new-instance v12, Ljava/util/HashMap;

    .line 256
    .line 257
    iget-object v14, v6, Los/e;->a:Ljava/util/HashMap;

    .line 258
    .line 259
    invoke-direct {v12, v14}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 260
    .line 261
    .line 262
    invoke-static {v12}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 263
    .line 264
    .line 265
    move-result-object v12
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 266
    :try_start_2
    monitor-exit v6

    .line 267
    iget-object v6, v2, Lss/b;->j:Ljava/lang/Object;

    .line 268
    .line 269
    check-cast v6, Lh01/v;

    .line 270
    .line 271
    invoke-virtual {v6}, Lh01/v;->a()Ljava/util/List;

    .line 272
    .line 273
    .line 274
    move-result-object v6

    .line 275
    iget-object v14, v2, Lss/b;->g:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast v14, Lns/d;

    .line 278
    .line 279
    iget-object v14, v14, Lns/d;->b:Lns/b;

    .line 280
    .line 281
    move-object/from16 v23, v1

    .line 282
    .line 283
    new-instance v1, Lc8/r;

    .line 284
    .line 285
    move-object/from16 v24, v5

    .line 286
    .line 287
    move-object v5, v6

    .line 288
    const/4 v6, 0x4

    .line 289
    move-object/from16 v31, v4

    .line 290
    .line 291
    move-object/from16 v17, v8

    .line 292
    .line 293
    move-object v4, v12

    .line 294
    move-object/from16 v12, v23

    .line 295
    .line 296
    move-object/from16 v32, v24

    .line 297
    .line 298
    const/4 v8, 0x4

    .line 299
    invoke-direct/range {v1 .. v6}, Lc8/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v14, v1}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 303
    .line 304
    .line 305
    monitor-exit v11
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 306
    goto :goto_3

    .line 307
    :catchall_0
    move-exception v0

    .line 308
    goto :goto_2

    .line 309
    :catchall_1
    move-exception v0

    .line 310
    :try_start_3
    monitor-exit v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 311
    :try_start_4
    throw v0

    .line 312
    :goto_2
    monitor-exit v11
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 313
    throw v0

    .line 314
    :cond_5
    move-object v12, v1

    .line 315
    move-object/from16 v31, v2

    .line 316
    .line 317
    move-object/from16 v32, v5

    .line 318
    .line 319
    move-object/from16 v17, v8

    .line 320
    .line 321
    const/4 v8, 0x4

    .line 322
    :goto_3
    iget-object v1, v0, Lms/l;->i:Los/f;

    .line 323
    .line 324
    iget-object v2, v1, Los/f;->e:Ljava/lang/Object;

    .line 325
    .line 326
    check-cast v2, Los/d;

    .line 327
    .line 328
    invoke-interface {v2}, Los/d;->a()V

    .line 329
    .line 330
    .line 331
    sget-object v2, Los/f;->f:Lgv/a;

    .line 332
    .line 333
    iput-object v2, v1, Los/f;->e:Ljava/lang/Object;

    .line 334
    .line 335
    if-nez v3, :cond_6

    .line 336
    .line 337
    goto :goto_4

    .line 338
    :cond_6
    iget-object v2, v1, Los/f;->d:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast v2, Lss/b;

    .line 341
    .line 342
    const-string v4, "userlog"

    .line 343
    .line 344
    invoke-virtual {v2, v3, v4}, Lss/b;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    .line 345
    .line 346
    .line 347
    move-result-object v2

    .line 348
    new-instance v4, Los/m;

    .line 349
    .line 350
    invoke-direct {v4, v2}, Los/m;-><init>(Ljava/io/File;)V

    .line 351
    .line 352
    .line 353
    iput-object v4, v1, Los/f;->e:Ljava/lang/Object;

    .line 354
    .line 355
    :goto_4
    iget-object v1, v0, Lms/l;->l:Lms/i;

    .line 356
    .line 357
    invoke-virtual {v1, v3}, Lms/i;->a(Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    iget-object v0, v0, Lms/l;->m:Lss/b;

    .line 361
    .line 362
    iget-object v1, v0, Lss/b;->e:Ljava/lang/Object;

    .line 363
    .line 364
    check-cast v1, Lms/q;

    .line 365
    .line 366
    sget-object v2, Lps/n2;->a:Ljava/nio/charset/Charset;

    .line 367
    .line 368
    new-instance v2, Lps/a0;

    .line 369
    .line 370
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 371
    .line 372
    .line 373
    const-string v4, "20.0.3"

    .line 374
    .line 375
    iput-object v4, v2, Lps/a0;->a:Ljava/lang/String;

    .line 376
    .line 377
    iget-object v4, v1, Lms/q;->c:Lcom/google/android/material/datepicker/d;

    .line 378
    .line 379
    iget-object v5, v4, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 380
    .line 381
    check-cast v5, Ljava/lang/String;

    .line 382
    .line 383
    if-eqz v5, :cond_18

    .line 384
    .line 385
    iput-object v5, v2, Lps/a0;->b:Ljava/lang/String;

    .line 386
    .line 387
    iget-object v5, v1, Lms/q;->b:Lms/u;

    .line 388
    .line 389
    invoke-virtual {v5}, Lms/u;->c()Lms/b;

    .line 390
    .line 391
    .line 392
    move-result-object v6

    .line 393
    iget-object v6, v6, Lms/b;->a:Ljava/lang/String;

    .line 394
    .line 395
    if-eqz v6, :cond_17

    .line 396
    .line 397
    iput-object v6, v2, Lps/a0;->d:Ljava/lang/String;

    .line 398
    .line 399
    invoke-virtual {v5}, Lms/u;->c()Lms/b;

    .line 400
    .line 401
    .line 402
    move-result-object v6

    .line 403
    iget-object v6, v6, Lms/b;->b:Ljava/lang/String;

    .line 404
    .line 405
    iput-object v6, v2, Lps/a0;->e:Ljava/lang/String;

    .line 406
    .line 407
    invoke-virtual {v5}, Lms/u;->c()Lms/b;

    .line 408
    .line 409
    .line 410
    move-result-object v6

    .line 411
    iget-object v6, v6, Lms/b;->c:Ljava/lang/String;

    .line 412
    .line 413
    iput-object v6, v2, Lps/a0;->f:Ljava/lang/String;

    .line 414
    .line 415
    iget-object v6, v4, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 416
    .line 417
    check-cast v6, Ljava/lang/String;

    .line 418
    .line 419
    if-eqz v6, :cond_16

    .line 420
    .line 421
    iput-object v6, v2, Lps/a0;->h:Ljava/lang/String;

    .line 422
    .line 423
    iget-object v11, v4, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 424
    .line 425
    check-cast v11, Ljava/lang/String;

    .line 426
    .line 427
    if-eqz v11, :cond_15

    .line 428
    .line 429
    iput-object v11, v2, Lps/a0;->i:Ljava/lang/String;

    .line 430
    .line 431
    iput v8, v2, Lps/a0;->c:I

    .line 432
    .line 433
    iget-byte v14, v2, Lps/a0;->m:B

    .line 434
    .line 435
    or-int/lit8 v14, v14, 0x1

    .line 436
    .line 437
    int-to-byte v14, v14

    .line 438
    iput-byte v14, v2, Lps/a0;->m:B

    .line 439
    .line 440
    new-instance v14, Lps/i0;

    .line 441
    .line 442
    invoke-direct {v14}, Ljava/lang/Object;-><init>()V

    .line 443
    .line 444
    .line 445
    move/from16 v30, v8

    .line 446
    .line 447
    const/4 v8, 0x0

    .line 448
    iput-boolean v8, v14, Lps/i0;->f:Z

    .line 449
    .line 450
    iget-byte v8, v14, Lps/i0;->m:B

    .line 451
    .line 452
    or-int/lit8 v8, v8, 0x2

    .line 453
    .line 454
    int-to-byte v8, v8

    .line 455
    iput-wide v9, v14, Lps/i0;->d:J

    .line 456
    .line 457
    or-int/lit8 v8, v8, 0x1

    .line 458
    .line 459
    int-to-byte v8, v8

    .line 460
    iput-byte v8, v14, Lps/i0;->m:B

    .line 461
    .line 462
    if-eqz v3, :cond_14

    .line 463
    .line 464
    iput-object v3, v14, Lps/i0;->b:Ljava/lang/String;

    .line 465
    .line 466
    sget-object v3, Lms/q;->g:Ljava/lang/String;

    .line 467
    .line 468
    if-eqz v3, :cond_13

    .line 469
    .line 470
    iput-object v3, v14, Lps/i0;->a:Ljava/lang/String;

    .line 471
    .line 472
    iget-object v3, v5, Lms/u;->c:Ljava/lang/String;

    .line 473
    .line 474
    if-eqz v3, :cond_12

    .line 475
    .line 476
    invoke-virtual {v5}, Lms/u;->c()Lms/b;

    .line 477
    .line 478
    .line 479
    move-result-object v5

    .line 480
    iget-object v5, v5, Lms/b;->a:Ljava/lang/String;

    .line 481
    .line 482
    iget-object v4, v4, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 483
    .line 484
    check-cast v4, Lb81/d;

    .line 485
    .line 486
    iget-object v8, v4, Lb81/d;->f:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast v8, Lb81/c;

    .line 489
    .line 490
    if-nez v8, :cond_7

    .line 491
    .line 492
    new-instance v8, Lb81/c;

    .line 493
    .line 494
    invoke-direct {v8, v4}, Lb81/c;-><init>(Lb81/d;)V

    .line 495
    .line 496
    .line 497
    iput-object v8, v4, Lb81/d;->f:Ljava/lang/Object;

    .line 498
    .line 499
    :cond_7
    iget-object v8, v4, Lb81/d;->f:Ljava/lang/Object;

    .line 500
    .line 501
    check-cast v8, Lb81/c;

    .line 502
    .line 503
    iget-object v9, v8, Lb81/c;->e:Ljava/lang/Object;

    .line 504
    .line 505
    move-object/from16 v28, v9

    .line 506
    .line 507
    check-cast v28, Ljava/lang/String;

    .line 508
    .line 509
    if-nez v8, :cond_8

    .line 510
    .line 511
    new-instance v8, Lb81/c;

    .line 512
    .line 513
    invoke-direct {v8, v4}, Lb81/c;-><init>(Lb81/d;)V

    .line 514
    .line 515
    .line 516
    iput-object v8, v4, Lb81/d;->f:Ljava/lang/Object;

    .line 517
    .line 518
    :cond_8
    iget-object v4, v4, Lb81/d;->f:Ljava/lang/Object;

    .line 519
    .line 520
    check-cast v4, Lb81/c;

    .line 521
    .line 522
    iget-object v4, v4, Lb81/c;->f:Ljava/lang/Object;

    .line 523
    .line 524
    move-object/from16 v29, v4

    .line 525
    .line 526
    check-cast v29, Ljava/lang/String;

    .line 527
    .line 528
    new-instance v23, Lps/k0;

    .line 529
    .line 530
    move-object/from16 v24, v3

    .line 531
    .line 532
    move-object/from16 v27, v5

    .line 533
    .line 534
    move-object/from16 v25, v6

    .line 535
    .line 536
    move-object/from16 v26, v11

    .line 537
    .line 538
    invoke-direct/range {v23 .. v29}, Lps/k0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 539
    .line 540
    .line 541
    move-object/from16 v3, v23

    .line 542
    .line 543
    iput-object v3, v14, Lps/i0;->g:Lps/u1;

    .line 544
    .line 545
    new-instance v3, Lps/h1;

    .line 546
    .line 547
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 548
    .line 549
    .line 550
    const/4 v4, 0x3

    .line 551
    iput v4, v3, Lps/h1;->a:I

    .line 552
    .line 553
    iget-byte v4, v3, Lps/h1;->e:B

    .line 554
    .line 555
    or-int/lit8 v4, v4, 0x1

    .line 556
    .line 557
    int-to-byte v4, v4

    .line 558
    iput-byte v4, v3, Lps/h1;->e:B

    .line 559
    .line 560
    if-eqz v15, :cond_11

    .line 561
    .line 562
    iput-object v15, v3, Lps/h1;->b:Ljava/lang/String;

    .line 563
    .line 564
    if-eqz v12, :cond_10

    .line 565
    .line 566
    iput-object v12, v3, Lps/h1;->c:Ljava/lang/String;

    .line 567
    .line 568
    invoke-static {}, Lms/f;->g()Z

    .line 569
    .line 570
    .line 571
    move-result v4

    .line 572
    iput-boolean v4, v3, Lps/h1;->d:Z

    .line 573
    .line 574
    iget-byte v4, v3, Lps/h1;->e:B

    .line 575
    .line 576
    or-int/lit8 v4, v4, 0x2

    .line 577
    .line 578
    int-to-byte v4, v4

    .line 579
    iput-byte v4, v3, Lps/h1;->e:B

    .line 580
    .line 581
    invoke-virtual {v3}, Lps/h1;->a()Lps/i1;

    .line 582
    .line 583
    .line 584
    move-result-object v3

    .line 585
    iput-object v3, v14, Lps/i0;->i:Lps/k2;

    .line 586
    .line 587
    new-instance v3, Landroid/os/StatFs;

    .line 588
    .line 589
    invoke-static {}, Landroid/os/Environment;->getDataDirectory()Ljava/io/File;

    .line 590
    .line 591
    .line 592
    move-result-object v4

    .line 593
    invoke-virtual {v4}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 594
    .line 595
    .line 596
    move-result-object v4

    .line 597
    invoke-direct {v3, v4}, Landroid/os/StatFs;-><init>(Ljava/lang/String;)V

    .line 598
    .line 599
    .line 600
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 601
    .line 602
    .line 603
    move-result v4

    .line 604
    const/4 v5, 0x7

    .line 605
    if-eqz v4, :cond_9

    .line 606
    .line 607
    goto :goto_5

    .line 608
    :cond_9
    sget-object v4, Lms/q;->f:Ljava/util/HashMap;

    .line 609
    .line 610
    invoke-virtual {v7, v13}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 611
    .line 612
    .line 613
    move-result-object v6

    .line 614
    invoke-virtual {v4, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 615
    .line 616
    .line 617
    move-result-object v4

    .line 618
    check-cast v4, Ljava/lang/Integer;

    .line 619
    .line 620
    if-nez v4, :cond_a

    .line 621
    .line 622
    goto :goto_5

    .line 623
    :cond_a
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 624
    .line 625
    .line 626
    move-result v5

    .line 627
    :goto_5
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 628
    .line 629
    .line 630
    move-result-object v4

    .line 631
    invoke-virtual {v4}, Ljava/lang/Runtime;->availableProcessors()I

    .line 632
    .line 633
    .line 634
    move-result v4

    .line 635
    iget-object v1, v1, Lms/q;->a:Landroid/content/Context;

    .line 636
    .line 637
    invoke-static {v1}, Lms/f;->a(Landroid/content/Context;)J

    .line 638
    .line 639
    .line 640
    move-result-wide v6

    .line 641
    invoke-virtual {v3}, Landroid/os/StatFs;->getBlockCount()I

    .line 642
    .line 643
    .line 644
    move-result v1

    .line 645
    int-to-long v8, v1

    .line 646
    invoke-virtual {v3}, Landroid/os/StatFs;->getBlockSize()I

    .line 647
    .line 648
    .line 649
    move-result v1

    .line 650
    int-to-long v10, v1

    .line 651
    mul-long/2addr v8, v10

    .line 652
    invoke-static {}, Lms/f;->f()Z

    .line 653
    .line 654
    .line 655
    move-result v1

    .line 656
    invoke-static {}, Lms/f;->c()I

    .line 657
    .line 658
    .line 659
    move-result v3

    .line 660
    new-instance v10, Lps/m0;

    .line 661
    .line 662
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 663
    .line 664
    .line 665
    iput v5, v10, Lps/m0;->a:I

    .line 666
    .line 667
    iget-byte v5, v10, Lps/m0;->j:B

    .line 668
    .line 669
    or-int/lit8 v5, v5, 0x1

    .line 670
    .line 671
    int-to-byte v5, v5

    .line 672
    iput-byte v5, v10, Lps/m0;->j:B

    .line 673
    .line 674
    if-eqz v17, :cond_f

    .line 675
    .line 676
    move-object/from16 v11, v17

    .line 677
    .line 678
    iput-object v11, v10, Lps/m0;->b:Ljava/lang/String;

    .line 679
    .line 680
    iput v4, v10, Lps/m0;->c:I

    .line 681
    .line 682
    or-int/lit8 v4, v5, 0x2

    .line 683
    .line 684
    int-to-byte v4, v4

    .line 685
    iput-wide v6, v10, Lps/m0;->d:J

    .line 686
    .line 687
    or-int/lit8 v4, v4, 0x4

    .line 688
    .line 689
    int-to-byte v4, v4

    .line 690
    iput-wide v8, v10, Lps/m0;->e:J

    .line 691
    .line 692
    or-int/lit8 v4, v4, 0x8

    .line 693
    .line 694
    int-to-byte v4, v4

    .line 695
    iput-boolean v1, v10, Lps/m0;->f:Z

    .line 696
    .line 697
    or-int/lit8 v1, v4, 0x10

    .line 698
    .line 699
    int-to-byte v1, v1

    .line 700
    iput v3, v10, Lps/m0;->g:I

    .line 701
    .line 702
    or-int/lit8 v1, v1, 0x20

    .line 703
    .line 704
    int-to-byte v1, v1

    .line 705
    iput-byte v1, v10, Lps/m0;->j:B

    .line 706
    .line 707
    move-object/from16 v4, v31

    .line 708
    .line 709
    if-eqz v4, :cond_e

    .line 710
    .line 711
    iput-object v4, v10, Lps/m0;->h:Ljava/lang/String;

    .line 712
    .line 713
    move-object/from16 v1, v32

    .line 714
    .line 715
    if-eqz v1, :cond_d

    .line 716
    .line 717
    iput-object v1, v10, Lps/m0;->i:Ljava/lang/String;

    .line 718
    .line 719
    invoke-virtual {v10}, Lps/m0;->a()Lps/n0;

    .line 720
    .line 721
    .line 722
    move-result-object v1

    .line 723
    iput-object v1, v14, Lps/i0;->j:Lps/v1;

    .line 724
    .line 725
    const/4 v4, 0x3

    .line 726
    iput v4, v14, Lps/i0;->l:I

    .line 727
    .line 728
    iget-byte v1, v14, Lps/i0;->m:B

    .line 729
    .line 730
    or-int/lit8 v1, v1, 0x4

    .line 731
    .line 732
    int-to-byte v1, v1

    .line 733
    iput-byte v1, v14, Lps/i0;->m:B

    .line 734
    .line 735
    invoke-virtual {v14}, Lps/i0;->a()Lps/j0;

    .line 736
    .line 737
    .line 738
    move-result-object v1

    .line 739
    iput-object v1, v2, Lps/a0;->j:Lps/m2;

    .line 740
    .line 741
    invoke-virtual {v2}, Lps/a0;->a()Lps/b0;

    .line 742
    .line 743
    .line 744
    move-result-object v1

    .line 745
    iget-object v0, v0, Lss/b;->f:Ljava/lang/Object;

    .line 746
    .line 747
    check-cast v0, Lss/a;

    .line 748
    .line 749
    iget-object v0, v0, Lss/a;->b:Lss/b;

    .line 750
    .line 751
    const-string v2, "FirebaseCrashlytics"

    .line 752
    .line 753
    iget-object v3, v1, Lps/b0;->k:Lps/m2;

    .line 754
    .line 755
    if-nez v3, :cond_b

    .line 756
    .line 757
    const-string v0, "Could not get session for report"

    .line 758
    .line 759
    const/4 v4, 0x3

    .line 760
    invoke-static {v2, v4}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 761
    .line 762
    .line 763
    move-result v1

    .line 764
    if-eqz v1, :cond_c

    .line 765
    .line 766
    const/4 v1, 0x0

    .line 767
    invoke-static {v2, v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 768
    .line 769
    .line 770
    return-void

    .line 771
    :cond_b
    move-object v4, v3

    .line 772
    check-cast v4, Lps/j0;

    .line 773
    .line 774
    iget-object v4, v4, Lps/j0;->b:Ljava/lang/String;

    .line 775
    .line 776
    :try_start_5
    sget-object v5, Lss/a;->g:Lqs/a;

    .line 777
    .line 778
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 779
    .line 780
    .line 781
    sget-object v5, Lqs/a;->a:Lbu/c;

    .line 782
    .line 783
    invoke-virtual {v5, v1}, Lbu/c;->l(Ljava/lang/Object;)Ljava/lang/String;

    .line 784
    .line 785
    .line 786
    move-result-object v1

    .line 787
    const-string v5, "report"

    .line 788
    .line 789
    invoke-virtual {v0, v4, v5}, Lss/b;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    .line 790
    .line 791
    .line 792
    move-result-object v5

    .line 793
    invoke-static {v5, v1}, Lss/a;->f(Ljava/io/File;Ljava/lang/String;)V

    .line 794
    .line 795
    .line 796
    const-string v1, "start-time"

    .line 797
    .line 798
    invoke-virtual {v0, v4, v1}, Lss/b;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    .line 799
    .line 800
    .line 801
    move-result-object v0

    .line 802
    const-string v1, ""

    .line 803
    .line 804
    check-cast v3, Lps/j0;

    .line 805
    .line 806
    iget-wide v5, v3, Lps/j0;->d:J

    .line 807
    .line 808
    new-instance v3, Ljava/io/OutputStreamWriter;

    .line 809
    .line 810
    new-instance v7, Ljava/io/FileOutputStream;

    .line 811
    .line 812
    invoke-direct {v7, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 813
    .line 814
    .line 815
    sget-object v8, Lss/a;->e:Ljava/nio/charset/Charset;

    .line 816
    .line 817
    invoke-direct {v3, v7, v8}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;Ljava/nio/charset/Charset;)V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0

    .line 818
    .line 819
    .line 820
    :try_start_6
    invoke-virtual {v3, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 821
    .line 822
    .line 823
    mul-long v5, v5, v18

    .line 824
    .line 825
    invoke-virtual {v0, v5, v6}, Ljava/io/File;->setLastModified(J)Z
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 826
    .line 827
    .line 828
    :try_start_7
    invoke-virtual {v3}, Ljava/io/OutputStreamWriter;->close()V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_0

    .line 829
    .line 830
    .line 831
    return-void

    .line 832
    :catchall_2
    move-exception v0

    .line 833
    move-object v1, v0

    .line 834
    :try_start_8
    invoke-virtual {v3}, Ljava/io/OutputStreamWriter;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 835
    .line 836
    .line 837
    goto :goto_6

    .line 838
    :catchall_3
    move-exception v0

    .line 839
    :try_start_9
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 840
    .line 841
    .line 842
    :goto_6
    throw v1
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_0

    .line 843
    :catch_0
    move-exception v0

    .line 844
    const-string v1, "Could not persist report for session "

    .line 845
    .line 846
    invoke-static {v1, v4}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 847
    .line 848
    .line 849
    move-result-object v1

    .line 850
    const/4 v4, 0x3

    .line 851
    invoke-static {v2, v4}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 852
    .line 853
    .line 854
    move-result v3

    .line 855
    if-eqz v3, :cond_c

    .line 856
    .line 857
    invoke-static {v2, v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 858
    .line 859
    .line 860
    :cond_c
    return-void

    .line 861
    :cond_d
    new-instance v0, Ljava/lang/NullPointerException;

    .line 862
    .line 863
    const-string v1, "Null modelClass"

    .line 864
    .line 865
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 866
    .line 867
    .line 868
    throw v0

    .line 869
    :cond_e
    new-instance v0, Ljava/lang/NullPointerException;

    .line 870
    .line 871
    const-string v1, "Null manufacturer"

    .line 872
    .line 873
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 874
    .line 875
    .line 876
    throw v0

    .line 877
    :cond_f
    new-instance v0, Ljava/lang/NullPointerException;

    .line 878
    .line 879
    const-string v1, "Null model"

    .line 880
    .line 881
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 882
    .line 883
    .line 884
    throw v0

    .line 885
    :cond_10
    new-instance v0, Ljava/lang/NullPointerException;

    .line 886
    .line 887
    const-string v1, "Null buildVersion"

    .line 888
    .line 889
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 890
    .line 891
    .line 892
    throw v0

    .line 893
    :cond_11
    new-instance v0, Ljava/lang/NullPointerException;

    .line 894
    .line 895
    const-string v1, "Null version"

    .line 896
    .line 897
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 898
    .line 899
    .line 900
    throw v0

    .line 901
    :cond_12
    new-instance v0, Ljava/lang/NullPointerException;

    .line 902
    .line 903
    const-string v1, "Null identifier"

    .line 904
    .line 905
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 906
    .line 907
    .line 908
    throw v0

    .line 909
    :cond_13
    new-instance v0, Ljava/lang/NullPointerException;

    .line 910
    .line 911
    const-string v1, "Null generator"

    .line 912
    .line 913
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 914
    .line 915
    .line 916
    throw v0

    .line 917
    :cond_14
    new-instance v0, Ljava/lang/NullPointerException;

    .line 918
    .line 919
    const-string v1, "Null identifier"

    .line 920
    .line 921
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 922
    .line 923
    .line 924
    throw v0

    .line 925
    :cond_15
    new-instance v0, Ljava/lang/NullPointerException;

    .line 926
    .line 927
    const-string v1, "Null displayVersion"

    .line 928
    .line 929
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 930
    .line 931
    .line 932
    throw v0

    .line 933
    :cond_16
    new-instance v0, Ljava/lang/NullPointerException;

    .line 934
    .line 935
    const-string v1, "Null buildVersion"

    .line 936
    .line 937
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 938
    .line 939
    .line 940
    throw v0

    .line 941
    :cond_17
    new-instance v0, Ljava/lang/NullPointerException;

    .line 942
    .line 943
    const-string v1, "Null installationUuid"

    .line 944
    .line 945
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 946
    .line 947
    .line 948
    throw v0

    .line 949
    :cond_18
    new-instance v0, Ljava/lang/NullPointerException;

    .line 950
    .line 951
    const-string v1, "Null gmpAppId"

    .line 952
    .line 953
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 954
    .line 955
    .line 956
    throw v0
.end method

.method public final d(Lqn/s;)Z
    .locals 5

    .line 1
    invoke-static {}, Lns/d;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lms/l;->n:Lms/r;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const-string v3, "FirebaseCrashlytics"

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, v0, Lms/r;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const-string p0, "Skipping session finalization because a crash has already occurred."

    .line 21
    .line 22
    invoke-static {v3, p0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 23
    .line 24
    .line 25
    return v2

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    invoke-static {v3, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    const-string v4, "Finalizing previously open sessions."

    .line 34
    .line 35
    invoke-static {v3, v4, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 36
    .line 37
    .line 38
    :cond_1
    const/4 v4, 0x1

    .line 39
    :try_start_0
    invoke-virtual {p0, v4, p1, v4}, Lms/l;->b(ZLqn/s;Z)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    .line 42
    invoke-static {v3, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_2

    .line 47
    .line 48
    const-string p0, "Closed all previously open sessions."

    .line 49
    .line 50
    invoke-static {v3, p0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 51
    .line 52
    .line 53
    :cond_2
    return v4

    .line 54
    :catch_0
    move-exception p0

    .line 55
    const-string p1, "Unable to finalize previously open sessions."

    .line 56
    .line 57
    invoke-static {v3, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 58
    .line 59
    .line 60
    return v2
.end method

.method public final e()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Lms/l;->m:Lss/b;

    .line 2
    .line 3
    iget-object p0, p0, Lss/b;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lss/a;

    .line 6
    .line 7
    invoke-virtual {p0}, Lss/a;->c()Ljava/util/NavigableSet;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {p0}, Ljava/util/Set;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/SortedSet;->first()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/lang/String;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return-object p0
.end method

.method public final f()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "com.google.firebase.crashlytics.version_control_info"

    .line 2
    .line 3
    const-string v1, "string"

    .line 4
    .line 5
    iget-object p0, p0, Lms/l;->a:Landroid/content/Context;

    .line 6
    .line 7
    invoke-static {p0, v0, v1}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    move-object p0, v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0, v0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    :goto_0
    const/4 v0, 0x3

    .line 25
    const/4 v2, 0x0

    .line 26
    const-string v3, "FirebaseCrashlytics"

    .line 27
    .line 28
    if-eqz p0, :cond_2

    .line 29
    .line 30
    invoke-static {v3, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    const-string v0, "Read version control info from string resource"

    .line 37
    .line 38
    invoke-static {v3, v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 39
    .line 40
    .line 41
    :cond_1
    sget-object v0, Lms/l;->s:Ljava/nio/charset/Charset;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-static {p0, v2}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :cond_2
    const-class p0, Lms/l;

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    if-nez p0, :cond_3

    .line 59
    .line 60
    const-string p0, "Couldn\'t get Class Loader"

    .line 61
    .line 62
    invoke-static {v3, p0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 63
    .line 64
    .line 65
    move-object p0, v1

    .line 66
    goto :goto_1

    .line 67
    :cond_3
    const-string v4, "META-INF/version-control-info.textproto"

    .line 68
    .line 69
    invoke-virtual {p0, v4}, Ljava/lang/ClassLoader;->getResourceAsStream(Ljava/lang/String;)Ljava/io/InputStream;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    :goto_1
    if-eqz p0, :cond_6

    .line 74
    .line 75
    :try_start_0
    const-string v4, "Read version control info from file"

    .line 76
    .line 77
    invoke-static {v3, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_4

    .line 82
    .line 83
    invoke-static {v3, v4, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 84
    .line 85
    .line 86
    :cond_4
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 87
    .line 88
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 89
    .line 90
    .line 91
    const/16 v1, 0x400

    .line 92
    .line 93
    :try_start_1
    new-array v1, v1, [B

    .line 94
    .line 95
    :goto_2
    invoke-virtual {p0, v1}, Ljava/io/InputStream;->read([B)I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    const/4 v4, -0x1

    .line 100
    if-eq v3, v4, :cond_5

    .line 101
    .line 102
    invoke-virtual {v0, v1, v2, v3}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    .line 103
    .line 104
    .line 105
    goto :goto_2

    .line 106
    :catchall_0
    move-exception v1

    .line 107
    goto :goto_3

    .line 108
    :cond_5
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 109
    .line 110
    .line 111
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 112
    :try_start_2
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->close()V

    .line 113
    .line 114
    .line 115
    invoke-static {v1, v2}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 119
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 120
    .line 121
    .line 122
    return-object v0

    .line 123
    :catchall_1
    move-exception v0

    .line 124
    goto :goto_5

    .line 125
    :goto_3
    :try_start_3
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 126
    .line 127
    .line 128
    goto :goto_4

    .line 129
    :catchall_2
    move-exception v0

    .line 130
    :try_start_4
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 131
    .line 132
    .line 133
    :goto_4
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 134
    :goto_5
    :try_start_5
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 135
    .line 136
    .line 137
    goto :goto_6

    .line 138
    :catchall_3
    move-exception p0

    .line 139
    invoke-virtual {v0, p0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 140
    .line 141
    .line 142
    :goto_6
    throw v0

    .line 143
    :cond_6
    if-eqz p0, :cond_7

    .line 144
    .line 145
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 146
    .line 147
    .line 148
    :cond_7
    const-string p0, "No version control information found"

    .line 149
    .line 150
    invoke-static {v3, p0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 151
    .line 152
    .line 153
    return-object v1
.end method

.method public final g()V
    .locals 5

    .line 1
    const-string v0, "FirebaseCrashlytics"

    .line 2
    .line 3
    :try_start_0
    invoke-virtual {p0}, Lms/l;->f()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eqz v1, :cond_3

    .line 8
    .line 9
    const-string v2, "com.crashlytics.version-control-info"
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    :try_start_1
    iget-object v4, p0, Lms/l;->d:Lss/b;

    .line 13
    .line 14
    iget-object v4, v4, Lss/b;->i:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v4, La8/b;

    .line 17
    .line 18
    invoke-virtual {v4, v2, v1}, La8/b;->r(Ljava/lang/String;Ljava/lang/String;)Z
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 19
    .line 20
    .line 21
    goto :goto_2

    .line 22
    :catch_0
    move-exception v1

    .line 23
    :try_start_2
    iget-object p0, p0, Lms/l;->a:Landroid/content/Context;

    .line 24
    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    iget p0, p0, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 32
    .line 33
    and-int/lit8 p0, p0, 0x2

    .line 34
    .line 35
    if-eqz p0, :cond_0

    .line 36
    .line 37
    const/4 p0, 0x1

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 p0, 0x0

    .line 40
    :goto_0
    if-nez p0, :cond_1

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    throw v1

    .line 44
    :cond_2
    :goto_1
    const-string p0, "Attempting to set custom attribute with null key, ignoring."

    .line 45
    .line 46
    invoke-static {v0, p0, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 47
    .line 48
    .line 49
    :goto_2
    const-string p0, "Saved version control info"

    .line 50
    .line 51
    invoke-static {v0, p0, v3}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1

    .line 52
    .line 53
    .line 54
    goto :goto_3

    .line 55
    :catch_1
    move-exception p0

    .line 56
    const-string v1, "Unable to save version control info"

    .line 57
    .line 58
    invoke-static {v0, v1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 59
    .line 60
    .line 61
    :cond_3
    :goto_3
    return-void
.end method

.method public final h(Laq/t;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lms/l;->o:Laq/k;

    .line 2
    .line 3
    const-string v1, "FirebaseCrashlytics"

    .line 4
    .line 5
    iget-object v2, p0, Lms/l;->m:Lss/b;

    .line 6
    .line 7
    iget-object v2, v2, Lss/b;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Lss/a;

    .line 10
    .line 11
    iget-object v2, v2, Lss/a;->b:Lss/b;

    .line 12
    .line 13
    iget-object v3, v2, Lss/b;->i:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, Ljava/io/File;

    .line 16
    .line 17
    invoke-virtual {v3}, Ljava/io/File;->listFiles()[Ljava/io/File;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    invoke-static {v3}, Lss/b;->m([Ljava/lang/Object;)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    const/4 v4, 0x0

    .line 30
    if-eqz v3, :cond_2

    .line 31
    .line 32
    iget-object v3, v2, Lss/b;->j:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v3, Ljava/io/File;

    .line 35
    .line 36
    invoke-virtual {v3}, Ljava/io/File;->listFiles()[Ljava/io/File;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-static {v3}, Lss/b;->m([Ljava/lang/Object;)Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_2

    .line 49
    .line 50
    iget-object v2, v2, Lss/b;->k:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v2, Ljava/io/File;

    .line 53
    .line 54
    invoke-virtual {v2}, Ljava/io/File;->listFiles()[Ljava/io/File;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-static {v2}, Lss/b;->m([Ljava/lang/Object;)Ljava/util/List;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-nez v2, :cond_0

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    const-string p0, "No crash reports are available to be sent."

    .line 70
    .line 71
    const/4 p1, 0x2

    .line 72
    invoke-static {v1, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eqz p1, :cond_1

    .line 77
    .line 78
    invoke-static {v1, p0, v4}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 79
    .line 80
    .line 81
    :cond_1
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 82
    .line 83
    invoke-virtual {v0, p0}, Laq/k;->d(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :cond_2
    :goto_0
    sget-object v2, Ljs/c;->a:Ljs/c;

    .line 88
    .line 89
    const-string v3, "Crash reports are available to be sent."

    .line 90
    .line 91
    invoke-virtual {v2, v3}, Ljs/c;->e(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iget-object v3, p0, Lms/l;->b:Lh8/o;

    .line 95
    .line 96
    invoke-virtual {v3}, Lh8/o;->a()Z

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    if-eqz v5, :cond_4

    .line 101
    .line 102
    const-string v2, "Automatic data collection is enabled. Allowing upload."

    .line 103
    .line 104
    const/4 v3, 0x3

    .line 105
    invoke-static {v1, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    if-eqz v3, :cond_3

    .line 110
    .line 111
    invoke-static {v1, v2, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 112
    .line 113
    .line 114
    :cond_3
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 115
    .line 116
    invoke-virtual {v0, v1}, Laq/k;->d(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 120
    .line 121
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    goto :goto_1

    .line 126
    :cond_4
    const-string v1, "Automatic data collection is disabled."

    .line 127
    .line 128
    invoke-virtual {v2, v1}, Ljs/c;->b(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    const-string v1, "Notifying that unsent reports are available."

    .line 132
    .line 133
    invoke-virtual {v2, v1}, Ljs/c;->e(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 137
    .line 138
    invoke-virtual {v0, v1}, Laq/k;->d(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    iget-object v0, v3, Lh8/o;->c:Ljava/lang/Object;

    .line 142
    .line 143
    monitor-enter v0

    .line 144
    :try_start_0
    iget-object v1, v3, Lh8/o;->d:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v1, Laq/k;

    .line 147
    .line 148
    iget-object v1, v1, Laq/k;->a:Laq/t;

    .line 149
    .line 150
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 151
    new-instance v0, Lst/b;

    .line 152
    .line 153
    const/16 v3, 0x9

    .line 154
    .line 155
    invoke-direct {v0, v3}, Lst/b;-><init>(I)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    sget-object v3, Laq/l;->a:Lj0/e;

    .line 162
    .line 163
    new-instance v4, Laq/t;

    .line 164
    .line 165
    invoke-direct {v4}, Laq/t;-><init>()V

    .line 166
    .line 167
    .line 168
    new-instance v5, Laq/q;

    .line 169
    .line 170
    invoke-direct {v5, v3, v0, v4}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/i;Laq/t;)V

    .line 171
    .line 172
    .line 173
    iget-object v0, v1, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 174
    .line 175
    invoke-virtual {v0, v5}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v1}, Laq/t;->s()V

    .line 179
    .line 180
    .line 181
    const-string v0, "Waiting for send/deleteUnsentReports to be called."

    .line 182
    .line 183
    invoke-virtual {v2, v0}, Ljs/c;->b(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    iget-object v0, p0, Lms/l;->p:Laq/k;

    .line 187
    .line 188
    iget-object v0, v0, Laq/k;->a:Laq/t;

    .line 189
    .line 190
    invoke-static {v4, v0}, Lns/a;->a(Laq/j;Laq/j;)Laq/t;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    :goto_1
    iget-object v1, p0, Lms/l;->e:Lns/d;

    .line 195
    .line 196
    iget-object v1, v1, Lns/d;->a:Lns/b;

    .line 197
    .line 198
    new-instance v2, Lb81/b;

    .line 199
    .line 200
    const/16 v3, 0x12

    .line 201
    .line 202
    const/4 v4, 0x0

    .line 203
    invoke-direct {v2, p0, p1, v4, v3}, Lb81/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v0, v1, v2}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 207
    .line 208
    .line 209
    return-void

    .line 210
    :catchall_0
    move-exception p0

    .line 211
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 212
    throw p0
.end method
