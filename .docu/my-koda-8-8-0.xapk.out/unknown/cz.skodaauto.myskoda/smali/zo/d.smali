.class public final Lzo/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lrb0/a;

.field public static final c:Lst/b;

.field public static final d:Lwe0/b;

.field public static final e:Lwq/f;

.field public static f:Ljava/lang/Boolean; = null

.field public static g:Ljava/lang/String; = null

.field public static h:Z = false

.field public static i:I = -0x1

.field public static j:Ljava/lang/Boolean;

.field public static final k:Ljava/lang/ThreadLocal;

.field public static final l:Ley0/b;

.field public static final m:Lpy/a;

.field public static n:Lzo/g;

.field public static o:Lzo/h;


# instance fields
.field public final a:Landroid/content/Context;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzo/d;->k:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    new-instance v0, Ley0/b;

    .line 9
    .line 10
    const/16 v1, 0xb

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ley0/b;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lzo/d;->l:Ley0/b;

    .line 16
    .line 17
    new-instance v0, Lpy/a;

    .line 18
    .line 19
    const/16 v1, 0x1b

    .line 20
    .line 21
    invoke-direct {v0, v1}, Lpy/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lzo/d;->m:Lpy/a;

    .line 25
    .line 26
    new-instance v0, Lrb0/a;

    .line 27
    .line 28
    invoke-direct {v0, v1}, Lrb0/a;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lzo/d;->b:Lrb0/a;

    .line 32
    .line 33
    new-instance v0, Lst/b;

    .line 34
    .line 35
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 36
    .line 37
    .line 38
    sput-object v0, Lzo/d;->c:Lst/b;

    .line 39
    .line 40
    new-instance v0, Lwe0/b;

    .line 41
    .line 42
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 43
    .line 44
    .line 45
    sput-object v0, Lzo/d;->d:Lwe0/b;

    .line 46
    .line 47
    new-instance v0, Lwq/f;

    .line 48
    .line 49
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 50
    .line 51
    .line 52
    sput-object v0, Lzo/d;->e:Lwq/f;

    .line 53
    .line 54
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzo/d;->a:Landroid/content/Context;

    .line 5
    .line 6
    return-void
.end method

.method public static a(Landroid/content/Context;Ljava/lang/String;)I
    .locals 6

    .line 1
    const-string v0, "DynamiteModule"

    .line 2
    .line 3
    const-string v1, "Module descriptor id \'"

    .line 4
    .line 5
    const-string v2, "com.google.android.gms.dynamite.descriptors."

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    new-instance v4, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    invoke-direct {v4, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string v2, ".ModuleDescriptor"

    .line 25
    .line 26
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {p0, v2}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string v2, "MODULE_ID"

    .line 38
    .line 39
    invoke-virtual {p0, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    const-string v4, "MODULE_VERSION"

    .line 44
    .line 45
    invoke-virtual {p0, v4}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const/4 v4, 0x0

    .line 50
    invoke-virtual {v2, v4}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    invoke-static {v5, p1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-nez v5, :cond_0

    .line 59
    .line 60
    invoke-virtual {v2, v4}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    new-instance v2, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string p0, "\' didn\'t match expected id \'"

    .line 77
    .line 78
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string p0, "\'"

    .line 85
    .line 86
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    return v3

    .line 97
    :catch_0
    move-exception p0

    .line 98
    goto :goto_0

    .line 99
    :cond_0
    invoke-virtual {p0, v4}, Ljava/lang/reflect/Field;->getInt(Ljava/lang/Object;)I

    .line 100
    .line 101
    .line 102
    move-result p0
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 103
    return p0

    .line 104
    :goto_0
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    const-string p1, "Failed to load module descriptor class: "

    .line 113
    .line 114
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    goto :goto_1

    .line 122
    :catch_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 123
    .line 124
    const-string v1, "Local module descriptor class for "

    .line 125
    .line 126
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string p1, " not found."

    .line 133
    .line 134
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 142
    .line 143
    .line 144
    :goto_1
    return v3
.end method

.method public static c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    const-string v0, "No acceptable module "

    .line 8
    .line 9
    const-string v4, "VersionPolicy returned invalid code:"

    .line 10
    .line 11
    const-string v5, "Selected remote version of "

    .line 12
    .line 13
    const-string v6, "Selected remote version of "

    .line 14
    .line 15
    const-string v7, "Considering local module "

    .line 16
    .line 17
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 18
    .line 19
    .line 20
    move-result-object v8

    .line 21
    if-eqz v8, :cond_17

    .line 22
    .line 23
    sget-object v9, Lzo/d;->k:Ljava/lang/ThreadLocal;

    .line 24
    .line 25
    invoke-virtual {v9}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v10

    .line 29
    check-cast v10, Lzo/f;

    .line 30
    .line 31
    new-instance v11, Lzo/f;

    .line 32
    .line 33
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v9, v11}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    sget-object v12, Lzo/d;->l:Ley0/b;

    .line 40
    .line 41
    invoke-virtual {v12}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v13

    .line 45
    check-cast v13, Ljava/lang/Long;

    .line 46
    .line 47
    invoke-virtual {v13}, Ljava/lang/Long;->longValue()J

    .line 48
    .line 49
    .line 50
    move-result-wide v14

    .line 51
    const-wide/16 v16, 0x0

    .line 52
    .line 53
    :try_start_0
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 54
    .line 55
    .line 56
    move-result-wide v18

    .line 57
    move-object/from16 v20, v9

    .line 58
    .line 59
    invoke-static/range {v18 .. v19}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 60
    .line 61
    .line 62
    move-result-object v9

    .line 63
    invoke-virtual {v12, v9}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    sget-object v9, Lzo/d;->m:Lpy/a;

    .line 67
    .line 68
    invoke-interface {v2, v1, v3, v9}, Lzo/c;->p(Landroid/content/Context;Ljava/lang/String;Lzo/b;)Lm8/j;

    .line 69
    .line 70
    .line 71
    move-result-object v9

    .line 72
    const-string v12, "DynamiteModule"
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_5

    .line 73
    .line 74
    move-wide/from16 v18, v14

    .line 75
    .line 76
    :try_start_1
    iget v14, v9, Lm8/j;->a:I

    .line 77
    .line 78
    iget v15, v9, Lm8/j;->b:I

    .line 79
    .line 80
    move-object/from16 v21, v0

    .line 81
    .line 82
    new-instance v0, Ljava/lang/StringBuilder;

    .line 83
    .line 84
    invoke-direct {v0, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v7, ":"

    .line 91
    .line 92
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string v7, " and remote module "

    .line 99
    .line 100
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string v7, ":"

    .line 107
    .line 108
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-static {v12, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    iget v0, v9, Lm8/j;->c:I

    .line 122
    .line 123
    if-eqz v0, :cond_14

    .line 124
    .line 125
    const/4 v7, -0x1

    .line 126
    if-ne v0, v7, :cond_0

    .line 127
    .line 128
    iget v0, v9, Lm8/j;->a:I

    .line 129
    .line 130
    if-eqz v0, :cond_14

    .line 131
    .line 132
    move v0, v7

    .line 133
    goto :goto_0

    .line 134
    :catchall_0
    move-exception v0

    .line 135
    goto/16 :goto_c

    .line 136
    .line 137
    :cond_0
    :goto_0
    const/4 v12, 0x1

    .line 138
    if-ne v0, v12, :cond_1

    .line 139
    .line 140
    iget v14, v9, Lm8/j;->b:I

    .line 141
    .line 142
    if-eqz v14, :cond_14

    .line 143
    .line 144
    :cond_1
    if-ne v0, v7, :cond_2

    .line 145
    .line 146
    const-string v0, "Selected local version of "

    .line 147
    .line 148
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    const-string v2, "DynamiteModule"

    .line 153
    .line 154
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-static {v2, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 159
    .line 160
    .line 161
    new-instance v0, Lzo/d;

    .line 162
    .line 163
    invoke-direct {v0, v8}, Lzo/d;-><init>(Landroid/content/Context;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 164
    .line 165
    .line 166
    goto/16 :goto_a

    .line 167
    .line 168
    :cond_2
    if-ne v0, v12, :cond_13

    .line 169
    .line 170
    :try_start_2
    iget v0, v9, Lm8/j;->b:I
    :try_end_2
    .catch Lzo/a; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 171
    .line 172
    :try_start_3
    const-class v4, Lzo/d;

    .line 173
    .line 174
    monitor-enter v4
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Lzo/a; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 175
    :try_start_4
    invoke-static {v1}, Lzo/d;->g(Landroid/content/Context;)Z

    .line 176
    .line 177
    .line 178
    move-result v14

    .line 179
    if-eqz v14, :cond_f

    .line 180
    .line 181
    sget-object v14, Lzo/d;->f:Ljava/lang/Boolean;

    .line 182
    .line 183
    monitor-exit v4
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 184
    if-eqz v14, :cond_e

    .line 185
    .line 186
    :try_start_5
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 187
    .line 188
    .line 189
    move-result v4

    .line 190
    const/4 v14, 0x2

    .line 191
    if-eqz v4, :cond_8

    .line 192
    .line 193
    const-string v4, "DynamiteModule"

    .line 194
    .line 195
    new-instance v5, Ljava/lang/StringBuilder;

    .line 196
    .line 197
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    const-string v6, ", version >= "

    .line 204
    .line 205
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object v5

    .line 215
    invoke-static {v4, v5}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 216
    .line 217
    .line 218
    const-class v4, Lzo/d;

    .line 219
    .line 220
    monitor-enter v4
    :try_end_5
    .catch Landroid/os/RemoteException; {:try_start_5 .. :try_end_5} :catch_1
    .catch Lzo/a; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 221
    :try_start_6
    sget-object v5, Lzo/d;->o:Lzo/h;

    .line 222
    .line 223
    monitor-exit v4
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 224
    if-eqz v5, :cond_7

    .line 225
    .line 226
    :try_start_7
    invoke-virtual/range {v20 .. v20}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v4

    .line 230
    check-cast v4, Lzo/f;

    .line 231
    .line 232
    if-eqz v4, :cond_6

    .line 233
    .line 234
    iget-object v6, v4, Lzo/f;->a:Landroid/database/Cursor;

    .line 235
    .line 236
    if-eqz v6, :cond_6

    .line 237
    .line 238
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 239
    .line 240
    .line 241
    move-result-object v6

    .line 242
    iget-object v4, v4, Lzo/f;->a:Landroid/database/Cursor;

    .line 243
    .line 244
    new-instance v15, Lyo/b;

    .line 245
    .line 246
    const/4 v12, 0x0

    .line 247
    invoke-direct {v15, v12}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 248
    .line 249
    .line 250
    const-class v12, Lzo/d;

    .line 251
    .line 252
    monitor-enter v12
    :try_end_7
    .catch Landroid/os/RemoteException; {:try_start_7 .. :try_end_7} :catch_1
    .catch Lzo/a; {:try_start_7 .. :try_end_7} :catch_0
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 253
    :try_start_8
    sget v15, Lzo/d;->i:I

    .line 254
    .line 255
    if-lt v15, v14, :cond_3

    .line 256
    .line 257
    const/4 v14, 0x1

    .line 258
    goto :goto_1

    .line 259
    :cond_3
    const/4 v14, 0x0

    .line 260
    :goto_1
    monitor-exit v12
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 261
    if-eqz v14, :cond_4

    .line 262
    .line 263
    :try_start_9
    const-string v12, "DynamiteModule"

    .line 264
    .line 265
    const-string v14, "Dynamite loader version >= 2, using loadModule2NoCrashUtils"

    .line 266
    .line 267
    invoke-static {v12, v14}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 268
    .line 269
    .line 270
    new-instance v12, Lyo/b;

    .line 271
    .line 272
    invoke-direct {v12, v6}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    new-instance v6, Lyo/b;

    .line 276
    .line 277
    invoke-direct {v6, v4}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v5, v12, v3, v0, v6}, Lzo/h;->X(Lyo/b;Ljava/lang/String;ILyo/b;)Lyo/a;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    goto :goto_2

    .line 285
    :catchall_1
    move-exception v0

    .line 286
    goto/16 :goto_6

    .line 287
    .line 288
    :catch_0
    move-exception v0

    .line 289
    goto/16 :goto_7

    .line 290
    .line 291
    :catch_1
    move-exception v0

    .line 292
    goto/16 :goto_8

    .line 293
    .line 294
    :cond_4
    const-string v12, "DynamiteModule"

    .line 295
    .line 296
    const-string v14, "Dynamite loader version < 2, falling back to loadModule2"

    .line 297
    .line 298
    invoke-static {v12, v14}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 299
    .line 300
    .line 301
    new-instance v12, Lyo/b;

    .line 302
    .line 303
    invoke-direct {v12, v6}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 304
    .line 305
    .line 306
    new-instance v6, Lyo/b;

    .line 307
    .line 308
    invoke-direct {v6, v4}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    invoke-virtual {v5, v12, v3, v0, v6}, Lzo/h;->W(Lyo/b;Ljava/lang/String;ILyo/b;)Lyo/a;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    :goto_2
    invoke-static {v0}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    check-cast v0, Landroid/content/Context;

    .line 320
    .line 321
    if-eqz v0, :cond_5

    .line 322
    .line 323
    new-instance v4, Lzo/d;

    .line 324
    .line 325
    invoke-direct {v4, v0}, Lzo/d;-><init>(Landroid/content/Context;)V

    .line 326
    .line 327
    .line 328
    :goto_3
    move-object v0, v4

    .line 329
    goto/16 :goto_a

    .line 330
    .line 331
    :cond_5
    new-instance v0, Lzo/a;

    .line 332
    .line 333
    const-string v4, "Failed to get module context"

    .line 334
    .line 335
    invoke-direct {v0, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    throw v0
    :try_end_9
    .catch Landroid/os/RemoteException; {:try_start_9 .. :try_end_9} :catch_1
    .catch Lzo/a; {:try_start_9 .. :try_end_9} :catch_0
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 339
    :catchall_2
    move-exception v0

    .line 340
    :try_start_a
    monitor-exit v12
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 341
    :try_start_b
    throw v0

    .line 342
    :cond_6
    new-instance v0, Lzo/a;

    .line 343
    .line 344
    const-string v4, "No result cursor"

    .line 345
    .line 346
    invoke-direct {v0, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    throw v0

    .line 350
    :cond_7
    new-instance v0, Lzo/a;

    .line 351
    .line 352
    const-string v4, "DynamiteLoaderV2 was not cached."

    .line 353
    .line 354
    invoke-direct {v0, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    throw v0
    :try_end_b
    .catch Landroid/os/RemoteException; {:try_start_b .. :try_end_b} :catch_1
    .catch Lzo/a; {:try_start_b .. :try_end_b} :catch_0
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 358
    :catchall_3
    move-exception v0

    .line 359
    :try_start_c
    monitor-exit v4
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_3

    .line 360
    :try_start_d
    throw v0

    .line 361
    :cond_8
    const-string v4, "DynamiteModule"

    .line 362
    .line 363
    new-instance v6, Ljava/lang/StringBuilder;

    .line 364
    .line 365
    invoke-direct {v6, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 369
    .line 370
    .line 371
    const-string v5, ", version >= "

    .line 372
    .line 373
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 374
    .line 375
    .line 376
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 377
    .line 378
    .line 379
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v5

    .line 383
    invoke-static {v4, v5}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 384
    .line 385
    .line 386
    invoke-static {v1}, Lzo/d;->h(Landroid/content/Context;)Lzo/g;

    .line 387
    .line 388
    .line 389
    move-result-object v4

    .line 390
    if-eqz v4, :cond_d

    .line 391
    .line 392
    invoke-virtual {v4}, Lbp/a;->S()Landroid/os/Parcel;

    .line 393
    .line 394
    .line 395
    move-result-object v5

    .line 396
    const/4 v6, 0x6

    .line 397
    invoke-virtual {v4, v5, v6}, Lbp/a;->b(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 398
    .line 399
    .line 400
    move-result-object v5

    .line 401
    invoke-virtual {v5}, Landroid/os/Parcel;->readInt()I

    .line 402
    .line 403
    .line 404
    move-result v6

    .line 405
    invoke-virtual {v5}, Landroid/os/Parcel;->recycle()V

    .line 406
    .line 407
    .line 408
    const/4 v5, 0x3

    .line 409
    if-lt v6, v5, :cond_a

    .line 410
    .line 411
    invoke-virtual/range {v20 .. v20}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object v5

    .line 415
    check-cast v5, Lzo/f;

    .line 416
    .line 417
    if-eqz v5, :cond_9

    .line 418
    .line 419
    new-instance v6, Lyo/b;

    .line 420
    .line 421
    invoke-direct {v6, v1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 422
    .line 423
    .line 424
    iget-object v5, v5, Lzo/f;->a:Landroid/database/Cursor;

    .line 425
    .line 426
    new-instance v12, Lyo/b;

    .line 427
    .line 428
    invoke-direct {v12, v5}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {v4, v6, v3, v0, v12}, Lzo/g;->X(Lyo/b;Ljava/lang/String;ILyo/b;)Lyo/a;

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    goto :goto_4

    .line 436
    :cond_9
    new-instance v0, Lzo/a;

    .line 437
    .line 438
    const-string v4, "No cached result cursor holder"

    .line 439
    .line 440
    invoke-direct {v0, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 441
    .line 442
    .line 443
    throw v0

    .line 444
    :cond_a
    if-ne v6, v14, :cond_b

    .line 445
    .line 446
    const-string v5, "DynamiteModule"

    .line 447
    .line 448
    const-string v6, "IDynamite loader version = 2"

    .line 449
    .line 450
    invoke-static {v5, v6}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 451
    .line 452
    .line 453
    new-instance v5, Lyo/b;

    .line 454
    .line 455
    invoke-direct {v5, v1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v4, v5, v3, v0}, Lzo/g;->Y(Lyo/b;Ljava/lang/String;I)Lyo/a;

    .line 459
    .line 460
    .line 461
    move-result-object v0

    .line 462
    goto :goto_4

    .line 463
    :cond_b
    const-string v5, "DynamiteModule"

    .line 464
    .line 465
    const-string v6, "Dynamite loader version < 2, falling back to createModuleContext"

    .line 466
    .line 467
    invoke-static {v5, v6}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 468
    .line 469
    .line 470
    new-instance v5, Lyo/b;

    .line 471
    .line 472
    invoke-direct {v5, v1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 473
    .line 474
    .line 475
    invoke-virtual {v4, v5, v3, v0}, Lzo/g;->W(Lyo/b;Ljava/lang/String;I)Lyo/a;

    .line 476
    .line 477
    .line 478
    move-result-object v0

    .line 479
    :goto_4
    invoke-static {v0}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v0

    .line 483
    if-eqz v0, :cond_c

    .line 484
    .line 485
    new-instance v4, Lzo/d;

    .line 486
    .line 487
    check-cast v0, Landroid/content/Context;

    .line 488
    .line 489
    invoke-direct {v4, v0}, Lzo/d;-><init>(Landroid/content/Context;)V

    .line 490
    .line 491
    .line 492
    goto/16 :goto_3

    .line 493
    .line 494
    :cond_c
    new-instance v0, Lzo/a;

    .line 495
    .line 496
    const-string v4, "Failed to load remote module."

    .line 497
    .line 498
    invoke-direct {v0, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 499
    .line 500
    .line 501
    throw v0

    .line 502
    :cond_d
    new-instance v0, Lzo/a;

    .line 503
    .line 504
    const-string v4, "Failed to create IDynamiteLoader."

    .line 505
    .line 506
    invoke-direct {v0, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    throw v0

    .line 510
    :cond_e
    new-instance v0, Lzo/a;

    .line 511
    .line 512
    const-string v4, "Failed to determine which loading route to use."

    .line 513
    .line 514
    invoke-direct {v0, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    throw v0
    :try_end_d
    .catch Landroid/os/RemoteException; {:try_start_d .. :try_end_d} :catch_1
    .catch Lzo/a; {:try_start_d .. :try_end_d} :catch_0
    .catchall {:try_start_d .. :try_end_d} :catchall_1

    .line 518
    :catchall_4
    move-exception v0

    .line 519
    goto :goto_5

    .line 520
    :cond_f
    :try_start_e
    new-instance v0, Lzo/a;

    .line 521
    .line 522
    const-string v5, "Remote loading disabled"

    .line 523
    .line 524
    invoke-direct {v0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 525
    .line 526
    .line 527
    throw v0

    .line 528
    :goto_5
    monitor-exit v4
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_4

    .line 529
    :try_start_f
    throw v0
    :try_end_f
    .catch Landroid/os/RemoteException; {:try_start_f .. :try_end_f} :catch_1
    .catch Lzo/a; {:try_start_f .. :try_end_f} :catch_0
    .catchall {:try_start_f .. :try_end_f} :catchall_1

    .line 530
    :goto_6
    :try_start_10
    new-instance v4, Lzo/a;

    .line 531
    .line 532
    const-string v5, "Failed to load remote module."

    .line 533
    .line 534
    invoke-direct {v4, v5, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 535
    .line 536
    .line 537
    throw v4

    .line 538
    :catch_2
    move-exception v0

    .line 539
    goto :goto_9

    .line 540
    :goto_7
    throw v0

    .line 541
    :goto_8
    new-instance v4, Lzo/a;

    .line 542
    .line 543
    const-string v5, "Failed to load remote module."

    .line 544
    .line 545
    invoke-direct {v4, v5, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 546
    .line 547
    .line 548
    throw v4
    :try_end_10
    .catch Lzo/a; {:try_start_10 .. :try_end_10} :catch_2
    .catchall {:try_start_10 .. :try_end_10} :catchall_0

    .line 549
    :goto_9
    :try_start_11
    const-string v4, "DynamiteModule"

    .line 550
    .line 551
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 552
    .line 553
    .line 554
    move-result-object v5

    .line 555
    new-instance v6, Ljava/lang/StringBuilder;

    .line 556
    .line 557
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 558
    .line 559
    .line 560
    const-string v12, "Failed to load remote module: "

    .line 561
    .line 562
    invoke-virtual {v6, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 563
    .line 564
    .line 565
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 566
    .line 567
    .line 568
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 569
    .line 570
    .line 571
    move-result-object v5

    .line 572
    invoke-static {v4, v5}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 573
    .line 574
    .line 575
    iget v4, v9, Lm8/j;->a:I

    .line 576
    .line 577
    if-eqz v4, :cond_12

    .line 578
    .line 579
    new-instance v5, Lc1/l2;

    .line 580
    .line 581
    const/16 v6, 0x9

    .line 582
    .line 583
    invoke-direct {v5, v4, v6}, Lc1/l2;-><init>(II)V

    .line 584
    .line 585
    .line 586
    invoke-interface {v2, v1, v3, v5}, Lzo/c;->p(Landroid/content/Context;Ljava/lang/String;Lzo/b;)Lm8/j;

    .line 587
    .line 588
    .line 589
    move-result-object v1

    .line 590
    iget v1, v1, Lm8/j;->c:I

    .line 591
    .line 592
    if-ne v1, v7, :cond_12

    .line 593
    .line 594
    const-string v0, "Selected local version of "

    .line 595
    .line 596
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 597
    .line 598
    .line 599
    move-result-object v1

    .line 600
    const-string v2, "DynamiteModule"

    .line 601
    .line 602
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 603
    .line 604
    .line 605
    move-result-object v0

    .line 606
    invoke-static {v2, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 607
    .line 608
    .line 609
    new-instance v0, Lzo/d;

    .line 610
    .line 611
    invoke-direct {v0, v8}, Lzo/d;-><init>(Landroid/content/Context;)V
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_0

    .line 612
    .line 613
    .line 614
    :goto_a
    cmp-long v1, v18, v16

    .line 615
    .line 616
    if-nez v1, :cond_10

    .line 617
    .line 618
    sget-object v1, Lzo/d;->l:Ley0/b;

    .line 619
    .line 620
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->remove()V

    .line 621
    .line 622
    .line 623
    goto :goto_b

    .line 624
    :cond_10
    sget-object v1, Lzo/d;->l:Ley0/b;

    .line 625
    .line 626
    invoke-virtual {v1, v13}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 627
    .line 628
    .line 629
    :goto_b
    iget-object v1, v11, Lzo/f;->a:Landroid/database/Cursor;

    .line 630
    .line 631
    if-eqz v1, :cond_11

    .line 632
    .line 633
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 634
    .line 635
    .line 636
    :cond_11
    sget-object v1, Lzo/d;->k:Ljava/lang/ThreadLocal;

    .line 637
    .line 638
    invoke-virtual {v1, v10}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 639
    .line 640
    .line 641
    return-object v0

    .line 642
    :cond_12
    :try_start_12
    new-instance v1, Lzo/a;

    .line 643
    .line 644
    const-string v2, "Remote load failed. No local fallback found."

    .line 645
    .line 646
    invoke-direct {v1, v2, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 647
    .line 648
    .line 649
    throw v1

    .line 650
    :cond_13
    new-instance v1, Lzo/a;

    .line 651
    .line 652
    new-instance v2, Ljava/lang/StringBuilder;

    .line 653
    .line 654
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 655
    .line 656
    .line 657
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 658
    .line 659
    .line 660
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 661
    .line 662
    .line 663
    move-result-object v0

    .line 664
    invoke-direct {v1, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 665
    .line 666
    .line 667
    throw v1

    .line 668
    :cond_14
    new-instance v0, Lzo/a;

    .line 669
    .line 670
    iget v1, v9, Lm8/j;->a:I

    .line 671
    .line 672
    iget v2, v9, Lm8/j;->b:I

    .line 673
    .line 674
    new-instance v4, Ljava/lang/StringBuilder;

    .line 675
    .line 676
    move-object/from16 v5, v21

    .line 677
    .line 678
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 679
    .line 680
    .line 681
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 682
    .line 683
    .line 684
    const-string v3, " found. Local version is "

    .line 685
    .line 686
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 687
    .line 688
    .line 689
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 690
    .line 691
    .line 692
    const-string v1, " and remote version is "

    .line 693
    .line 694
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 695
    .line 696
    .line 697
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 698
    .line 699
    .line 700
    const-string v1, "."

    .line 701
    .line 702
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 703
    .line 704
    .line 705
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 706
    .line 707
    .line 708
    move-result-object v1

    .line 709
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 710
    .line 711
    .line 712
    throw v0
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_0

    .line 713
    :catchall_5
    move-exception v0

    .line 714
    move-wide/from16 v18, v14

    .line 715
    .line 716
    :goto_c
    cmp-long v1, v18, v16

    .line 717
    .line 718
    if-nez v1, :cond_15

    .line 719
    .line 720
    sget-object v1, Lzo/d;->l:Ley0/b;

    .line 721
    .line 722
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->remove()V

    .line 723
    .line 724
    .line 725
    goto :goto_d

    .line 726
    :cond_15
    sget-object v1, Lzo/d;->l:Ley0/b;

    .line 727
    .line 728
    invoke-virtual {v1, v13}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 729
    .line 730
    .line 731
    :goto_d
    iget-object v1, v11, Lzo/f;->a:Landroid/database/Cursor;

    .line 732
    .line 733
    if-eqz v1, :cond_16

    .line 734
    .line 735
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 736
    .line 737
    .line 738
    :cond_16
    sget-object v1, Lzo/d;->k:Ljava/lang/ThreadLocal;

    .line 739
    .line 740
    invoke-virtual {v1, v10}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 741
    .line 742
    .line 743
    throw v0

    .line 744
    :cond_17
    new-instance v0, Lzo/a;

    .line 745
    .line 746
    const-string v1, "null application Context"

    .line 747
    .line 748
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 749
    .line 750
    .line 751
    throw v0
.end method

.method public static d(Landroid/content/Context;Ljava/lang/String;Z)I
    .locals 11

    .line 1
    :try_start_0
    const-class v1, Lzo/d;

    .line 2
    .line 3
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 4
    :try_start_1
    sget-object v0, Lzo/d;->f:Ljava/lang/Boolean;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    if-nez v0, :cond_8

    .line 10
    .line 11
    :try_start_2
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-class v5, Lcom/google/android/gms/dynamite/DynamiteModule$DynamiteLoaderClassLoader;

    .line 20
    .line 21
    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v5

    .line 25
    invoke-virtual {v0, v5}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v5, "sClassLoader"

    .line 30
    .line 31
    invoke-virtual {v0, v5}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getDeclaringClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    monitor-enter v5
    :try_end_2
    .catch Ljava/lang/ClassNotFoundException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/IllegalAccessException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/NoSuchFieldException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 40
    :try_start_3
    invoke-virtual {v0, v3}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    check-cast v6, Ljava/lang/ClassLoader;

    .line 45
    .line 46
    invoke-static {}, Ljava/lang/ClassLoader;->getSystemClassLoader()Ljava/lang/ClassLoader;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    if-ne v6, v7, :cond_0

    .line 51
    .line 52
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 53
    .line 54
    goto/16 :goto_3

    .line 55
    .line 56
    :catchall_0
    move-exception v0

    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_0
    if-eqz v6, :cond_1

    .line 60
    .line 61
    :try_start_4
    invoke-static {v6}, Lzo/d;->f(Ljava/lang/ClassLoader;)V
    :try_end_4
    .catch Lzo/a; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 62
    .line 63
    .line 64
    :catch_0
    :try_start_5
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_1
    invoke-static {p0}, Lzo/d;->g(Landroid/content/Context;)Z

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    if-nez v6, :cond_2

    .line 72
    .line 73
    monitor-exit v5
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 74
    :try_start_6
    monitor-exit v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 75
    return v4

    .line 76
    :catchall_1
    move-exception v0

    .line 77
    move-object p1, v0

    .line 78
    goto/16 :goto_11

    .line 79
    .line 80
    :cond_2
    :try_start_7
    sget-boolean v6, Lzo/d;->h:Z

    .line 81
    .line 82
    if-nez v6, :cond_7

    .line 83
    .line 84
    sget-object v6, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 85
    .line 86
    invoke-virtual {v6, v3}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v7
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 90
    if-eqz v7, :cond_3

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    :try_start_8
    invoke-static {p0, p1, p2, v2}, Lzo/d;->e(Landroid/content/Context;Ljava/lang/String;ZZ)I

    .line 94
    .line 95
    .line 96
    move-result v7

    .line 97
    sget-object v8, Lzo/d;->g:Ljava/lang/String;

    .line 98
    .line 99
    if-eqz v8, :cond_6

    .line 100
    .line 101
    invoke-virtual {v8}, Ljava/lang/String;->isEmpty()Z

    .line 102
    .line 103
    .line 104
    move-result v8

    .line 105
    if-eqz v8, :cond_4

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_4
    invoke-static {}, Lzo/e;->d()Ljava/lang/ClassLoader;

    .line 109
    .line 110
    .line 111
    move-result-object v8

    .line 112
    if-eqz v8, :cond_5

    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_5
    new-instance v8, Ldalvik/system/DelegateLastClassLoader;

    .line 116
    .line 117
    sget-object v9, Lzo/d;->g:Ljava/lang/String;

    .line 118
    .line 119
    invoke-static {v9}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    invoke-static {}, Ljava/lang/ClassLoader;->getSystemClassLoader()Ljava/lang/ClassLoader;

    .line 123
    .line 124
    .line 125
    move-result-object v10

    .line 126
    invoke-direct {v8, v9, v10}, Ldalvik/system/DelegateLastClassLoader;-><init>(Ljava/lang/String;Ljava/lang/ClassLoader;)V

    .line 127
    .line 128
    .line 129
    :goto_0
    invoke-static {v8}, Lzo/d;->f(Ljava/lang/ClassLoader;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, v3, v8}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    sput-object v6, Lzo/d;->f:Ljava/lang/Boolean;
    :try_end_8
    .catch Lzo/a; {:try_start_8 .. :try_end_8} :catch_1
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 136
    .line 137
    :try_start_9
    monitor-exit v5
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 138
    :try_start_a
    monitor-exit v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    .line 139
    return v7

    .line 140
    :cond_6
    :goto_1
    :try_start_b
    monitor-exit v5
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 141
    :try_start_c
    monitor-exit v1
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_1

    .line 142
    return v7

    .line 143
    :catch_1
    :try_start_d
    invoke-static {}, Ljava/lang/ClassLoader;->getSystemClassLoader()Ljava/lang/ClassLoader;

    .line 144
    .line 145
    .line 146
    move-result-object v6

    .line 147
    invoke-virtual {v0, v3, v6}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_7
    :goto_2
    invoke-static {}, Ljava/lang/ClassLoader;->getSystemClassLoader()Ljava/lang/ClassLoader;

    .line 154
    .line 155
    .line 156
    move-result-object v6

    .line 157
    invoke-virtual {v0, v3, v6}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 161
    .line 162
    :goto_3
    monitor-exit v5

    .line 163
    goto :goto_5

    .line 164
    :goto_4
    monitor-exit v5
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_0

    .line 165
    :try_start_e
    throw v0
    :try_end_e
    .catch Ljava/lang/ClassNotFoundException; {:try_start_e .. :try_end_e} :catch_2
    .catch Ljava/lang/IllegalAccessException; {:try_start_e .. :try_end_e} :catch_2
    .catch Ljava/lang/NoSuchFieldException; {:try_start_e .. :try_end_e} :catch_2
    .catchall {:try_start_e .. :try_end_e} :catchall_1

    .line 166
    :catch_2
    move-exception v0

    .line 167
    :try_start_f
    const-string v5, "DynamiteModule"

    .line 168
    .line 169
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    new-instance v6, Ljava/lang/StringBuilder;

    .line 174
    .line 175
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 176
    .line 177
    .line 178
    const-string v7, "Failed to load module via V2: "

    .line 179
    .line 180
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-static {v5, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 191
    .line 192
    .line 193
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 194
    .line 195
    :goto_5
    sput-object v0, Lzo/d;->f:Ljava/lang/Boolean;

    .line 196
    .line 197
    :cond_8
    monitor-exit v1
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_1

    .line 198
    :try_start_10
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 199
    .line 200
    .line 201
    move-result v0
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_2

    .line 202
    if-eqz v0, :cond_9

    .line 203
    .line 204
    :try_start_11
    invoke-static {p0, p1, p2, v4}, Lzo/d;->e(Landroid/content/Context;Ljava/lang/String;ZZ)I

    .line 205
    .line 206
    .line 207
    move-result p0
    :try_end_11
    .catch Lzo/a; {:try_start_11 .. :try_end_11} :catch_3
    .catchall {:try_start_11 .. :try_end_11} :catchall_2

    .line 208
    return p0

    .line 209
    :catchall_2
    move-exception v0

    .line 210
    move-object p1, v0

    .line 211
    goto/16 :goto_12

    .line 212
    .line 213
    :catch_3
    move-exception v0

    .line 214
    move-object p1, v0

    .line 215
    :try_start_12
    const-string p2, "DynamiteModule"

    .line 216
    .line 217
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p1

    .line 221
    new-instance v0, Ljava/lang/StringBuilder;

    .line 222
    .line 223
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 224
    .line 225
    .line 226
    const-string v1, "Failed to retrieve remote module version: "

    .line 227
    .line 228
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 232
    .line 233
    .line 234
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    invoke-static {p2, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 239
    .line 240
    .line 241
    return v4

    .line 242
    :cond_9
    invoke-static {p0}, Lzo/d;->h(Landroid/content/Context;)Lzo/g;

    .line 243
    .line 244
    .line 245
    move-result-object v5
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_2

    .line 246
    if-nez v5, :cond_a

    .line 247
    .line 248
    goto/16 :goto_f

    .line 249
    .line 250
    :cond_a
    :try_start_13
    invoke-virtual {v5}, Lbp/a;->S()Landroid/os/Parcel;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    const/4 v1, 0x6

    .line 255
    invoke-virtual {v5, v0, v1}, Lbp/a;->b(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 260
    .line 261
    .line 262
    move-result v1

    .line 263
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 264
    .line 265
    .line 266
    const/4 v0, 0x3

    .line 267
    if-lt v1, v0, :cond_11

    .line 268
    .line 269
    sget-object v0, Lzo/d;->k:Ljava/lang/ThreadLocal;

    .line 270
    .line 271
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    check-cast v1, Lzo/f;

    .line 276
    .line 277
    if-eqz v1, :cond_b

    .line 278
    .line 279
    iget-object v1, v1, Lzo/f;->a:Landroid/database/Cursor;

    .line 280
    .line 281
    if-eqz v1, :cond_b

    .line 282
    .line 283
    invoke-interface {v1, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 284
    .line 285
    .line 286
    move-result v4

    .line 287
    goto/16 :goto_f

    .line 288
    .line 289
    :catch_4
    move-exception v0

    .line 290
    move-object p1, v0

    .line 291
    goto/16 :goto_d

    .line 292
    .line 293
    :cond_b
    new-instance v6, Lyo/b;

    .line 294
    .line 295
    invoke-direct {v6, p0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    sget-object v1, Lzo/d;->l:Ley0/b;

    .line 299
    .line 300
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v1

    .line 304
    check-cast v1, Ljava/lang/Long;

    .line 305
    .line 306
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 307
    .line 308
    .line 309
    move-result-wide v9

    .line 310
    move-object v7, p1

    .line 311
    move v8, p2

    .line 312
    invoke-virtual/range {v5 .. v10}, Lzo/g;->Z(Lyo/b;Ljava/lang/String;ZJ)Lyo/a;

    .line 313
    .line 314
    .line 315
    move-result-object p1

    .line 316
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object p1

    .line 320
    check-cast p1, Landroid/database/Cursor;
    :try_end_13
    .catch Landroid/os/RemoteException; {:try_start_13 .. :try_end_13} :catch_4
    .catchall {:try_start_13 .. :try_end_13} :catchall_4

    .line 321
    .line 322
    if-eqz p1, :cond_10

    .line 323
    .line 324
    :try_start_14
    invoke-interface {p1}, Landroid/database/Cursor;->moveToFirst()Z

    .line 325
    .line 326
    .line 327
    move-result p2

    .line 328
    if-nez p2, :cond_c

    .line 329
    .line 330
    goto :goto_9

    .line 331
    :cond_c
    invoke-interface {p1, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 332
    .line 333
    .line 334
    move-result p2

    .line 335
    if-lez p2, :cond_e

    .line 336
    .line 337
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    check-cast v0, Lzo/f;

    .line 342
    .line 343
    if-eqz v0, :cond_d

    .line 344
    .line 345
    iget-object v1, v0, Lzo/f;->a:Landroid/database/Cursor;

    .line 346
    .line 347
    if-nez v1, :cond_d

    .line 348
    .line 349
    iput-object p1, v0, Lzo/f;->a:Landroid/database/Cursor;
    :try_end_14
    .catch Landroid/os/RemoteException; {:try_start_14 .. :try_end_14} :catch_5
    .catchall {:try_start_14 .. :try_end_14} :catchall_3

    .line 350
    .line 351
    goto :goto_6

    .line 352
    :cond_d
    move v2, v4

    .line 353
    :goto_6
    if-eqz v2, :cond_e

    .line 354
    .line 355
    goto :goto_7

    .line 356
    :cond_e
    move-object v3, p1

    .line 357
    :goto_7
    if-eqz v3, :cond_f

    .line 358
    .line 359
    :try_start_15
    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    :try_end_15
    .catchall {:try_start_15 .. :try_end_15} :catchall_2

    .line 360
    .line 361
    .line 362
    :cond_f
    :goto_8
    move v4, p2

    .line 363
    goto/16 :goto_f

    .line 364
    .line 365
    :catchall_3
    move-exception v0

    .line 366
    move-object p2, v0

    .line 367
    goto :goto_a

    .line 368
    :catch_5
    move-exception v0

    .line 369
    move-object p2, v0

    .line 370
    goto :goto_b

    .line 371
    :cond_10
    :goto_9
    :try_start_16
    const-string p2, "DynamiteModule"

    .line 372
    .line 373
    const-string v0, "Failed to retrieve remote module version."

    .line 374
    .line 375
    invoke-static {p2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_16
    .catch Landroid/os/RemoteException; {:try_start_16 .. :try_end_16} :catch_5
    .catchall {:try_start_16 .. :try_end_16} :catchall_3

    .line 376
    .line 377
    .line 378
    if-eqz p1, :cond_13

    .line 379
    .line 380
    :try_start_17
    invoke-interface {p1}, Landroid/database/Cursor;->close()V
    :try_end_17
    .catchall {:try_start_17 .. :try_end_17} :catchall_2

    .line 381
    .line 382
    .line 383
    goto/16 :goto_f

    .line 384
    .line 385
    :goto_a
    move-object v3, p1

    .line 386
    goto/16 :goto_10

    .line 387
    .line 388
    :goto_b
    move-object v3, p1

    .line 389
    goto :goto_e

    .line 390
    :cond_11
    move-object v7, p1

    .line 391
    move v8, p2

    .line 392
    const/4 p1, 0x2

    .line 393
    if-ne v1, p1, :cond_12

    .line 394
    .line 395
    :try_start_18
    const-string p1, "DynamiteModule"

    .line 396
    .line 397
    const-string p2, "IDynamite loader version = 2, no high precision latency measurement."

    .line 398
    .line 399
    invoke-static {p1, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 400
    .line 401
    .line 402
    new-instance p1, Lyo/b;

    .line 403
    .line 404
    invoke-direct {p1, p0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 405
    .line 406
    .line 407
    invoke-virtual {v5}, Lbp/a;->S()Landroid/os/Parcel;

    .line 408
    .line 409
    .line 410
    move-result-object p2

    .line 411
    invoke-static {p2, p1}, Lep/a;->c(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {p2, v7}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    invoke-virtual {p2, v8}, Landroid/os/Parcel;->writeInt(I)V

    .line 418
    .line 419
    .line 420
    const/4 p1, 0x5

    .line 421
    invoke-virtual {v5, p2, p1}, Lbp/a;->b(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 422
    .line 423
    .line 424
    move-result-object p1

    .line 425
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 426
    .line 427
    .line 428
    move-result p2

    .line 429
    invoke-virtual {p1}, Landroid/os/Parcel;->recycle()V

    .line 430
    .line 431
    .line 432
    goto :goto_8

    .line 433
    :cond_12
    const-string p1, "DynamiteModule"

    .line 434
    .line 435
    const-string p2, "IDynamite loader version < 2, falling back to getModuleVersion2"

    .line 436
    .line 437
    invoke-static {p1, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 438
    .line 439
    .line 440
    new-instance p1, Lyo/b;

    .line 441
    .line 442
    invoke-direct {p1, p0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 443
    .line 444
    .line 445
    invoke-virtual {v5}, Lbp/a;->S()Landroid/os/Parcel;

    .line 446
    .line 447
    .line 448
    move-result-object p2

    .line 449
    invoke-static {p2, p1}, Lep/a;->c(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 450
    .line 451
    .line 452
    invoke-virtual {p2, v7}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {p2, v8}, Landroid/os/Parcel;->writeInt(I)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v5, p2, v0}, Lbp/a;->b(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 459
    .line 460
    .line 461
    move-result-object p1

    .line 462
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 463
    .line 464
    .line 465
    move-result p2

    .line 466
    invoke-virtual {p1}, Landroid/os/Parcel;->recycle()V
    :try_end_18
    .catch Landroid/os/RemoteException; {:try_start_18 .. :try_end_18} :catch_4
    .catchall {:try_start_18 .. :try_end_18} :catchall_4

    .line 467
    .line 468
    .line 469
    goto :goto_8

    .line 470
    :goto_c
    move-object p2, p1

    .line 471
    goto :goto_10

    .line 472
    :goto_d
    move-object p2, p1

    .line 473
    :goto_e
    :try_start_19
    const-string p1, "DynamiteModule"

    .line 474
    .line 475
    invoke-virtual {p2}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 476
    .line 477
    .line 478
    move-result-object p2

    .line 479
    new-instance v0, Ljava/lang/StringBuilder;

    .line 480
    .line 481
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 482
    .line 483
    .line 484
    const-string v1, "Failed to retrieve remote module version: "

    .line 485
    .line 486
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 487
    .line 488
    .line 489
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 490
    .line 491
    .line 492
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object p2

    .line 496
    invoke-static {p1, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_19
    .catchall {:try_start_19 .. :try_end_19} :catchall_4

    .line 497
    .line 498
    .line 499
    if-eqz v3, :cond_13

    .line 500
    .line 501
    :try_start_1a
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 502
    .line 503
    .line 504
    :cond_13
    :goto_f
    return v4

    .line 505
    :catchall_4
    move-exception v0

    .line 506
    move-object p1, v0

    .line 507
    goto :goto_c

    .line 508
    :goto_10
    if-eqz v3, :cond_14

    .line 509
    .line 510
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 511
    .line 512
    .line 513
    :cond_14
    throw p2
    :try_end_1a
    .catchall {:try_start_1a .. :try_end_1a} :catchall_2

    .line 514
    :goto_11
    :try_start_1b
    monitor-exit v1
    :try_end_1b
    .catchall {:try_start_1b .. :try_end_1b} :catchall_1

    .line 515
    :try_start_1c
    throw p1
    :try_end_1c
    .catchall {:try_start_1c .. :try_end_1c} :catchall_2

    .line 516
    :goto_12
    :try_start_1d
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V
    :try_end_1d
    .catch Ljava/lang/Exception; {:try_start_1d .. :try_end_1d} :catch_6

    .line 517
    .line 518
    .line 519
    goto :goto_13

    .line 520
    :catch_6
    move-exception v0

    .line 521
    move-object p0, v0

    .line 522
    const-string p2, "CrashUtils"

    .line 523
    .line 524
    const-string v0, "Error adding exception to DropBox!"

    .line 525
    .line 526
    invoke-static {p2, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 527
    .line 528
    .line 529
    :goto_13
    throw p1
.end method

.method public static e(Landroid/content/Context;Ljava/lang/String;ZZ)I
    .locals 12

    .line 1
    const/4 v1, 0x0

    .line 2
    :try_start_0
    sget-object v0, Lzo/d;->l:Ley0/b;

    .line 3
    .line 4
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Ljava/lang/Long;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    const-string v0, "api_force_staging"

    .line 15
    .line 16
    const-string v4, "api"

    .line 17
    .line 18
    const/4 v5, 0x1

    .line 19
    if-eq v5, p2, :cond_0

    .line 20
    .line 21
    move-object v0, v4

    .line 22
    :cond_0
    new-instance p2, Landroid/net/Uri$Builder;

    .line 23
    .line 24
    invoke-direct {p2}, Landroid/net/Uri$Builder;-><init>()V

    .line 25
    .line 26
    .line 27
    const-string v4, "content"

    .line 28
    .line 29
    invoke-virtual {p2, v4}, Landroid/net/Uri$Builder;->scheme(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    const-string v4, "com.google.android.gms.chimera"

    .line 34
    .line 35
    invoke-virtual {p2, v4}, Landroid/net/Uri$Builder;->authority(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    invoke-virtual {p2, v0}, Landroid/net/Uri$Builder;->path(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-virtual {p2, p1}, Landroid/net/Uri$Builder;->appendPath(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    const-string p2, "requestStartUptime"

    .line 48
    .line 49
    invoke-static {v2, v3}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-virtual {p1, p2, v0}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-virtual {p1}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {p0, v7}, Landroid/content/ContentResolver;->acquireUnstableContentProviderClient(Landroid/net/Uri;)Landroid/content/ContentProviderClient;

    .line 66
    .line 67
    .line 68
    move-result-object v6
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_5

    .line 69
    const/4 p0, 0x2

    .line 70
    const/4 p1, 0x0

    .line 71
    if-nez v6, :cond_1

    .line 72
    .line 73
    :goto_0
    move-object v3, v1

    .line 74
    goto/16 :goto_7

    .line 75
    .line 76
    :cond_1
    const/4 v10, 0x0

    .line 77
    const/4 v11, 0x0

    .line 78
    const/4 v8, 0x0

    .line 79
    const/4 v9, 0x0

    .line 80
    :try_start_1
    invoke-virtual/range {v6 .. v11}, Landroid/content/ContentProviderClient;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 81
    .line 82
    .line 83
    move-result-object p2
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 84
    if-nez p2, :cond_2

    .line 85
    .line 86
    :catch_0
    :try_start_2
    invoke-virtual {v6}, Landroid/content/ContentProviderClient;->release()Z
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_2
    :try_start_3
    invoke-interface {p2}, Landroid/database/Cursor;->getCount()I

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    invoke-interface {p2}, Landroid/database/Cursor;->getColumnCount()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    new-instance v3, Landroid/database/MatrixCursor;

    .line 99
    .line 100
    invoke-interface {p2}, Landroid/database/Cursor;->getColumnNames()[Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    invoke-direct {v3, v4, v0}, Landroid/database/MatrixCursor;-><init>([Ljava/lang/String;I)V

    .line 105
    .line 106
    .line 107
    move v4, p1

    .line 108
    :goto_1
    if-ge v4, v0, :cond_a

    .line 109
    .line 110
    invoke-interface {p2, v4}, Landroid/database/Cursor;->moveToPosition(I)Z

    .line 111
    .line 112
    .line 113
    move-result v7

    .line 114
    if-eqz v7, :cond_9

    .line 115
    .line 116
    new-array v7, v2, [Ljava/lang/Object;

    .line 117
    .line 118
    move v8, p1

    .line 119
    :goto_2
    if-ge v8, v2, :cond_8

    .line 120
    .line 121
    invoke-interface {p2, v8}, Landroid/database/Cursor;->getType(I)I

    .line 122
    .line 123
    .line 124
    move-result v9

    .line 125
    if-eqz v9, :cond_7

    .line 126
    .line 127
    if-eq v9, v5, :cond_6

    .line 128
    .line 129
    if-eq v9, p0, :cond_5

    .line 130
    .line 131
    const/4 v10, 0x3

    .line 132
    if-eq v9, v10, :cond_4

    .line 133
    .line 134
    const/4 v10, 0x4

    .line 135
    if-ne v9, v10, :cond_3

    .line 136
    .line 137
    invoke-interface {p2, v8}, Landroid/database/Cursor;->getBlob(I)[B

    .line 138
    .line 139
    .line 140
    move-result-object v9

    .line 141
    aput-object v9, v7, v8

    .line 142
    .line 143
    goto :goto_3

    .line 144
    :catchall_0
    move-exception v0

    .line 145
    move-object v2, v0

    .line 146
    goto :goto_4

    .line 147
    :cond_3
    new-instance v0, Landroid/os/RemoteException;

    .line 148
    .line 149
    const-string v2, "Unknown column type"

    .line 150
    .line 151
    invoke-direct {v0, v2}, Landroid/os/RemoteException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw v0

    .line 155
    :cond_4
    invoke-interface {p2, v8}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v9

    .line 159
    aput-object v9, v7, v8

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_5
    invoke-interface {p2, v8}, Landroid/database/Cursor;->getDouble(I)D

    .line 163
    .line 164
    .line 165
    move-result-wide v9

    .line 166
    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 167
    .line 168
    .line 169
    move-result-object v9

    .line 170
    aput-object v9, v7, v8

    .line 171
    .line 172
    goto :goto_3

    .line 173
    :cond_6
    invoke-interface {p2, v8}, Landroid/database/Cursor;->getLong(I)J

    .line 174
    .line 175
    .line 176
    move-result-wide v9

    .line 177
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 178
    .line 179
    .line 180
    move-result-object v9

    .line 181
    aput-object v9, v7, v8

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_7
    aput-object v1, v7, v8

    .line 185
    .line 186
    :goto_3
    add-int/lit8 v8, v8, 0x1

    .line 187
    .line 188
    goto :goto_2

    .line 189
    :cond_8
    invoke-virtual {v3, v7}, Landroid/database/MatrixCursor;->addRow([Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    add-int/lit8 v4, v4, 0x1

    .line 193
    .line 194
    goto :goto_1

    .line 195
    :cond_9
    new-instance v0, Landroid/os/RemoteException;

    .line 196
    .line 197
    const-string v2, "Cursor read incomplete (ContentProvider dead?)"

    .line 198
    .line 199
    invoke-direct {v0, v2}, Landroid/os/RemoteException;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 203
    :cond_a
    :try_start_4
    invoke-interface {p2}, Landroid/database/Cursor;->close()V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 204
    .line 205
    .line 206
    :try_start_5
    invoke-virtual {v6}, Landroid/content/ContentProviderClient;->release()Z
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_2
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 207
    .line 208
    .line 209
    goto :goto_7

    .line 210
    :catchall_1
    move-exception v0

    .line 211
    move-object p0, v0

    .line 212
    goto :goto_6

    .line 213
    :goto_4
    :try_start_6
    invoke-interface {p2}, Landroid/database/Cursor;->close()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 214
    .line 215
    .line 216
    goto :goto_5

    .line 217
    :catchall_2
    move-exception v0

    .line 218
    move-object p2, v0

    .line 219
    :try_start_7
    invoke-virtual {v2, p2}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 220
    .line 221
    .line 222
    :goto_5
    throw v2
    :try_end_7
    .catch Landroid/os/RemoteException; {:try_start_7 .. :try_end_7} :catch_0
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 223
    :goto_6
    :try_start_8
    invoke-virtual {v6}, Landroid/content/ContentProviderClient;->release()Z

    .line 224
    .line 225
    .line 226
    throw p0
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_2
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 227
    :goto_7
    if-eqz v3, :cond_13

    .line 228
    .line 229
    :try_start_9
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 230
    .line 231
    .line 232
    move-result p2

    .line 233
    if-eqz p2, :cond_13

    .line 234
    .line 235
    invoke-interface {v3, p1}, Landroid/database/Cursor;->getInt(I)I

    .line 236
    .line 237
    .line 238
    move-result p2

    .line 239
    if-lez p2, :cond_f

    .line 240
    .line 241
    const-class v2, Lzo/d;

    .line 242
    .line 243
    monitor-enter v2
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_1
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 244
    :try_start_a
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    sput-object p0, Lzo/d;->g:Ljava/lang/String;

    .line 249
    .line 250
    const-string p0, "loaderVersion"

    .line 251
    .line 252
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 253
    .line 254
    .line 255
    move-result p0

    .line 256
    if-ltz p0, :cond_b

    .line 257
    .line 258
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getInt(I)I

    .line 259
    .line 260
    .line 261
    move-result p0

    .line 262
    sput p0, Lzo/d;->i:I

    .line 263
    .line 264
    goto :goto_8

    .line 265
    :catchall_3
    move-exception v0

    .line 266
    move-object p0, v0

    .line 267
    goto :goto_c

    .line 268
    :cond_b
    :goto_8
    const-string p0, "disableStandaloneDynamiteLoader2"

    .line 269
    .line 270
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 271
    .line 272
    .line 273
    move-result p0

    .line 274
    if-ltz p0, :cond_d

    .line 275
    .line 276
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getInt(I)I

    .line 277
    .line 278
    .line 279
    move-result p0

    .line 280
    if-eqz p0, :cond_c

    .line 281
    .line 282
    move p0, v5

    .line 283
    goto :goto_9

    .line 284
    :cond_c
    move p0, p1

    .line 285
    :goto_9
    sput-boolean p0, Lzo/d;->h:Z

    .line 286
    .line 287
    goto :goto_a

    .line 288
    :cond_d
    move p0, p1

    .line 289
    :goto_a
    monitor-exit v2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 290
    :try_start_b
    sget-object v0, Lzo/d;->k:Ljava/lang/ThreadLocal;

    .line 291
    .line 292
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v0

    .line 296
    check-cast v0, Lzo/f;

    .line 297
    .line 298
    if-eqz v0, :cond_e

    .line 299
    .line 300
    iget-object v2, v0, Lzo/f;->a:Landroid/database/Cursor;

    .line 301
    .line 302
    if-nez v2, :cond_e

    .line 303
    .line 304
    iput-object v3, v0, Lzo/f;->a:Landroid/database/Cursor;
    :try_end_b
    .catch Ljava/lang/Exception; {:try_start_b .. :try_end_b} :catch_1
    .catchall {:try_start_b .. :try_end_b} :catchall_4

    .line 305
    .line 306
    goto :goto_b

    .line 307
    :cond_e
    move v5, p1

    .line 308
    :goto_b
    move p1, p0

    .line 309
    if-eqz v5, :cond_f

    .line 310
    .line 311
    goto :goto_d

    .line 312
    :cond_f
    move-object v1, v3

    .line 313
    goto :goto_d

    .line 314
    :goto_c
    :try_start_c
    monitor-exit v2
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_3

    .line 315
    :try_start_d
    throw p0
    :try_end_d
    .catch Ljava/lang/Exception; {:try_start_d .. :try_end_d} :catch_1
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 316
    :catchall_4
    move-exception v0

    .line 317
    move-object p0, v0

    .line 318
    goto :goto_f

    .line 319
    :catch_1
    move-exception v0

    .line 320
    move-object p0, v0

    .line 321
    goto :goto_10

    .line 322
    :goto_d
    if-eqz p3, :cond_11

    .line 323
    .line 324
    if-nez p1, :cond_10

    .line 325
    .line 326
    goto :goto_e

    .line 327
    :cond_10
    :try_start_e
    new-instance p0, Lzo/a;

    .line 328
    .line 329
    const-string p1, "forcing fallback to container DynamiteLoader impl"

    .line 330
    .line 331
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 332
    .line 333
    .line 334
    throw p0
    :try_end_e
    .catch Ljava/lang/Exception; {:try_start_e .. :try_end_e} :catch_2
    .catchall {:try_start_e .. :try_end_e} :catchall_5

    .line 335
    :catchall_5
    move-exception v0

    .line 336
    move-object p0, v0

    .line 337
    goto :goto_12

    .line 338
    :catch_2
    move-exception v0

    .line 339
    move-object p0, v0

    .line 340
    goto :goto_11

    .line 341
    :cond_11
    :goto_e
    if-eqz v1, :cond_12

    .line 342
    .line 343
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 344
    .line 345
    .line 346
    :cond_12
    return p2

    .line 347
    :cond_13
    :try_start_f
    const-string p0, "DynamiteModule"

    .line 348
    .line 349
    const-string p1, "Failed to retrieve remote module version."

    .line 350
    .line 351
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 352
    .line 353
    .line 354
    new-instance p0, Lzo/a;

    .line 355
    .line 356
    const-string p1, "Failed to connect to dynamite module ContentResolver."

    .line 357
    .line 358
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    throw p0
    :try_end_f
    .catch Ljava/lang/Exception; {:try_start_f .. :try_end_f} :catch_1
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    .line 362
    :goto_f
    move-object v1, v3

    .line 363
    goto :goto_12

    .line 364
    :goto_10
    move-object v1, v3

    .line 365
    :goto_11
    :try_start_10
    instance-of p1, p0, Lzo/a;

    .line 366
    .line 367
    if-eqz p1, :cond_14

    .line 368
    .line 369
    throw p0

    .line 370
    :cond_14
    new-instance p1, Lzo/a;

    .line 371
    .line 372
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object p2

    .line 376
    new-instance p3, Ljava/lang/StringBuilder;

    .line 377
    .line 378
    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    .line 379
    .line 380
    .line 381
    const-string v0, "V2 version check failed: "

    .line 382
    .line 383
    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 384
    .line 385
    .line 386
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 387
    .line 388
    .line 389
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 390
    .line 391
    .line 392
    move-result-object p2

    .line 393
    invoke-direct {p1, p2, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 394
    .line 395
    .line 396
    throw p1
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_5

    .line 397
    :goto_12
    if-eqz v1, :cond_15

    .line 398
    .line 399
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 400
    .line 401
    .line 402
    :cond_15
    throw p0
.end method

.method public static f(Ljava/lang/ClassLoader;)V
    .locals 3

    .line 1
    const-string v0, "com.google.android.gms.dynamite.IDynamiteLoaderV2"

    .line 2
    .line 3
    :try_start_0
    const-string v1, "com.google.android.gms.dynamiteloader.DynamiteLoaderV2"

    .line 4
    .line 5
    invoke-virtual {p0, v1}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-virtual {p0, v1}, Ljava/lang/Class;->getConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p0, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Landroid/os/IBinder;

    .line 19
    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-interface {p0, v0}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    instance-of v2, v1, Lzo/h;

    .line 28
    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    check-cast v1, Lzo/h;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    new-instance v1, Lzo/h;

    .line 35
    .line 36
    const/4 v2, 0x3

    .line 37
    invoke-direct {v1, p0, v0, v2}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    :goto_0
    sput-object v1, Lzo/d;->o:Lzo/h;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/InstantiationException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    .line 42
    return-void

    .line 43
    :catch_0
    move-exception p0

    .line 44
    new-instance v0, Lzo/a;

    .line 45
    .line 46
    const-string v1, "Failed to instantiate dynamite loader"

    .line 47
    .line 48
    invoke-direct {v0, v1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 49
    .line 50
    .line 51
    throw v0
.end method

.method public static g(Landroid/content/Context;)Z
    .locals 6

    .line 1
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    const/4 v2, 0x1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    return v2

    .line 12
    :cond_0
    sget-object v1, Lzo/d;->j:Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    return v2

    .line 21
    :cond_1
    sget-object v0, Lzo/d;->j:Ljava/lang/Boolean;

    .line 22
    .line 23
    const-string v1, "DynamiteModule"

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    if-nez v0, :cond_3

    .line 27
    .line 28
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const/high16 v4, 0x10000000

    .line 33
    .line 34
    const-string v5, "com.google.android.gms.chimera"

    .line 35
    .line 36
    invoke-virtual {v0, v5, v4}, Landroid/content/pm/PackageManager;->resolveContentProvider(Ljava/lang/String;I)Landroid/content/pm/ProviderInfo;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    sget-object v4, Ljo/f;->b:Ljo/f;

    .line 41
    .line 42
    const v5, 0x989680

    .line 43
    .line 44
    .line 45
    invoke-virtual {v4, p0, v5}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    if-nez p0, :cond_2

    .line 50
    .line 51
    if-eqz v0, :cond_2

    .line 52
    .line 53
    const-string p0, "com.google.android.gms"

    .line 54
    .line 55
    iget-object v4, v0, Landroid/content/pm/ProviderInfo;->packageName:Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {p0, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-eqz p0, :cond_2

    .line 62
    .line 63
    move v3, v2

    .line 64
    :cond_2
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    sput-object p0, Lzo/d;->j:Ljava/lang/Boolean;

    .line 69
    .line 70
    if-eqz v3, :cond_3

    .line 71
    .line 72
    iget-object p0, v0, Landroid/content/pm/ProviderInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 73
    .line 74
    if-eqz p0, :cond_3

    .line 75
    .line 76
    iget p0, p0, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 77
    .line 78
    and-int/lit16 p0, p0, 0x81

    .line 79
    .line 80
    if-nez p0, :cond_3

    .line 81
    .line 82
    const-string p0, "Non-system-image GmsCore APK, forcing V1"

    .line 83
    .line 84
    invoke-static {v1, p0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 85
    .line 86
    .line 87
    sput-boolean v2, Lzo/d;->h:Z

    .line 88
    .line 89
    :cond_3
    if-nez v3, :cond_4

    .line 90
    .line 91
    const-string p0, "Invalid GmsCore APK, remote loading disabled."

    .line 92
    .line 93
    invoke-static {v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    :cond_4
    return v3
.end method

.method public static h(Landroid/content/Context;)Lzo/g;
    .locals 6

    .line 1
    const-string v0, "Failed to load IDynamiteLoader from GmsCore: "

    .line 2
    .line 3
    const-class v1, Lzo/d;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    sget-object v2, Lzo/d;->n:Lzo/g;

    .line 7
    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    return-object v2

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto :goto_2

    .line 14
    :cond_0
    const/4 v2, 0x0

    .line 15
    :try_start_1
    const-string v3, "com.google.android.gms"

    .line 16
    .line 17
    const/4 v4, 0x3

    .line 18
    invoke-virtual {p0, v3, v4}, Landroid/content/Context;->createPackageContext(Ljava/lang/String;I)Landroid/content/Context;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    const-string v3, "com.google.android.gms.chimera.container.DynamiteLoaderImpl"

    .line 27
    .line 28
    invoke-virtual {p0, v3}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {p0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Landroid/os/IBinder;

    .line 37
    .line 38
    if-nez p0, :cond_1

    .line 39
    .line 40
    move-object v3, v2

    .line 41
    goto :goto_0

    .line 42
    :cond_1
    const-string v3, "com.google.android.gms.dynamite.IDynamiteLoader"

    .line 43
    .line 44
    invoke-interface {p0, v3}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    instance-of v4, v3, Lzo/g;

    .line 49
    .line 50
    if-eqz v4, :cond_2

    .line 51
    .line 52
    check-cast v3, Lzo/g;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :catch_0
    move-exception p0

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    new-instance v3, Lzo/g;

    .line 58
    .line 59
    const-string v4, "com.google.android.gms.dynamite.IDynamiteLoader"

    .line 60
    .line 61
    const/4 v5, 0x3

    .line 62
    invoke-direct {v3, p0, v4, v5}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 63
    .line 64
    .line 65
    :goto_0
    if-eqz v3, :cond_3

    .line 66
    .line 67
    sput-object v3, Lzo/d;->n:Lzo/g;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    .line 69
    :try_start_2
    monitor-exit v1

    .line 70
    return-object v3

    .line 71
    :goto_1
    const-string v3, "DynamiteModule"

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    new-instance v4, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-static {v3, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 90
    .line 91
    .line 92
    :cond_3
    monitor-exit v1

    .line 93
    return-object v2

    .line 94
    :goto_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 95
    throw p0
.end method


# virtual methods
.method public final b(Ljava/lang/String;)Landroid/os/IBinder;
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lzo/d;->a:Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Landroid/os/IBinder;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/InstantiationException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    return-object p0

    .line 18
    :catch_0
    move-exception p0

    .line 19
    new-instance v0, Lzo/a;

    .line 20
    .line 21
    const-string v1, "Failed to instantiate module class: "

    .line 22
    .line 23
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-direct {v0, p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw v0
.end method
