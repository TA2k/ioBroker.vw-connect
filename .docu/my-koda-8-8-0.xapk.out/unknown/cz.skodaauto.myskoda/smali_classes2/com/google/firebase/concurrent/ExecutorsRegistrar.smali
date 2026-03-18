.class public Lcom/google/firebase/concurrent/ExecutorsRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "ThreadPoolCreation"
    }
.end annotation


# static fields
.field public static final a:Lgs/o;

.field public static final b:Lgs/o;

.field public static final c:Lgs/o;

.field public static final d:Lgs/o;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lgs/o;

    .line 2
    .line 3
    new-instance v1, Lcom/google/firebase/messaging/l;

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/l;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, v1}, Lgs/o;-><init>(Lgt/b;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->a:Lgs/o;

    .line 13
    .line 14
    new-instance v0, Lgs/o;

    .line 15
    .line 16
    new-instance v1, Lcom/google/firebase/messaging/l;

    .line 17
    .line 18
    const/4 v2, 0x5

    .line 19
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/l;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-direct {v0, v1}, Lgs/o;-><init>(Lgt/b;)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->b:Lgs/o;

    .line 26
    .line 27
    new-instance v0, Lgs/o;

    .line 28
    .line 29
    new-instance v1, Lcom/google/firebase/messaging/l;

    .line 30
    .line 31
    const/4 v2, 0x6

    .line 32
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/l;-><init>(I)V

    .line 33
    .line 34
    .line 35
    invoke-direct {v0, v1}, Lgs/o;-><init>(Lgt/b;)V

    .line 36
    .line 37
    .line 38
    sput-object v0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->c:Lgs/o;

    .line 39
    .line 40
    new-instance v0, Lgs/o;

    .line 41
    .line 42
    new-instance v1, Lcom/google/firebase/messaging/l;

    .line 43
    .line 44
    const/4 v2, 0x7

    .line 45
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/l;-><init>(I)V

    .line 46
    .line 47
    .line 48
    invoke-direct {v0, v1}, Lgs/o;-><init>(Lgt/b;)V

    .line 49
    .line 50
    .line 51
    sput-object v0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->d:Lgs/o;

    .line 52
    .line 53
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final getComponents()Ljava/util/List;
    .locals 24

    .line 1
    new-instance v0, Lgs/s;

    .line 2
    .line 3
    const-class v1, Lyr/a;

    .line 4
    .line 5
    const-class v2, Ljava/util/concurrent/ScheduledExecutorService;

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 8
    .line 9
    .line 10
    new-instance v3, Lgs/s;

    .line 11
    .line 12
    const-class v4, Ljava/util/concurrent/ExecutorService;

    .line 13
    .line 14
    invoke-direct {v3, v1, v4}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 15
    .line 16
    .line 17
    new-instance v5, Lgs/s;

    .line 18
    .line 19
    const-class v6, Ljava/util/concurrent/Executor;

    .line 20
    .line 21
    invoke-direct {v5, v1, v6}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 22
    .line 23
    .line 24
    filled-new-array {v3, v5}, [Lgs/s;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    new-instance v3, Ljava/util/HashSet;

    .line 29
    .line 30
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 31
    .line 32
    .line 33
    new-instance v5, Ljava/util/HashSet;

    .line 34
    .line 35
    invoke-direct {v5}, Ljava/util/HashSet;-><init>()V

    .line 36
    .line 37
    .line 38
    new-instance v14, Ljava/util/HashSet;

    .line 39
    .line 40
    invoke-direct {v14}, Ljava/util/HashSet;-><init>()V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    array-length v0, v1

    .line 47
    const/4 v11, 0x0

    .line 48
    move v7, v11

    .line 49
    :goto_0
    const-string v15, "Null interface"

    .line 50
    .line 51
    if-ge v7, v0, :cond_0

    .line 52
    .line 53
    aget-object v8, v1, v7

    .line 54
    .line 55
    invoke-static {v8, v15}, Lkp/o9;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    add-int/lit8 v7, v7, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-static {v3, v1}, Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    new-instance v13, Lf3/d;

    .line 65
    .line 66
    const/16 v0, 0xe

    .line 67
    .line 68
    invoke-direct {v13, v0}, Lf3/d;-><init>(I)V

    .line 69
    .line 70
    .line 71
    new-instance v7, Lgs/b;

    .line 72
    .line 73
    new-instance v9, Ljava/util/HashSet;

    .line 74
    .line 75
    invoke-direct {v9, v3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 76
    .line 77
    .line 78
    new-instance v10, Ljava/util/HashSet;

    .line 79
    .line 80
    invoke-direct {v10, v5}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 81
    .line 82
    .line 83
    const/4 v8, 0x0

    .line 84
    move v12, v11

    .line 85
    invoke-direct/range {v7 .. v14}, Lgs/b;-><init>(Ljava/lang/String;Ljava/util/Set;Ljava/util/Set;IILgs/e;Ljava/util/Set;)V

    .line 86
    .line 87
    .line 88
    new-instance v0, Lgs/s;

    .line 89
    .line 90
    const-class v1, Lyr/b;

    .line 91
    .line 92
    invoke-direct {v0, v1, v2}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 93
    .line 94
    .line 95
    new-instance v3, Lgs/s;

    .line 96
    .line 97
    invoke-direct {v3, v1, v4}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 98
    .line 99
    .line 100
    new-instance v5, Lgs/s;

    .line 101
    .line 102
    invoke-direct {v5, v1, v6}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 103
    .line 104
    .line 105
    filled-new-array {v3, v5}, [Lgs/s;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    new-instance v3, Ljava/util/HashSet;

    .line 110
    .line 111
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 112
    .line 113
    .line 114
    new-instance v5, Ljava/util/HashSet;

    .line 115
    .line 116
    invoke-direct {v5}, Ljava/util/HashSet;-><init>()V

    .line 117
    .line 118
    .line 119
    new-instance v23, Ljava/util/HashSet;

    .line 120
    .line 121
    invoke-direct/range {v23 .. v23}, Ljava/util/HashSet;-><init>()V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v3, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    array-length v0, v1

    .line 128
    const/16 v20, 0x0

    .line 129
    .line 130
    move/from16 v8, v20

    .line 131
    .line 132
    :goto_1
    if-ge v8, v0, :cond_1

    .line 133
    .line 134
    aget-object v9, v1, v8

    .line 135
    .line 136
    invoke-static {v9, v15}, Lkp/o9;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    add-int/lit8 v8, v8, 0x1

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_1
    invoke-static {v3, v1}, Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    new-instance v0, Lf3/d;

    .line 146
    .line 147
    const/16 v1, 0xf

    .line 148
    .line 149
    invoke-direct {v0, v1}, Lf3/d;-><init>(I)V

    .line 150
    .line 151
    .line 152
    new-instance v16, Lgs/b;

    .line 153
    .line 154
    new-instance v1, Ljava/util/HashSet;

    .line 155
    .line 156
    invoke-direct {v1, v3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 157
    .line 158
    .line 159
    new-instance v3, Ljava/util/HashSet;

    .line 160
    .line 161
    invoke-direct {v3, v5}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 162
    .line 163
    .line 164
    const/16 v17, 0x0

    .line 165
    .line 166
    move/from16 v21, v20

    .line 167
    .line 168
    move-object/from16 v22, v0

    .line 169
    .line 170
    move-object/from16 v18, v1

    .line 171
    .line 172
    move-object/from16 v19, v3

    .line 173
    .line 174
    invoke-direct/range {v16 .. v23}, Lgs/b;-><init>(Ljava/lang/String;Ljava/util/Set;Ljava/util/Set;IILgs/e;Ljava/util/Set;)V

    .line 175
    .line 176
    .line 177
    move-object/from16 v0, v16

    .line 178
    .line 179
    new-instance v1, Lgs/s;

    .line 180
    .line 181
    const-class v3, Lyr/c;

    .line 182
    .line 183
    invoke-direct {v1, v3, v2}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 184
    .line 185
    .line 186
    new-instance v2, Lgs/s;

    .line 187
    .line 188
    invoke-direct {v2, v3, v4}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 189
    .line 190
    .line 191
    new-instance v4, Lgs/s;

    .line 192
    .line 193
    invoke-direct {v4, v3, v6}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 194
    .line 195
    .line 196
    filled-new-array {v2, v4}, [Lgs/s;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    new-instance v3, Ljava/util/HashSet;

    .line 201
    .line 202
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 203
    .line 204
    .line 205
    new-instance v4, Ljava/util/HashSet;

    .line 206
    .line 207
    invoke-direct {v4}, Ljava/util/HashSet;-><init>()V

    .line 208
    .line 209
    .line 210
    new-instance v23, Ljava/util/HashSet;

    .line 211
    .line 212
    invoke-direct/range {v23 .. v23}, Ljava/util/HashSet;-><init>()V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v3, v1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    array-length v1, v2

    .line 219
    const/16 v20, 0x0

    .line 220
    .line 221
    move/from16 v5, v20

    .line 222
    .line 223
    :goto_2
    if-ge v5, v1, :cond_2

    .line 224
    .line 225
    aget-object v8, v2, v5

    .line 226
    .line 227
    invoke-static {v8, v15}, Lkp/o9;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    add-int/lit8 v5, v5, 0x1

    .line 231
    .line 232
    goto :goto_2

    .line 233
    :cond_2
    invoke-static {v3, v2}, Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    new-instance v1, Lf3/d;

    .line 237
    .line 238
    const/16 v2, 0x10

    .line 239
    .line 240
    invoke-direct {v1, v2}, Lf3/d;-><init>(I)V

    .line 241
    .line 242
    .line 243
    new-instance v16, Lgs/b;

    .line 244
    .line 245
    new-instance v2, Ljava/util/HashSet;

    .line 246
    .line 247
    invoke-direct {v2, v3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 248
    .line 249
    .line 250
    new-instance v3, Ljava/util/HashSet;

    .line 251
    .line 252
    invoke-direct {v3, v4}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 253
    .line 254
    .line 255
    const/16 v17, 0x0

    .line 256
    .line 257
    move/from16 v21, v20

    .line 258
    .line 259
    move-object/from16 v22, v1

    .line 260
    .line 261
    move-object/from16 v18, v2

    .line 262
    .line 263
    move-object/from16 v19, v3

    .line 264
    .line 265
    invoke-direct/range {v16 .. v23}, Lgs/b;-><init>(Ljava/lang/String;Ljava/util/Set;Ljava/util/Set;IILgs/e;Ljava/util/Set;)V

    .line 266
    .line 267
    .line 268
    move-object/from16 v1, v16

    .line 269
    .line 270
    new-instance v2, Lgs/s;

    .line 271
    .line 272
    const-class v3, Lyr/d;

    .line 273
    .line 274
    invoke-direct {v2, v3, v6}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 275
    .line 276
    .line 277
    invoke-static {v2}, Lgs/b;->a(Lgs/s;)Lgs/a;

    .line 278
    .line 279
    .line 280
    move-result-object v2

    .line 281
    new-instance v3, Lf3/d;

    .line 282
    .line 283
    const/16 v4, 0x11

    .line 284
    .line 285
    invoke-direct {v3, v4}, Lf3/d;-><init>(I)V

    .line 286
    .line 287
    .line 288
    iput-object v3, v2, Lgs/a;->f:Lgs/e;

    .line 289
    .line 290
    invoke-virtual {v2}, Lgs/a;->b()Lgs/b;

    .line 291
    .line 292
    .line 293
    move-result-object v2

    .line 294
    filled-new-array {v7, v0, v1, v2}, [Lgs/b;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    return-object v0
.end method
