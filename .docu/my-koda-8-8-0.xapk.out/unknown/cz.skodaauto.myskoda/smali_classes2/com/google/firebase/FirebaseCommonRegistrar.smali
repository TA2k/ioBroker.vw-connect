.class public Lcom/google/firebase/FirebaseCommonRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static a(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    const/16 v1, 0x5f

    .line 4
    .line 5
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/16 v0, 0x2f

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method


# virtual methods
.method public final getComponents()Ljava/util/List;
    .locals 7

    .line 1
    new-instance p0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    const-class v0, Lbu/b;

    .line 7
    .line 8
    invoke-static {v0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    new-instance v2, Lgs/k;

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    const/4 v4, 0x0

    .line 16
    const-class v5, Lbu/a;

    .line 17
    .line 18
    invoke-direct {v2, v3, v4, v5}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 22
    .line 23
    .line 24
    new-instance v2, Lb8/b;

    .line 25
    .line 26
    const/16 v5, 0x1c

    .line 27
    .line 28
    invoke-direct {v2, v5}, Lb8/b;-><init>(I)V

    .line 29
    .line 30
    .line 31
    iput-object v2, v1, Lgs/a;->f:Lgs/e;

    .line 32
    .line 33
    invoke-virtual {v1}, Lgs/a;->b()Lgs/b;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    new-instance v1, Lgs/s;

    .line 41
    .line 42
    const-class v2, Lyr/a;

    .line 43
    .line 44
    const-class v5, Ljava/util/concurrent/Executor;

    .line 45
    .line 46
    invoke-direct {v1, v2, v5}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 47
    .line 48
    .line 49
    const-class v2, Let/e;

    .line 50
    .line 51
    const-class v5, Let/f;

    .line 52
    .line 53
    filled-new-array {v2, v5}, [Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    new-instance v5, Lgs/a;

    .line 58
    .line 59
    const-class v6, Let/c;

    .line 60
    .line 61
    invoke-direct {v5, v6, v2}, Lgs/a;-><init>(Ljava/lang/Class;[Ljava/lang/Class;)V

    .line 62
    .line 63
    .line 64
    const-class v2, Landroid/content/Context;

    .line 65
    .line 66
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {v5, v2}, Lgs/a;->a(Lgs/k;)V

    .line 71
    .line 72
    .line 73
    const-class v2, Lsr/f;

    .line 74
    .line 75
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-virtual {v5, v2}, Lgs/a;->a(Lgs/k;)V

    .line 80
    .line 81
    .line 82
    new-instance v2, Lgs/k;

    .line 83
    .line 84
    const-class v6, Let/d;

    .line 85
    .line 86
    invoke-direct {v2, v3, v4, v6}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v5, v2}, Lgs/a;->a(Lgs/k;)V

    .line 90
    .line 91
    .line 92
    new-instance v2, Lgs/k;

    .line 93
    .line 94
    const/4 v3, 0x1

    .line 95
    invoke-direct {v2, v3, v3, v0}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v5, v2}, Lgs/a;->a(Lgs/k;)V

    .line 99
    .line 100
    .line 101
    new-instance v0, Lgs/k;

    .line 102
    .line 103
    invoke-direct {v0, v1, v3, v4}, Lgs/k;-><init>(Lgs/s;II)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5, v0}, Lgs/a;->a(Lgs/k;)V

    .line 107
    .line 108
    .line 109
    new-instance v0, Lcom/google/firebase/messaging/p;

    .line 110
    .line 111
    const/4 v2, 0x2

    .line 112
    invoke-direct {v0, v1, v2}, Lcom/google/firebase/messaging/p;-><init>(Lgs/s;I)V

    .line 113
    .line 114
    .line 115
    iput-object v0, v5, Lgs/a;->f:Lgs/e;

    .line 116
    .line 117
    invoke-virtual {v5}, Lgs/a;->b()Lgs/b;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 125
    .line 126
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    const-string v1, "fire-android"

    .line 131
    .line 132
    invoke-static {v1, v0}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    const-string v0, "fire-core"

    .line 140
    .line 141
    const-string v1, "22.0.1"

    .line 142
    .line 143
    invoke-static {v0, v1}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    sget-object v0, Landroid/os/Build;->PRODUCT:Ljava/lang/String;

    .line 151
    .line 152
    invoke-static {v0}, Lcom/google/firebase/FirebaseCommonRegistrar;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    const-string v1, "device-name"

    .line 157
    .line 158
    invoke-static {v1, v0}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    sget-object v0, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 166
    .line 167
    invoke-static {v0}, Lcom/google/firebase/FirebaseCommonRegistrar;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    const-string v1, "device-model"

    .line 172
    .line 173
    invoke-static {v1, v0}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    sget-object v0, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 181
    .line 182
    invoke-static {v0}, Lcom/google/firebase/FirebaseCommonRegistrar;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    const-string v1, "device-brand"

    .line 187
    .line 188
    invoke-static {v1, v0}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    new-instance v0, Lj9/d;

    .line 196
    .line 197
    const/16 v1, 0x1a

    .line 198
    .line 199
    invoke-direct {v0, v1}, Lj9/d;-><init>(I)V

    .line 200
    .line 201
    .line 202
    const-string v1, "android-target-sdk"

    .line 203
    .line 204
    invoke-static {v1, v0}, Ljp/gb;->c(Ljava/lang/String;Lj9/d;)Lgs/b;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    new-instance v0, Lj9/d;

    .line 212
    .line 213
    const/16 v1, 0x1b

    .line 214
    .line 215
    invoke-direct {v0, v1}, Lj9/d;-><init>(I)V

    .line 216
    .line 217
    .line 218
    const-string v1, "android-min-sdk"

    .line 219
    .line 220
    invoke-static {v1, v0}, Ljp/gb;->c(Ljava/lang/String;Lj9/d;)Lgs/b;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    new-instance v0, Lj9/d;

    .line 228
    .line 229
    const/16 v1, 0x1c

    .line 230
    .line 231
    invoke-direct {v0, v1}, Lj9/d;-><init>(I)V

    .line 232
    .line 233
    .line 234
    const-string v1, "android-platform"

    .line 235
    .line 236
    invoke-static {v1, v0}, Ljp/gb;->c(Ljava/lang/String;Lj9/d;)Lgs/b;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 241
    .line 242
    .line 243
    new-instance v0, Lj9/d;

    .line 244
    .line 245
    const/16 v1, 0x1d

    .line 246
    .line 247
    invoke-direct {v0, v1}, Lj9/d;-><init>(I)V

    .line 248
    .line 249
    .line 250
    const-string v1, "android-installer"

    .line 251
    .line 252
    invoke-static {v1, v0}, Ljp/gb;->c(Ljava/lang/String;Lj9/d;)Lgs/b;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 257
    .line 258
    .line 259
    :try_start_0
    sget-object v0, Llx0/h;->h:Llx0/h;

    .line 260
    .line 261
    invoke-virtual {v0}, Llx0/h;->toString()Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_0

    .line 265
    goto :goto_0

    .line 266
    :catch_0
    const/4 v0, 0x0

    .line 267
    :goto_0
    if-eqz v0, :cond_0

    .line 268
    .line 269
    const-string v1, "kotlin"

    .line 270
    .line 271
    invoke-static {v1, v0}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    :cond_0
    return-object p0
.end method
