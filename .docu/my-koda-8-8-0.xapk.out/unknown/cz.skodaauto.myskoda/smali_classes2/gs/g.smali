.class public final synthetic Lgs/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgt/b;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lgs/g;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lgs/g;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lgs/g;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lgs/g;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lgs/g;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lsr/f;

    .line 9
    .line 10
    iget-object p0, p0, Lgs/g;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/content/Context;

    .line 13
    .line 14
    new-instance v1, Lmt/a;

    .line 15
    .line 16
    invoke-virtual {v0}, Lsr/f;->d()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    iget-object v0, v0, Lsr/f;->d:Lgs/h;

    .line 21
    .line 22
    const-class v3, Ldt/b;

    .line 23
    .line 24
    invoke-interface {v0, v3}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Ldt/b;

    .line 29
    .line 30
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/content/Context;->createDeviceProtectedStorageContext()Landroid/content/Context;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance v0, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v3, "com.google.firebase.common.prefs:"

    .line 40
    .line 41
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const/4 v2, 0x0

    .line 52
    invoke-virtual {p0, v0, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    const-string v2, "firebase_data_collection_default_enabled"

    .line 57
    .line 58
    invoke-interface {v0, v2}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    const/4 v4, 0x1

    .line 63
    if-eqz v3, :cond_0

    .line 64
    .line 65
    invoke-interface {v0, v2, v4}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    goto :goto_0

    .line 70
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    if-eqz v0, :cond_1

    .line 75
    .line 76
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const/16 v3, 0x80

    .line 81
    .line 82
    invoke-virtual {v0, p0, v3}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    if-eqz p0, :cond_1

    .line 87
    .line 88
    iget-object v0, p0, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    .line 89
    .line 90
    if-eqz v0, :cond_1

    .line 91
    .line 92
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    if-eqz v0, :cond_1

    .line 97
    .line 98
    iget-object p0, p0, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    .line 99
    .line 100
    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 101
    .line 102
    .line 103
    move-result v4
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 104
    :catch_0
    :cond_1
    :goto_0
    iput-boolean v4, v1, Lmt/a;->a:Z

    .line 105
    .line 106
    return-object v1

    .line 107
    :pswitch_0
    iget-object v0, p0, Lgs/g;->b:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v0, Lgs/h;

    .line 110
    .line 111
    iget-object p0, p0, Lgs/g;->c:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast p0, Lgs/b;

    .line 114
    .line 115
    iget-object v1, p0, Lgs/b;->f:Lgs/e;

    .line 116
    .line 117
    new-instance v2, Lin/z1;

    .line 118
    .line 119
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 120
    .line 121
    .line 122
    new-instance v3, Ljava/util/HashSet;

    .line 123
    .line 124
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 125
    .line 126
    .line 127
    new-instance v4, Ljava/util/HashSet;

    .line 128
    .line 129
    invoke-direct {v4}, Ljava/util/HashSet;-><init>()V

    .line 130
    .line 131
    .line 132
    new-instance v5, Ljava/util/HashSet;

    .line 133
    .line 134
    invoke-direct {v5}, Ljava/util/HashSet;-><init>()V

    .line 135
    .line 136
    .line 137
    new-instance v6, Ljava/util/HashSet;

    .line 138
    .line 139
    invoke-direct {v6}, Ljava/util/HashSet;-><init>()V

    .line 140
    .line 141
    .line 142
    new-instance v7, Ljava/util/HashSet;

    .line 143
    .line 144
    invoke-direct {v7}, Ljava/util/HashSet;-><init>()V

    .line 145
    .line 146
    .line 147
    iget-object v8, p0, Lgs/b;->c:Ljava/util/Set;

    .line 148
    .line 149
    iget-object p0, p0, Lgs/b;->g:Ljava/util/Set;

    .line 150
    .line 151
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 152
    .line 153
    .line 154
    move-result-object v8

    .line 155
    :goto_1
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 156
    .line 157
    .line 158
    move-result v9

    .line 159
    if-eqz v9, :cond_7

    .line 160
    .line 161
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v9

    .line 165
    check-cast v9, Lgs/k;

    .line 166
    .line 167
    iget v10, v9, Lgs/k;->c:I

    .line 168
    .line 169
    iget v11, v9, Lgs/k;->b:I

    .line 170
    .line 171
    if-nez v10, :cond_2

    .line 172
    .line 173
    const/4 v12, 0x1

    .line 174
    goto :goto_2

    .line 175
    :cond_2
    const/4 v12, 0x0

    .line 176
    :goto_2
    iget-object v9, v9, Lgs/k;->a:Lgs/s;

    .line 177
    .line 178
    const/4 v13, 0x2

    .line 179
    if-eqz v12, :cond_4

    .line 180
    .line 181
    if-ne v11, v13, :cond_3

    .line 182
    .line 183
    invoke-virtual {v6, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_3
    invoke-virtual {v3, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    goto :goto_1

    .line 191
    :cond_4
    if-ne v10, v13, :cond_5

    .line 192
    .line 193
    invoke-virtual {v5, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    goto :goto_1

    .line 197
    :cond_5
    if-ne v11, v13, :cond_6

    .line 198
    .line 199
    invoke-virtual {v7, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    goto :goto_1

    .line 203
    :cond_6
    invoke-virtual {v4, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    goto :goto_1

    .line 207
    :cond_7
    invoke-interface {p0}, Ljava/util/Set;->isEmpty()Z

    .line 208
    .line 209
    .line 210
    move-result p0

    .line 211
    if-nez p0, :cond_8

    .line 212
    .line 213
    const-class p0, Ldt/b;

    .line 214
    .line 215
    invoke-static {p0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    invoke-virtual {v3, p0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    :cond_8
    invoke-static {v3}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    iput-object p0, v2, Lin/z1;->a:Ljava/lang/Object;

    .line 227
    .line 228
    invoke-static {v4}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 229
    .line 230
    .line 231
    move-result-object p0

    .line 232
    iput-object p0, v2, Lin/z1;->b:Ljava/lang/Object;

    .line 233
    .line 234
    invoke-static {v5}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    iput-object p0, v2, Lin/z1;->c:Ljava/lang/Object;

    .line 239
    .line 240
    invoke-static {v6}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    iput-object p0, v2, Lin/z1;->d:Ljava/lang/Object;

    .line 245
    .line 246
    invoke-static {v7}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    iput-object p0, v2, Lin/z1;->e:Ljava/lang/Object;

    .line 251
    .line 252
    iput-object v0, v2, Lin/z1;->f:Ljava/lang/Object;

    .line 253
    .line 254
    invoke-interface {v1, v2}, Lgs/e;->e(Lin/z1;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    return-object p0

    .line 259
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
