.class public final Landroidx/fragment/app/d1;
.super Lf/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Landroidx/fragment/app/d1;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Ljava/lang/Object;)Landroid/content/Intent;
    .locals 3

    .line 1
    iget p0, p0, Landroidx/fragment/app/d1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Landroid/content/Intent;

    .line 7
    .line 8
    const-string p0, "input"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-object p2

    .line 14
    :pswitch_0
    check-cast p2, Ljava/lang/String;

    .line 15
    .line 16
    const-string p0, "input"

    .line 17
    .line 18
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    filled-new-array {p2}, [Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    new-instance p1, Landroid/content/Intent;

    .line 26
    .line 27
    const-string p2, "androidx.activity.result.contract.action.REQUEST_PERMISSIONS"

    .line 28
    .line 29
    invoke-direct {p1, p2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const-string p2, "androidx.activity.result.contract.extra.PERMISSIONS"

    .line 33
    .line 34
    invoke-virtual {p1, p2, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;[Ljava/lang/String;)Landroid/content/Intent;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    const-string p1, "putExtra(...)"

    .line 39
    .line 40
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_1
    check-cast p2, [Ljava/lang/String;

    .line 45
    .line 46
    const-string p0, "input"

    .line 47
    .line 48
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    new-instance p0, Landroid/content/Intent;

    .line 52
    .line 53
    const-string p1, "androidx.activity.result.contract.action.REQUEST_PERMISSIONS"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-string p1, "androidx.activity.result.contract.extra.PERMISSIONS"

    .line 59
    .line 60
    invoke-virtual {p0, p1, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;[Ljava/lang/String;)Landroid/content/Intent;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    const-string p1, "putExtra(...)"

    .line 65
    .line 66
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-object p0

    .line 70
    :pswitch_2
    check-cast p2, Le/k;

    .line 71
    .line 72
    const-string p0, "input"

    .line 73
    .line 74
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 78
    .line 79
    const/16 v0, 0x21

    .line 80
    .line 81
    const/4 v1, 0x1

    .line 82
    if-lt p0, v0, :cond_0

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_0
    const/16 v0, 0x1e

    .line 86
    .line 87
    if-lt p0, v0, :cond_1

    .line 88
    .line 89
    invoke-static {}, Ld6/t1;->D()I

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    const/4 v0, 0x2

    .line 94
    if-lt p0, v0, :cond_1

    .line 95
    .line 96
    :goto_0
    new-instance p0, Landroid/content/Intent;

    .line 97
    .line 98
    const-string p1, "android.provider.action.PICK_IMAGES"

    .line 99
    .line 100
    invoke-direct {p0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget-object p1, p2, Le/k;->a:Lf/f;

    .line 104
    .line 105
    invoke-static {p1}, Lkp/x6;->c(Lf/f;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-virtual {p0, p1}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 110
    .line 111
    .line 112
    iget-object p1, p2, Le/k;->c:Lf/c;

    .line 113
    .line 114
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    const-string p1, "android.provider.extra.PICK_IMAGES_LAUNCH_TAB"

    .line 118
    .line 119
    invoke-virtual {p0, p1, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_1
    invoke-static {p1}, Lkp/x6;->b(Landroid/content/Context;)Landroid/content/pm/ResolveInfo;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    if-eqz p0, :cond_3

    .line 128
    .line 129
    invoke-static {p1}, Lkp/x6;->b(Landroid/content/Context;)Landroid/content/pm/ResolveInfo;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    if-eqz p0, :cond_2

    .line 134
    .line 135
    iget-object p0, p0, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    .line 136
    .line 137
    new-instance p1, Landroid/content/Intent;

    .line 138
    .line 139
    const-string v0, "androidx.activity.result.contract.action.PICK_IMAGES"

    .line 140
    .line 141
    invoke-direct {p1, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    iget-object v0, p0, Landroid/content/pm/ActivityInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 145
    .line 146
    iget-object v0, v0, Landroid/content/pm/ApplicationInfo;->packageName:Ljava/lang/String;

    .line 147
    .line 148
    iget-object p0, p0, Landroid/content/pm/ActivityInfo;->name:Ljava/lang/String;

    .line 149
    .line 150
    invoke-virtual {p1, v0, p0}, Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 151
    .line 152
    .line 153
    iget-object p0, p2, Le/k;->a:Lf/f;

    .line 154
    .line 155
    invoke-static {p0}, Lkp/x6;->c(Lf/f;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    invoke-virtual {p1, p0}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 160
    .line 161
    .line 162
    iget-object p0, p2, Le/k;->c:Lf/c;

    .line 163
    .line 164
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 165
    .line 166
    .line 167
    const-string p0, "androidx.activity.result.contract.extra.PICK_IMAGES_LAUNCH_TAB"

    .line 168
    .line 169
    invoke-virtual {p1, p0, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 170
    .line 171
    .line 172
    move-object p0, p1

    .line 173
    goto :goto_1

    .line 174
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 175
    .line 176
    const-string p1, "Required value was null."

    .line 177
    .line 178
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    throw p0

    .line 182
    :cond_3
    new-instance p0, Landroid/content/Intent;

    .line 183
    .line 184
    const-string p1, "android.intent.action.OPEN_DOCUMENT"

    .line 185
    .line 186
    invoke-direct {p0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    iget-object p1, p2, Le/k;->a:Lf/f;

    .line 190
    .line 191
    invoke-static {p1}, Lkp/x6;->c(Lf/f;)Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    invoke-virtual {p0, p1}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 196
    .line 197
    .line 198
    invoke-virtual {p0}, Landroid/content/Intent;->getType()Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    if-nez p1, :cond_4

    .line 203
    .line 204
    const-string p1, "*/*"

    .line 205
    .line 206
    invoke-virtual {p0, p1}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 207
    .line 208
    .line 209
    const-string p1, "image/*"

    .line 210
    .line 211
    const-string p2, "video/*"

    .line 212
    .line 213
    filled-new-array {p1, p2}, [Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    const-string p2, "android.intent.extra.MIME_TYPES"

    .line 218
    .line 219
    invoke-virtual {p0, p2, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;[Ljava/lang/String;)Landroid/content/Intent;

    .line 220
    .line 221
    .line 222
    :cond_4
    :goto_1
    return-object p0

    .line 223
    :pswitch_3
    check-cast p2, Le/j;

    .line 224
    .line 225
    new-instance p0, Landroid/content/Intent;

    .line 226
    .line 227
    const-string p1, "androidx.activity.result.contract.action.INTENT_SENDER_REQUEST"

    .line 228
    .line 229
    invoke-direct {p0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    iget-object p1, p2, Le/j;->e:Landroid/content/Intent;

    .line 233
    .line 234
    if-eqz p1, :cond_5

    .line 235
    .line 236
    const-string v0, "androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE"

    .line 237
    .line 238
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getBundleExtra(Ljava/lang/String;)Landroid/os/Bundle;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    if-eqz v1, :cond_5

    .line 243
    .line 244
    invoke-virtual {p0, v0, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/Intent;

    .line 245
    .line 246
    .line 247
    invoke-virtual {p1, v0}, Landroid/content/Intent;->removeExtra(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    const-string v0, "androidx.fragment.extra.ACTIVITY_OPTIONS_BUNDLE"

    .line 251
    .line 252
    const/4 v1, 0x0

    .line 253
    invoke-virtual {p1, v0, v1}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    .line 254
    .line 255
    .line 256
    move-result p1

    .line 257
    if-eqz p1, :cond_5

    .line 258
    .line 259
    iget-object p1, p2, Le/j;->d:Landroid/content/IntentSender;

    .line 260
    .line 261
    iget v0, p2, Le/j;->g:I

    .line 262
    .line 263
    iget p2, p2, Le/j;->f:I

    .line 264
    .line 265
    new-instance v1, Le/j;

    .line 266
    .line 267
    const/4 v2, 0x0

    .line 268
    invoke-direct {v1, p1, v2, p2, v0}, Le/j;-><init>(Landroid/content/IntentSender;Landroid/content/Intent;II)V

    .line 269
    .line 270
    .line 271
    move-object p2, v1

    .line 272
    :cond_5
    const-string p1, "androidx.activity.result.contract.extra.INTENT_SENDER_REQUEST"

    .line 273
    .line 274
    invoke-virtual {p0, p1, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 275
    .line 276
    .line 277
    const/4 p1, 0x2

    .line 278
    invoke-static {p1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 279
    .line 280
    .line 281
    move-result p1

    .line 282
    if-eqz p1, :cond_6

    .line 283
    .line 284
    new-instance p1, Ljava/lang/StringBuilder;

    .line 285
    .line 286
    const-string p2, "CreateIntent created the following intent: "

    .line 287
    .line 288
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 292
    .line 293
    .line 294
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object p1

    .line 298
    const-string p2, "FragmentManager"

    .line 299
    .line 300
    invoke-static {p2, p1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 301
    .line 302
    .line 303
    :cond_6
    return-object p0

    .line 304
    nop

    .line 305
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b(Landroid/content/Context;Ljava/lang/Object;)Lbu/c;
    .locals 3

    .line 1
    iget v0, p0, Landroidx/fragment/app/d1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lf/a;->b(Landroid/content/Context;Ljava/lang/Object;)Lbu/c;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    check-cast p2, Ljava/lang/String;

    .line 12
    .line 13
    const-string p0, "input"

    .line 14
    .line 15
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {p1, p2}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-nez p0, :cond_0

    .line 23
    .line 24
    new-instance p0, Lbu/c;

    .line 25
    .line 26
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-direct {p0, p1}, Lbu/c;-><init>(Ljava/io/Serializable;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    :goto_0
    return-object p0

    .line 34
    :pswitch_1
    check-cast p2, [Ljava/lang/String;

    .line 35
    .line 36
    const-string p0, "input"

    .line 37
    .line 38
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    array-length p0, p2

    .line 42
    if-nez p0, :cond_1

    .line 43
    .line 44
    new-instance p0, Lbu/c;

    .line 45
    .line 46
    sget-object p1, Lmx0/t;->d:Lmx0/t;

    .line 47
    .line 48
    invoke-direct {p0, p1}, Lbu/c;-><init>(Ljava/io/Serializable;)V

    .line 49
    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_1
    array-length p0, p2

    .line 53
    const/4 v0, 0x0

    .line 54
    move v1, v0

    .line 55
    :goto_1
    if-ge v1, p0, :cond_3

    .line 56
    .line 57
    aget-object v2, p2, v1

    .line 58
    .line 59
    invoke-static {p1, v2}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-nez v2, :cond_2

    .line 64
    .line 65
    add-int/lit8 v1, v1, 0x1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    const/4 p0, 0x0

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    array-length p0, p2

    .line 71
    invoke-static {p0}, Lmx0/x;->k(I)I

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    const/16 p1, 0x10

    .line 76
    .line 77
    if-ge p0, p1, :cond_4

    .line 78
    .line 79
    move p0, p1

    .line 80
    :cond_4
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 81
    .line 82
    invoke-direct {p1, p0}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 83
    .line 84
    .line 85
    array-length p0, p2

    .line 86
    :goto_2
    if-ge v0, p0, :cond_5

    .line 87
    .line 88
    aget-object v1, p2, v0

    .line 89
    .line 90
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 91
    .line 92
    invoke-interface {p1, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    add-int/lit8 v0, v0, 0x1

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_5
    new-instance p0, Lbu/c;

    .line 99
    .line 100
    invoke-direct {p0, p1}, Lbu/c;-><init>(Ljava/io/Serializable;)V

    .line 101
    .line 102
    .line 103
    :goto_3
    return-object p0

    .line 104
    :pswitch_2
    check-cast p2, Le/k;

    .line 105
    .line 106
    const-string p0, "input"

    .line 107
    .line 108
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    const/4 p0, 0x0

    .line 112
    return-object p0

    .line 113
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Landroid/content/Intent;I)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Landroidx/fragment/app/d1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Le/a;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2}, Le/a;-><init>(Landroid/content/Intent;I)V

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_0
    if-eqz p1, :cond_3

    .line 13
    .line 14
    const/4 p0, -0x1

    .line 15
    if-eq p2, p0, :cond_0

    .line 16
    .line 17
    goto :goto_2

    .line 18
    :cond_0
    const-string p0, "androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS"

    .line 19
    .line 20
    invoke-virtual {p1, p0}, Landroid/content/Intent;->getIntArrayExtra(Ljava/lang/String;)[I

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const/4 p1, 0x0

    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    array-length p2, p0

    .line 28
    move v0, p1

    .line 29
    :goto_0
    if-ge v0, p2, :cond_2

    .line 30
    .line 31
    aget v1, p0, v0

    .line 32
    .line 33
    if-nez v1, :cond_1

    .line 34
    .line 35
    const/4 p1, 0x1

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    :goto_1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    goto :goto_3

    .line 45
    :cond_3
    :goto_2
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 46
    .line 47
    :goto_3
    return-object p0

    .line 48
    :pswitch_1
    const/4 p0, -0x1

    .line 49
    if-eq p2, p0, :cond_4

    .line 50
    .line 51
    goto :goto_6

    .line 52
    :cond_4
    if-nez p1, :cond_5

    .line 53
    .line 54
    goto :goto_6

    .line 55
    :cond_5
    const-string p0, "androidx.activity.result.contract.extra.PERMISSIONS"

    .line 56
    .line 57
    invoke-virtual {p1, p0}, Landroid/content/Intent;->getStringArrayExtra(Ljava/lang/String;)[Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string p2, "androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS"

    .line 62
    .line 63
    invoke-virtual {p1, p2}, Landroid/content/Intent;->getIntArrayExtra(Ljava/lang/String;)[I

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    if-eqz p1, :cond_9

    .line 68
    .line 69
    if-nez p0, :cond_6

    .line 70
    .line 71
    goto :goto_6

    .line 72
    :cond_6
    new-instance p2, Ljava/util/ArrayList;

    .line 73
    .line 74
    array-length v0, p1

    .line 75
    invoke-direct {p2, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 76
    .line 77
    .line 78
    array-length v0, p1

    .line 79
    const/4 v1, 0x0

    .line 80
    move v2, v1

    .line 81
    :goto_4
    if-ge v2, v0, :cond_8

    .line 82
    .line 83
    aget v3, p1, v2

    .line 84
    .line 85
    if-nez v3, :cond_7

    .line 86
    .line 87
    const/4 v3, 0x1

    .line 88
    goto :goto_5

    .line 89
    :cond_7
    move v3, v1

    .line 90
    :goto_5
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    invoke-virtual {p2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    add-int/lit8 v2, v2, 0x1

    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_8
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-static {p0, p2}, Lmx0/q;->E0(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-static {p0}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    goto :goto_7

    .line 113
    :cond_9
    :goto_6
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 114
    .line 115
    :goto_7
    return-object p0

    .line 116
    :pswitch_2
    const/4 p0, -0x1

    .line 117
    const/4 v0, 0x0

    .line 118
    if-ne p2, p0, :cond_a

    .line 119
    .line 120
    goto :goto_8

    .line 121
    :cond_a
    move-object p1, v0

    .line 122
    :goto_8
    if-eqz p1, :cond_f

    .line 123
    .line 124
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    if-nez v0, :cond_f

    .line 129
    .line 130
    new-instance p0, Ljava/util/LinkedHashSet;

    .line 131
    .line 132
    invoke-direct {p0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 136
    .line 137
    .line 138
    move-result-object p2

    .line 139
    if-eqz p2, :cond_b

    .line 140
    .line 141
    invoke-virtual {p0, p2}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    :cond_b
    invoke-virtual {p1}, Landroid/content/Intent;->getClipData()Landroid/content/ClipData;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    if-nez p1, :cond_c

    .line 149
    .line 150
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 151
    .line 152
    .line 153
    move-result p2

    .line 154
    if-eqz p2, :cond_c

    .line 155
    .line 156
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 157
    .line 158
    goto :goto_a

    .line 159
    :cond_c
    if-eqz p1, :cond_e

    .line 160
    .line 161
    invoke-virtual {p1}, Landroid/content/ClipData;->getItemCount()I

    .line 162
    .line 163
    .line 164
    move-result p2

    .line 165
    const/4 v0, 0x0

    .line 166
    :goto_9
    if-ge v0, p2, :cond_e

    .line 167
    .line 168
    invoke-virtual {p1, v0}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    invoke-virtual {v1}, Landroid/content/ClipData$Item;->getUri()Landroid/net/Uri;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    if-eqz v1, :cond_d

    .line 177
    .line 178
    invoke-virtual {p0, v1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    :cond_d
    add-int/lit8 v0, v0, 0x1

    .line 182
    .line 183
    goto :goto_9

    .line 184
    :cond_e
    new-instance p1, Ljava/util/ArrayList;

    .line 185
    .line 186
    invoke-direct {p1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 187
    .line 188
    .line 189
    move-object p0, p1

    .line 190
    :goto_a
    invoke-static {p0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    move-object v0, p0

    .line 195
    check-cast v0, Landroid/net/Uri;

    .line 196
    .line 197
    :cond_f
    return-object v0

    .line 198
    :pswitch_3
    new-instance p0, Le/a;

    .line 199
    .line 200
    invoke-direct {p0, p1, p2}, Le/a;-><init>(Landroid/content/Intent;I)V

    .line 201
    .line 202
    .line 203
    return-object p0

    .line 204
    nop

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
