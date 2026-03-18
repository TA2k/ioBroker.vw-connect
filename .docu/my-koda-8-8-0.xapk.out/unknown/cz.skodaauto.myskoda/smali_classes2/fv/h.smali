.class public abstract Lfv/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[Ljo/d;

.field public static final b:Ljo/d;

.field public static final c:Ljo/d;

.field public static final d:Lip/l;

.field public static final e:Lip/l;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljo/d;

    .line 3
    .line 4
    sput-object v0, Lfv/h;->a:[Ljo/d;

    .line 5
    .line 6
    new-instance v0, Ljo/d;

    .line 7
    .line 8
    const-wide/16 v1, 0x1

    .line 9
    .line 10
    const-string v3, "vision.barcode"

    .line 11
    .line 12
    invoke-direct {v0, v1, v2, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lfv/h;->b:Ljo/d;

    .line 16
    .line 17
    new-instance v3, Ljo/d;

    .line 18
    .line 19
    const-string v4, "vision.custom.ica"

    .line 20
    .line 21
    invoke-direct {v3, v1, v2, v4}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    new-instance v4, Ljo/d;

    .line 25
    .line 26
    const-string v5, "vision.face"

    .line 27
    .line 28
    invoke-direct {v4, v1, v2, v5}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    new-instance v5, Ljo/d;

    .line 32
    .line 33
    const-string v6, "vision.ica"

    .line 34
    .line 35
    invoke-direct {v5, v1, v2, v6}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    new-instance v6, Ljo/d;

    .line 39
    .line 40
    const-string v7, "vision.ocr"

    .line 41
    .line 42
    invoke-direct {v6, v1, v2, v7}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 43
    .line 44
    .line 45
    sput-object v6, Lfv/h;->c:Ljo/d;

    .line 46
    .line 47
    new-instance v7, Ljo/d;

    .line 48
    .line 49
    const-string v8, "mlkit.langid"

    .line 50
    .line 51
    invoke-direct {v7, v1, v2, v8}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 52
    .line 53
    .line 54
    new-instance v8, Ljo/d;

    .line 55
    .line 56
    const-string v9, "mlkit.nlclassifier"

    .line 57
    .line 58
    invoke-direct {v8, v1, v2, v9}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    new-instance v9, Ljo/d;

    .line 62
    .line 63
    const-string v10, "tflite_dynamite"

    .line 64
    .line 65
    invoke-direct {v9, v1, v2, v10}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 66
    .line 67
    .line 68
    new-instance v11, Ljo/d;

    .line 69
    .line 70
    const-string v12, "mlkit.barcode.ui"

    .line 71
    .line 72
    invoke-direct {v11, v1, v2, v12}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 73
    .line 74
    .line 75
    new-instance v12, Ljo/d;

    .line 76
    .line 77
    const-string v13, "mlkit.smartreply"

    .line 78
    .line 79
    invoke-direct {v12, v1, v2, v13}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance v1, Lbb/g0;

    .line 83
    .line 84
    const/4 v2, 0x7

    .line 85
    const/4 v13, 0x0

    .line 86
    invoke-direct {v1, v13, v2}, Lbb/g0;-><init>(BI)V

    .line 87
    .line 88
    .line 89
    const-string v2, "barcode"

    .line 90
    .line 91
    invoke-virtual {v1, v2, v0}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 92
    .line 93
    .line 94
    const-string v2, "custom_ica"

    .line 95
    .line 96
    invoke-virtual {v1, v2, v3}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 97
    .line 98
    .line 99
    const-string v2, "face"

    .line 100
    .line 101
    invoke-virtual {v1, v2, v4}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 102
    .line 103
    .line 104
    const-string v2, "ica"

    .line 105
    .line 106
    invoke-virtual {v1, v2, v5}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 107
    .line 108
    .line 109
    const-string v2, "ocr"

    .line 110
    .line 111
    invoke-virtual {v1, v2, v6}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 112
    .line 113
    .line 114
    const-string v2, "langid"

    .line 115
    .line 116
    invoke-virtual {v1, v2, v7}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 117
    .line 118
    .line 119
    const-string v2, "nlclassifier"

    .line 120
    .line 121
    invoke-virtual {v1, v2, v8}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v1, v10, v9}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 125
    .line 126
    .line 127
    const-string v2, "barcode_ui"

    .line 128
    .line 129
    invoke-virtual {v1, v2, v11}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 130
    .line 131
    .line 132
    const-string v2, "smart_reply"

    .line 133
    .line 134
    invoke-virtual {v1, v2, v12}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 135
    .line 136
    .line 137
    iget-object v2, v1, Lbb/g0;->g:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v2, Lip/e;

    .line 140
    .line 141
    if-nez v2, :cond_3

    .line 142
    .line 143
    iget v2, v1, Lbb/g0;->e:I

    .line 144
    .line 145
    iget-object v10, v1, Lbb/g0;->f:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v10, [Ljava/lang/Object;

    .line 148
    .line 149
    invoke-static {v2, v10, v1}, Lip/l;->a(I[Ljava/lang/Object;Lbb/g0;)Lip/l;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    iget-object v1, v1, Lbb/g0;->g:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast v1, Lip/e;

    .line 156
    .line 157
    if-nez v1, :cond_2

    .line 158
    .line 159
    sput-object v2, Lfv/h;->d:Lip/l;

    .line 160
    .line 161
    new-instance v1, Lbb/g0;

    .line 162
    .line 163
    const/4 v2, 0x7

    .line 164
    const/4 v10, 0x0

    .line 165
    invoke-direct {v1, v10, v2}, Lbb/g0;-><init>(BI)V

    .line 166
    .line 167
    .line 168
    const-string v2, "com.google.android.gms.vision.barcode"

    .line 169
    .line 170
    invoke-virtual {v1, v2, v0}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 171
    .line 172
    .line 173
    const-string v0, "com.google.android.gms.vision.custom.ica"

    .line 174
    .line 175
    invoke-virtual {v1, v0, v3}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 176
    .line 177
    .line 178
    const-string v0, "com.google.android.gms.vision.face"

    .line 179
    .line 180
    invoke-virtual {v1, v0, v4}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 181
    .line 182
    .line 183
    const-string v0, "com.google.android.gms.vision.ica"

    .line 184
    .line 185
    invoke-virtual {v1, v0, v5}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 186
    .line 187
    .line 188
    const-string v0, "com.google.android.gms.vision.ocr"

    .line 189
    .line 190
    invoke-virtual {v1, v0, v6}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 191
    .line 192
    .line 193
    const-string v0, "com.google.android.gms.mlkit.langid"

    .line 194
    .line 195
    invoke-virtual {v1, v0, v7}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 196
    .line 197
    .line 198
    const-string v0, "com.google.android.gms.mlkit.nlclassifier"

    .line 199
    .line 200
    invoke-virtual {v1, v0, v8}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 201
    .line 202
    .line 203
    const-string v0, "com.google.android.gms.tflite_dynamite"

    .line 204
    .line 205
    invoke-virtual {v1, v0, v9}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 206
    .line 207
    .line 208
    const-string v0, "com.google.android.gms.mlkit_smartreply"

    .line 209
    .line 210
    invoke-virtual {v1, v0, v12}, Lbb/g0;->v(Ljava/lang/String;Ljo/d;)V

    .line 211
    .line 212
    .line 213
    iget-object v0, v1, Lbb/g0;->g:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v0, Lip/e;

    .line 216
    .line 217
    if-nez v0, :cond_1

    .line 218
    .line 219
    iget v0, v1, Lbb/g0;->e:I

    .line 220
    .line 221
    iget-object v2, v1, Lbb/g0;->f:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v2, [Ljava/lang/Object;

    .line 224
    .line 225
    invoke-static {v0, v2, v1}, Lip/l;->a(I[Ljava/lang/Object;Lbb/g0;)Lip/l;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    iget-object v1, v1, Lbb/g0;->g:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast v1, Lip/e;

    .line 232
    .line 233
    if-nez v1, :cond_0

    .line 234
    .line 235
    sput-object v0, Lfv/h;->e:Lip/l;

    .line 236
    .line 237
    return-void

    .line 238
    :cond_0
    invoke-virtual {v1}, Lip/e;->a()Ljava/lang/IllegalArgumentException;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    throw v0

    .line 243
    :cond_1
    invoke-virtual {v0}, Lip/e;->a()Ljava/lang/IllegalArgumentException;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    throw v0

    .line 248
    :cond_2
    invoke-virtual {v1}, Lip/e;->a()Ljava/lang/IllegalArgumentException;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    throw v0

    .line 253
    :cond_3
    invoke-virtual {v2}, Lip/e;->a()Ljava/lang/IllegalArgumentException;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    throw v0
.end method

.method public static a(Landroid/content/Context;Ljava/util/List;)V
    .locals 3

    .line 1
    sget-object v0, Ljo/f;->b:Ljo/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljo/f;->a(Landroid/content/Context;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const v1, 0xd33d260

    .line 11
    .line 12
    .line 13
    if-lt v0, v1, :cond_0

    .line 14
    .line 15
    sget-object v0, Lfv/h;->d:Lip/l;

    .line 16
    .line 17
    invoke-static {v0, p1}, Lfv/h;->c(Lip/l;Ljava/util/List;)[Ljo/d;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-static {p0, p1}, Lfv/h;->b(Landroid/content/Context;[Ljo/d;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    new-instance v0, Landroid/content/Intent;

    .line 26
    .line 27
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V

    .line 28
    .line 29
    .line 30
    const-string v1, "com.google.android.gms"

    .line 31
    .line 32
    const-string v2, "com.google.android.gms.vision.DependencyBroadcastReceiverProxy"

    .line 33
    .line 34
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 35
    .line 36
    .line 37
    const-string v1, "com.google.android.gms.vision.DEPENDENCY"

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 40
    .line 41
    .line 42
    const-string v1, ","

    .line 43
    .line 44
    invoke-static {v1, p1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    const-string v1, "com.google.android.gms.vision.DEPENDENCIES"

    .line 49
    .line 50
    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    iget-object p1, p1, Landroid/content/pm/ApplicationInfo;->packageName:Ljava/lang/String;

    .line 58
    .line 59
    const-string v1, "requester_app_package"

    .line 60
    .line 61
    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public static b(Landroid/content/Context;[Ljo/d;)V
    .locals 9

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lfv/q;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, p1, v2}, Lfv/q;-><init>([Ljo/d;I)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    const/4 v1, 0x1

    .line 20
    xor-int/2addr p1, v1

    .line 21
    const-string v2, "APIs must not be empty."

    .line 22
    .line 23
    invoke-static {p1, v2}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v3, Lro/h;

    .line 27
    .line 28
    sget-object v8, Lko/h;->c:Lko/h;

    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    sget-object v6, Lro/h;->n:Lc2/k;

    .line 32
    .line 33
    sget-object v7, Lko/b;->a:Lko/a;

    .line 34
    .line 35
    move-object v4, p0

    .line 36
    invoke-direct/range {v3 .. v8}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0, v1}, Lro/a;->x0(Ljava/util/List;Z)Lro/a;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    iget-object p1, p0, Lro/a;->d:Ljava/util/List;

    .line 44
    .line 45
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    const/4 v0, 0x0

    .line 50
    if-eqz p1, :cond_0

    .line 51
    .line 52
    new-instance p0, Lqo/c;

    .line 53
    .line 54
    invoke-direct {p0, v0, v0}, Lqo/c;-><init>(IZ)V

    .line 55
    .line 56
    .line 57
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    sget-object v2, Lcp/b;->c:Ljo/d;

    .line 67
    .line 68
    filled-new-array {v2}, [Ljo/d;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    iput-object v2, p1, Lh6/i;->e:Ljava/lang/Object;

    .line 73
    .line 74
    iput-boolean v1, p1, Lh6/i;->c:Z

    .line 75
    .line 76
    const/16 v1, 0x6aa8

    .line 77
    .line 78
    iput v1, p1, Lh6/i;->b:I

    .line 79
    .line 80
    new-instance v1, Lpv/g;

    .line 81
    .line 82
    const/4 v2, 0x4

    .line 83
    invoke-direct {v1, v2, v3, p0}, Lpv/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    iput-object v1, p1, Lh6/i;->d:Ljava/lang/Object;

    .line 87
    .line 88
    invoke-virtual {p1}, Lh6/i;->a()Lbp/s;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-virtual {v3, v0, p0}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    :goto_0
    new-instance p1, Lfv/b;

    .line 97
    .line 98
    const/4 v0, 0x5

    .line 99
    invoke-direct {p1, v0}, Lfv/b;-><init>(I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0, p1}, Laq/t;->l(Laq/f;)Laq/t;

    .line 103
    .line 104
    .line 105
    return-void
.end method

.method public static c(Lip/l;Ljava/util/List;)[Ljo/d;
    .locals 3

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [Ljo/d;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    if-ge v1, v2, :cond_0

    .line 13
    .line 14
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {p0, v2}, Lip/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Ljo/d;

    .line 23
    .line 24
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    aput-object v2, v0, v1

    .line 28
    .line 29
    add-int/lit8 v1, v1, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    return-object v0
.end method
