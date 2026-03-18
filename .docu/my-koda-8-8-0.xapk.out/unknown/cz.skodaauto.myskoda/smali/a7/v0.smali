.class public final La7/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:La7/p0;

.field public static final e:Lp6/b;

.field public static f:Lm6/g;

.field public static final g:Lq6/e;


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Landroid/appwidget/AppWidgetManager;

.field public final c:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, La7/p0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, La7/v0;->d:La7/p0;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/16 v1, 0xe

    .line 10
    .line 11
    const-string v2, "GlanceAppWidgetManager"

    .line 12
    .line 13
    invoke-static {v2, v0, v0, v1}, Ljp/gd;->a(Ljava/lang/String;Lb3/g;Lws/a;I)Lp6/b;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, La7/v0;->e:Lp6/b;

    .line 18
    .line 19
    const-string v0, "list::Providers"

    .line 20
    .line 21
    invoke-static {v0}, Ljp/ne;->c(Ljava/lang/String;)Lq6/e;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, La7/v0;->g:Lq6/e;

    .line 26
    .line 27
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La7/v0;->a:Landroid/content/Context;

    .line 5
    .line 6
    invoke-static {p1}, Landroid/appwidget/AppWidgetManager;->getInstance(Landroid/content/Context;)Landroid/appwidget/AppWidgetManager;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, La7/v0;->b:Landroid/appwidget/AppWidgetManager;

    .line 11
    .line 12
    new-instance p1, La7/j;

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-direct {p1, p0, v0}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, La7/v0;->c:Llx0/q;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Class;Lrx0/c;)Ljava/io/Serializable;
    .locals 6

    .line 1
    instance-of v0, p2, La7/s0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, La7/s0;

    .line 7
    .line 8
    iget v1, v0, La7/s0;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, La7/s0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/s0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, La7/s0;-><init>(La7/v0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, La7/s0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La7/s0;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, La7/s0;->e:Ljava/lang/Class;

    .line 37
    .line 38
    iget-object p0, v0, La7/s0;->d:La7/v0;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iput-object p0, v0, La7/s0;->d:La7/v0;

    .line 56
    .line 57
    iput-object p1, v0, La7/s0;->e:Ljava/lang/Class;

    .line 58
    .line 59
    iput v3, v0, La7/s0;->h:I

    .line 60
    .line 61
    invoke-virtual {p0, v0}, La7/v0;->b(Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-ne p2, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p2, La7/q0;

    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    if-eqz p1, :cond_7

    .line 75
    .line 76
    iget-object p2, p2, La7/q0;->b:Ljava/util/Map;

    .line 77
    .line 78
    invoke-interface {p2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    check-cast p1, Ljava/util/List;

    .line 83
    .line 84
    if-nez p1, :cond_4

    .line 85
    .line 86
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 87
    .line 88
    return-object p0

    .line 89
    :cond_4
    check-cast p1, Ljava/lang/Iterable;

    .line 90
    .line 91
    new-instance p2, Ljava/util/ArrayList;

    .line 92
    .line 93
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 94
    .line 95
    .line 96
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-eqz v0, :cond_6

    .line 105
    .line 106
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    check-cast v0, Landroid/content/ComponentName;

    .line 111
    .line 112
    iget-object v1, p0, La7/v0;->b:Landroid/appwidget/AppWidgetManager;

    .line 113
    .line 114
    invoke-virtual {v1, v0}, Landroid/appwidget/AppWidgetManager;->getAppWidgetIds(Landroid/content/ComponentName;)[I

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    new-instance v1, Ljava/util/ArrayList;

    .line 119
    .line 120
    array-length v2, v0

    .line 121
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 122
    .line 123
    .line 124
    array-length v2, v0

    .line 125
    const/4 v3, 0x0

    .line 126
    :goto_3
    if-ge v3, v2, :cond_5

    .line 127
    .line 128
    aget v4, v0, v3

    .line 129
    .line 130
    new-instance v5, La7/c;

    .line 131
    .line 132
    invoke-direct {v5, v4}, La7/c;-><init>(I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    add-int/lit8 v3, v3, 0x1

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_5
    invoke-static {v1, p2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 142
    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_6
    return-object p2

    .line 146
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 147
    .line 148
    const-string p1, "no canonical provider name"

    .line 149
    .line 150
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, La7/t0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, La7/t0;

    .line 7
    .line 8
    iget v1, v0, La7/t0;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, La7/t0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/t0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, La7/t0;-><init>(La7/v0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, La7/t0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La7/t0;->h:I

    .line 30
    .line 31
    sget-object v3, La7/v0;->d:La7/p0;

    .line 32
    .line 33
    sget-object v4, La7/v0;->g:Lq6/e;

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    const/4 v7, 0x0

    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    if-eq v2, v6, :cond_2

    .line 41
    .line 42
    if-ne v2, v5, :cond_1

    .line 43
    .line 44
    iget-object p0, v0, La7/t0;->d:La7/v0;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto/16 :goto_7

    .line 50
    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    iget-object p0, v0, La7/t0;->e:La7/v0;

    .line 60
    .line 61
    iget-object v2, v0, La7/t0;->d:La7/v0;

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iget-object p1, p0, La7/v0;->c:Llx0/q;

    .line 71
    .line 72
    invoke-virtual {p1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    check-cast p1, Lm6/g;

    .line 77
    .line 78
    invoke-interface {p1}, Lm6/g;->getData()Lyy0/i;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    iput-object p0, v0, La7/t0;->d:La7/v0;

    .line 83
    .line 84
    iput-object p0, v0, La7/t0;->e:La7/v0;

    .line 85
    .line 86
    iput v6, v0, La7/t0;->h:I

    .line 87
    .line 88
    invoke-static {p1, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    if-ne p1, v1, :cond_4

    .line 93
    .line 94
    goto/16 :goto_6

    .line 95
    .line 96
    :cond_4
    move-object v2, p0

    .line 97
    :goto_1
    move-object v6, p1

    .line 98
    check-cast v6, Lq6/b;

    .line 99
    .line 100
    invoke-virtual {v6, v4}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    if-eqz v6, :cond_5

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_5
    move-object p1, v7

    .line 108
    :goto_2
    check-cast p1, Lq6/b;

    .line 109
    .line 110
    if-nez p1, :cond_c

    .line 111
    .line 112
    iput-object p0, v0, La7/t0;->d:La7/v0;

    .line 113
    .line 114
    iput-object v7, v0, La7/t0;->e:La7/v0;

    .line 115
    .line 116
    iput v5, v0, La7/t0;->h:I

    .line 117
    .line 118
    iget-object p1, v2, La7/v0;->b:Landroid/appwidget/AppWidgetManager;

    .line 119
    .line 120
    invoke-virtual {p1}, Landroid/appwidget/AppWidgetManager;->getInstalledProviders()Ljava/util/List;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    check-cast p1, Ljava/lang/Iterable;

    .line 125
    .line 126
    new-instance v5, Ljava/util/ArrayList;

    .line 127
    .line 128
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 129
    .line 130
    .line 131
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    :cond_6
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 136
    .line 137
    .line 138
    move-result v6

    .line 139
    if-eqz v6, :cond_7

    .line 140
    .line 141
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v6

    .line 145
    move-object v8, v6

    .line 146
    check-cast v8, Landroid/appwidget/AppWidgetProviderInfo;

    .line 147
    .line 148
    iget-object v8, v8, Landroid/appwidget/AppWidgetProviderInfo;->provider:Landroid/content/ComponentName;

    .line 149
    .line 150
    invoke-virtual {v8}, Landroid/content/ComponentName;->getPackageName()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    iget-object v9, v2, La7/v0;->a:Landroid/content/Context;

    .line 155
    .line 156
    invoke-virtual {v9}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v9

    .line 160
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    if-eqz v8, :cond_6

    .line 165
    .line 166
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_7
    new-instance p1, Ljava/util/ArrayList;

    .line 171
    .line 172
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 176
    .line 177
    .line 178
    move-result-object v5

    .line 179
    :cond_8
    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 180
    .line 181
    .line 182
    move-result v6

    .line 183
    if-eqz v6, :cond_a

    .line 184
    .line 185
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v6

    .line 189
    check-cast v6, Landroid/appwidget/AppWidgetProviderInfo;

    .line 190
    .line 191
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 192
    .line 193
    .line 194
    iget-object v6, v6, Landroid/appwidget/AppWidgetProviderInfo;->provider:Landroid/content/ComponentName;

    .line 195
    .line 196
    invoke-virtual {v6}, Landroid/content/ComponentName;->getClassName()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v6

    .line 200
    invoke-static {v6}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 201
    .line 202
    .line 203
    move-result-object v6

    .line 204
    invoke-virtual {v6, v7}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    invoke-virtual {v6, v7}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v6

    .line 212
    instance-of v8, v6, La7/z0;

    .line 213
    .line 214
    if-eqz v8, :cond_9

    .line 215
    .line 216
    check-cast v6, La7/z0;

    .line 217
    .line 218
    goto :goto_5

    .line 219
    :cond_9
    move-object v6, v7

    .line 220
    :goto_5
    if-eqz v6, :cond_8

    .line 221
    .line 222
    invoke-virtual {p1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    goto :goto_4

    .line 226
    :cond_a
    iget-object v2, v2, La7/v0;->c:Llx0/q;

    .line 227
    .line 228
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    check-cast v2, Lm6/g;

    .line 233
    .line 234
    new-instance v5, La60/f;

    .line 235
    .line 236
    const/4 v6, 0x1

    .line 237
    invoke-direct {v5, p1, v7, v6}, La60/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 238
    .line 239
    .line 240
    invoke-interface {v2, v5, v0}, Lm6/g;->a(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    if-ne p1, v1, :cond_b

    .line 245
    .line 246
    :goto_6
    return-object v1

    .line 247
    :cond_b
    :goto_7
    check-cast p1, Lq6/b;

    .line 248
    .line 249
    :cond_c
    iget-object p0, p0, La7/v0;->a:Landroid/content/Context;

    .line 250
    .line 251
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    invoke-virtual {p1, v4}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    check-cast v0, Ljava/util/Set;

    .line 260
    .line 261
    if-nez v0, :cond_d

    .line 262
    .line 263
    new-instance p0, La7/q0;

    .line 264
    .line 265
    sget-object p1, Lmx0/t;->d:Lmx0/t;

    .line 266
    .line 267
    invoke-direct {p0, p1, p1}, La7/q0;-><init>(Ljava/util/Map;Ljava/util/Map;)V

    .line 268
    .line 269
    .line 270
    return-object p0

    .line 271
    :cond_d
    check-cast v0, Ljava/lang/Iterable;

    .line 272
    .line 273
    new-instance v1, Ljava/util/ArrayList;

    .line 274
    .line 275
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 276
    .line 277
    .line 278
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    :cond_e
    :goto_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 283
    .line 284
    .line 285
    move-result v2

    .line 286
    if-eqz v2, :cond_10

    .line 287
    .line 288
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    check-cast v2, Ljava/lang/String;

    .line 293
    .line 294
    new-instance v4, Landroid/content/ComponentName;

    .line 295
    .line 296
    invoke-direct {v4, p0, v2}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    invoke-static {v3, v2}, La7/p0;->a(La7/p0;Ljava/lang/String;)Lq6/e;

    .line 300
    .line 301
    .line 302
    move-result-object v2

    .line 303
    invoke-virtual {p1, v2}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v2

    .line 307
    check-cast v2, Ljava/lang/String;

    .line 308
    .line 309
    if-nez v2, :cond_f

    .line 310
    .line 311
    move-object v5, v7

    .line 312
    goto :goto_9

    .line 313
    :cond_f
    new-instance v5, Llx0/l;

    .line 314
    .line 315
    invoke-direct {v5, v4, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 316
    .line 317
    .line 318
    :goto_9
    if-eqz v5, :cond_e

    .line 319
    .line 320
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 321
    .line 322
    .line 323
    goto :goto_8

    .line 324
    :cond_10
    invoke-static {v1}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 325
    .line 326
    .line 327
    move-result-object p0

    .line 328
    new-instance p1, La7/q0;

    .line 329
    .line 330
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    check-cast v0, Ljava/lang/Iterable;

    .line 335
    .line 336
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 337
    .line 338
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 339
    .line 340
    .line 341
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    :goto_a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 346
    .line 347
    .line 348
    move-result v2

    .line 349
    if-eqz v2, :cond_12

    .line 350
    .line 351
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v2

    .line 355
    check-cast v2, Ljava/util/Map$Entry;

    .line 356
    .line 357
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v3

    .line 361
    check-cast v3, Ljava/lang/String;

    .line 362
    .line 363
    invoke-virtual {v1, v3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v4

    .line 367
    if-nez v4, :cond_11

    .line 368
    .line 369
    new-instance v4, Ljava/util/ArrayList;

    .line 370
    .line 371
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 372
    .line 373
    .line 374
    invoke-interface {v1, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    :cond_11
    check-cast v4, Ljava/util/List;

    .line 378
    .line 379
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v2

    .line 383
    check-cast v2, Landroid/content/ComponentName;

    .line 384
    .line 385
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 386
    .line 387
    .line 388
    goto :goto_a

    .line 389
    :cond_12
    invoke-direct {p1, p0, v1}, La7/q0;-><init>(Ljava/util/Map;Ljava/util/Map;)V

    .line 390
    .line 391
    .line 392
    return-object p1
.end method

.method public final c(La7/z0;La7/m0;La50/c;)Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, La7/v0;->d:La7/p0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    if-eqz p1, :cond_2

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    invoke-virtual {p2}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    if-eqz p2, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, La7/v0;->c:Llx0/q;

    .line 27
    .line 28
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Lm6/g;

    .line 33
    .line 34
    new-instance v0, La7/u0;

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    const/4 v2, 0x0

    .line 38
    invoke-direct {v0, p1, p2, v1, v2}, La7/u0;-><init>(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    invoke-interface {p0, v0, p3}, Lm6/g;->a(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 46
    .line 47
    if-ne p0, p1, :cond_0

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 54
    .line 55
    const-string p1, "no provider name"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    const-string p1, "no receiver name"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0
.end method
