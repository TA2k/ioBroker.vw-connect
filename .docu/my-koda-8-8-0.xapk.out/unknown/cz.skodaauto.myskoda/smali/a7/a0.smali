.class public final La7/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpx0/f;


# static fields
.field public static final synthetic d:La7/a0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, La7/a0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, La7/a0;->d:La7/a0;

    .line 7
    .line 8
    return-void
.end method

.method public static a(I)V
    .locals 2

    .line 1
    sget-object v0, Landroidx/glance/appwidget/UnmanagedSessionReceiver;->a:La7/a0;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Landroidx/glance/appwidget/UnmanagedSessionReceiver;->b:Ljava/util/LinkedHashMap;

    .line 5
    .line 6
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {v1, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    monitor-exit v0

    .line 17
    return-void

    .line 18
    :cond_0
    :try_start_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    monitor-exit v0

    .line 26
    throw p0
.end method


# virtual methods
.method public b(Landroid/content/Context;ILrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, La7/e1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, La7/e1;

    .line 7
    .line 8
    iget v1, v0, La7/e1;->h:I

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
    iput v1, v0, La7/e1;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/e1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, La7/e1;-><init>(La7/a0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, La7/e1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p3, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, La7/e1;->h:I

    .line 30
    .line 31
    const-string v2, "GlanceAppWidget"

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    if-ne v1, v3, :cond_1

    .line 37
    .line 38
    iget p2, v0, La7/e1;->e:I

    .line 39
    .line 40
    iget-object p1, v0, La7/e1;->d:Landroid/content/Context;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lm6/b; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :catch_0
    move-exception v0

    .line 47
    move-object p0, v0

    .line 48
    goto :goto_3

    .line 49
    :catch_1
    move-exception v0

    .line 50
    move-object p0, v0

    .line 51
    goto :goto_4

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :try_start_1
    sget-object p0, Li7/f;->a:Li7/f;

    .line 64
    .line 65
    sget-object v1, La7/l1;->a:La7/l1;

    .line 66
    .line 67
    new-instance v4, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    const-string v5, "appWidgetLayout-"

    .line 70
    .line 71
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    iput-object p1, v0, La7/e1;->d:Landroid/content/Context;

    .line 82
    .line 83
    iput p2, v0, La7/e1;->e:I

    .line 84
    .line 85
    iput v3, v0, La7/e1;->h:I

    .line 86
    .line 87
    invoke-virtual {p0, p1, v1, v4, v0}, Li7/f;->c(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-ne p0, p3, :cond_3

    .line 92
    .line 93
    return-object p3

    .line 94
    :cond_3
    :goto_1
    check-cast p0, Lc7/e;
    :try_end_1
    .catch Lm6/b; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 95
    .line 96
    :goto_2
    move-object v1, p1

    .line 97
    move v4, p2

    .line 98
    goto :goto_5

    .line 99
    :goto_3
    new-instance p3, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    const-string v0, "I/O error reading set of layout structures for App Widget id "

    .line 102
    .line 103
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p3

    .line 113
    invoke-static {v2, p3, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 114
    .line 115
    .line 116
    invoke-static {}, Lc7/e;->n()Lc7/e;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    goto :goto_2

    .line 121
    :goto_4
    new-instance p3, Ljava/lang/StringBuilder;

    .line 122
    .line 123
    const-string v0, "Set of layout structures for App Widget id "

    .line 124
    .line 125
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    const-string v0, " is corrupted"

    .line 132
    .line 133
    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p3

    .line 140
    invoke-static {v2, p3, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 141
    .line 142
    .line 143
    invoke-static {}, Lc7/e;->n()Lc7/e;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    goto :goto_2

    .line 148
    :goto_5
    invoke-virtual {p0}, Lc7/e;->o()Landroidx/glance/appwidget/protobuf/x;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    const/16 p2, 0xa

    .line 153
    .line 154
    invoke-static {p1, p2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 155
    .line 156
    .line 157
    move-result p2

    .line 158
    invoke-static {p2}, Lmx0/x;->k(I)I

    .line 159
    .line 160
    .line 161
    move-result p2

    .line 162
    const/16 p3, 0x10

    .line 163
    .line 164
    if-ge p2, p3, :cond_4

    .line 165
    .line 166
    move p2, p3

    .line 167
    :cond_4
    new-instance p3, Ljava/util/LinkedHashMap;

    .line 168
    .line 169
    invoke-direct {p3, p2}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 170
    .line 171
    .line 172
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    :goto_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 177
    .line 178
    .line 179
    move-result p2

    .line 180
    if-eqz p2, :cond_5

    .line 181
    .line 182
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p2

    .line 186
    check-cast p2, Lc7/g;

    .line 187
    .line 188
    invoke-virtual {p2}, Lc7/g;->m()Lc7/i;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    invoke-virtual {p2}, Lc7/g;->n()I

    .line 193
    .line 194
    .line 195
    move-result p2

    .line 196
    new-instance v2, Ljava/lang/Integer;

    .line 197
    .line 198
    invoke-direct {v2, p2}, Ljava/lang/Integer;-><init>(I)V

    .line 199
    .line 200
    .line 201
    invoke-interface {p3, v0, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    goto :goto_6

    .line 205
    :cond_5
    invoke-static {p3}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    new-instance v0, La7/f1;

    .line 210
    .line 211
    invoke-virtual {p0}, Lc7/e;->p()I

    .line 212
    .line 213
    .line 214
    move-result v3

    .line 215
    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    check-cast p0, Ljava/lang/Iterable;

    .line 220
    .line 221
    invoke-static {p0}, Lmx0/q;->B0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    invoke-direct/range {v0 .. v5}, La7/f1;-><init>(Landroid/content/Context;Ljava/util/LinkedHashMap;IILjava/util/Set;)V

    .line 226
    .line 227
    .line 228
    return-object v0
.end method
