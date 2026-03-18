.class public final synthetic Lny/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcz/skodaauto/myskoda/app/main/system/MainApplication;


# direct methods
.method public synthetic constructor <init>(Lcz/skodaauto/myskoda/app/main/system/MainApplication;I)V
    .locals 0

    .line 1
    iput p2, p0, Lny/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lny/u;->e:Lcz/skodaauto/myskoda/app/main/system/MainApplication;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lny/u;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Lny/u;->e:Lcz/skodaauto/myskoda/app/main/system/MainApplication;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p1, Le21/a;

    .line 11
    .line 12
    const-string v0, "$this$module"

    .line 13
    .line 14
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v6, Ltj/g;

    .line 18
    .line 19
    const/16 v0, 0x8

    .line 20
    .line 21
    invoke-direct {v6, p0, v0}, Ltj/g;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    sget-object v3, Li21/b;->e:Lh21/b;

    .line 25
    .line 26
    sget-object v7, La21/c;->d:La21/c;

    .line 27
    .line 28
    new-instance v2, La21/a;

    .line 29
    .line 30
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 31
    .line 32
    const-class v0, Landroid/app/Application;

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    const/4 v5, 0x0

    .line 39
    invoke-direct/range {v2 .. v7}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v2, p1}, Lia/b;->d(La21/a;Le21/a;)Lc21/d;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const-class v2, Landroid/content/Context;

    .line 47
    .line 48
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const-string v2, "clazz"

    .line 53
    .line 54
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v2, v0, Lc21/b;->a:La21/a;

    .line 58
    .line 59
    iget-object v3, v2, La21/a;->f:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v3, Ljava/util/Collection;

    .line 62
    .line 63
    invoke-static {v3, p0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    iput-object v3, v2, La21/a;->f:Ljava/lang/Object;

    .line 68
    .line 69
    iget-object v3, v2, La21/a;->c:Lh21/a;

    .line 70
    .line 71
    iget-object v2, v2, La21/a;->a:Lh21/a;

    .line 72
    .line 73
    new-instance v4, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 76
    .line 77
    .line 78
    const/16 v5, 0x3a

    .line 79
    .line 80
    invoke-static {p0, v4, v5}, Lia/b;->s(Lhy0/d;Ljava/lang/StringBuilder;C)V

    .line 81
    .line 82
    .line 83
    if-eqz v3, :cond_0

    .line 84
    .line 85
    invoke-interface {v3}, Lh21/a;->getValue()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-nez p0, :cond_1

    .line 90
    .line 91
    :cond_0
    const-string p0, ""

    .line 92
    .line 93
    :cond_1
    invoke-static {v4, p0, v5, v2}, Lia/b;->h(Ljava/lang/StringBuilder;Ljava/lang/String;CLh21/a;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-virtual {p1, p0, v0}, Le21/a;->b(Ljava/lang/String;Lc21/b;)V

    .line 98
    .line 99
    .line 100
    return-object v1

    .line 101
    :pswitch_0
    check-cast p1, Lx11/a;

    .line 102
    .line 103
    const-string v0, "$this$startKoin"

    .line 104
    .line 105
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    new-instance v0, Ld21/a;

    .line 109
    .line 110
    sget-object v2, Ld21/b;->e:Ld21/b;

    .line 111
    .line 112
    const/4 v3, 0x1

    .line 113
    invoke-direct {v0, v2, v3}, Ld21/a;-><init>(Ld21/b;I)V

    .line 114
    .line 115
    .line 116
    iget-object v4, p1, Lx11/a;->a:Landroidx/lifecycle/c1;

    .line 117
    .line 118
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    iput-object v0, v4, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 122
    .line 123
    invoke-virtual {v2, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    if-gtz v0, :cond_2

    .line 128
    .line 129
    iget-object v0, v4, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v0, Lap0/o;

    .line 132
    .line 133
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 134
    .line 135
    .line 136
    const-string v5, "[init] declare Android Context"

    .line 137
    .line 138
    invoke-virtual {v0, v2, v5}, Lap0/o;->N(Ld21/b;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    :cond_2
    new-instance v0, Lny/u;

    .line 142
    .line 143
    invoke-direct {v0, p0, v3}, Lny/u;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainApplication;I)V

    .line 144
    .line 145
    .line 146
    new-instance p0, Le21/a;

    .line 147
    .line 148
    invoke-direct {p0}, Le21/a;-><init>()V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v0, p0}, Lny/u;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    invoke-virtual {v4, p0, v3}, Landroidx/lifecycle/c1;->C(Ljava/util/List;Z)V

    .line 159
    .line 160
    .line 161
    sget-object p0, Ljy/a;->a:Ljava/util/List;

    .line 162
    .line 163
    iget-boolean p1, p1, Lx11/a;->b:Z

    .line 164
    .line 165
    const-string v0, "modules"

    .line 166
    .line 167
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    iget-object v0, v4, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v0, Lap0/o;

    .line 173
    .line 174
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v0, Ld21/b;

    .line 177
    .line 178
    invoke-virtual {v0, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 179
    .line 180
    .line 181
    move-result v0

    .line 182
    if-gtz v0, :cond_3

    .line 183
    .line 184
    invoke-static {}, Lmy0/j;->b()J

    .line 185
    .line 186
    .line 187
    move-result-wide v5

    .line 188
    invoke-virtual {v4, p0, p1}, Landroidx/lifecycle/c1;->C(Ljava/util/List;Z)V

    .line 189
    .line 190
    .line 191
    invoke-static {v5, v6}, Lmy0/l;->a(J)J

    .line 192
    .line 193
    .line 194
    move-result-wide p0

    .line 195
    iget-object v0, v4, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v0, Lgw0/c;

    .line 198
    .line 199
    iget-object v0, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 202
    .line 203
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->size()I

    .line 204
    .line 205
    .line 206
    move-result v0

    .line 207
    iget-object v3, v4, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 208
    .line 209
    check-cast v3, Lap0/o;

    .line 210
    .line 211
    const-string v4, "Started "

    .line 212
    .line 213
    const-string v5, " definitions in "

    .line 214
    .line 215
    invoke-static {v4, v0, v5}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    sget v4, Lmy0/c;->g:I

    .line 220
    .line 221
    sget-object v4, Lmy0/e;->f:Lmy0/e;

    .line 222
    .line 223
    invoke-static {p0, p1, v4}, Lmy0/c;->n(JLmy0/e;)J

    .line 224
    .line 225
    .line 226
    move-result-wide p0

    .line 227
    long-to-double p0, p0

    .line 228
    const-wide v4, 0x408f400000000000L    # 1000.0

    .line 229
    .line 230
    .line 231
    .line 232
    .line 233
    div-double/2addr p0, v4

    .line 234
    const-string v4, " ms"

    .line 235
    .line 236
    invoke-static {v0, p0, p1, v4}, Lp3/m;->n(Ljava/lang/StringBuilder;DLjava/lang/String;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    invoke-virtual {v3, v2, p0}, Lap0/o;->v(Ld21/b;Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    goto :goto_0

    .line 244
    :cond_3
    invoke-virtual {v4, p0, p1}, Landroidx/lifecycle/c1;->C(Ljava/util/List;Z)V

    .line 245
    .line 246
    .line 247
    :goto_0
    return-object v1

    .line 248
    nop

    .line 249
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
