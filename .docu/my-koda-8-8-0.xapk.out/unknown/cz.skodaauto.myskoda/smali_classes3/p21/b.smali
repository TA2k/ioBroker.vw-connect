.class public final Lp21/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/e1;


# instance fields
.field public final a:Lhy0/d;

.field public final b:Lk21/a;

.field public final c:Lh21/a;

.field public final d:Lay0/a;


# direct methods
.method public constructor <init>(Lhy0/d;Lk21/a;Lh21/a;Lay0/a;)V
    .locals 1

    .line 1
    const-string v0, "kClass"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lp21/b;->a:Lhy0/d;

    .line 10
    .line 11
    iput-object p2, p0, Lp21/b;->b:Lk21/a;

    .line 12
    .line 13
    iput-object p3, p0, Lp21/b;->c:Lh21/a;

    .line 14
    .line 15
    iput-object p4, p0, Lp21/b;->d:Lay0/a;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lhy0/d;Lp7/e;)Landroidx/lifecycle/b1;
    .locals 12

    .line 1
    const-string v0, "modelClass"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lp21/a;

    .line 7
    .line 8
    iget-object v1, p0, Lp21/b;->d:Lay0/a;

    .line 9
    .line 10
    invoke-direct {v0, v1, p2}, Lp21/a;-><init>(Lay0/a;Lp7/e;)V

    .line 11
    .line 12
    .line 13
    iget-object p2, p0, Lp21/b;->b:Lk21/a;

    .line 14
    .line 15
    iget-object v1, p2, Lk21/a;->e:Landroidx/lifecycle/c1;

    .line 16
    .line 17
    iget-object v2, v1, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Li21/a;

    .line 20
    .line 21
    const-string v3, "<this>"

    .line 22
    .line 23
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    sget-object v3, Lf21/a;->d:Lf21/a;

    .line 27
    .line 28
    iget-object v2, v2, Li21/a;->a:Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-nez v2, :cond_0

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    :cond_0
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 38
    .line 39
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    const-string v3, "clazz"

    .line 44
    .line 45
    iget-object v4, p0, Lp21/b;->c:Lh21/a;

    .line 46
    .line 47
    iget-object p0, p0, Lp21/b;->a:Lhy0/d;

    .line 48
    .line 49
    if-nez v2, :cond_1

    .line 50
    .line 51
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p2, v0, v4, p0}, Lk21/a;->c(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    check-cast p0, Landroidx/lifecycle/b1;

    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_1
    new-instance p2, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const/16 v2, 0x2d

    .line 74
    .line 75
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-static {}, Ljp/wc;->d()Loy0/b;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    invoke-virtual {v2}, Loy0/b;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    new-instance v6, Lh21/c;

    .line 94
    .line 95
    invoke-direct {v6, p1}, Lh21/c;-><init>(Lhy0/d;)V

    .line 96
    .line 97
    .line 98
    sget-object v8, Lq21/a;->a:Lh21/c;

    .line 99
    .line 100
    const-string p1, "scopeId"

    .line 101
    .line 102
    invoke-static {v7, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    iget-object p1, v1, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p1, Li21/b;

    .line 108
    .line 109
    iget-object p2, p1, Li21/b;->c:Ljava/util/concurrent/ConcurrentHashMap;

    .line 110
    .line 111
    iget-object v9, p1, Li21/b;->a:Landroidx/lifecycle/c1;

    .line 112
    .line 113
    iget-object v2, v9, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v2, Lap0/o;

    .line 116
    .line 117
    new-instance v5, Ljava/lang/StringBuilder;

    .line 118
    .line 119
    const-string v10, "| (+) Scope - id:\'"

    .line 120
    .line 121
    invoke-direct {v5, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string v10, "\' q:\'"

    .line 128
    .line 129
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const/16 v10, 0x27

    .line 136
    .line 137
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    invoke-virtual {v2, v5}, Lap0/o;->u(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    iget-object v2, p1, Li21/b;->b:Ljava/util/Set;

    .line 148
    .line 149
    invoke-interface {v2, v6}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v5

    .line 153
    if-nez v5, :cond_2

    .line 154
    .line 155
    iget-object v5, v9, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v5, Lap0/o;

    .line 158
    .line 159
    new-instance v10, Ljava/lang/StringBuilder;

    .line 160
    .line 161
    const-string v11, "| Scope \'"

    .line 162
    .line 163
    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    const-string v11, "\' not defined. Creating it ..."

    .line 170
    .line 171
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v10

    .line 178
    invoke-virtual {v5, v10}, Lap0/o;->u(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    invoke-interface {v2, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    :cond_2
    invoke-virtual {p2, v7}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    if-nez v2, :cond_4

    .line 189
    .line 190
    new-instance v5, Lk21/a;

    .line 191
    .line 192
    const/4 v10, 0x4

    .line 193
    invoke-direct/range {v5 .. v10}, Lk21/a;-><init>(Lh21/a;Ljava/lang/String;Lh21/c;Landroidx/lifecycle/c1;I)V

    .line 194
    .line 195
    .line 196
    iget-object p1, p1, Li21/b;->d:Lk21/a;

    .line 197
    .line 198
    filled-new-array {p1}, [Lk21/a;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    iget-boolean v2, v5, Lk21/a;->c:Z

    .line 203
    .line 204
    if-nez v2, :cond_3

    .line 205
    .line 206
    invoke-static {p1}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 207
    .line 208
    .line 209
    move-result-object p1

    .line 210
    check-cast p1, Ljava/util/Collection;

    .line 211
    .line 212
    iget-object v2, v5, Lk21/a;->f:Ljava/util/ArrayList;

    .line 213
    .line 214
    const/4 v6, 0x0

    .line 215
    invoke-virtual {v2, v6, p1}, Ljava/util/ArrayList;->addAll(ILjava/util/Collection;)Z

    .line 216
    .line 217
    .line 218
    invoke-virtual {p2, v7, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v5, v0, v4, p0}, Lk21/a;->c(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    check-cast p0, Landroidx/lifecycle/b1;

    .line 229
    .line 230
    new-instance p1, Lp21/c;

    .line 231
    .line 232
    invoke-direct {p1, v7, v1}, Lp21/c;-><init>(Ljava/lang/String;Landroidx/lifecycle/c1;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {p0, p1}, Landroidx/lifecycle/b1;->addCloseable(Ljava/lang/AutoCloseable;)V

    .line 236
    .line 237
    .line 238
    return-object p0

    .line 239
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 240
    .line 241
    const-string p1, "Can\'t add scope link to a root scope"

    .line 242
    .line 243
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    throw p0

    .line 247
    :cond_4
    new-instance p0, Lb0/l;

    .line 248
    .line 249
    new-instance p1, Ljava/lang/StringBuilder;

    .line 250
    .line 251
    const-string p2, "Scope with id \'"

    .line 252
    .line 253
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {p1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    const-string p2, "\' is already created"

    .line 260
    .line 261
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 262
    .line 263
    .line 264
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object p1

    .line 268
    const-string p2, "s"

    .line 269
    .line 270
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 271
    .line 272
    .line 273
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    throw p0
.end method
