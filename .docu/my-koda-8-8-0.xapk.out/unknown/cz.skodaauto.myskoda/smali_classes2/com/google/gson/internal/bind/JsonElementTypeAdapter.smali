.class Lcom/google/gson/internal/bind/JsonElementTypeAdapter;
.super Lcom/google/gson/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/google/gson/y;"
    }
.end annotation


# static fields
.field public static final a:Lcom/google/gson/internal/bind/JsonElementTypeAdapter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;->a:Lcom/google/gson/internal/bind/JsonElementTypeAdapter;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static d(Lpu/a;I)Lcom/google/gson/n;
    .locals 2

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x5

    .line 6
    if-eq v0, v1, :cond_3

    .line 7
    .line 8
    const/4 v1, 0x6

    .line 9
    if-eq v0, v1, :cond_2

    .line 10
    .line 11
    const/4 v1, 0x7

    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    const/16 v1, 0x8

    .line 15
    .line 16
    if-ne v0, v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lpu/a;->W()V

    .line 19
    .line 20
    .line 21
    sget-object p0, Lcom/google/gson/p;->d:Lcom/google/gson/p;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    invoke-static {p1}, Lp3/m;->z(I)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    const-string v0, "Unexpected token: "

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    new-instance p1, Lcom/google/gson/r;

    .line 41
    .line 42
    invoke-virtual {p0}, Lpu/a;->E()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-direct {p1, p0}, Lcom/google/gson/r;-><init>(Ljava/lang/Boolean;)V

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    :cond_2
    invoke-virtual {p0}, Lpu/a;->h0()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    new-instance p1, Lcom/google/gson/r;

    .line 59
    .line 60
    new-instance v0, Lcom/google/gson/internal/h;

    .line 61
    .line 62
    invoke-direct {v0, p0}, Lcom/google/gson/internal/h;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-direct {p1, v0}, Lcom/google/gson/r;-><init>(Ljava/lang/Number;)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :cond_3
    new-instance p1, Lcom/google/gson/r;

    .line 70
    .line 71
    invoke-virtual {p0}, Lpu/a;->h0()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-direct {p1, p0}, Lcom/google/gson/r;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    return-object p1
.end method

.method public static e(Lpu/b;Lcom/google/gson/n;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_c

    .line 2
    .line 3
    instance-of v0, p1, Lcom/google/gson/p;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_3

    .line 8
    .line 9
    :cond_0
    instance-of v0, p1, Lcom/google/gson/r;

    .line 10
    .line 11
    if-eqz v0, :cond_5

    .line 12
    .line 13
    if-eqz v0, :cond_4

    .line 14
    .line 15
    check-cast p1, Lcom/google/gson/r;

    .line 16
    .line 17
    iget-object v0, p1, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 18
    .line 19
    instance-of v1, v0, Ljava/lang/Number;

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    invoke-virtual {p1}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {p0, p1}, Lpu/b;->U(Ljava/lang/Number;)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    instance-of v1, v0, Ljava/lang/Boolean;

    .line 32
    .line 33
    if-eqz v1, :cond_3

    .line 34
    .line 35
    instance-of v1, v0, Ljava/lang/Boolean;

    .line 36
    .line 37
    if-eqz v1, :cond_2

    .line 38
    .line 39
    check-cast v0, Ljava/lang/Boolean;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    invoke-virtual {p1}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-static {p1}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    :goto_0
    invoke-virtual {p0, p1}, Lpu/b;->W(Z)V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :cond_3
    invoke-virtual {p1}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p0, p1}, Lpu/b;->V(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    new-instance v0, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    const-string v1, "Not a JSON Primitive: "

    .line 71
    .line 72
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_5
    instance-of v0, p1, Lcom/google/gson/l;

    .line 87
    .line 88
    if-eqz v0, :cond_8

    .line 89
    .line 90
    invoke-virtual {p0}, Lpu/b;->b()V

    .line 91
    .line 92
    .line 93
    if-eqz v0, :cond_7

    .line 94
    .line 95
    check-cast p1, Lcom/google/gson/l;

    .line 96
    .line 97
    iget-object p1, p1, Lcom/google/gson/l;->d:Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    if-eqz v0, :cond_6

    .line 108
    .line 109
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    check-cast v0, Lcom/google/gson/n;

    .line 114
    .line 115
    invoke-static {p0, v0}, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;->e(Lpu/b;Lcom/google/gson/n;)V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_6
    invoke-virtual {p0}, Lpu/b;->g()V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    new-instance v0, Ljava/lang/StringBuilder;

    .line 126
    .line 127
    const-string v1, "Not a JSON Array: "

    .line 128
    .line 129
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p0

    .line 143
    :cond_8
    instance-of v0, p1, Lcom/google/gson/q;

    .line 144
    .line 145
    if-eqz v0, :cond_b

    .line 146
    .line 147
    invoke-virtual {p0}, Lpu/b;->d()V

    .line 148
    .line 149
    .line 150
    if-eqz v0, :cond_a

    .line 151
    .line 152
    check-cast p1, Lcom/google/gson/q;

    .line 153
    .line 154
    iget-object p1, p1, Lcom/google/gson/q;->d:Lcom/google/gson/internal/l;

    .line 155
    .line 156
    invoke-virtual {p1}, Lcom/google/gson/internal/l;->entrySet()Ljava/util/Set;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    check-cast p1, Lcom/google/gson/internal/j;

    .line 161
    .line 162
    invoke-virtual {p1}, Lcom/google/gson/internal/j;->iterator()Ljava/util/Iterator;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    :goto_2
    move-object v0, p1

    .line 167
    check-cast v0, Lcom/google/gson/internal/i;

    .line 168
    .line 169
    invoke-virtual {v0}, Lcom/google/gson/internal/i;->hasNext()Z

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-eqz v0, :cond_9

    .line 174
    .line 175
    move-object v0, p1

    .line 176
    check-cast v0, Lcom/google/gson/internal/i;

    .line 177
    .line 178
    invoke-virtual {v0}, Lcom/google/gson/internal/i;->b()Lcom/google/gson/internal/k;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    check-cast v1, Ljava/lang/String;

    .line 187
    .line 188
    invoke-virtual {p0, v1}, Lpu/b;->j(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    check-cast v0, Lcom/google/gson/n;

    .line 196
    .line 197
    invoke-static {p0, v0}, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;->e(Lpu/b;Lcom/google/gson/n;)V

    .line 198
    .line 199
    .line 200
    goto :goto_2

    .line 201
    :cond_9
    invoke-virtual {p0}, Lpu/b;->h()V

    .line 202
    .line 203
    .line 204
    return-void

    .line 205
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 206
    .line 207
    new-instance v0, Ljava/lang/StringBuilder;

    .line 208
    .line 209
    const-string v1, "Not a JSON Object: "

    .line 210
    .line 211
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p1

    .line 221
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw p0

    .line 225
    :cond_b
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 226
    .line 227
    new-instance v0, Ljava/lang/StringBuilder;

    .line 228
    .line 229
    const-string v1, "Couldn\'t write "

    .line 230
    .line 231
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object p1

    .line 245
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    throw p0

    .line 249
    :cond_c
    :goto_3
    invoke-virtual {p0}, Lpu/b;->l()Lpu/b;

    .line 250
    .line 251
    .line 252
    return-void
.end method


# virtual methods
.method public final b(Lpu/a;)Ljava/lang/Object;
    .locals 7

    .line 1
    invoke-virtual {p1}, Lpu/a;->l0()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Lu/w;->o(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x2

    .line 10
    const/4 v2, 0x0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    move-object v0, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {p1}, Lpu/a;->b()V

    .line 18
    .line 19
    .line 20
    new-instance v0, Lcom/google/gson/q;

    .line 21
    .line 22
    invoke-direct {v0}, Lcom/google/gson/q;-><init>()V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-virtual {p1}, Lpu/a;->a()V

    .line 27
    .line 28
    .line 29
    new-instance v0, Lcom/google/gson/l;

    .line 30
    .line 31
    invoke-direct {v0}, Lcom/google/gson/l;-><init>()V

    .line 32
    .line 33
    .line 34
    :goto_0
    if-nez v0, :cond_2

    .line 35
    .line 36
    invoke-static {p1, p0}, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;->d(Lpu/a;I)Lcom/google/gson/n;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_2
    new-instance p0, Ljava/util/ArrayDeque;

    .line 42
    .line 43
    invoke-direct {p0}, Ljava/util/ArrayDeque;-><init>()V

    .line 44
    .line 45
    .line 46
    :cond_3
    :goto_1
    invoke-virtual {p1}, Lpu/a;->l()Z

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-eqz v3, :cond_a

    .line 51
    .line 52
    instance-of v3, v0, Lcom/google/gson/q;

    .line 53
    .line 54
    if-eqz v3, :cond_4

    .line 55
    .line 56
    invoke-virtual {p1}, Lpu/a;->U()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    goto :goto_2

    .line 61
    :cond_4
    move-object v3, v2

    .line 62
    :goto_2
    invoke-virtual {p1}, Lpu/a;->l0()I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    invoke-static {v4}, Lu/w;->o(I)I

    .line 67
    .line 68
    .line 69
    move-result v5

    .line 70
    if-eqz v5, :cond_6

    .line 71
    .line 72
    if-eq v5, v1, :cond_5

    .line 73
    .line 74
    move-object v5, v2

    .line 75
    goto :goto_3

    .line 76
    :cond_5
    invoke-virtual {p1}, Lpu/a;->b()V

    .line 77
    .line 78
    .line 79
    new-instance v5, Lcom/google/gson/q;

    .line 80
    .line 81
    invoke-direct {v5}, Lcom/google/gson/q;-><init>()V

    .line 82
    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_6
    invoke-virtual {p1}, Lpu/a;->a()V

    .line 86
    .line 87
    .line 88
    new-instance v5, Lcom/google/gson/l;

    .line 89
    .line 90
    invoke-direct {v5}, Lcom/google/gson/l;-><init>()V

    .line 91
    .line 92
    .line 93
    :goto_3
    if-eqz v5, :cond_7

    .line 94
    .line 95
    const/4 v6, 0x1

    .line 96
    goto :goto_4

    .line 97
    :cond_7
    const/4 v6, 0x0

    .line 98
    :goto_4
    if-nez v5, :cond_8

    .line 99
    .line 100
    invoke-static {p1, v4}, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;->d(Lpu/a;I)Lcom/google/gson/n;

    .line 101
    .line 102
    .line 103
    move-result-object v5

    .line 104
    :cond_8
    instance-of v4, v0, Lcom/google/gson/l;

    .line 105
    .line 106
    if-eqz v4, :cond_9

    .line 107
    .line 108
    move-object v3, v0

    .line 109
    check-cast v3, Lcom/google/gson/l;

    .line 110
    .line 111
    iget-object v3, v3, Lcom/google/gson/l;->d:Ljava/util/ArrayList;

    .line 112
    .line 113
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    goto :goto_5

    .line 117
    :cond_9
    move-object v4, v0

    .line 118
    check-cast v4, Lcom/google/gson/q;

    .line 119
    .line 120
    iget-object v4, v4, Lcom/google/gson/q;->d:Lcom/google/gson/internal/l;

    .line 121
    .line 122
    invoke-virtual {v4, v3, v5}, Lcom/google/gson/internal/l;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    :goto_5
    if-eqz v6, :cond_3

    .line 126
    .line 127
    invoke-virtual {p0, v0}, Ljava/util/ArrayDeque;->addLast(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    move-object v0, v5

    .line 131
    goto :goto_1

    .line 132
    :cond_a
    instance-of v3, v0, Lcom/google/gson/l;

    .line 133
    .line 134
    if-eqz v3, :cond_b

    .line 135
    .line 136
    invoke-virtual {p1}, Lpu/a;->g()V

    .line 137
    .line 138
    .line 139
    goto :goto_6

    .line 140
    :cond_b
    invoke-virtual {p1}, Lpu/a;->h()V

    .line 141
    .line 142
    .line 143
    :goto_6
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 144
    .line 145
    .line 146
    move-result v3

    .line 147
    if-eqz v3, :cond_c

    .line 148
    .line 149
    return-object v0

    .line 150
    :cond_c
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->removeLast()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    check-cast v0, Lcom/google/gson/n;

    .line 155
    .line 156
    goto :goto_1
.end method

.method public final bridge synthetic c(Lpu/b;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lcom/google/gson/n;

    .line 2
    .line 3
    invoke-static {p1, p2}, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;->e(Lpu/b;Lcom/google/gson/n;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
