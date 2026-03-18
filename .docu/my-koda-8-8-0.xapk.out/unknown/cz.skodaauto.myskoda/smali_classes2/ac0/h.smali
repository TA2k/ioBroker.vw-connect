.class public final Lac0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttCallback;


# instance fields
.field public final synthetic a:Lac0/w;


# direct methods
.method public constructor <init>(Lac0/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lac0/h;->a:Lac0/w;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final authPacketArrived(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final connectComplete(ZLjava/lang/String;)V
    .locals 2

    .line 1
    new-instance v0, Lac0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p1, p2, v1}, Lac0/g;-><init>(ZLjava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-static {p1, p0, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lac0/h;->a:Lac0/w;

    .line 12
    .line 13
    iget-object p0, p0, Lac0/w;->q:Lyy0/q1;

    .line 14
    .line 15
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final deliveryComplete(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final disconnected(Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;)V
    .locals 5

    .line 1
    new-instance v0, La71/u;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, p1, v1}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    iget-object p0, p0, Lac0/h;->a:Lac0/w;

    .line 9
    .line 10
    invoke-static {p1, p0, v0}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 11
    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    invoke-virtual {p0, p1}, Lac0/w;->c(Z)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 18
    .line 19
    new-instance v1, Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->size()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->entrySet()Ljava/util/Set;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_0

    .line 41
    .line 42
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    check-cast v3, Ljava/util/Map$Entry;

    .line 47
    .line 48
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    check-cast v3, Ldc0/b;

    .line 53
    .line 54
    iget-object v3, v3, Ldc0/b;->a:Ljava/lang/String;

    .line 55
    .line 56
    new-instance v4, Ldc0/b;

    .line 57
    .line 58
    invoke-direct {v4, v3}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_1

    .line 74
    .line 75
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Ldc0/b;

    .line 80
    .line 81
    iget-object v2, v2, Ldc0/b;->a:Ljava/lang/String;

    .line 82
    .line 83
    new-instance v3, Ldc0/b;

    .line 84
    .line 85
    invoke-direct {v3, v2}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    new-instance v4, Ldc0/b;

    .line 89
    .line 90
    invoke-direct {v4, v2}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-static {v0, v4}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    check-cast v2, Lac0/l;

    .line 98
    .line 99
    const/4 v4, 0x3

    .line 100
    invoke-static {v2, p1, p1, v4}, Lac0/l;->a(Lac0/l;IZI)Lac0/l;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    invoke-virtual {v0, v3, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_1
    iget-object p0, p0, Lac0/w;->q:Lyy0/q1;

    .line 109
    .line 110
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 111
    .line 112
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    return-void
.end method

.method public final messageArrived(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 10

    .line 1
    iget-object p0, p0, Lac0/h;->a:Lac0/w;

    .line 2
    .line 3
    iget-object v0, p0, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    new-instance p1, La2/m;

    .line 9
    .line 10
    const/4 p2, 0x6

    .line 11
    invoke-direct {p1, p2}, La2/m;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v1, p0, p1}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object v2, p0, Lac0/w;->t:Ljava/util/concurrent/ConcurrentHashMap;

    .line 19
    .line 20
    new-instance v3, Ldc0/b;

    .line 21
    .line 22
    invoke-direct {v3, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v2, v3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Lvy0/i1;

    .line 30
    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    invoke-interface {v2, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    new-instance v2, Laa/k;

    .line 37
    .line 38
    const/4 v3, 0x1

    .line 39
    invoke-direct {v2, v3, p2, p1}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v1, p0, v2}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 43
    .line 44
    .line 45
    const/4 v2, 0x0

    .line 46
    if-eqz p2, :cond_3

    .line 47
    .line 48
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getPayload()[B

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    if-eqz v3, :cond_3

    .line 53
    .line 54
    array-length v3, v3

    .line 55
    const/4 v4, 0x1

    .line 56
    if-nez v3, :cond_2

    .line 57
    .line 58
    move v3, v4

    .line 59
    goto :goto_0

    .line 60
    :cond_2
    move v3, v2

    .line 61
    :goto_0
    xor-int/2addr v3, v4

    .line 62
    if-ne v3, v4, :cond_3

    .line 63
    .line 64
    new-instance v3, Ldc0/a;

    .line 65
    .line 66
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getPayload()[B

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    const-string v4, "getPayload(...)"

    .line 71
    .line 72
    invoke-static {p2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    new-instance v4, Ljava/lang/String;

    .line 76
    .line 77
    sget-object v5, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 78
    .line 79
    invoke-direct {v4, p2, v5}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 80
    .line 81
    .line 82
    invoke-direct {v3, p1, v4}, Ldc0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_3
    new-instance v3, Ldc0/a;

    .line 87
    .line 88
    invoke-direct {v3, p1, v1}, Ldc0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    :goto_1
    new-instance p2, Ldc0/b;

    .line 92
    .line 93
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    filled-new-array {p2}, [Ldc0/b;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    invoke-static {p2}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->keySet()Ljava/util/Set;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    const-string v5, "<get-keys>(...)"

    .line 109
    .line 110
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    check-cast v4, Ljava/lang/Iterable;

    .line 114
    .line 115
    new-instance v5, Ljava/util/ArrayList;

    .line 116
    .line 117
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 118
    .line 119
    .line 120
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    :cond_4
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 125
    .line 126
    .line 127
    move-result v6

    .line 128
    if-eqz v6, :cond_5

    .line 129
    .line 130
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v6

    .line 134
    move-object v7, v6

    .line 135
    check-cast v7, Ldc0/b;

    .line 136
    .line 137
    iget-object v7, v7, Ldc0/b;->a:Ljava/lang/String;

    .line 138
    .line 139
    const-string v8, "+"

    .line 140
    .line 141
    invoke-static {v7, v8, v2}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 142
    .line 143
    .line 144
    move-result v9

    .line 145
    if-eqz v9, :cond_4

    .line 146
    .line 147
    const-string v9, ".*[^/]"

    .line 148
    .line 149
    invoke-static {v2, v7, v8, v9}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    invoke-static {v7}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    const-string v8, "compile(...)"

    .line 158
    .line 159
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v7, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 163
    .line 164
    .line 165
    move-result-object v7

    .line 166
    invoke-virtual {v7}, Ljava/util/regex/Matcher;->matches()Z

    .line 167
    .line 168
    .line 169
    move-result v7

    .line 170
    if-eqz v7, :cond_4

    .line 171
    .line 172
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_5
    invoke-virtual {p2, v5}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 177
    .line 178
    .line 179
    new-instance v2, Ljava/util/ArrayList;

    .line 180
    .line 181
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 185
    .line 186
    .line 187
    move-result-object p2

    .line 188
    :cond_6
    :goto_3
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 189
    .line 190
    .line 191
    move-result v4

    .line 192
    if-eqz v4, :cond_7

    .line 193
    .line 194
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    check-cast v4, Ldc0/b;

    .line 199
    .line 200
    iget-object v4, v4, Ldc0/b;->a:Ljava/lang/String;

    .line 201
    .line 202
    new-instance v5, Ldc0/b;

    .line 203
    .line 204
    invoke-direct {v5, v4}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v0, v5}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    check-cast v4, Lac0/l;

    .line 212
    .line 213
    if-eqz v4, :cond_6

    .line 214
    .line 215
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    goto :goto_3

    .line 219
    :cond_7
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 220
    .line 221
    .line 222
    move-result p2

    .line 223
    if-nez p2, :cond_8

    .line 224
    .line 225
    goto :goto_4

    .line 226
    :cond_8
    move-object v2, v1

    .line 227
    :goto_4
    if-eqz v2, :cond_a

    .line 228
    .line 229
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    :goto_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 234
    .line 235
    .line 236
    move-result p1

    .line 237
    if-eqz p1, :cond_9

    .line 238
    .line 239
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object p1

    .line 243
    check-cast p1, Lac0/l;

    .line 244
    .line 245
    iget-object p1, p1, Lac0/l;->b:Lyy0/i1;

    .line 246
    .line 247
    new-instance p2, Lne0/e;

    .line 248
    .line 249
    invoke-direct {p2, v3}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    invoke-interface {p1, p2}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    goto :goto_5

    .line 256
    :cond_9
    return-void

    .line 257
    :cond_a
    new-instance p2, Lac0/a;

    .line 258
    .line 259
    const/4 v0, 0x6

    .line 260
    invoke-direct {p2, p1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 261
    .line 262
    .line 263
    invoke-static {v1, p0, p2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 264
    .line 265
    .line 266
    return-void
.end method

.method public final mqttErrorOccurred(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 3

    .line 1
    new-instance v0, La2/m;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, La2/m;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    iget-object p0, p0, Lac0/h;->a:Lac0/w;

    .line 9
    .line 10
    invoke-static {v1, p0, v0}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 11
    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    new-instance v0, Lac0/c;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-direct {v0, p1, v2}, Lac0/c;-><init>(Lorg/eclipse/paho/mqttv5/common/MqttException;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v1, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method
