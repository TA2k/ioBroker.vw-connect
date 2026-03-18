.class public abstract Lx41/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/LinkedHashSet;)Ljava/util/ArrayList;
    .locals 10

    .line 1
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    move-object v3, v2

    .line 21
    check-cast v3, Lx41/n;

    .line 22
    .line 23
    invoke-interface {v3}, Lx41/n;->getVin()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-virtual {v0, v3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    if-nez v4, :cond_0

    .line 32
    .line 33
    new-instance v4, Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 36
    .line 37
    .line 38
    invoke-interface {v0, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    :cond_0
    check-cast v4, Ljava/util/List;

    .line 42
    .line 43
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    .line 48
    .line 49
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_8

    .line 69
    .line 70
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    check-cast v2, Ljava/util/Map$Entry;

    .line 75
    .line 76
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    check-cast v3, Ljava/lang/String;

    .line 81
    .line 82
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    check-cast v2, Ljava/util/List;

    .line 87
    .line 88
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    const/4 v5, 0x1

    .line 93
    if-ne v4, v5, :cond_2

    .line 94
    .line 95
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    check-cast v2, Lx41/n;

    .line 100
    .line 101
    goto/16 :goto_3

    .line 102
    .line 103
    :cond_2
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    check-cast v4, Lx41/n;

    .line 108
    .line 109
    check-cast v2, Ljava/lang/Iterable;

    .line 110
    .line 111
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    if-eqz v5, :cond_7

    .line 120
    .line 121
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    check-cast v5, Lx41/n;

    .line 126
    .line 127
    invoke-interface {v5}, Lx41/n;->a()Lx41/f;

    .line 128
    .line 129
    .line 130
    move-result-object v6

    .line 131
    const-string v7, "Car2PhonePairing"

    .line 132
    .line 133
    const/4 v8, 0x0

    .line 134
    if-eqz v6, :cond_3

    .line 135
    .line 136
    invoke-interface {v4}, Lx41/n;->a()Lx41/f;

    .line 137
    .line 138
    .line 139
    move-result-object v6

    .line 140
    if-eqz v6, :cond_3

    .line 141
    .line 142
    invoke-interface {v5}, Lx41/n;->a()Lx41/f;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    invoke-interface {v4}, Lx41/n;->a()Lx41/f;

    .line 147
    .line 148
    .line 149
    move-result-object v9

    .line 150
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v6

    .line 154
    if-nez v6, :cond_3

    .line 155
    .line 156
    new-instance v6, Lx41/a;

    .line 157
    .line 158
    const/4 v9, 0x0

    .line 159
    invoke-direct {v6, v4, v5, v9}, Lx41/a;-><init>(Lx41/n;Lx41/n;I)V

    .line 160
    .line 161
    .line 162
    invoke-static {p0, v7, v8, v6}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 163
    .line 164
    .line 165
    :cond_3
    invoke-interface {v5}, Lx41/n;->b()Lx41/f;

    .line 166
    .line 167
    .line 168
    move-result-object v6

    .line 169
    if-eqz v6, :cond_4

    .line 170
    .line 171
    invoke-interface {v4}, Lx41/n;->b()Lx41/f;

    .line 172
    .line 173
    .line 174
    move-result-object v6

    .line 175
    if-eqz v6, :cond_4

    .line 176
    .line 177
    invoke-interface {v5}, Lx41/n;->b()Lx41/f;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    invoke-interface {v4}, Lx41/n;->b()Lx41/f;

    .line 182
    .line 183
    .line 184
    move-result-object v9

    .line 185
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v6

    .line 189
    if-nez v6, :cond_4

    .line 190
    .line 191
    new-instance v6, Lx41/a;

    .line 192
    .line 193
    const/4 v9, 0x1

    .line 194
    invoke-direct {v6, v4, v5, v9}, Lx41/a;-><init>(Lx41/n;Lx41/n;I)V

    .line 195
    .line 196
    .line 197
    invoke-static {p0, v7, v8, v6}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 198
    .line 199
    .line 200
    :cond_4
    invoke-interface {v5}, Lx41/n;->a()Lx41/f;

    .line 201
    .line 202
    .line 203
    move-result-object v6

    .line 204
    if-nez v6, :cond_5

    .line 205
    .line 206
    invoke-interface {v4}, Lx41/n;->a()Lx41/f;

    .line 207
    .line 208
    .line 209
    move-result-object v6

    .line 210
    :cond_5
    invoke-interface {v5}, Lx41/n;->b()Lx41/f;

    .line 211
    .line 212
    .line 213
    move-result-object v5

    .line 214
    if-nez v5, :cond_6

    .line 215
    .line 216
    invoke-interface {v4}, Lx41/n;->b()Lx41/f;

    .line 217
    .line 218
    .line 219
    move-result-object v5

    .line 220
    :cond_6
    invoke-static {v4, v3, v6, v5}, Lx41/p;->a(Lx41/n;Ljava/lang/String;Lx41/f;Lx41/f;)Lx41/n;

    .line 221
    .line 222
    .line 223
    move-result-object v4

    .line 224
    goto :goto_2

    .line 225
    :cond_7
    move-object v2, v4

    .line 226
    :goto_3
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    goto/16 :goto_1

    .line 230
    .line 231
    :cond_8
    return-object v1
.end method

.method public static final b(Lx41/f;Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/VehicleAntenna$Information;
    .locals 8

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "antenna"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "keyPair"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 17
    .line 18
    new-instance v2, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 19
    .line 20
    invoke-direct {v2, p1, p2}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;)V

    .line 21
    .line 22
    .line 23
    iget-object v4, p0, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 24
    .line 25
    iget-short v5, p0, Lx41/f;->b:S

    .line 26
    .line 27
    iget-short v6, p0, Lx41/f;->c:S

    .line 28
    .line 29
    const/4 v7, 0x0

    .line 30
    move-object v3, p3

    .line 31
    invoke-direct/range {v1 .. v7}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLkotlin/jvm/internal/g;)V

    .line 32
    .line 33
    .line 34
    return-object v1
.end method
