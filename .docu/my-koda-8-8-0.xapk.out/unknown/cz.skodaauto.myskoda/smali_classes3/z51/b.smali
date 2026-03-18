.class public final Lz51/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lio/opentelemetry/api/logs/Logger;


# virtual methods
.method public final a(Ljava/lang/String;Ljava/util/Map;Lz51/c;Lgz0/w;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p5, Lz51/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p5

    .line 6
    check-cast v0, Lz51/a;

    .line 7
    .line 8
    iget v1, v0, Lz51/a;->f:I

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
    iput v1, v0, Lz51/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lz51/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p5}, Lz51/a;-><init>(Lz51/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p5, v0, Lz51/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lz51/a;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    if-eqz v2, :cond_5

    .line 35
    .line 36
    const/4 p1, 0x1

    .line 37
    const/4 p2, 0x2

    .line 38
    if-eq v2, p1, :cond_2

    .line 39
    .line 40
    if-ne v2, p2, :cond_1

    .line 41
    .line 42
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object v3

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    check-cast p5, Ljava/lang/Boolean;

    .line 58
    .line 59
    invoke-virtual {p5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 60
    .line 61
    .line 62
    move-result p3

    .line 63
    if-ne p3, p1, :cond_3

    .line 64
    .line 65
    move-object p1, v4

    .line 66
    move-object p2, p1

    .line 67
    move-object p3, p2

    .line 68
    move-object p4, p3

    .line 69
    goto :goto_1

    .line 70
    :cond_3
    sget-object p1, Lmy0/g;->a:Lmy0/b;

    .line 71
    .line 72
    invoke-interface {p1}, Lmy0/b;->now()Lmy0/f;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    sget-object p3, Lgz0/b0;->Companion:Lgz0/a0;

    .line 77
    .line 78
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    invoke-static {}, Lgz0/a0;->a()Lgz0/b0;

    .line 82
    .line 83
    .line 84
    move-result-object p3

    .line 85
    invoke-static {p1, p3}, Lkp/u9;->f(Lmy0/f;Lgz0/b0;)Lgz0/w;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    new-instance p3, Lc61/c;

    .line 90
    .line 91
    invoke-direct {p3, p1}, Lc61/c;-><init>(Lgz0/w;)V

    .line 92
    .line 93
    .line 94
    iput p2, v0, Lz51/a;->f:I

    .line 95
    .line 96
    sget-object p1, Lvy0/p0;->a:Lcz0/e;

    .line 97
    .line 98
    sget-object p1, Lcz0/d;->e:Lcz0/d;

    .line 99
    .line 100
    new-instance p2, Lwa0/c;

    .line 101
    .line 102
    const/16 p4, 0xf

    .line 103
    .line 104
    invoke-direct {p2, p4, p0, p3, v4}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 105
    .line 106
    .line 107
    invoke-static {p1, p2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    if-ne p0, v1, :cond_4

    .line 112
    .line 113
    return-object v1

    .line 114
    :cond_4
    return-object v3

    .line 115
    :cond_5
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    sget-object p5, Lz81/p;->b:Ljava/lang/String;

    .line 119
    .line 120
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    new-instance v1, Llx0/l;

    .line 129
    .line 130
    invoke-direct {v1, p5, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    invoke-static {p2, v1}, Lmx0/x;->q(Ljava/util/Map;Llx0/l;)Ljava/util/Map;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    :goto_1
    iget-object p0, p0, Lz51/b;->a:Lio/opentelemetry/api/logs/Logger;

    .line 138
    .line 139
    invoke-interface {p0}, Lio/opentelemetry/api/logs/Logger;->logRecordBuilder()Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    const-string p5, "level"

    .line 144
    .line 145
    invoke-static {p5}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 146
    .line 147
    .line 148
    move-result-object p5

    .line 149
    invoke-virtual {p3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object p3

    .line 153
    invoke-interface {p0, p5, p3}, Lio/opentelemetry/api/logs/LogRecordBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-interface {p0, p1}, Lio/opentelemetry/api/logs/LogRecordBuilder;->setBody(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 162
    .line 163
    .line 164
    move-result-object p3

    .line 165
    invoke-interface {p0, p3}, Lio/opentelemetry/api/logs/LogRecordBuilder;->setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 170
    .line 171
    .line 172
    move-result-object p2

    .line 173
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 174
    .line 175
    .line 176
    move-result-object p2

    .line 177
    :goto_2
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 178
    .line 179
    .line 180
    move-result p3

    .line 181
    if-eqz p3, :cond_6

    .line 182
    .line 183
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object p3

    .line 187
    check-cast p3, Ljava/util/Map$Entry;

    .line 188
    .line 189
    invoke-interface {p3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p5

    .line 193
    check-cast p5, Ljava/lang/String;

    .line 194
    .line 195
    invoke-static {p5}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 196
    .line 197
    .line 198
    move-result-object p5

    .line 199
    invoke-interface {p3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object p3

    .line 203
    invoke-interface {p0, p5, p3}, Lio/opentelemetry/api/logs/LogRecordBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 204
    .line 205
    .line 206
    goto :goto_2

    .line 207
    :cond_6
    if-eqz p4, :cond_7

    .line 208
    .line 209
    sget-object p2, Lgz0/b0;->Companion:Lgz0/a0;

    .line 210
    .line 211
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 212
    .line 213
    .line 214
    invoke-static {}, Lgz0/a0;->a()Lgz0/b0;

    .line 215
    .line 216
    .line 217
    move-result-object p2

    .line 218
    invoke-static {p4, p2}, Lkp/u9;->d(Lgz0/w;Lgz0/b0;)Lmy0/f;

    .line 219
    .line 220
    .line 221
    move-result-object p2

    .line 222
    invoke-static {p2}, Ljp/ab;->c(Lmy0/f;)Ljava/time/Instant;

    .line 223
    .line 224
    .line 225
    move-result-object p2

    .line 226
    invoke-interface {p0, p2}, Lio/opentelemetry/api/logs/LogRecordBuilder;->setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 227
    .line 228
    .line 229
    :cond_7
    invoke-interface {p0}, Lio/opentelemetry/api/logs/LogRecordBuilder;->emit()V

    .line 230
    .line 231
    .line 232
    sget-object p0, Lx51/c;->o1:Lx51/b;

    .line 233
    .line 234
    new-instance p2, Lq61/c;

    .line 235
    .line 236
    const/16 p3, 0x15

    .line 237
    .line 238
    invoke-direct {p2, p1, p3}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 239
    .line 240
    .line 241
    const/4 p1, 0x7

    .line 242
    invoke-static {p0, v4, p2, p1}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 243
    .line 244
    .line 245
    return-object v3
.end method
