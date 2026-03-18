.class Lcom/auth0/android/jwt/JWTDeserializer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/m;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lcom/google/gson/m;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static a(Lcom/google/gson/q;Ljava/lang/String;)Ljava/util/Date;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/gson/q;->d:Lcom/google/gson/internal/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/google/gson/internal/l;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/gson/internal/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lcom/google/gson/n;

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/google/gson/n;->c()J

    .line 18
    .line 19
    .line 20
    move-result-wide p0

    .line 21
    const-wide/16 v0, 0x3e8

    .line 22
    .line 23
    mul-long/2addr p0, v0

    .line 24
    new-instance v0, Ljava/util/Date;

    .line 25
    .line 26
    invoke-direct {v0, p0, p1}, Ljava/util/Date;-><init>(J)V

    .line 27
    .line 28
    .line 29
    return-object v0
.end method


# virtual methods
.method public final b(Lcom/google/gson/n;Ljava/lang/reflect/Type;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of p0, p1, Lcom/google/gson/p;

    .line 5
    .line 6
    if-nez p0, :cond_9

    .line 7
    .line 8
    instance-of p0, p1, Lcom/google/gson/q;

    .line 9
    .line 10
    if-eqz p0, :cond_9

    .line 11
    .line 12
    if-eqz p0, :cond_8

    .line 13
    .line 14
    check-cast p1, Lcom/google/gson/q;

    .line 15
    .line 16
    iget-object p0, p1, Lcom/google/gson/q;->d:Lcom/google/gson/internal/l;

    .line 17
    .line 18
    const-string p2, "iss"

    .line 19
    .line 20
    invoke-virtual {p0, p2}, Lcom/google/gson/internal/l;->containsKey(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-nez v0, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {p0, p2}, Lcom/google/gson/internal/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    check-cast p2, Lcom/google/gson/n;

    .line 32
    .line 33
    invoke-virtual {p2}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    :goto_0
    const-string p2, "sub"

    .line 37
    .line 38
    invoke-virtual {p0, p2}, Lcom/google/gson/internal/l;->containsKey(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-nez v0, :cond_1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    invoke-virtual {p0, p2}, Lcom/google/gson/internal/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    check-cast p2, Lcom/google/gson/n;

    .line 50
    .line 51
    invoke-virtual {p2}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    :goto_1
    const-string p2, "exp"

    .line 55
    .line 56
    invoke-static {p1, p2}, Lcom/auth0/android/jwt/JWTDeserializer;->a(Lcom/google/gson/q;Ljava/lang/String;)Ljava/util/Date;

    .line 57
    .line 58
    .line 59
    const-string p2, "nbf"

    .line 60
    .line 61
    invoke-static {p1, p2}, Lcom/auth0/android/jwt/JWTDeserializer;->a(Lcom/google/gson/q;Ljava/lang/String;)Ljava/util/Date;

    .line 62
    .line 63
    .line 64
    const-string p2, "iat"

    .line 65
    .line 66
    invoke-static {p1, p2}, Lcom/auth0/android/jwt/JWTDeserializer;->a(Lcom/google/gson/q;Ljava/lang/String;)Ljava/util/Date;

    .line 67
    .line 68
    .line 69
    const-string p1, "jti"

    .line 70
    .line 71
    invoke-virtual {p0, p1}, Lcom/google/gson/internal/l;->containsKey(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    if-nez p2, :cond_2

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_2
    invoke-virtual {p0, p1}, Lcom/google/gson/internal/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    check-cast p1, Lcom/google/gson/n;

    .line 83
    .line 84
    invoke-virtual {p1}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    :goto_2
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 88
    .line 89
    const-string p2, "aud"

    .line 90
    .line 91
    invoke-virtual {p0, p2}, Lcom/google/gson/internal/l;->containsKey(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_6

    .line 96
    .line 97
    invoke-virtual {p0, p2}, Lcom/google/gson/internal/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    check-cast p1, Lcom/google/gson/n;

    .line 102
    .line 103
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    instance-of p2, p1, Lcom/google/gson/l;

    .line 107
    .line 108
    if-eqz p2, :cond_5

    .line 109
    .line 110
    if-eqz p2, :cond_4

    .line 111
    .line 112
    check-cast p1, Lcom/google/gson/l;

    .line 113
    .line 114
    iget-object p1, p1, Lcom/google/gson/l;->d:Ljava/util/ArrayList;

    .line 115
    .line 116
    new-instance p2, Ljava/util/ArrayList;

    .line 117
    .line 118
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    invoke-direct {p2, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 123
    .line 124
    .line 125
    const/4 v0, 0x0

    .line 126
    :goto_3
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-ge v0, v1, :cond_3

    .line 131
    .line 132
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    check-cast v1, Lcom/google/gson/n;

    .line 137
    .line 138
    invoke-virtual {v1}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-virtual {p2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    add-int/lit8 v0, v0, 0x1

    .line 146
    .line 147
    goto :goto_3

    .line 148
    :cond_3
    move-object p1, p2

    .line 149
    goto :goto_4

    .line 150
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 151
    .line 152
    new-instance p2, Ljava/lang/StringBuilder;

    .line 153
    .line 154
    const-string v0, "Not a JSON Array: "

    .line 155
    .line 156
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw p0

    .line 170
    :cond_5
    invoke-virtual {p1}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    :cond_6
    :goto_4
    new-instance p2, Ljava/util/HashMap;

    .line 179
    .line 180
    invoke-direct {p2}, Ljava/util/HashMap;-><init>()V

    .line 181
    .line 182
    .line 183
    invoke-virtual {p0}, Lcom/google/gson/internal/l;->entrySet()Ljava/util/Set;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    check-cast p0, Lcom/google/gson/internal/j;

    .line 188
    .line 189
    invoke-virtual {p0}, Lcom/google/gson/internal/j;->iterator()Ljava/util/Iterator;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    :goto_5
    move-object v0, p0

    .line 194
    check-cast v0, Lcom/google/gson/internal/i;

    .line 195
    .line 196
    invoke-virtual {v0}, Lcom/google/gson/internal/i;->hasNext()Z

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    if-eqz v0, :cond_7

    .line 201
    .line 202
    move-object v0, p0

    .line 203
    check-cast v0, Lcom/google/gson/internal/i;

    .line 204
    .line 205
    invoke-virtual {v0}, Lcom/google/gson/internal/i;->b()Lcom/google/gson/internal/k;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    new-instance v2, Lcom/auth0/android/jwt/b;

    .line 214
    .line 215
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    check-cast v0, Lcom/google/gson/n;

    .line 220
    .line 221
    invoke-direct {v2, v0}, Lcom/auth0/android/jwt/b;-><init>(Lcom/google/gson/n;)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {p2, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    goto :goto_5

    .line 228
    :cond_7
    new-instance p0, Lcom/auth0/android/jwt/d;

    .line 229
    .line 230
    invoke-direct {p0, p1, p2}, Lcom/auth0/android/jwt/d;-><init>(Ljava/util/List;Ljava/util/HashMap;)V

    .line 231
    .line 232
    .line 233
    return-object p0

    .line 234
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 235
    .line 236
    new-instance p2, Ljava/lang/StringBuilder;

    .line 237
    .line 238
    const-string v0, "Not a JSON Object: "

    .line 239
    .line 240
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 244
    .line 245
    .line 246
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object p1

    .line 250
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    throw p0

    .line 254
    :cond_9
    new-instance p0, La8/r0;

    .line 255
    .line 256
    const-string p1, "The token\'s payload had an invalid JSON format."

    .line 257
    .line 258
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    throw p0
.end method
