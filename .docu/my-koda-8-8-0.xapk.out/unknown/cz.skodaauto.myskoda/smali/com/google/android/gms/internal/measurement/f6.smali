.class public abstract Lcom/google/android/gms/internal/measurement/f6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[C


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x50

    .line 2
    .line 3
    new-array v0, v0, [C

    .line 4
    .line 5
    sput-object v0, Lcom/google/android/gms/internal/measurement/f6;->a:[C

    .line 6
    .line 7
    const/16 v1, 0x20

    .line 8
    .line 9
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([CC)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public static a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V
    .locals 4

    .line 1
    instance-of v0, p3, Ljava/util/List;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p3, Ljava/util/List;

    .line 6
    .line 7
    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p3

    .line 11
    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {p0, p1, p2, v0}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    instance-of v0, p3, Ljava/util/Map;

    .line 26
    .line 27
    if-eqz v0, :cond_2

    .line 28
    .line 29
    check-cast p3, Ljava/util/Map;

    .line 30
    .line 31
    invoke-interface {p3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 32
    .line 33
    .line 34
    move-result-object p3

    .line 35
    invoke-interface {p3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p3

    .line 39
    :goto_1
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Ljava/util/Map$Entry;

    .line 50
    .line 51
    invoke-static {p0, p1, p2, v0}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    return-void

    .line 56
    :cond_2
    const/16 v0, 0xa

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-static {p1, p0}, Lcom/google/android/gms/internal/measurement/f6;->c(ILjava/lang/StringBuilder;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p2}, Ljava/lang/String;->isEmpty()Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-nez v0, :cond_5

    .line 69
    .line 70
    new-instance v0, Ljava/lang/StringBuilder;

    .line 71
    .line 72
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 73
    .line 74
    .line 75
    const/4 v1, 0x0

    .line 76
    invoke-virtual {p2, v1}, Ljava/lang/String;->charAt(I)C

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    invoke-static {v1}, Ljava/lang/Character;->toLowerCase(C)C

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const/4 v1, 0x1

    .line 88
    :goto_2
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    if-ge v1, v2, :cond_4

    .line 93
    .line 94
    invoke-virtual {p2, v1}, Ljava/lang/String;->charAt(I)C

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    invoke-static {v2}, Ljava/lang/Character;->isUpperCase(C)Z

    .line 99
    .line 100
    .line 101
    move-result v3

    .line 102
    if-eqz v3, :cond_3

    .line 103
    .line 104
    const-string v3, "_"

    .line 105
    .line 106
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    :cond_3
    invoke-static {v2}, Ljava/lang/Character;->toLowerCase(C)C

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    add-int/lit8 v1, v1, 0x1

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_4
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    :cond_5
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    instance-of p2, p3, Ljava/lang/String;

    .line 127
    .line 128
    const/16 v0, 0x22

    .line 129
    .line 130
    const-string v1, ": \""

    .line 131
    .line 132
    if-eqz p2, :cond_6

    .line 133
    .line 134
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    check-cast p3, Ljava/lang/String;

    .line 138
    .line 139
    sget-object p1, Lcom/google/android/gms/internal/measurement/a5;->f:Lcom/google/android/gms/internal/measurement/a5;

    .line 140
    .line 141
    new-instance p1, Lcom/google/android/gms/internal/measurement/a5;

    .line 142
    .line 143
    sget-object p2, Lcom/google/android/gms/internal/measurement/s5;->a:Ljava/nio/charset/Charset;

    .line 144
    .line 145
    invoke-virtual {p3, p2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 146
    .line 147
    .line 148
    move-result-object p2

    .line 149
    invoke-direct {p1, p2}, Lcom/google/android/gms/internal/measurement/a5;-><init>([B)V

    .line 150
    .line 151
    .line 152
    invoke-static {p1}, Ljp/be;->c(Lcom/google/android/gms/internal/measurement/a5;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    return-void

    .line 163
    :cond_6
    instance-of p2, p3, Lcom/google/android/gms/internal/measurement/a5;

    .line 164
    .line 165
    if-eqz p2, :cond_7

    .line 166
    .line 167
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    check-cast p3, Lcom/google/android/gms/internal/measurement/a5;

    .line 171
    .line 172
    invoke-static {p3}, Ljp/be;->c(Lcom/google/android/gms/internal/measurement/a5;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    return-void

    .line 183
    :cond_7
    instance-of p2, p3, Lcom/google/android/gms/internal/measurement/l5;

    .line 184
    .line 185
    const-string v0, "}"

    .line 186
    .line 187
    const-string v1, "\n"

    .line 188
    .line 189
    const-string v2, " {"

    .line 190
    .line 191
    if-eqz p2, :cond_8

    .line 192
    .line 193
    add-int/lit8 p2, p1, 0x2

    .line 194
    .line 195
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    check-cast p3, Lcom/google/android/gms/internal/measurement/l5;

    .line 199
    .line 200
    invoke-static {p3, p0, p2}, Lcom/google/android/gms/internal/measurement/f6;->b(Lcom/google/android/gms/internal/measurement/l5;Ljava/lang/StringBuilder;I)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    invoke-static {p1, p0}, Lcom/google/android/gms/internal/measurement/f6;->c(ILjava/lang/StringBuilder;)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 210
    .line 211
    .line 212
    return-void

    .line 213
    :cond_8
    instance-of p2, p3, Ljava/util/Map$Entry;

    .line 214
    .line 215
    if-eqz p2, :cond_9

    .line 216
    .line 217
    add-int/lit8 p2, p1, 0x2

    .line 218
    .line 219
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    check-cast p3, Ljava/util/Map$Entry;

    .line 223
    .line 224
    invoke-interface {p3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v2

    .line 228
    const-string v3, "key"

    .line 229
    .line 230
    invoke-static {p0, p2, v3, v2}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    invoke-interface {p3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object p3

    .line 237
    const-string v2, "value"

    .line 238
    .line 239
    invoke-static {p0, p2, v2, p3}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 243
    .line 244
    .line 245
    invoke-static {p1, p0}, Lcom/google/android/gms/internal/measurement/f6;->c(ILjava/lang/StringBuilder;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    return-void

    .line 252
    :cond_9
    const-string p1, ": "

    .line 253
    .line 254
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 258
    .line 259
    .line 260
    return-void
.end method

.method public static b(Lcom/google/android/gms/internal/measurement/l5;Ljava/lang/StringBuilder;I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    new-instance v3, Ljava/util/HashSet;

    .line 8
    .line 9
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 10
    .line 11
    .line 12
    new-instance v4, Ljava/util/HashMap;

    .line 13
    .line 14
    invoke-direct {v4}, Ljava/util/HashMap;-><init>()V

    .line 15
    .line 16
    .line 17
    new-instance v5, Ljava/util/TreeMap;

    .line 18
    .line 19
    invoke-direct {v5}, Ljava/util/TreeMap;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v6

    .line 26
    invoke-virtual {v6}, Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    array-length v7, v6

    .line 31
    const/4 v8, 0x0

    .line 32
    move v9, v8

    .line 33
    :goto_0
    const-string v10, "get"

    .line 34
    .line 35
    const-string v11, "has"

    .line 36
    .line 37
    const-string v12, "set"

    .line 38
    .line 39
    const/4 v13, 0x3

    .line 40
    if-ge v9, v7, :cond_4

    .line 41
    .line 42
    aget-object v14, v6, v9

    .line 43
    .line 44
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getModifiers()I

    .line 45
    .line 46
    .line 47
    move-result v15

    .line 48
    invoke-static {v15}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 49
    .line 50
    .line 51
    move-result v15

    .line 52
    if-eqz v15, :cond_0

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_0
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v15

    .line 59
    invoke-virtual {v15}, Ljava/lang/String;->length()I

    .line 60
    .line 61
    .line 62
    move-result v15

    .line 63
    if-lt v15, v13, :cond_3

    .line 64
    .line 65
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v13

    .line 69
    invoke-virtual {v13, v12}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 70
    .line 71
    .line 72
    move-result v12

    .line 73
    if-eqz v12, :cond_1

    .line 74
    .line 75
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v10

    .line 79
    invoke-virtual {v3, v10}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_1
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getModifiers()I

    .line 84
    .line 85
    .line 86
    move-result v12

    .line 87
    invoke-static {v12}, Ljava/lang/reflect/Modifier;->isPublic(I)Z

    .line 88
    .line 89
    .line 90
    move-result v12

    .line 91
    if-eqz v12, :cond_3

    .line 92
    .line 93
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    move-result-object v12

    .line 97
    array-length v12, v12

    .line 98
    if-nez v12, :cond_3

    .line 99
    .line 100
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v12

    .line 104
    invoke-virtual {v12, v11}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 105
    .line 106
    .line 107
    move-result v11

    .line 108
    if-eqz v11, :cond_2

    .line 109
    .line 110
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v10

    .line 114
    invoke-virtual {v4, v10, v14}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_2
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v11

    .line 122
    invoke-virtual {v11, v10}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 123
    .line 124
    .line 125
    move-result v10

    .line 126
    if-eqz v10, :cond_3

    .line 127
    .line 128
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v10

    .line 132
    invoke-virtual {v5, v10, v14}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    :cond_3
    :goto_1
    add-int/lit8 v9, v9, 0x1

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_4
    invoke-virtual {v5}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    invoke-interface {v6}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    :goto_2
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 147
    .line 148
    .line 149
    move-result v7

    .line 150
    if-eqz v7, :cond_13

    .line 151
    .line 152
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v7

    .line 156
    check-cast v7, Ljava/util/Map$Entry;

    .line 157
    .line 158
    invoke-interface {v7}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v9

    .line 162
    check-cast v9, Ljava/lang/String;

    .line 163
    .line 164
    invoke-virtual {v9, v13}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v9

    .line 168
    const-string v14, "List"

    .line 169
    .line 170
    invoke-virtual {v9, v14}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 171
    .line 172
    .line 173
    move-result v15

    .line 174
    if-eqz v15, :cond_6

    .line 175
    .line 176
    const-string v15, "OrBuilderList"

    .line 177
    .line 178
    invoke-virtual {v9, v15}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 179
    .line 180
    .line 181
    move-result v15

    .line 182
    if-nez v15, :cond_6

    .line 183
    .line 184
    invoke-virtual {v9, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v14

    .line 188
    if-nez v14, :cond_6

    .line 189
    .line 190
    invoke-interface {v7}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v14

    .line 194
    check-cast v14, Ljava/lang/reflect/Method;

    .line 195
    .line 196
    if-eqz v14, :cond_6

    .line 197
    .line 198
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 199
    .line 200
    .line 201
    move-result-object v15

    .line 202
    move/from16 v16, v13

    .line 203
    .line 204
    const-class v13, Ljava/util/List;

    .line 205
    .line 206
    invoke-virtual {v15, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v13

    .line 210
    if-eqz v13, :cond_7

    .line 211
    .line 212
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 213
    .line 214
    .line 215
    move-result v7

    .line 216
    add-int/lit8 v7, v7, -0x4

    .line 217
    .line 218
    invoke-virtual {v9, v8, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object v7

    .line 222
    new-array v9, v8, [Ljava/lang/Object;

    .line 223
    .line 224
    invoke-static {v14, v0, v9}, Lcom/google/android/gms/internal/measurement/l5;->n(Ljava/lang/reflect/Method;Lcom/google/android/gms/internal/measurement/l5;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v9

    .line 228
    invoke-static {v1, v2, v7, v9}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    :cond_5
    :goto_3
    move/from16 v13, v16

    .line 232
    .line 233
    goto :goto_2

    .line 234
    :cond_6
    move/from16 v16, v13

    .line 235
    .line 236
    :cond_7
    const-string v13, "Map"

    .line 237
    .line 238
    invoke-virtual {v9, v13}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 239
    .line 240
    .line 241
    move-result v14

    .line 242
    if-eqz v14, :cond_8

    .line 243
    .line 244
    invoke-virtual {v9, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result v13

    .line 248
    if-nez v13, :cond_8

    .line 249
    .line 250
    invoke-interface {v7}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v13

    .line 254
    check-cast v13, Ljava/lang/reflect/Method;

    .line 255
    .line 256
    if-eqz v13, :cond_8

    .line 257
    .line 258
    invoke-virtual {v13}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 259
    .line 260
    .line 261
    move-result-object v14

    .line 262
    const-class v15, Ljava/util/Map;

    .line 263
    .line 264
    invoke-virtual {v14, v15}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v14

    .line 268
    if-eqz v14, :cond_8

    .line 269
    .line 270
    const-class v14, Ljava/lang/Deprecated;

    .line 271
    .line 272
    invoke-virtual {v13, v14}, Ljava/lang/reflect/AccessibleObject;->isAnnotationPresent(Ljava/lang/Class;)Z

    .line 273
    .line 274
    .line 275
    move-result v14

    .line 276
    if-nez v14, :cond_8

    .line 277
    .line 278
    invoke-virtual {v13}, Ljava/lang/reflect/Method;->getModifiers()I

    .line 279
    .line 280
    .line 281
    move-result v14

    .line 282
    invoke-static {v14}, Ljava/lang/reflect/Modifier;->isPublic(I)Z

    .line 283
    .line 284
    .line 285
    move-result v14

    .line 286
    if-eqz v14, :cond_8

    .line 287
    .line 288
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 289
    .line 290
    .line 291
    move-result v7

    .line 292
    add-int/lit8 v7, v7, -0x3

    .line 293
    .line 294
    invoke-virtual {v9, v8, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v7

    .line 298
    new-array v9, v8, [Ljava/lang/Object;

    .line 299
    .line 300
    invoke-static {v13, v0, v9}, Lcom/google/android/gms/internal/measurement/l5;->n(Ljava/lang/reflect/Method;Lcom/google/android/gms/internal/measurement/l5;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v9

    .line 304
    invoke-static {v1, v2, v7, v9}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    goto :goto_3

    .line 308
    :cond_8
    invoke-virtual {v12, v9}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v13

    .line 312
    invoke-virtual {v3, v13}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    move-result v13

    .line 316
    if-eqz v13, :cond_5

    .line 317
    .line 318
    const-string v13, "Bytes"

    .line 319
    .line 320
    invoke-virtual {v9, v13}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 321
    .line 322
    .line 323
    move-result v13

    .line 324
    if-eqz v13, :cond_9

    .line 325
    .line 326
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 327
    .line 328
    .line 329
    move-result v13

    .line 330
    add-int/lit8 v13, v13, -0x5

    .line 331
    .line 332
    invoke-virtual {v9, v8, v13}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object v13

    .line 336
    invoke-static {v13}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v13

    .line 340
    invoke-virtual {v10, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v13

    .line 344
    invoke-virtual {v5, v13}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    move-result v13

    .line 348
    if-nez v13, :cond_5

    .line 349
    .line 350
    :cond_9
    invoke-interface {v7}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v7

    .line 354
    check-cast v7, Ljava/lang/reflect/Method;

    .line 355
    .line 356
    invoke-virtual {v11, v9}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object v13

    .line 360
    invoke-virtual {v4, v13}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 361
    .line 362
    .line 363
    move-result-object v13

    .line 364
    check-cast v13, Ljava/lang/reflect/Method;

    .line 365
    .line 366
    if-eqz v7, :cond_5

    .line 367
    .line 368
    new-array v14, v8, [Ljava/lang/Object;

    .line 369
    .line 370
    invoke-static {v7, v0, v14}, Lcom/google/android/gms/internal/measurement/l5;->n(Ljava/lang/reflect/Method;Lcom/google/android/gms/internal/measurement/l5;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v7

    .line 374
    if-nez v13, :cond_11

    .line 375
    .line 376
    instance-of v13, v7, Ljava/lang/Boolean;

    .line 377
    .line 378
    if-eqz v13, :cond_a

    .line 379
    .line 380
    move-object v13, v7

    .line 381
    check-cast v13, Ljava/lang/Boolean;

    .line 382
    .line 383
    invoke-virtual {v13}, Ljava/lang/Boolean;->booleanValue()Z

    .line 384
    .line 385
    .line 386
    move-result v13

    .line 387
    if-eqz v13, :cond_5

    .line 388
    .line 389
    goto/16 :goto_5

    .line 390
    .line 391
    :cond_a
    instance-of v13, v7, Ljava/lang/Integer;

    .line 392
    .line 393
    if-eqz v13, :cond_b

    .line 394
    .line 395
    move-object v13, v7

    .line 396
    check-cast v13, Ljava/lang/Integer;

    .line 397
    .line 398
    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    .line 399
    .line 400
    .line 401
    move-result v13

    .line 402
    if-eqz v13, :cond_5

    .line 403
    .line 404
    goto/16 :goto_5

    .line 405
    .line 406
    :cond_b
    instance-of v13, v7, Ljava/lang/Float;

    .line 407
    .line 408
    if-eqz v13, :cond_c

    .line 409
    .line 410
    move-object v13, v7

    .line 411
    check-cast v13, Ljava/lang/Float;

    .line 412
    .line 413
    invoke-virtual {v13}, Ljava/lang/Float;->floatValue()F

    .line 414
    .line 415
    .line 416
    move-result v13

    .line 417
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 418
    .line 419
    .line 420
    move-result v13

    .line 421
    if-eqz v13, :cond_5

    .line 422
    .line 423
    goto :goto_5

    .line 424
    :cond_c
    instance-of v13, v7, Ljava/lang/Double;

    .line 425
    .line 426
    if-eqz v13, :cond_d

    .line 427
    .line 428
    move-object v13, v7

    .line 429
    check-cast v13, Ljava/lang/Double;

    .line 430
    .line 431
    invoke-virtual {v13}, Ljava/lang/Double;->doubleValue()D

    .line 432
    .line 433
    .line 434
    move-result-wide v13

    .line 435
    invoke-static {v13, v14}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 436
    .line 437
    .line 438
    move-result-wide v13

    .line 439
    const-wide/16 v17, 0x0

    .line 440
    .line 441
    cmp-long v13, v13, v17

    .line 442
    .line 443
    if-eqz v13, :cond_5

    .line 444
    .line 445
    goto :goto_5

    .line 446
    :cond_d
    instance-of v13, v7, Ljava/lang/String;

    .line 447
    .line 448
    if-eqz v13, :cond_e

    .line 449
    .line 450
    const-string v13, ""

    .line 451
    .line 452
    invoke-virtual {v7, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 453
    .line 454
    .line 455
    move-result v13

    .line 456
    goto :goto_4

    .line 457
    :cond_e
    instance-of v13, v7, Lcom/google/android/gms/internal/measurement/a5;

    .line 458
    .line 459
    if-eqz v13, :cond_f

    .line 460
    .line 461
    sget-object v13, Lcom/google/android/gms/internal/measurement/a5;->f:Lcom/google/android/gms/internal/measurement/a5;

    .line 462
    .line 463
    invoke-virtual {v7, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 464
    .line 465
    .line 466
    move-result v13

    .line 467
    :goto_4
    if-nez v13, :cond_5

    .line 468
    .line 469
    goto :goto_5

    .line 470
    :cond_f
    instance-of v13, v7, Lcom/google/android/gms/internal/measurement/t4;

    .line 471
    .line 472
    if-eqz v13, :cond_10

    .line 473
    .line 474
    move-object v13, v7

    .line 475
    check-cast v13, Lcom/google/android/gms/internal/measurement/t4;

    .line 476
    .line 477
    check-cast v13, Lcom/google/android/gms/internal/measurement/l5;

    .line 478
    .line 479
    const/4 v14, 0x6

    .line 480
    invoke-virtual {v13, v14}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v13

    .line 484
    check-cast v13, Lcom/google/android/gms/internal/measurement/l5;

    .line 485
    .line 486
    if-eq v7, v13, :cond_5

    .line 487
    .line 488
    goto :goto_5

    .line 489
    :cond_10
    instance-of v13, v7, Ljava/lang/Enum;

    .line 490
    .line 491
    if-eqz v13, :cond_12

    .line 492
    .line 493
    move-object v13, v7

    .line 494
    check-cast v13, Ljava/lang/Enum;

    .line 495
    .line 496
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    .line 497
    .line 498
    .line 499
    move-result v13

    .line 500
    if-eqz v13, :cond_5

    .line 501
    .line 502
    goto :goto_5

    .line 503
    :cond_11
    new-array v14, v8, [Ljava/lang/Object;

    .line 504
    .line 505
    invoke-static {v13, v0, v14}, Lcom/google/android/gms/internal/measurement/l5;->n(Ljava/lang/reflect/Method;Lcom/google/android/gms/internal/measurement/l5;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 506
    .line 507
    .line 508
    move-result-object v13

    .line 509
    check-cast v13, Ljava/lang/Boolean;

    .line 510
    .line 511
    invoke-virtual {v13}, Ljava/lang/Boolean;->booleanValue()Z

    .line 512
    .line 513
    .line 514
    move-result v13

    .line 515
    if-eqz v13, :cond_5

    .line 516
    .line 517
    :cond_12
    :goto_5
    invoke-static {v1, v2, v9, v7}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 518
    .line 519
    .line 520
    goto/16 :goto_3

    .line 521
    .line 522
    :cond_13
    move/from16 v16, v13

    .line 523
    .line 524
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/l5;->zzc:Lcom/google/android/gms/internal/measurement/r6;

    .line 525
    .line 526
    if-eqz v0, :cond_14

    .line 527
    .line 528
    :goto_6
    iget v3, v0, Lcom/google/android/gms/internal/measurement/r6;->a:I

    .line 529
    .line 530
    if-ge v8, v3, :cond_14

    .line 531
    .line 532
    iget-object v3, v0, Lcom/google/android/gms/internal/measurement/r6;->b:[I

    .line 533
    .line 534
    aget v3, v3, v8

    .line 535
    .line 536
    ushr-int/lit8 v3, v3, 0x3

    .line 537
    .line 538
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 539
    .line 540
    .line 541
    move-result-object v3

    .line 542
    iget-object v4, v0, Lcom/google/android/gms/internal/measurement/r6;->c:[Ljava/lang/Object;

    .line 543
    .line 544
    aget-object v4, v4, v8

    .line 545
    .line 546
    invoke-static {v1, v2, v3, v4}, Lcom/google/android/gms/internal/measurement/f6;->a(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 547
    .line 548
    .line 549
    add-int/lit8 v8, v8, 0x1

    .line 550
    .line 551
    goto :goto_6

    .line 552
    :cond_14
    return-void
.end method

.method public static c(ILjava/lang/StringBuilder;)V
    .locals 3

    .line 1
    :goto_0
    if-lez p0, :cond_1

    .line 2
    .line 3
    const/16 v0, 0x50

    .line 4
    .line 5
    if-le p0, v0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    move v0, p0

    .line 9
    :goto_1
    sget-object v1, Lcom/google/android/gms/internal/measurement/f6;->a:[C

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-virtual {p1, v1, v2, v0}, Ljava/lang/StringBuilder;->append([CII)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    sub-int/2addr p0, v0

    .line 16
    goto :goto_0

    .line 17
    :cond_1
    return-void
.end method
