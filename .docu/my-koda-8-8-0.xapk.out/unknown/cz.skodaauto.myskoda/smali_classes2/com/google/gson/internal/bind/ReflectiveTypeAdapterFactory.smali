.class public final Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/z;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$RecordAdapter;,
        Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$FieldReflectionAdapter;,
        Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$Adapter;
    }
.end annotation


# instance fields
.field public final d:Lcom/google/android/gms/internal/measurement/i4;

.field public final e:Lcom/google/gson/h;

.field public final f:Lcom/google/gson/internal/Excluder;

.field public final g:Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;

.field public final h:Ljava/util/List;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/i4;Lcom/google/gson/h;Lcom/google/gson/internal/Excluder;Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->e:Lcom/google/gson/h;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->f:Lcom/google/gson/internal/Excluder;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->g:Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;

    .line 11
    .line 12
    iput-object p5, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->h:Ljava/util/List;

    .line 13
    .line 14
    return-void
.end method

.method public static b(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/reflect/Field;Ljava/lang/reflect/Field;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "Class "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, " declares multiple JSON fields named \'"

    .line 18
    .line 19
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, "\'; conflict is caused by fields "

    .line 26
    .line 27
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-static {p2}, Lou/c;->c(Ljava/lang/reflect/Field;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string p0, " and "

    .line 38
    .line 39
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-static {p3}, Lou/c;->c(Ljava/lang/reflect/Field;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string p0, "\nSee "

    .line 50
    .line 51
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string p0, "duplicate-fields"

    .line 55
    .line 56
    const-string p1, "https://github.com/google/gson/blob/main/Troubleshooting.md#"

    .line 57
    .line 58
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0
.end method


# virtual methods
.method public final a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 4

    .line 1
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-class v1, Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    return-object p0

    .line 15
    :cond_0
    sget-object v1, Lou/c;->a:Ljp/fc;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/Class;->getModifiers()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    invoke-static {v1}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_2

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/Class;->isAnonymousClass()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-nez v1, :cond_1

    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/Class;->isLocalClass()Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_2

    .line 38
    .line 39
    :cond_1
    new-instance p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$1;

    .line 40
    .line 41
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_2
    iget-object v1, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->h:Ljava/util/List;

    .line 46
    .line 47
    invoke-static {v1}, Lcom/google/gson/internal/f;->f(Ljava/util/List;)V

    .line 48
    .line 49
    .line 50
    sget-object v1, Lou/c;->a:Ljp/fc;

    .line 51
    .line 52
    invoke-virtual {v1, v0}, Ljp/fc;->f(Ljava/lang/Class;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    const/4 v2, 0x1

    .line 57
    if-eqz v1, :cond_3

    .line 58
    .line 59
    new-instance v1, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$RecordAdapter;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2, v0, v2}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->c(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Ljava/lang/Class;Z)Lcom/google/gson/internal/bind/d;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-direct {v1, v0, p0}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$RecordAdapter;-><init>(Ljava/lang/Class;Lcom/google/gson/internal/bind/d;)V

    .line 66
    .line 67
    .line 68
    return-object v1

    .line 69
    :cond_3
    iget-object v1, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 70
    .line 71
    invoke-virtual {v1, p2, v2}, Lcom/google/android/gms/internal/measurement/i4;->r(Lcom/google/gson/reflect/TypeToken;Z)Lcom/google/gson/internal/m;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    new-instance v2, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$FieldReflectionAdapter;

    .line 76
    .line 77
    const/4 v3, 0x0

    .line 78
    invoke-virtual {p0, p1, p2, v0, v3}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->c(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Ljava/lang/Class;Z)Lcom/google/gson/internal/bind/d;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-direct {v2, v1, p0}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory$FieldReflectionAdapter;-><init>(Lcom/google/gson/internal/m;Lcom/google/gson/internal/bind/d;)V

    .line 83
    .line 84
    .line 85
    return-object v2
.end method

.method public final c(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Ljava/lang/Class;Z)Lcom/google/gson/internal/bind/d;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v7, p3

    .line 4
    .line 5
    invoke-virtual {v7}, Ljava/lang/Class;->isInterface()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    sget-object v0, Lcom/google/gson/internal/bind/d;->c:Lcom/google/gson/internal/bind/d;

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    new-instance v8, Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-direct {v8}, Ljava/util/LinkedHashMap;-><init>()V

    .line 17
    .line 18
    .line 19
    new-instance v9, Ljava/util/LinkedHashMap;

    .line 20
    .line 21
    invoke-direct {v9}, Ljava/util/LinkedHashMap;-><init>()V

    .line 22
    .line 23
    .line 24
    move-object/from16 v10, p2

    .line 25
    .line 26
    move-object v11, v7

    .line 27
    :goto_0
    const-class v1, Ljava/lang/Object;

    .line 28
    .line 29
    if-eq v11, v1, :cond_16

    .line 30
    .line 31
    invoke-virtual {v11}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    .line 32
    .line 33
    .line 34
    move-result-object v12

    .line 35
    if-eq v11, v7, :cond_1

    .line 36
    .line 37
    array-length v1, v12

    .line 38
    if-lez v1, :cond_1

    .line 39
    .line 40
    iget-object v1, v0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->h:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v1}, Lcom/google/gson/internal/f;->f(Ljava/util/List;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    array-length v13, v12

    .line 46
    const/4 v14, 0x0

    .line 47
    move v15, v14

    .line 48
    :goto_1
    if-ge v15, v13, :cond_15

    .line 49
    .line 50
    aget-object v1, v12, v15

    .line 51
    .line 52
    const/4 v2, 0x1

    .line 53
    invoke-virtual {v0, v1, v2}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->d(Ljava/lang/reflect/Field;Z)Z

    .line 54
    .line 55
    .line 56
    move-result v24

    .line 57
    invoke-virtual {v0, v1, v14}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->d(Ljava/lang/reflect/Field;Z)Z

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    if-nez v24, :cond_2

    .line 62
    .line 63
    if-nez v3, :cond_2

    .line 64
    .line 65
    move-object/from16 v3, p1

    .line 66
    .line 67
    goto/16 :goto_e

    .line 68
    .line 69
    :cond_2
    const-class v4, Lmu/b;

    .line 70
    .line 71
    const/16 v25, 0x0

    .line 72
    .line 73
    if-eqz p4, :cond_6

    .line 74
    .line 75
    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getModifiers()I

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    invoke-static {v5}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    if-eqz v5, :cond_3

    .line 84
    .line 85
    move/from16 v26, v14

    .line 86
    .line 87
    :goto_2
    move-object/from16 v19, v25

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_3
    sget-object v5, Lou/c;->a:Ljp/fc;

    .line 91
    .line 92
    invoke-virtual {v5, v11, v1}, Ljp/fc;->c(Ljava/lang/Class;Ljava/lang/reflect/Field;)Ljava/lang/reflect/Method;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    invoke-static {v5}, Lou/c;->f(Ljava/lang/reflect/AccessibleObject;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v5, v4}, Ljava/lang/reflect/Method;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    if-eqz v6, :cond_5

    .line 104
    .line 105
    invoke-virtual {v1, v4}, Ljava/lang/reflect/Field;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    if-eqz v6, :cond_4

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_4
    invoke-static {v5, v14}, Lou/c;->d(Ljava/lang/reflect/AccessibleObject;Z)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    new-instance v1, Lcom/google/gson/o;

    .line 117
    .line 118
    const-string v2, "@SerializedName on "

    .line 119
    .line 120
    const-string v3, " is not supported"

    .line 121
    .line 122
    invoke-static {v2, v0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw v1

    .line 130
    :cond_5
    :goto_3
    move/from16 v26, v3

    .line 131
    .line 132
    move-object/from16 v19, v5

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_6
    move/from16 v26, v3

    .line 136
    .line 137
    goto :goto_2

    .line 138
    :goto_4
    if-nez v19, :cond_7

    .line 139
    .line 140
    invoke-static {v1}, Lou/c;->f(Ljava/lang/reflect/AccessibleObject;)V

    .line 141
    .line 142
    .line 143
    :cond_7
    invoke-virtual {v10}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 144
    .line 145
    .line 146
    move-result-object v3

    .line 147
    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getGenericType()Ljava/lang/reflect/Type;

    .line 148
    .line 149
    .line 150
    move-result-object v5

    .line 151
    new-instance v6, Ljava/util/HashMap;

    .line 152
    .line 153
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 154
    .line 155
    .line 156
    invoke-static {v3, v11, v5, v6}, Lcom/google/gson/internal/f;->j(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    invoke-virtual {v1, v4}, Ljava/lang/reflect/Field;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    check-cast v4, Lmu/b;

    .line 165
    .line 166
    if-nez v4, :cond_8

    .line 167
    .line 168
    iget-object v4, v0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->e:Lcom/google/gson/h;

    .line 169
    .line 170
    invoke-virtual {v4, v1}, Lcom/google/gson/h;->b(Ljava/lang/reflect/Field;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v4

    .line 174
    sget-object v5, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 175
    .line 176
    goto :goto_5

    .line 177
    :cond_8
    invoke-interface {v4}, Lmu/b;->value()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    invoke-interface {v4}, Lmu/b;->alternate()[Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v4

    .line 185
    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    move-object/from16 v28, v5

    .line 190
    .line 191
    move-object v5, v4

    .line 192
    move-object/from16 v4, v28

    .line 193
    .line 194
    :goto_5
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 195
    .line 196
    .line 197
    move-result v6

    .line 198
    if-eqz v6, :cond_9

    .line 199
    .line 200
    invoke-static {v4}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    move/from16 p2, v2

    .line 205
    .line 206
    move-object v2, v4

    .line 207
    goto :goto_6

    .line 208
    :cond_9
    new-instance v6, Ljava/util/ArrayList;

    .line 209
    .line 210
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 211
    .line 212
    .line 213
    move-result v16

    .line 214
    move/from16 p2, v2

    .line 215
    .line 216
    add-int/lit8 v2, v16, 0x1

    .line 217
    .line 218
    invoke-direct {v6, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 225
    .line 226
    .line 227
    move-object v2, v6

    .line 228
    :goto_6
    invoke-interface {v2, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v4

    .line 232
    move-object/from16 v17, v4

    .line 233
    .line 234
    check-cast v17, Ljava/lang/String;

    .line 235
    .line 236
    invoke-static {v3}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 237
    .line 238
    .line 239
    move-result-object v4

    .line 240
    invoke-virtual {v4}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 241
    .line 242
    .line 243
    move-result-object v3

    .line 244
    if-eqz v3, :cond_a

    .line 245
    .line 246
    invoke-virtual {v3}, Ljava/lang/Class;->isPrimitive()Z

    .line 247
    .line 248
    .line 249
    move-result v3

    .line 250
    if-eqz v3, :cond_a

    .line 251
    .line 252
    move/from16 v22, p2

    .line 253
    .line 254
    goto :goto_7

    .line 255
    :cond_a
    move/from16 v22, v14

    .line 256
    .line 257
    :goto_7
    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getModifiers()I

    .line 258
    .line 259
    .line 260
    move-result v3

    .line 261
    invoke-static {v3}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 262
    .line 263
    .line 264
    move-result v5

    .line 265
    if-eqz v5, :cond_b

    .line 266
    .line 267
    invoke-static {v3}, Ljava/lang/reflect/Modifier;->isFinal(I)Z

    .line 268
    .line 269
    .line 270
    move-result v3

    .line 271
    if-eqz v3, :cond_b

    .line 272
    .line 273
    move/from16 v23, p2

    .line 274
    .line 275
    goto :goto_8

    .line 276
    :cond_b
    move/from16 v23, v14

    .line 277
    .line 278
    :goto_8
    const-class v3, Lmu/a;

    .line 279
    .line 280
    invoke-virtual {v1, v3}, Ljava/lang/reflect/Field;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 281
    .line 282
    .line 283
    move-result-object v3

    .line 284
    move-object v5, v3

    .line 285
    check-cast v5, Lmu/a;

    .line 286
    .line 287
    if-eqz v5, :cond_c

    .line 288
    .line 289
    move-object v6, v2

    .line 290
    iget-object v2, v0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 291
    .line 292
    move-object v3, v6

    .line 293
    const/4 v6, 0x0

    .line 294
    move-object/from16 v18, v1

    .line 295
    .line 296
    iget-object v1, v0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->g:Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;

    .line 297
    .line 298
    move/from16 v16, p2

    .line 299
    .line 300
    move-object/from16 v27, v3

    .line 301
    .line 302
    move-object/from16 v3, p1

    .line 303
    .line 304
    invoke-virtual/range {v1 .. v6}, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->b(Lcom/google/android/gms/internal/measurement/i4;Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Lmu/a;Z)Lcom/google/gson/y;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    goto :goto_9

    .line 309
    :cond_c
    move-object/from16 v3, p1

    .line 310
    .line 311
    move/from16 v16, p2

    .line 312
    .line 313
    move-object/from16 v18, v1

    .line 314
    .line 315
    move-object/from16 v27, v2

    .line 316
    .line 317
    move-object/from16 v1, v25

    .line 318
    .line 319
    :goto_9
    if-eqz v1, :cond_d

    .line 320
    .line 321
    move/from16 v2, v16

    .line 322
    .line 323
    goto :goto_a

    .line 324
    :cond_d
    move v2, v14

    .line 325
    :goto_a
    if-nez v1, :cond_e

    .line 326
    .line 327
    invoke-virtual {v3, v4}, Lcom/google/gson/j;->c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 328
    .line 329
    .line 330
    move-result-object v1

    .line 331
    :cond_e
    if-eqz v24, :cond_10

    .line 332
    .line 333
    if-eqz v2, :cond_f

    .line 334
    .line 335
    move-object v2, v1

    .line 336
    goto :goto_b

    .line 337
    :cond_f
    new-instance v2, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 338
    .line 339
    invoke-virtual {v4}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 340
    .line 341
    .line 342
    move-result-object v4

    .line 343
    invoke-direct {v2, v3, v1, v4}, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;-><init>(Lcom/google/gson/j;Lcom/google/gson/y;Ljava/lang/reflect/Type;)V

    .line 344
    .line 345
    .line 346
    :goto_b
    move-object/from16 v20, v2

    .line 347
    .line 348
    goto :goto_c

    .line 349
    :cond_10
    move-object/from16 v20, v1

    .line 350
    .line 351
    :goto_c
    new-instance v16, Lcom/google/gson/internal/bind/c;

    .line 352
    .line 353
    move-object/from16 v21, v1

    .line 354
    .line 355
    invoke-direct/range {v16 .. v23}, Lcom/google/gson/internal/bind/c;-><init>(Ljava/lang/String;Ljava/lang/reflect/Field;Ljava/lang/reflect/Method;Lcom/google/gson/y;Lcom/google/gson/y;ZZ)V

    .line 356
    .line 357
    .line 358
    move-object/from16 v2, v16

    .line 359
    .line 360
    move-object/from16 v4, v17

    .line 361
    .line 362
    move-object/from16 v1, v18

    .line 363
    .line 364
    if-eqz v26, :cond_12

    .line 365
    .line 366
    invoke-interface/range {v27 .. v27}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 367
    .line 368
    .line 369
    move-result-object v5

    .line 370
    :goto_d
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 371
    .line 372
    .line 373
    move-result v6

    .line 374
    if-eqz v6, :cond_12

    .line 375
    .line 376
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v6

    .line 380
    check-cast v6, Ljava/lang/String;

    .line 381
    .line 382
    invoke-interface {v8, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v16

    .line 386
    move-object/from16 v14, v16

    .line 387
    .line 388
    check-cast v14, Lcom/google/gson/internal/bind/c;

    .line 389
    .line 390
    if-nez v14, :cond_11

    .line 391
    .line 392
    const/4 v14, 0x0

    .line 393
    goto :goto_d

    .line 394
    :cond_11
    iget-object v0, v14, Lcom/google/gson/internal/bind/c;->b:Ljava/lang/reflect/Field;

    .line 395
    .line 396
    invoke-static {v7, v6, v0, v1}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->b(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/reflect/Field;Ljava/lang/reflect/Field;)V

    .line 397
    .line 398
    .line 399
    throw v25

    .line 400
    :cond_12
    if-eqz v24, :cond_14

    .line 401
    .line 402
    invoke-interface {v9, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    move-result-object v2

    .line 406
    check-cast v2, Lcom/google/gson/internal/bind/c;

    .line 407
    .line 408
    if-nez v2, :cond_13

    .line 409
    .line 410
    goto :goto_e

    .line 411
    :cond_13
    iget-object v0, v2, Lcom/google/gson/internal/bind/c;->b:Ljava/lang/reflect/Field;

    .line 412
    .line 413
    invoke-static {v7, v4, v0, v1}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->b(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/reflect/Field;Ljava/lang/reflect/Field;)V

    .line 414
    .line 415
    .line 416
    throw v25

    .line 417
    :cond_14
    :goto_e
    add-int/lit8 v15, v15, 0x1

    .line 418
    .line 419
    const/4 v14, 0x0

    .line 420
    goto/16 :goto_1

    .line 421
    .line 422
    :cond_15
    move-object/from16 v3, p1

    .line 423
    .line 424
    invoke-virtual {v10}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 425
    .line 426
    .line 427
    move-result-object v1

    .line 428
    invoke-virtual {v11}, Ljava/lang/Class;->getGenericSuperclass()Ljava/lang/reflect/Type;

    .line 429
    .line 430
    .line 431
    move-result-object v2

    .line 432
    new-instance v4, Ljava/util/HashMap;

    .line 433
    .line 434
    invoke-direct {v4}, Ljava/util/HashMap;-><init>()V

    .line 435
    .line 436
    .line 437
    invoke-static {v1, v11, v2, v4}, Lcom/google/gson/internal/f;->j(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    invoke-static {v1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 442
    .line 443
    .line 444
    move-result-object v10

    .line 445
    invoke-virtual {v10}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 446
    .line 447
    .line 448
    move-result-object v11

    .line 449
    goto/16 :goto_0

    .line 450
    .line 451
    :cond_16
    new-instance v0, Lcom/google/gson/internal/bind/d;

    .line 452
    .line 453
    new-instance v1, Ljava/util/ArrayList;

    .line 454
    .line 455
    invoke-virtual {v9}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 460
    .line 461
    .line 462
    invoke-direct {v0, v1, v8}, Lcom/google/gson/internal/bind/d;-><init>(Ljava/util/List;Ljava/util/Map;)V

    .line 463
    .line 464
    .line 465
    return-object v0
.end method

.method public final d(Ljava/lang/reflect/Field;Z)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;->f:Lcom/google/gson/internal/Excluder;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/16 v0, 0x88

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/reflect/Field;->getModifiers()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    and-int/2addr v0, v1

    .line 13
    const/4 v1, 0x1

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    :goto_0
    move p0, v1

    .line 17
    goto :goto_3

    .line 18
    :cond_0
    invoke-virtual {p1}, Ljava/lang/reflect/Field;->isSynthetic()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-virtual {p1}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-virtual {p0, p1, p2}, Lcom/google/gson/internal/Excluder;->b(Ljava/lang/Class;Z)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_2

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    if-eqz p2, :cond_3

    .line 37
    .line 38
    iget-object p0, p0, Lcom/google/gson/internal/Excluder;->d:Ljava/util/List;

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_3
    iget-object p0, p0, Lcom/google/gson/internal/Excluder;->e:Ljava/util/List;

    .line 42
    .line 43
    :goto_1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-nez p1, :cond_5

    .line 48
    .line 49
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    if-nez p1, :cond_4

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_4
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    throw p0

    .line 65
    :cond_5
    :goto_2
    const/4 p0, 0x0

    .line 66
    :goto_3
    xor-int/2addr p0, v1

    .line 67
    return p0
.end method
