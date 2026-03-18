.class public final Landroidx/lifecycle/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Landroidx/lifecycle/d;


# instance fields
.field public final a:Ljava/util/HashMap;

.field public final b:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroidx/lifecycle/d;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/lifecycle/d;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/lifecycle/d;->c:Landroidx/lifecycle/d;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Landroidx/lifecycle/d;->a:Ljava/util/HashMap;

    .line 10
    .line 11
    new-instance v0, Ljava/util/HashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Landroidx/lifecycle/d;->b:Ljava/util/HashMap;

    .line 17
    .line 18
    return-void
.end method

.method public static b(Ljava/util/HashMap;Landroidx/lifecycle/c;Landroidx/lifecycle/p;Ljava/lang/Class;)V
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Landroidx/lifecycle/p;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    if-ne p2, v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object p0, p1, Landroidx/lifecycle/c;->b:Ljava/lang/reflect/Method;

    .line 13
    .line 14
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "Method "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, " in "

    .line 31
    .line 32
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, " already declared with different @OnLifecycleEvent value: previous value "

    .line 43
    .line 44
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, ", new value "

    .line 51
    .line 52
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p1

    .line 66
    :cond_1
    :goto_0
    if-nez v0, :cond_2

    .line 67
    .line 68
    invoke-virtual {p0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    :cond_2
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Class;[Ljava/lang/reflect/Method;)Landroidx/lifecycle/b;
    .locals 12

    .line 1
    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 8
    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Landroidx/lifecycle/d;->a:Ljava/util/HashMap;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v3, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    check-cast v4, Landroidx/lifecycle/b;

    .line 20
    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p0, v0, v2}, Landroidx/lifecycle/d;->a(Ljava/lang/Class;[Ljava/lang/reflect/Method;)Landroidx/lifecycle/b;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    :goto_0
    iget-object v0, v4, Landroidx/lifecycle/b;->b:Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->putAll(Ljava/util/Map;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    invoke-virtual {p1}, Ljava/lang/Class;->getInterfaces()[Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    array-length v4, v0

    .line 38
    const/4 v5, 0x0

    .line 39
    move v6, v5

    .line 40
    :goto_1
    if-ge v6, v4, :cond_4

    .line 41
    .line 42
    aget-object v7, v0, v6

    .line 43
    .line 44
    invoke-virtual {v3, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v8

    .line 48
    check-cast v8, Landroidx/lifecycle/b;

    .line 49
    .line 50
    if-eqz v8, :cond_2

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    invoke-virtual {p0, v7, v2}, Landroidx/lifecycle/d;->a(Ljava/lang/Class;[Ljava/lang/reflect/Method;)Landroidx/lifecycle/b;

    .line 54
    .line 55
    .line 56
    move-result-object v8

    .line 57
    :goto_2
    iget-object v7, v8, Landroidx/lifecycle/b;->b:Ljava/util/HashMap;

    .line 58
    .line 59
    invoke-virtual {v7}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    invoke-interface {v7}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v7

    .line 67
    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v8

    .line 71
    if-eqz v8, :cond_3

    .line 72
    .line 73
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v8

    .line 77
    check-cast v8, Ljava/util/Map$Entry;

    .line 78
    .line 79
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v9

    .line 83
    check-cast v9, Landroidx/lifecycle/c;

    .line 84
    .line 85
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v8

    .line 89
    check-cast v8, Landroidx/lifecycle/p;

    .line 90
    .line 91
    invoke-static {v1, v9, v8, p1}, Landroidx/lifecycle/d;->b(Ljava/util/HashMap;Landroidx/lifecycle/c;Landroidx/lifecycle/p;Ljava/lang/Class;)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_4
    if-eqz p2, :cond_5

    .line 99
    .line 100
    goto :goto_4

    .line 101
    :cond_5
    :try_start_0
    invoke-virtual {p1}, Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;

    .line 102
    .line 103
    .line 104
    move-result-object p2
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_0

    .line 105
    :goto_4
    array-length v0, p2

    .line 106
    move v2, v5

    .line 107
    move v4, v2

    .line 108
    :goto_5
    if-ge v2, v0, :cond_d

    .line 109
    .line 110
    aget-object v6, p2, v2

    .line 111
    .line 112
    const-class v7, Landroidx/lifecycle/k0;

    .line 113
    .line 114
    invoke-virtual {v6, v7}, Ljava/lang/reflect/Method;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    check-cast v7, Landroidx/lifecycle/k0;

    .line 119
    .line 120
    if-nez v7, :cond_6

    .line 121
    .line 122
    goto :goto_8

    .line 123
    :cond_6
    invoke-virtual {v6}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    array-length v8, v4

    .line 128
    const/4 v9, 0x1

    .line 129
    if-lez v8, :cond_8

    .line 130
    .line 131
    const-class v8, Landroidx/lifecycle/x;

    .line 132
    .line 133
    aget-object v10, v4, v5

    .line 134
    .line 135
    invoke-virtual {v8, v10}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 136
    .line 137
    .line 138
    move-result v8

    .line 139
    if-eqz v8, :cond_7

    .line 140
    .line 141
    move v8, v9

    .line 142
    goto :goto_6

    .line 143
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 144
    .line 145
    const-string p1, "invalid parameter type. Must be one and instanceof LifecycleOwner"

    .line 146
    .line 147
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0

    .line 151
    :cond_8
    move v8, v5

    .line 152
    :goto_6
    invoke-interface {v7}, Landroidx/lifecycle/k0;->value()Landroidx/lifecycle/p;

    .line 153
    .line 154
    .line 155
    move-result-object v7

    .line 156
    array-length v10, v4

    .line 157
    const/4 v11, 0x2

    .line 158
    if-le v10, v9, :cond_b

    .line 159
    .line 160
    const-class v8, Landroidx/lifecycle/p;

    .line 161
    .line 162
    aget-object v10, v4, v9

    .line 163
    .line 164
    invoke-virtual {v8, v10}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    if-eqz v8, :cond_a

    .line 169
    .line 170
    sget-object v8, Landroidx/lifecycle/p;->ON_ANY:Landroidx/lifecycle/p;

    .line 171
    .line 172
    if-ne v7, v8, :cond_9

    .line 173
    .line 174
    move v8, v11

    .line 175
    goto :goto_7

    .line 176
    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 177
    .line 178
    const-string p1, "Second arg is supported only for ON_ANY value"

    .line 179
    .line 180
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    throw p0

    .line 184
    :cond_a
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 185
    .line 186
    const-string p1, "invalid parameter type. second arg must be an event"

    .line 187
    .line 188
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    throw p0

    .line 192
    :cond_b
    :goto_7
    array-length v4, v4

    .line 193
    if-gt v4, v11, :cond_c

    .line 194
    .line 195
    new-instance v4, Landroidx/lifecycle/c;

    .line 196
    .line 197
    invoke-direct {v4, v8, v6}, Landroidx/lifecycle/c;-><init>(ILjava/lang/reflect/Method;)V

    .line 198
    .line 199
    .line 200
    invoke-static {v1, v4, v7, p1}, Landroidx/lifecycle/d;->b(Ljava/util/HashMap;Landroidx/lifecycle/c;Landroidx/lifecycle/p;Ljava/lang/Class;)V

    .line 201
    .line 202
    .line 203
    move v4, v9

    .line 204
    :goto_8
    add-int/lit8 v2, v2, 0x1

    .line 205
    .line 206
    goto :goto_5

    .line 207
    :cond_c
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 208
    .line 209
    const-string p1, "cannot have more than 2 params"

    .line 210
    .line 211
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p0

    .line 215
    :cond_d
    new-instance p2, Landroidx/lifecycle/b;

    .line 216
    .line 217
    invoke-direct {p2, v1}, Landroidx/lifecycle/b;-><init>(Ljava/util/HashMap;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v3, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    iget-object p0, p0, Landroidx/lifecycle/d;->b:Ljava/util/HashMap;

    .line 224
    .line 225
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    invoke-virtual {p0, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    return-object p2

    .line 233
    :catch_0
    move-exception p0

    .line 234
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 235
    .line 236
    const-string p2, "The observer class has some methods that use newer APIs which are not available in the current OS version. Lifecycles cannot access even other methods so you should make sure that your observer classes only access framework classes that are available in your min API level OR use lifecycle:compiler annotation processor."

    .line 237
    .line 238
    invoke-direct {p1, p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 239
    .line 240
    .line 241
    throw p1
.end method
