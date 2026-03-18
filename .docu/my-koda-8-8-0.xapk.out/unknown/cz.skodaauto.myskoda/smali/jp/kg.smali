.class public abstract Ljp/kg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lorg/json/JSONArray;Lay0/k;)Ljava/util/List;
    .locals 5

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lorg/json/JSONArray;->length()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x0

    .line 16
    :goto_0
    if-ge v2, v1, :cond_2

    .line 17
    .line 18
    invoke-virtual {p0, v2}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    const-string v4, "getJSONObject(...)"

    .line 23
    .line 24
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p1, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    return-object v0
.end method

.method public static final b(Lorg/json/JSONObject;Ldl0/k;)Ljava/util/List;
    .locals 5

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lorg/json/JSONObject;->keys()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    const-string v2, "keys(...)"

    .line 16
    .line 17
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {p0, v2}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    const-string v4, "getJSONObject(...)"

    .line 37
    .line 38
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1, v3, v2}, Ldl0/k;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    return-object v0
.end method

.method public static final c(Ljava/lang/Iterable;)Lqy0/b;
    .locals 4

    .line 1
    instance-of v0, p0, Lqy0/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object v0, p0

    .line 7
    check-cast v0, Lqy0/b;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move-object v0, v1

    .line 11
    :goto_0
    if-nez v0, :cond_9

    .line 12
    .line 13
    instance-of v0, p0, Lry0/a;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    check-cast v0, Lry0/a;

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object v0, v1

    .line 22
    :goto_1
    if-nez v0, :cond_9

    .line 23
    .line 24
    instance-of v0, p0, Lqy0/d;

    .line 25
    .line 26
    if-eqz v0, :cond_2

    .line 27
    .line 28
    move-object v0, p0

    .line 29
    check-cast v0, Lqy0/d;

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    move-object v0, v1

    .line 33
    :goto_2
    if-eqz v0, :cond_3

    .line 34
    .line 35
    check-cast v0, Lry0/e;

    .line 36
    .line 37
    invoke-virtual {v0}, Lry0/e;->g()Lry0/a;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    :cond_3
    if-nez v1, :cond_8

    .line 42
    .line 43
    sget-object v0, Lry0/h;->e:Lry0/h;

    .line 44
    .line 45
    const-string v1, "<this>"

    .line 46
    .line 47
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    instance-of v1, p0, Ljava/util/Collection;

    .line 51
    .line 52
    if-eqz v1, :cond_7

    .line 53
    .line 54
    check-cast p0, Ljava/util/Collection;

    .line 55
    .line 56
    iget-object v1, v0, Lry0/h;->d:[Ljava/lang/Object;

    .line 57
    .line 58
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_4

    .line 63
    .line 64
    goto :goto_4

    .line 65
    :cond_4
    array-length v2, v1

    .line 66
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    add-int/2addr v3, v2

    .line 71
    const/16 v2, 0x20

    .line 72
    .line 73
    if-gt v3, v2, :cond_6

    .line 74
    .line 75
    array-length v0, v1

    .line 76
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    add-int/2addr v2, v0

    .line 81
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    const-string v2, "copyOf(...)"

    .line 86
    .line 87
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    array-length v1, v1

    .line 91
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_5

    .line 100
    .line 101
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    add-int/lit8 v3, v1, 0x1

    .line 106
    .line 107
    aput-object v2, v0, v1

    .line 108
    .line 109
    move v1, v3

    .line 110
    goto :goto_3

    .line 111
    :cond_5
    new-instance p0, Lry0/h;

    .line 112
    .line 113
    invoke-direct {p0, v0}, Lry0/h;-><init>([Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    move-object v0, p0

    .line 117
    goto :goto_4

    .line 118
    :cond_6
    invoke-virtual {v0}, Lry0/h;->e()Lry0/e;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-virtual {v0, p0}, Lry0/e;->addAll(Ljava/util/Collection;)Z

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0}, Lry0/e;->g()Lry0/a;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    :goto_4
    return-object v0

    .line 130
    :cond_7
    invoke-virtual {v0}, Lry0/h;->e()Lry0/e;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    invoke-static {p0, v0}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0}, Lry0/e;->g()Lry0/a;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    return-object p0

    .line 142
    :cond_8
    return-object v1

    .line 143
    :cond_9
    return-object v0
.end method

.method public static final d(Ljava/lang/Iterable;)Lqy0/c;
    .locals 2

    .line 1
    instance-of v0, p0, Lqy0/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object v0, p0

    .line 7
    check-cast v0, Lqy0/c;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move-object v0, v1

    .line 11
    :goto_0
    if-nez v0, :cond_6

    .line 12
    .line 13
    instance-of v0, p0, Lqy0/e;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    check-cast v0, Lqy0/e;

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object v0, v1

    .line 22
    :goto_1
    if-eqz v0, :cond_2

    .line 23
    .line 24
    check-cast v0, Lty0/c;

    .line 25
    .line 26
    invoke-virtual {v0}, Lty0/c;->c()Lty0/b;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    :cond_2
    if-eqz v1, :cond_3

    .line 31
    .line 32
    return-object v1

    .line 33
    :cond_3
    sget-object v0, Lty0/b;->g:Lty0/b;

    .line 34
    .line 35
    const-string v1, "<this>"

    .line 36
    .line 37
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    instance-of v1, p0, Ljava/util/Collection;

    .line 41
    .line 42
    if-eqz v1, :cond_5

    .line 43
    .line 44
    check-cast p0, Ljava/util/Collection;

    .line 45
    .line 46
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_4

    .line 51
    .line 52
    return-object v0

    .line 53
    :cond_4
    new-instance v1, Lty0/c;

    .line 54
    .line 55
    invoke-direct {v1, v0}, Lty0/c;-><init>(Lty0/b;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1, p0}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1}, Lty0/c;->c()Lty0/b;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :cond_5
    new-instance v1, Lty0/c;

    .line 67
    .line 68
    invoke-direct {v1, v0}, Lty0/c;-><init>(Lty0/b;)V

    .line 69
    .line 70
    .line 71
    invoke-static {p0, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1}, Lty0/c;->c()Lty0/b;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :cond_6
    return-object v0
.end method
