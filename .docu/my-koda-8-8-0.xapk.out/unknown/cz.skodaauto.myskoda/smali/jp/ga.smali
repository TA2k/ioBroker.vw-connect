.class public abstract Ljp/ga;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;
    .locals 9

    .line 1
    const-string v0, "db"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lla/u;->h()Lla/h;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v1, p2

    .line 11
    invoke-static {p2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    check-cast p2, [Ljava/lang/String;

    .line 16
    .line 17
    const-string v1, "tables"

    .line 18
    .line 19
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v4, v0, Lla/h;->b:Lla/l0;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    new-instance v0, Lnx0/i;

    .line 28
    .line 29
    invoke-direct {v0}, Lnx0/i;-><init>()V

    .line 30
    .line 31
    .line 32
    array-length v1, p2

    .line 33
    const/4 v2, 0x0

    .line 34
    move v3, v2

    .line 35
    :goto_0
    const-string v5, "toLowerCase(...)"

    .line 36
    .line 37
    if-ge v3, v1, :cond_1

    .line 38
    .line 39
    aget-object v6, p2, v3

    .line 40
    .line 41
    iget-object v7, v4, Lla/l0;->c:Ljava/util/LinkedHashMap;

    .line 42
    .line 43
    sget-object v8, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 44
    .line 45
    invoke-virtual {v6, v8}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v8

    .line 49
    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v7, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    check-cast v5, Ljava/util/Set;

    .line 57
    .line 58
    if-eqz v5, :cond_0

    .line 59
    .line 60
    check-cast v5, Ljava/util/Collection;

    .line 61
    .line 62
    invoke-virtual {v0, v5}, Lnx0/i;->addAll(Ljava/util/Collection;)Z

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_0
    invoke-virtual {v0, v6}, Lnx0/i;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_1
    invoke-static {v0}, Ljp/m1;->c(Lnx0/i;)Lnx0/i;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    new-array v0, v2, [Ljava/lang/String;

    .line 77
    .line 78
    invoke-virtual {p2, v0}, Ljava/util/AbstractCollection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    check-cast p2, [Ljava/lang/String;

    .line 83
    .line 84
    array-length v0, p2

    .line 85
    new-array v1, v0, [I

    .line 86
    .line 87
    :goto_2
    if-ge v2, v0, :cond_3

    .line 88
    .line 89
    aget-object v3, p2, v2

    .line 90
    .line 91
    iget-object v6, v4, Lla/l0;->f:Ljava/util/LinkedHashMap;

    .line 92
    .line 93
    sget-object v7, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 94
    .line 95
    invoke-virtual {v3, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v7

    .line 99
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v6, v7}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v6

    .line 106
    check-cast v6, Ljava/lang/Integer;

    .line 107
    .line 108
    if-eqz v6, :cond_2

    .line 109
    .line 110
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 111
    .line 112
    .line 113
    move-result v3

    .line 114
    aput v3, v1, v2

    .line 115
    .line 116
    add-int/lit8 v2, v2, 0x1

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 120
    .line 121
    const-string p1, "There is no table with name "

    .line 122
    .line 123
    invoke-virtual {p1, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0

    .line 131
    :cond_3
    new-instance v0, Llx0/l;

    .line 132
    .line 133
    invoke-direct {v0, p2, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iget-object p2, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 137
    .line 138
    move-object v6, p2

    .line 139
    check-cast v6, [Ljava/lang/String;

    .line 140
    .line 141
    iget-object p2, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 142
    .line 143
    move-object v5, p2

    .line 144
    check-cast v5, [I

    .line 145
    .line 146
    const-string p2, "resolvedTableNames"

    .line 147
    .line 148
    invoke-static {v6, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    const-string p2, "tableIds"

    .line 152
    .line 153
    invoke-static {v5, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    new-instance v2, Lh7/z;

    .line 157
    .line 158
    const/4 v7, 0x0

    .line 159
    const/16 v3, 0xa

    .line 160
    .line 161
    invoke-direct/range {v2 .. v7}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 162
    .line 163
    .line 164
    new-instance p2, Lyy0/m1;

    .line 165
    .line 166
    invoke-direct {p2, v2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 167
    .line 168
    .line 169
    const/4 v0, -0x1

    .line 170
    invoke-static {p2, v0}, Lyy0/u;->g(Lyy0/i;I)Lyy0/i;

    .line 171
    .line 172
    .line 173
    move-result-object p2

    .line 174
    new-instance v0, Lna/j;

    .line 175
    .line 176
    invoke-direct {v0, p2, p0, p1, p3}, Lna/j;-><init>(Lyy0/i;Lla/u;ZLay0/k;)V

    .line 177
    .line 178
    .line 179
    return-object v0
.end method

.method public static final b(II[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 2
    .line 3
    check-cast p3, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p3

    .line 9
    check-cast p3, Landroid/content/res/Resources;

    .line 10
    .line 11
    array-length v0, p2

    .line 12
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    invoke-virtual {p3, p0, p1, p2}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static final c(I[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 2
    .line 3
    check-cast p2, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    check-cast p2, Landroid/content/res/Resources;

    .line 10
    .line 11
    array-length v0, p1

    .line 12
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p2, p0, p1}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static final d(Ll2/o;I)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Landroid/content/res/Resources;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
