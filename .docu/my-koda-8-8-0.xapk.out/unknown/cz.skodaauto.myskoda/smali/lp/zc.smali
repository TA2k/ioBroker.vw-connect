.class public abstract Llp/zc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/List;)Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    check-cast p0, Ljava/lang/Iterable;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_3

    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    add-int/lit8 v3, v1, 0x1

    .line 24
    .line 25
    if-ltz v1, :cond_2

    .line 26
    .line 27
    check-cast v2, Lw71/c;

    .line 28
    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    if-lez v1, :cond_0

    .line 32
    .line 33
    const-string v1, ", "

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    :cond_0
    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    :cond_1
    move v1, v3

    .line 46
    goto :goto_0

    .line 47
    :cond_2
    invoke-static {}, Ljp/k1;->r()V

    .line 48
    .line 49
    .line 50
    const/4 p0, 0x0

    .line 51
    throw p0

    .line 52
    :cond_3
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public static final b(Landroid/graphics/Typeface;Lk4/w;Landroid/content/Context;)Landroid/graphics/Typeface;
    .locals 6

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    sget-object v1, Lk4/e0;->a:Ljava/lang/ThreadLocal;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    return-object v1

    .line 9
    :cond_0
    iget-object p1, p1, Lk4/w;->a:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_1
    sget-object v2, Lk4/e0;->a:Ljava/lang/ThreadLocal;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast v3, Landroid/graphics/Paint;

    .line 25
    .line 26
    if-nez v3, :cond_2

    .line 27
    .line 28
    new-instance v3, Landroid/graphics/Paint;

    .line 29
    .line 30
    invoke-direct {v3}, Landroid/graphics/Paint;-><init>()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v2, v3}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :cond_2
    invoke-virtual {v3, v1}, Landroid/graphics/Paint;->setFontVariationSettings(Ljava/lang/String;)Z

    .line 37
    .line 38
    .line 39
    invoke-virtual {v3, p0}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 40
    .line 41
    .line 42
    invoke-static {p2}, Lkp/z8;->a(Landroid/content/Context;)Lt4/e;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    const/16 v2, 0x1f

    .line 47
    .line 48
    const/4 v4, 0x0

    .line 49
    if-lt v0, v2, :cond_3

    .line 50
    .line 51
    invoke-virtual {p2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    invoke-static {v0}, Lh4/b;->a(Landroid/content/res/Configuration;)I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    const v5, 0x7fffffff

    .line 64
    .line 65
    .line 66
    if-ne v0, v5, :cond_4

    .line 67
    .line 68
    :cond_3
    move p2, v4

    .line 69
    goto :goto_0

    .line 70
    :cond_4
    invoke-virtual {p2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    invoke-virtual {p2}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    invoke-static {p2}, Lh4/b;->a(Landroid/content/res/Configuration;)I

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    :goto_0
    if-nez p2, :cond_5

    .line 83
    .line 84
    new-instance p2, Ljy/b;

    .line 85
    .line 86
    invoke-direct {p2, p0}, Ljy/b;-><init>(Lt4/e;)V

    .line 87
    .line 88
    .line 89
    invoke-static {p1, v1, p2, v2}, Lv4/a;->a(Ljava/util/List;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    goto :goto_2

    .line 94
    :cond_5
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    if-gtz p0, :cond_7

    .line 99
    .line 100
    const/high16 p0, 0x43c80000    # 400.0f

    .line 101
    .line 102
    int-to-float p2, p2

    .line 103
    add-float/2addr p2, p0

    .line 104
    const/high16 p0, 0x3f800000    # 1.0f

    .line 105
    .line 106
    const/high16 v0, 0x447a0000    # 1000.0f

    .line 107
    .line 108
    invoke-static {p2, p0, v0}, Lkp/r9;->d(FFF)F

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 113
    .line 114
    .line 115
    move-result p1

    .line 116
    if-nez p1, :cond_6

    .line 117
    .line 118
    const-string p1, ","

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_6
    const-string p1, ""

    .line 122
    .line 123
    :goto_1
    new-instance p2, Ljava/lang/StringBuilder;

    .line 124
    .line 125
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    const-string p1, "\'wght\' "

    .line 132
    .line 133
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    :goto_2
    invoke-virtual {v3, p0}, Landroid/graphics/Paint;->setFontVariationSettings(Ljava/lang/String;)Z

    .line 144
    .line 145
    .line 146
    invoke-virtual {v3}, Landroid/graphics/Paint;->getTypeface()Landroid/graphics/Typeface;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    return-object p0

    .line 151
    :cond_7
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 156
    .line 157
    .line 158
    new-instance p0, Ljava/lang/ClassCastException;

    .line 159
    .line 160
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 161
    .line 162
    .line 163
    throw p0
.end method
