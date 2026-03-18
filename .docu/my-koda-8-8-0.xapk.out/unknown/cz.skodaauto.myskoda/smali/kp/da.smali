.class public abstract Lkp/da;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroid/graphics/Typeface;)Lk4/n;
    .locals 2

    .line 1
    sget-object v0, Landroid/graphics/Typeface;->SANS_SERIF:Landroid/graphics/Typeface;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Lk4/n;->e:Lk4/z;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object v0, Landroid/graphics/Typeface;->SERIF:Landroid/graphics/Typeface;

    .line 13
    .line 14
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    sget-object p0, Lk4/n;->f:Lk4/z;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_1
    sget-object v0, Landroid/graphics/Typeface;->MONOSPACE:Landroid/graphics/Typeface;

    .line 24
    .line 25
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    sget-object p0, Lk4/n;->g:Lk4/z;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_2
    if-eqz p0, :cond_3

    .line 35
    .line 36
    new-instance v0, Ltm/k;

    .line 37
    .line 38
    invoke-direct {v0, p0}, Ltm/k;-><init>(Landroid/graphics/Typeface;)V

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x1

    .line 42
    new-array p0, p0, [Lk4/l;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    aput-object v0, p0, v1

    .line 46
    .line 47
    new-instance v0, Lk4/q;

    .line 48
    .line 49
    invoke-static {p0}, Lmx0/n;->b([Ljava/lang/Object;)Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-direct {v0, p0}, Lk4/q;-><init>(Ljava/util/List;)V

    .line 54
    .line 55
    .line 56
    return-object v0

    .line 57
    :cond_3
    const/4 p0, 0x0

    .line 58
    return-object p0
.end method

.method public static final b(Ljava/lang/String;)Lk4/n;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_0

    .line 3
    .line 4
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const-string v2, "this as java.lang.String).toLowerCase(Locale.ROOT)"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object v1, v0

    .line 17
    :goto_0
    const-string v2, "sans-serif"

    .line 18
    .line 19
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    sget-object p0, Lk4/n;->e:Lk4/z;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_1
    const-string v2, "serif"

    .line 29
    .line 30
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    sget-object p0, Lk4/n;->f:Lk4/z;

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_2
    const-string v2, "monospace"

    .line 40
    .line 41
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-eqz v2, :cond_3

    .line 46
    .line 47
    sget-object p0, Lk4/n;->g:Lk4/z;

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_3
    const-string v2, "cursive"

    .line 51
    .line 52
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_4

    .line 57
    .line 58
    sget-object p0, Lk4/n;->h:Lk4/z;

    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_4
    if-eqz p0, :cond_5

    .line 62
    .line 63
    const/4 v0, 0x0

    .line 64
    invoke-static {p0, v0}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    const-string v1, "create(family, Typeface.NORMAL)"

    .line 69
    .line 70
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    new-instance v1, Ltm/k;

    .line 74
    .line 75
    invoke-direct {v1, p0}, Ltm/k;-><init>(Landroid/graphics/Typeface;)V

    .line 76
    .line 77
    .line 78
    const/4 p0, 0x1

    .line 79
    new-array p0, p0, [Lk4/l;

    .line 80
    .line 81
    aput-object v1, p0, v0

    .line 82
    .line 83
    new-instance v0, Lk4/q;

    .line 84
    .line 85
    invoke-static {p0}, Lmx0/n;->b([Ljava/lang/Object;)Ljava/util/List;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-direct {v0, p0}, Lk4/q;-><init>(Ljava/util/List;)V

    .line 90
    .line 91
    .line 92
    :cond_5
    return-object v0
.end method

.method public static final c(Lm1/l;)I
    .locals 4

    .line 1
    iget-object v0, p0, Lm1/l;->o:Lg1/w1;

    .line 2
    .line 3
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lm1/l;->e()J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    const-wide v2, 0xffffffffL

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    and-long/2addr v0, v2

    .line 17
    :goto_0
    long-to-int p0, v0

    .line 18
    return p0

    .line 19
    :cond_0
    invoke-virtual {p0}, Lm1/l;->e()J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    const/16 p0, 0x20

    .line 24
    .line 25
    shr-long/2addr v0, p0

    .line 26
    goto :goto_0
.end method
