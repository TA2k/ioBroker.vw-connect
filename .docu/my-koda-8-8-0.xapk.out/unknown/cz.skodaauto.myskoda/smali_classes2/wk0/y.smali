.class public final Lwk0/y;
.super Lwk0/z1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final j(Lwk0/x1;Lvk0/j0;Lwk0/y1;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p2, Lvk0/r;

    .line 2
    .line 3
    new-instance p0, Lwk0/x;

    .line 4
    .line 5
    instance-of p3, p2, Lvk0/p;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    if-eqz p3, :cond_0

    .line 9
    .line 10
    move-object v1, p2

    .line 11
    check-cast v1, Lvk0/p;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v1, v0

    .line 15
    :goto_0
    const/4 v2, 0x2

    .line 16
    const-string v3, " / l"

    .line 17
    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    iget-object v1, v1, Lvk0/p;->c:Lol0/a;

    .line 21
    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-static {v1, v2}, Ljp/qd;->a(Lol0/a;I)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-static {v1, v3}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move-object v1, v0

    .line 34
    :goto_1
    if-eqz p3, :cond_2

    .line 35
    .line 36
    check-cast p2, Lvk0/p;

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    move-object p2, v0

    .line 40
    :goto_2
    if-eqz p2, :cond_4

    .line 41
    .line 42
    iget-object p2, p2, Lvk0/p;->d:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/Iterable;

    .line 45
    .line 46
    const/16 p3, 0xa

    .line 47
    .line 48
    invoke-static {p2, p3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 49
    .line 50
    .line 51
    move-result p3

    .line 52
    invoke-static {p3}, Lmx0/x;->k(I)I

    .line 53
    .line 54
    .line 55
    move-result p3

    .line 56
    const/16 v4, 0x10

    .line 57
    .line 58
    if-ge p3, v4, :cond_3

    .line 59
    .line 60
    move p3, v4

    .line 61
    :cond_3
    new-instance v4, Ljava/util/LinkedHashMap;

    .line 62
    .line 63
    invoke-direct {v4, p3}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 64
    .line 65
    .line 66
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    :goto_3
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 71
    .line 72
    .line 73
    move-result p3

    .line 74
    if-eqz p3, :cond_5

    .line 75
    .line 76
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p3

    .line 80
    check-cast p3, Lvk0/o;

    .line 81
    .line 82
    const-string v5, "<this>"

    .line 83
    .line 84
    invoke-static {p3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    iget-object v5, p3, Lvk0/o;->a:Ljava/lang/String;

    .line 88
    .line 89
    iget-object p3, p3, Lvk0/o;->b:Lol0/a;

    .line 90
    .line 91
    invoke-static {p3, v2}, Ljp/qd;->a(Lol0/a;I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p3

    .line 95
    new-instance v6, Ljava/lang/StringBuilder;

    .line 96
    .line 97
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v6, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p3

    .line 110
    invoke-interface {v4, v5, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_4
    move-object v4, v0

    .line 115
    :cond_5
    invoke-direct {p0, v1, v4}, Lwk0/x;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 116
    .line 117
    .line 118
    const p2, 0xefff

    .line 119
    .line 120
    .line 121
    invoke-static {p1, v0, p0, p2}, Lwk0/x1;->a(Lwk0/x1;Lnx0/f;Ljava/lang/Object;I)Lwk0/x1;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    return-object p0
.end method
