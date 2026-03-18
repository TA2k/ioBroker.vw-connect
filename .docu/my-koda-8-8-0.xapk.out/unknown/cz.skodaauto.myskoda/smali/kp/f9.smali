.class public abstract Lkp/f9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(II)J
    .locals 4

    .line 1
    int-to-long v0, p0

    .line 2
    const/16 p0, 0x20

    .line 3
    .line 4
    shl-long/2addr v0, p0

    .line 5
    int-to-long p0, p1

    .line 6
    const-wide v2, 0xffffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    and-long/2addr p0, v2

    .line 12
    or-long/2addr p0, v0

    .line 13
    return-wide p0
.end method

.method public static final b(Lgp0/f;)Lhp0/e;
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lgp0/f;->a:Lgp0/b;

    .line 7
    .line 8
    iget-object p0, p0, Lgp0/f;->b:Ljava/util/List;

    .line 9
    .line 10
    iget-object v2, v1, Lgp0/b;->e:Lgp0/e;

    .line 11
    .line 12
    if-eqz v2, :cond_6

    .line 13
    .line 14
    new-instance v3, Lhp0/c;

    .line 15
    .line 16
    iget-object v4, v2, Lgp0/e;->a:Ljava/lang/Integer;

    .line 17
    .line 18
    iget-object v5, v2, Lgp0/e;->b:Ljava/lang/Integer;

    .line 19
    .line 20
    iget-object v6, v2, Lgp0/e;->c:Ljava/lang/Integer;

    .line 21
    .line 22
    iget-object v7, v2, Lgp0/e;->d:Ljava/lang/Integer;

    .line 23
    .line 24
    iget-object v8, v2, Lgp0/e;->f:Ljava/lang/String;

    .line 25
    .line 26
    if-eqz v8, :cond_5

    .line 27
    .line 28
    invoke-virtual {v8}, Ljava/lang/String;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v9

    .line 32
    const v10, 0x241427

    .line 33
    .line 34
    .line 35
    if-eq v9, v10, :cond_3

    .line 36
    .line 37
    const v10, 0x4b4d1fc

    .line 38
    .line 39
    .line 40
    if-eq v9, v10, :cond_2

    .line 41
    .line 42
    const v10, 0x7817b875

    .line 43
    .line 44
    .line 45
    if-eq v9, v10, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const-string v9, "Center"

    .line 49
    .line 50
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v8

    .line 54
    if-nez v8, :cond_1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    sget-object v8, Lhp0/b;->f:Lhp0/b;

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    const-string v9, "Right"

    .line 61
    .line 62
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    if-eqz v8, :cond_5

    .line 67
    .line 68
    sget-object v8, Lhp0/b;->e:Lhp0/b;

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_3
    const-string v9, "Left"

    .line 72
    .line 73
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v8

    .line 77
    if-nez v8, :cond_4

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_4
    sget-object v8, Lhp0/b;->d:Lhp0/b;

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_5
    :goto_0
    sget-object v8, Lhp0/b;->d:Lhp0/b;

    .line 84
    .line 85
    :goto_1
    iget-boolean v9, v2, Lgp0/e;->e:Z

    .line 86
    .line 87
    invoke-direct/range {v3 .. v9}, Lhp0/c;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lhp0/b;Z)V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_6
    const/4 v3, 0x0

    .line 92
    :goto_2
    check-cast p0, Ljava/lang/Iterable;

    .line 93
    .line 94
    new-instance v2, Ljava/util/ArrayList;

    .line 95
    .line 96
    const/16 v4, 0xa

    .line 97
    .line 98
    invoke-static {p0, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 103
    .line 104
    .line 105
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    if-eqz v4, :cond_7

    .line 114
    .line 115
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    check-cast v4, Lgp0/d;

    .line 120
    .line 121
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    new-instance v5, Lhp0/a;

    .line 125
    .line 126
    iget-object v6, v4, Lgp0/d;->c:Ljava/lang/String;

    .line 127
    .line 128
    iget v4, v4, Lgp0/d;->d:I

    .line 129
    .line 130
    invoke-direct {v5, v6, v4}, Lhp0/a;-><init>(Ljava/lang/String;I)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_7
    iget-object p0, v1, Lgp0/b;->d:Ljava/lang/String;

    .line 138
    .line 139
    :try_start_0
    invoke-static {p0}, Lhp0/d;->valueOf(Ljava/lang/String;)Lhp0/d;

    .line 140
    .line 141
    .line 142
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 143
    goto :goto_4

    .line 144
    :catch_0
    sget-object p0, Lhp0/d;->q:Lhp0/d;

    .line 145
    .line 146
    :goto_4
    new-instance v0, Lhp0/e;

    .line 147
    .line 148
    invoke-direct {v0, v2, v3, p0}, Lhp0/e;-><init>(Ljava/util/ArrayList;Lhp0/c;Lhp0/d;)V

    .line 149
    .line 150
    .line 151
    return-object v0
.end method

.method public static final c(J)J
    .locals 6

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    shr-long v1, p0, v0

    .line 4
    .line 5
    long-to-int v1, v1

    .line 6
    int-to-float v1, v1

    .line 7
    const-wide v2, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr p0, v2

    .line 13
    long-to-int p0, p0

    .line 14
    int-to-float p0, p0

    .line 15
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    int-to-long v4, p1

    .line 20
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    int-to-long p0, p0

    .line 25
    shl-long v0, v4, v0

    .line 26
    .line 27
    and-long/2addr p0, v2

    .line 28
    or-long/2addr p0, v0

    .line 29
    return-wide p0
.end method
