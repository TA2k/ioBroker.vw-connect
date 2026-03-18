.class public abstract Llp/hc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/n;Lay0/p;Lay0/n;Lay0/p;Lt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    check-cast p5, Ll2/t;

    .line 2
    .line 3
    const v0, -0x49a2b396

    .line 4
    .line 5
    .line 6
    invoke-virtual {p5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p5, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p6

    .line 19
    invoke-virtual {p5, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x100

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x80

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    const v1, 0xb6db

    .line 32
    .line 33
    .line 34
    and-int/2addr v0, v1

    .line 35
    const/16 v1, 0x2492

    .line 36
    .line 37
    if-ne v0, v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p5}, Ll2/t;->A()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    invoke-virtual {p5}, Ll2/t;->R()V

    .line 47
    .line 48
    .line 49
    goto :goto_7

    .line 50
    :cond_3
    :goto_2
    sget-object v0, Lvv/q0;->a:Ll2/e0;

    .line 51
    .line 52
    new-instance v1, Lvv/p0;

    .line 53
    .line 54
    if-nez p0, :cond_4

    .line 55
    .line 56
    sget-object v2, Lvv/p0;->e:Lvv/p0;

    .line 57
    .line 58
    iget-object v2, v2, Lvv/p0;->a:Lay0/n;

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_4
    move-object v2, p0

    .line 62
    :goto_3
    if-nez p1, :cond_5

    .line 63
    .line 64
    sget-object v3, Lvv/p0;->e:Lvv/p0;

    .line 65
    .line 66
    iget-object v3, v3, Lvv/p0;->b:Lay0/p;

    .line 67
    .line 68
    goto :goto_4

    .line 69
    :cond_5
    move-object v3, p1

    .line 70
    :goto_4
    if-nez p2, :cond_6

    .line 71
    .line 72
    sget-object v4, Lvv/p0;->e:Lvv/p0;

    .line 73
    .line 74
    iget-object v4, v4, Lvv/p0;->c:Lay0/n;

    .line 75
    .line 76
    goto :goto_5

    .line 77
    :cond_6
    move-object v4, p2

    .line 78
    :goto_5
    if-nez p3, :cond_7

    .line 79
    .line 80
    sget-object v5, Lvv/p0;->e:Lvv/p0;

    .line 81
    .line 82
    iget-object v5, v5, Lvv/p0;->d:Lay0/p;

    .line 83
    .line 84
    goto :goto_6

    .line 85
    :cond_7
    move-object v5, p3

    .line 86
    :goto_6
    invoke-direct {v1, v2, v3, v4, v5}, Lvv/p0;-><init>(Lay0/n;Lay0/p;Lay0/n;Lay0/p;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    new-instance v1, Lvv/w;

    .line 94
    .line 95
    const/4 v2, 0x3

    .line 96
    invoke-direct {v1, p4, v2}, Lvv/w;-><init>(Lt2/b;I)V

    .line 97
    .line 98
    .line 99
    const v2, -0x737d6ed6

    .line 100
    .line 101
    .line 102
    invoke-static {v2, p5, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    const/16 v2, 0x38

    .line 107
    .line 108
    invoke-static {v0, v1, p5, v2}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 109
    .line 110
    .line 111
    :goto_7
    invoke-virtual {p5}, Ll2/t;->s()Ll2/u1;

    .line 112
    .line 113
    .line 114
    move-result-object p5

    .line 115
    if-eqz p5, :cond_8

    .line 116
    .line 117
    new-instance v0, Lel/i;

    .line 118
    .line 119
    move-object v1, p0

    .line 120
    move-object v2, p1

    .line 121
    move-object v3, p2

    .line 122
    move-object v4, p3

    .line 123
    move-object v5, p4

    .line 124
    move v6, p6

    .line 125
    invoke-direct/range {v0 .. v6}, Lel/i;-><init>(Lay0/n;Lay0/p;Lay0/n;Lay0/p;Lt2/b;I)V

    .line 126
    .line 127
    .line 128
    iput-object v0, p5, Ll2/u1;->d:Lay0/n;

    .line 129
    .line 130
    :cond_8
    return-void
.end method

.method public static b(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p0, p1, :cond_1

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return v0

    .line 14
    :cond_0
    return v1

    .line 15
    :cond_1
    return v0
.end method
