.class public final Lk31/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# virtual methods
.method public final a(Lk31/g;)Ljava/util/List;
    .locals 7

    .line 1
    iget-object p0, p1, Lk31/g;->a:Lz70/d;

    .line 2
    .line 3
    const-string p1, "newRequestStrings"

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance p1, Li31/s;

    .line 9
    .line 10
    iget-object p0, p0, Lz70/d;->a:Lg1/q;

    .line 11
    .line 12
    iget-object p0, p0, Lg1/q;->k:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lz70/c;

    .line 15
    .line 16
    iget-object v0, p0, Lz70/c;->a:Lij0/a;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    new-array v2, v1, [Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Ljj0/f;

    .line 22
    .line 23
    const v3, 0x7f121152

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-direct {p1, v0}, Li31/s;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance v0, Li31/l;

    .line 34
    .line 35
    iget-object p0, p0, Lz70/c;->a:Lij0/a;

    .line 36
    .line 37
    new-array v2, v1, [Ljava/lang/Object;

    .line 38
    .line 39
    move-object v3, p0

    .line 40
    check-cast v3, Ljj0/f;

    .line 41
    .line 42
    const v4, 0x7f121148

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-direct {v0, v2}, Li31/l;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance v2, Li31/k;

    .line 53
    .line 54
    new-array v3, v1, [Ljava/lang/Object;

    .line 55
    .line 56
    move-object v4, p0

    .line 57
    check-cast v4, Ljj0/f;

    .line 58
    .line 59
    const v5, 0x7f121147

    .line 60
    .line 61
    .line 62
    invoke-virtual {v4, v5, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-direct {v2, v3}, Li31/k;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    new-instance v3, Li31/t;

    .line 70
    .line 71
    new-array v4, v1, [Ljava/lang/Object;

    .line 72
    .line 73
    move-object v5, p0

    .line 74
    check-cast v5, Ljj0/f;

    .line 75
    .line 76
    const v6, 0x7f121153

    .line 77
    .line 78
    .line 79
    invoke-virtual {v5, v6, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-direct {v3, v4}, Li31/t;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    new-instance v4, Li31/q;

    .line 87
    .line 88
    new-array v5, v1, [Ljava/lang/Object;

    .line 89
    .line 90
    check-cast p0, Ljj0/f;

    .line 91
    .line 92
    const v6, 0x7f121150

    .line 93
    .line 94
    .line 95
    invoke-virtual {p0, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-direct {v4, p0}, Li31/q;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    const/4 p0, 0x5

    .line 103
    new-array p0, p0, [Li31/u;

    .line 104
    .line 105
    aput-object p1, p0, v1

    .line 106
    .line 107
    const/4 p1, 0x1

    .line 108
    aput-object v0, p0, p1

    .line 109
    .line 110
    const/4 p1, 0x2

    .line 111
    aput-object v2, p0, p1

    .line 112
    .line 113
    const/4 p1, 0x3

    .line 114
    aput-object v3, p0, p1

    .line 115
    .line 116
    const/4 p1, 0x4

    .line 117
    aput-object v4, p0, p1

    .line 118
    .line 119
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lk31/g;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lk31/h;->a(Lk31/g;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
