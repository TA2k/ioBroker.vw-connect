.class public abstract Llp/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lhz0/a0;[Lay0/k;Lay0/k;)V
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lhz0/b;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    check-cast p0, Lhz0/b;

    .line 11
    .line 12
    array-length v0, p1

    .line 13
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, [Lay0/k;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-static {v0, p2}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    const-string v0, "otherFormats"

    .line 24
    .line 25
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    new-instance v0, Ljava/util/ArrayList;

    .line 29
    .line 30
    array-length v1, p1

    .line 31
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 32
    .line 33
    .line 34
    array-length v1, p1

    .line 35
    const/4 v2, 0x0

    .line 36
    :goto_0
    if-ge v2, v1, :cond_0

    .line 37
    .line 38
    aget-object v3, p1, v2

    .line 39
    .line 40
    invoke-interface {p0}, Lhz0/b;->l()Lhz0/b;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-interface {v3, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    invoke-interface {v4}, Lhz0/b;->e()Lbn/c;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    new-instance v4, Ljz0/f;

    .line 52
    .line 53
    iget-object v3, v3, Lbn/c;->d:Ljava/util/ArrayList;

    .line 54
    .line 55
    invoke-direct {v4, v3}, Ljz0/f;-><init>(Ljava/util/List;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    add-int/lit8 v2, v2, 0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_0
    invoke-interface {p0}, Lhz0/b;->l()Lhz0/b;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-interface {p2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    invoke-interface {p1}, Lhz0/b;->e()Lbn/c;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    new-instance p2, Ljz0/f;

    .line 76
    .line 77
    iget-object p1, p1, Lbn/c;->d:Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-direct {p2, p1}, Ljz0/f;-><init>(Ljava/util/List;)V

    .line 80
    .line 81
    .line 82
    invoke-interface {p0}, Lhz0/b;->e()Lbn/c;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    new-instance p1, Ljz0/b;

    .line 87
    .line 88
    invoke-direct {p1, p2, v0}, Ljz0/b;-><init>(Ljz0/f;Ljava/util/ArrayList;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0, p1}, Lbn/c;->f(Ljz0/k;)V

    .line 92
    .line 93
    .line 94
    return-void

    .line 95
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 96
    .line 97
    const-string p1, "impossible"

    .line 98
    .line 99
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0
.end method

.method public static final b(Lhz0/a0;C)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-interface {p0, p1}, Lhz0/a0;->c(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static final d(Lhz0/a0;Ljava/lang/String;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lhz0/b;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Lhz0/b;

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    invoke-static {v0, p2}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Lhz0/b;->e()Lbn/c;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {p0}, Lhz0/b;->l()Lhz0/b;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-interface {p2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    invoke-interface {p0}, Lhz0/b;->e()Lbn/c;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    new-instance p2, Ljz0/f;

    .line 32
    .line 33
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-direct {p2, p0}, Ljz0/f;-><init>(Ljava/util/List;)V

    .line 36
    .line 37
    .line 38
    new-instance p0, Ljz0/p;

    .line 39
    .line 40
    invoke-direct {p0, p1, p2}, Ljz0/p;-><init>(Ljava/lang/String;Ljz0/f;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lbn/c;->f(Ljz0/k;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "impossible"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0
.end method


# virtual methods
.method public abstract c([Landroid/text/InputFilter;)[Landroid/text/InputFilter;
.end method

.method public abstract e(Z)V
.end method

.method public abstract f(Z)V
.end method
