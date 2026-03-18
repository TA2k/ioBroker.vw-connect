.class public abstract Ljp/pb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lyy0/a2;Ljava/lang/Object;Ll2/o;)Ll2/b1;
    .locals 8

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    new-instance p0, Lyy0/m;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-direct {p0, p1, v0}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    :cond_0
    move-object v1, p0

    .line 10
    sget-object p0, Ln7/c;->a:Ll2/s1;

    .line 11
    .line 12
    move-object v0, p2

    .line 13
    check-cast v0, Ll2/t;

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Landroidx/lifecycle/x;

    .line 20
    .line 21
    sget-object v4, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 22
    .line 23
    invoke-interface {p0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const/16 v7, 0x30

    .line 28
    .line 29
    sget-object v5, Lpx0/h;->d:Lpx0/h;

    .line 30
    .line 31
    move-object v2, p1

    .line 32
    move-object v6, p2

    .line 33
    invoke-static/range {v1 .. v7}, Ljp/b2;->b(Lyy0/i;Ljava/lang/Object;Landroidx/lifecycle/r;Landroidx/lifecycle/q;Lpx0/g;Ll2/o;I)Ll2/b1;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public static final b(Lhl0/i;Lij0/a;)Laz/d;
    .locals 3

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lhl0/f;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    check-cast p0, Lhl0/f;

    .line 12
    .line 13
    iget-object p1, p0, Lhl0/f;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object p0, p0, Lhl0/f;->b:Ljava/lang/String;

    .line 16
    .line 17
    sget-object v0, Laz/e;->f:Laz/e;

    .line 18
    .line 19
    new-instance v2, Laz/d;

    .line 20
    .line 21
    invoke-direct {v2, p0, p1, v1, v0}, Laz/d;-><init>(Ljava/lang/String;Ljava/lang/String;Lxj0/f;Laz/e;)V

    .line 22
    .line 23
    .line 24
    return-object v2

    .line 25
    :cond_0
    instance-of v0, p0, Lhl0/h;

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    new-array v0, v2, [Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Ljj0/f;

    .line 33
    .line 34
    const v2, 0x7f120704

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1, v2, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    check-cast p0, Lhl0/h;

    .line 42
    .line 43
    iget-object p0, p0, Lhl0/h;->a:Lxj0/f;

    .line 44
    .line 45
    sget-object v0, Laz/e;->d:Laz/e;

    .line 46
    .line 47
    new-instance v2, Laz/d;

    .line 48
    .line 49
    invoke-direct {v2, p1, v1, p0, v0}, Laz/d;-><init>(Ljava/lang/String;Ljava/lang/String;Lxj0/f;Laz/e;)V

    .line 50
    .line 51
    .line 52
    return-object v2

    .line 53
    :cond_1
    instance-of v0, p0, Lhl0/c;

    .line 54
    .line 55
    if-eqz v0, :cond_2

    .line 56
    .line 57
    new-array v0, v2, [Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p1, Ljj0/f;

    .line 60
    .line 61
    const v2, 0x7f120705

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1, v2, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    check-cast p0, Lhl0/c;

    .line 69
    .line 70
    iget-object p0, p0, Lhl0/c;->a:Lxj0/f;

    .line 71
    .line 72
    sget-object v0, Laz/e;->e:Laz/e;

    .line 73
    .line 74
    new-instance v2, Laz/d;

    .line 75
    .line 76
    invoke-direct {v2, p1, v1, p0, v0}, Laz/d;-><init>(Ljava/lang/String;Ljava/lang/String;Lxj0/f;Laz/e;)V

    .line 77
    .line 78
    .line 79
    return-object v2

    .line 80
    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 81
    .line 82
    new-instance v0, Ljava/lang/StringBuilder;

    .line 83
    .line 84
    const-string v1, "Unknown AI trip map search result type: "

    .line 85
    .line 86
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p1
.end method
