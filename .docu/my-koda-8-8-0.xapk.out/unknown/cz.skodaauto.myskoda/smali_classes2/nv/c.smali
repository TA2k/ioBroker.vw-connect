.class public abstract Lnv/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Llw/e;Lc1/h2;)Z
    .locals 1

    .line 1
    iget-object p1, p1, Lc1/h2;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lkw/g;

    .line 4
    .line 5
    const-string v0, "<this>"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Llw/d;->a:Llw/d;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-interface {p1}, Lpw/f;->e()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :cond_0
    sget-object v0, Llw/c;->a:Llw/c;

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-eqz p0, :cond_2

    .line 30
    .line 31
    invoke-interface {p1}, Lpw/f;->e()Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-nez p0, :cond_1

    .line 36
    .line 37
    const/4 p0, 0x1

    .line 38
    return p0

    .line 39
    :cond_1
    const/4 p0, 0x0

    .line 40
    return p0

    .line 41
    :cond_2
    new-instance p0, La8/r0;

    .line 42
    .line 43
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 44
    .line 45
    .line 46
    throw p0
.end method

.method public static final b(Lcq0/l;Lij0/a;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;)Llp/ie;
    .locals 3

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x0

    .line 11
    if-eqz p0, :cond_6

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    if-eq p0, v1, :cond_5

    .line 15
    .line 16
    const/4 p1, 0x2

    .line 17
    const/4 v2, 0x0

    .line 18
    if-eq p0, p1, :cond_3

    .line 19
    .line 20
    const/4 p1, 0x3

    .line 21
    if-eq p0, p1, :cond_3

    .line 22
    .line 23
    const/4 p1, 0x4

    .line 24
    if-eq p0, p1, :cond_1

    .line 25
    .line 26
    const/4 p1, 0x5

    .line 27
    if-ne p0, p1, :cond_0

    .line 28
    .line 29
    return-object v2

    .line 30
    :cond_0
    new-instance p0, La8/r0;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_1
    new-instance p0, Lx70/e;

    .line 37
    .line 38
    if-eqz p3, :cond_2

    .line 39
    .line 40
    invoke-static {p3}, Lvo/a;->i(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    :cond_2
    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-direct {p0, p1, v0}, Lx70/e;-><init>(Ljava/lang/String;Z)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_3
    new-instance p0, Lx70/e;

    .line 53
    .line 54
    if-eqz p2, :cond_4

    .line 55
    .line 56
    invoke-static {p2}, Lvo/a;->i(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    :cond_4
    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-direct {p0, p1, v1}, Lx70/e;-><init>(Ljava/lang/String;Z)V

    .line 65
    .line 66
    .line 67
    return-object p0

    .line 68
    :cond_5
    new-instance p0, Lx70/d;

    .line 69
    .line 70
    new-array p2, v0, [Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p1, Ljj0/f;

    .line 73
    .line 74
    const p3, 0x7f121189

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, p3, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    sget-object p2, Li91/k1;->d:Li91/k1;

    .line 82
    .line 83
    invoke-direct {p0, p1}, Lx70/d;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    return-object p0

    .line 87
    :cond_6
    new-instance p0, Lx70/d;

    .line 88
    .line 89
    new-array p2, v0, [Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p1, Ljj0/f;

    .line 92
    .line 93
    const p3, 0x7f121184

    .line 94
    .line 95
    .line 96
    invoke-virtual {p1, p3, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    sget-object p2, Li91/k1;->d:Li91/k1;

    .line 101
    .line 102
    invoke-direct {p0, p1}, Lx70/d;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    return-object p0
.end method
