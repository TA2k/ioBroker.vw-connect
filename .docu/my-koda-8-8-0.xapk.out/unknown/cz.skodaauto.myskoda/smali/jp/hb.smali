.class public abstract Ljp/hb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lnz0/i;J)J
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, p1, p2}, Lnz0/i;->c(J)Z

    .line 7
    .line 8
    .line 9
    invoke-static {p0}, Ljp/hb;->c(Lnz0/i;)J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    invoke-static {p1, p2, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 14
    .line 15
    .line 16
    move-result-wide p1

    .line 17
    invoke-interface {p0}, Lnz0/i;->n()Lnz0/a;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p0, p1, p2}, Lnz0/a;->skip(J)V

    .line 22
    .line 23
    .line 24
    return-wide p1
.end method

.method public static final b(Lqr0/q;Lij0/a;)Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lqr0/q;->a:D

    .line 12
    .line 13
    invoke-static {p0}, Lkp/p6;->e(Lqr0/q;)D

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    cmpg-double v2, v0, v2

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    new-array p0, v3, [Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p1, Ljj0/f;

    .line 25
    .line 26
    const v0, 0x7f120100

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_0
    invoke-static {p0}, Lkp/p6;->d(Lqr0/q;)D

    .line 35
    .line 36
    .line 37
    move-result-wide v4

    .line 38
    cmpg-double v0, v0, v4

    .line 39
    .line 40
    if-nez v0, :cond_1

    .line 41
    .line 42
    new-array p0, v3, [Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p1, Ljj0/f;

    .line 45
    .line 46
    const v0, 0x7f1200ff

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_1
    invoke-static {p0, p1}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method public static final c(Lnz0/i;)J
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lnz0/i;->n()Lnz0/a;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 11
    .line 12
    return-wide v0
.end method
