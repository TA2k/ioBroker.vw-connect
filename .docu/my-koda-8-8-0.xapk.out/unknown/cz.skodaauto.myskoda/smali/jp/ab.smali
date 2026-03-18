.class public abstract Ljp/ab;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lao0/c;)Ljava/lang/String;
    .locals 6

    .line 1
    iget-object p0, p0, Lao0/c;->e:Ljava/util/Set;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Ljava/lang/Iterable;

    .line 5
    .line 6
    new-instance v4, Lb30/a;

    .line 7
    .line 8
    const/16 p0, 0xf

    .line 9
    .line 10
    invoke-direct {v4, p0}, Lb30/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    const/16 v5, 0x1f

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    const/4 v2, 0x0

    .line 17
    const/4 v3, 0x0

    .line 18
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public static final b(Lao0/c;Lij0/a;)Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lao0/c;->d:Lao0/f;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    invoke-static {p0}, Ljp/ab;->a(Lao0/c;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p1, Ljj0/f;

    .line 26
    .line 27
    const v0, 0x7f12008c

    .line 28
    .line 29
    .line 30
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :cond_0
    new-instance p0, La8/r0;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    iget-object p0, p0, Lao0/c;->e:Ljava/util/Set;

    .line 42
    .line 43
    move-object v0, p0

    .line 44
    check-cast v0, Ljava/lang/Iterable;

    .line 45
    .line 46
    new-instance v4, Lb30/a;

    .line 47
    .line 48
    const/16 p0, 0x10

    .line 49
    .line 50
    invoke-direct {v4, p0}, Lb30/a;-><init>(I)V

    .line 51
    .line 52
    .line 53
    const/16 v5, 0x1f

    .line 54
    .line 55
    const/4 v1, 0x0

    .line 56
    const/4 v2, 0x0

    .line 57
    const/4 v3, 0x0

    .line 58
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p1, Ljj0/f;

    .line 67
    .line 68
    const v0, 0x7f12008b

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0
.end method

.method public static final c(Lmy0/f;)Ljava/time/Instant;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lmy0/f;->d:J

    .line 7
    .line 8
    iget p0, p0, Lmy0/f;->e:I

    .line 9
    .line 10
    int-to-long v2, p0

    .line 11
    invoke-static {v0, v1, v2, v3}, Ljava/time/Instant;->ofEpochSecond(JJ)Ljava/time/Instant;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, "ofEpochSecond(...)"

    .line 16
    .line 17
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-object p0
.end method
