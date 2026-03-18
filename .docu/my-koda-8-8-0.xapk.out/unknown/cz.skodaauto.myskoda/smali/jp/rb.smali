.class public abstract Ljp/rb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Laz0/p;ZLaz0/p;Lay0/n;)Ljava/lang/Object;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    instance-of v1, p3, Lrx0/a;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    invoke-static {p3, p2, p0}, Ljp/hg;->e(Lay0/n;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    goto :goto_1

    .line 11
    :catchall_0
    move-exception p2

    .line 12
    goto :goto_0

    .line 13
    :catch_0
    move-exception p1

    .line 14
    goto :goto_4

    .line 15
    :cond_0
    const/4 v1, 0x2

    .line 16
    invoke-static {v1, p3}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p3, p2, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p2
    :try_end_0
    .catch Lvy0/l0; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    goto :goto_1

    .line 24
    :goto_0
    new-instance p3, Lvy0/u;

    .line 25
    .line 26
    invoke-direct {p3, p2, v0}, Lvy0/u;-><init>(Ljava/lang/Throwable;Z)V

    .line 27
    .line 28
    .line 29
    move-object p2, p3

    .line 30
    :goto_1
    sget-object p3, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    if-ne p2, p3, :cond_1

    .line 33
    .line 34
    goto :goto_2

    .line 35
    :cond_1
    invoke-virtual {p0, p2}, Lvy0/p1;->X(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    sget-object v1, Lvy0/e0;->e:Lj51/i;

    .line 40
    .line 41
    if-ne v0, v1, :cond_2

    .line 42
    .line 43
    :goto_2
    return-object p3

    .line 44
    :cond_2
    invoke-virtual {p0}, Laz0/p;->o0()V

    .line 45
    .line 46
    .line 47
    instance-of p3, v0, Lvy0/u;

    .line 48
    .line 49
    if-eqz p3, :cond_5

    .line 50
    .line 51
    if-nez p1, :cond_4

    .line 52
    .line 53
    move-object p1, v0

    .line 54
    check-cast p1, Lvy0/u;

    .line 55
    .line 56
    iget-object p1, p1, Lvy0/u;->a:Ljava/lang/Throwable;

    .line 57
    .line 58
    instance-of p3, p1, Lvy0/e2;

    .line 59
    .line 60
    if-eqz p3, :cond_4

    .line 61
    .line 62
    check-cast p1, Lvy0/e2;

    .line 63
    .line 64
    iget-object p1, p1, Lvy0/e2;->d:Lvy0/i1;

    .line 65
    .line 66
    if-ne p1, p0, :cond_4

    .line 67
    .line 68
    instance-of p0, p2, Lvy0/u;

    .line 69
    .line 70
    if-nez p0, :cond_3

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    check-cast p2, Lvy0/u;

    .line 74
    .line 75
    iget-object p0, p2, Lvy0/u;->a:Ljava/lang/Throwable;

    .line 76
    .line 77
    throw p0

    .line 78
    :cond_4
    check-cast v0, Lvy0/u;

    .line 79
    .line 80
    iget-object p0, v0, Lvy0/u;->a:Ljava/lang/Throwable;

    .line 81
    .line 82
    throw p0

    .line 83
    :cond_5
    invoke-static {v0}, Lvy0/e0;->P(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    :goto_3
    return-object p2

    .line 88
    :goto_4
    new-instance p2, Lvy0/u;

    .line 89
    .line 90
    iget-object p1, p1, Lvy0/l0;->d:Ljava/lang/Throwable;

    .line 91
    .line 92
    invoke-direct {p2, p1, v0}, Lvy0/u;-><init>(Ljava/lang/Throwable;Z)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p0, p2}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    throw p1
.end method

.method public static final b(Lrd0/c0;Ljava/time/ZoneId;)Llx0/l;
    .locals 2

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lrd0/c0;->a:Ljava/time/LocalDate;

    .line 4
    .line 5
    sget-object v1, Ljava/time/LocalTime;->MIN:Ljava/time/LocalTime;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ljava/time/LocalDate;->atTime(Ljava/time/LocalTime;)Ljava/time/LocalDateTime;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {v0, p1}, Ljava/time/LocalDateTime;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Ljava/time/ZonedDateTime;->toOffsetDateTime()Ljava/time/OffsetDateTime;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget-object p0, p0, Lrd0/c0;->b:Ljava/time/LocalDate;

    .line 20
    .line 21
    sget-object v1, Ljava/time/LocalTime;->MAX:Ljava/time/LocalTime;

    .line 22
    .line 23
    invoke-virtual {p0, v1}, Ljava/time/LocalDate;->atTime(Ljava/time/LocalTime;)Ljava/time/LocalDateTime;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {p0, p1}, Ljava/time/LocalDateTime;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0}, Ljava/time/ZonedDateTime;->toOffsetDateTime()Ljava/time/OffsetDateTime;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    new-instance p1, Llx0/l;

    .line 36
    .line 37
    invoke-direct {p1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    return-object p1

    .line 41
    :cond_0
    new-instance p0, Llx0/l;

    .line 42
    .line 43
    const/4 p1, 0x0

    .line 44
    invoke-direct {p0, p1, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object p0
.end method

.method public static final c(Lcz/myskoda/api/bff/v1/ChargingSessionDto;)Lrd0/u;
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget v0, Lmy0/c;->g:I

    .line 7
    .line 8
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingSessionDto;->getDurationInMinutes()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    sget-object v1, Lmy0/e;->i:Lmy0/e;

    .line 13
    .line 14
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 15
    .line 16
    .line 17
    move-result-wide v3

    .line 18
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingSessionDto;->getStartAt()Ljava/time/OffsetDateTime;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/time/OffsetDateTime;->atZoneSameInstant(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {v0}, Ljava/time/ZonedDateTime;->toOffsetDateTime()Ljava/time/OffsetDateTime;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    const-string v0, "toOffsetDateTime(...)"

    .line 35
    .line 36
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingSessionDto;->getChargedInKWh()Ljava/lang/Double;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    const/4 v1, 0x0

    .line 44
    if-eqz v0, :cond_0

    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 47
    .line 48
    .line 49
    move-result-wide v6

    .line 50
    invoke-static {v6, v7}, Ljava/lang/Math;->ceil(D)D

    .line 51
    .line 52
    .line 53
    move-result-wide v6

    .line 54
    double-to-int v0, v6

    .line 55
    new-instance v2, Lqr0/h;

    .line 56
    .line 57
    invoke-direct {v2, v0}, Lqr0/h;-><init>(I)V

    .line 58
    .line 59
    .line 60
    move-object v6, v2

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    move-object v6, v1

    .line 63
    :goto_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingSessionDto;->getCurrentType()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    if-eqz p0, :cond_2

    .line 68
    .line 69
    const-string v0, "AC"

    .line 70
    .line 71
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-eqz v0, :cond_1

    .line 76
    .line 77
    sget-object v1, Lqr0/a;->d:Lqr0/a;

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_1
    const-string v0, "DC"

    .line 81
    .line 82
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    if-eqz p0, :cond_2

    .line 87
    .line 88
    sget-object v1, Lqr0/a;->e:Lqr0/a;

    .line 89
    .line 90
    :cond_2
    :goto_1
    move-object v7, v1

    .line 91
    new-instance v2, Lrd0/u;

    .line 92
    .line 93
    invoke-direct/range {v2 .. v7}, Lrd0/u;-><init>(JLjava/time/OffsetDateTime;Lqr0/h;Lqr0/a;)V

    .line 94
    .line 95
    .line 96
    return-object v2
.end method
