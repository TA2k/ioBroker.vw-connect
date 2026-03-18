.class public abstract Lwn0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lao0/c;)Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-wide v2, p0, Lao0/c;->a:J

    .line 7
    .line 8
    iget-boolean v4, p0, Lao0/c;->b:Z

    .line 9
    .line 10
    iget-object v0, p0, Lao0/c;->c:Ljava/time/LocalTime;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/time/LocalTime;->toString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v5

    .line 16
    const-string v0, "toString(...)"

    .line 17
    .line 18
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lao0/c;->d:Lao0/f;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    if-ne v0, v1, :cond_0

    .line 31
    .line 32
    sget-object v0, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto$Type;->RECURRING:Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto$Type;

    .line 33
    .line 34
    :goto_0
    move-object v6, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    new-instance p0, La8/r0;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_1
    sget-object v0, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto$Type;->ONE_OFF:Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto$Type;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :goto_1
    iget-object p0, p0, Lao0/c;->e:Ljava/util/Set;

    .line 46
    .line 47
    check-cast p0, Ljava/lang/Iterable;

    .line 48
    .line 49
    new-instance v7, Ljava/util/ArrayList;

    .line 50
    .line 51
    const/16 v0, 0xa

    .line 52
    .line 53
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    invoke-direct {v7, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 58
    .line 59
    .line 60
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_2

    .line 69
    .line 70
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    check-cast v0, Ljava/time/DayOfWeek;

    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-interface {v7, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_2
    new-instance v1, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;

    .line 85
    .line 86
    invoke-direct/range {v1 .. v7}, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;-><init>(JZLjava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto$Type;Ljava/util/List;)V

    .line 87
    .line 88
    .line 89
    return-object v1
.end method

.method public static final b(Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;)Lao0/c;
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;->getId()J

    .line 7
    .line 8
    .line 9
    move-result-wide v2

    .line 10
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;->getEnabled()Z

    .line 11
    .line 12
    .line 13
    move-result v4

    .line 14
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;->getTime()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-static {v0}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    const-string v0, "parse(...)"

    .line 23
    .line 24
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;->getType()Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto$Type;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sget-object v1, Lwn0/b;->a:[I

    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    aget v0, v1, v0

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    if-eq v0, v1, :cond_1

    .line 41
    .line 42
    const/4 v1, 0x2

    .line 43
    if-ne v0, v1, :cond_0

    .line 44
    .line 45
    sget-object v0, Lao0/f;->e:Lao0/f;

    .line 46
    .line 47
    :goto_0
    move-object v6, v0

    .line 48
    goto :goto_1

    .line 49
    :cond_0
    new-instance p0, La8/r0;

    .line 50
    .line 51
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_1
    sget-object v0, Lao0/f;->d:Lao0/f;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :goto_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;->getSelectedDays()Ljava/util/List;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Ljava/lang/Iterable;

    .line 63
    .line 64
    new-instance v0, Ljava/util/ArrayList;

    .line 65
    .line 66
    const/16 v1, 0xa

    .line 67
    .line 68
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 73
    .line 74
    .line 75
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-eqz v1, :cond_2

    .line 84
    .line 85
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Ljava/lang/String;

    .line 90
    .line 91
    invoke-static {v1}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_2
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 100
    .line 101
    .line 102
    move-result-object v7

    .line 103
    new-instance v1, Lao0/c;

    .line 104
    .line 105
    const/4 v8, 0x0

    .line 106
    invoke-direct/range {v1 .. v8}, Lao0/c;-><init>(JZLjava/time/LocalTime;Lao0/f;Ljava/util/Set;Z)V

    .line 107
    .line 108
    .line 109
    return-object v1
.end method
