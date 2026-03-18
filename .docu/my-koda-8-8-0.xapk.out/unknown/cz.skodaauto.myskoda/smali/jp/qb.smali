.class public abstract Ljp/qb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V
    .locals 1

    .line 1
    instance-of v0, p0, Lvy0/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lvy0/l0;

    .line 6
    .line 7
    iget-object p0, p0, Lvy0/l0;->d:Ljava/lang/Throwable;

    .line 8
    .line 9
    :cond_0
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {p1, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method

.method public static final b(Lkotlin/coroutines/Continuation;Lvy0/a;)V
    .locals 1

    .line 1
    :try_start_0
    invoke-static {p0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    invoke-static {v0, p0}, Laz0/b;->h(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    invoke-static {p0, p1}, Ljp/qb;->a(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    throw p0
.end method

.method public static final c(Ljava/lang/String;)Lrd0/h;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    sparse-switch v0, :sswitch_data_0

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :sswitch_0
    const-string v0, "PREFERRED_CHARGING_TIMES"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    sget-object p0, Lrd0/h;->g:Lrd0/h;

    .line 24
    .line 25
    return-object p0

    .line 26
    :sswitch_1
    const-string v0, "TIMER_CHARGING_WITH_CLIMATISATION"

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    sget-object p0, Lrd0/h;->f:Lrd0/h;

    .line 36
    .line 37
    return-object p0

    .line 38
    :sswitch_2
    const-string v0, "HOME_STORAGE_CHARGING"

    .line 39
    .line 40
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-nez p0, :cond_2

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_2
    sget-object p0, Lrd0/h;->j:Lrd0/h;

    .line 48
    .line 49
    return-object p0

    .line 50
    :sswitch_3
    const-string v0, "TIMER"

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-nez p0, :cond_3

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    sget-object p0, Lrd0/h;->e:Lrd0/h;

    .line 60
    .line 61
    return-object p0

    .line 62
    :sswitch_4
    const-string v0, "ONLY_OWN_CURRENT"

    .line 63
    .line 64
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-nez p0, :cond_4

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_4
    sget-object p0, Lrd0/h;->h:Lrd0/h;

    .line 72
    .line 73
    return-object p0

    .line 74
    :sswitch_5
    const-string v0, "IMMEDIATE_DISCHARGING"

    .line 75
    .line 76
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    if-nez p0, :cond_5

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_5
    sget-object p0, Lrd0/h;->i:Lrd0/h;

    .line 84
    .line 85
    return-object p0

    .line 86
    :sswitch_6
    const-string v0, "MANUAL"

    .line 87
    .line 88
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    if-nez p0, :cond_6

    .line 93
    .line 94
    :goto_0
    const/4 p0, 0x0

    .line 95
    return-object p0

    .line 96
    :cond_6
    sget-object p0, Lrd0/h;->d:Lrd0/h;

    .line 97
    .line 98
    return-object p0

    .line 99
    :sswitch_data_0
    .sparse-switch
        -0x78e2243a -> :sswitch_6
        -0x47929ecf -> :sswitch_5
        -0xfe74e93 -> :sswitch_4
        0x4c20f25 -> :sswitch_3
        0x253c9b35 -> :sswitch_2
        0x467a6666 -> :sswitch_1
        0x57974f76 -> :sswitch_0
    .end sparse-switch
.end method

.method public static final d(Lrd0/g0;)Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-ne p0, v0, :cond_0

    .line 9
    .line 10
    new-instance p0, Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;

    .line 11
    .line 12
    const-string v0, "OFF"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance p0, La8/r0;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    new-instance p0, Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;

    .line 25
    .line 26
    const-string v0, "PERMANENT"

    .line 27
    .line 28
    invoke-direct {p0, v0}, Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method

.method public static final e(Lrd0/g;)Lcz/myskoda/api/bff/v1/ChargingCurrentDto;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x2

    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    if-ne p0, v2, :cond_0

    .line 16
    .line 17
    new-instance p0, Lcz/myskoda/api/bff/v1/ChargingCurrentDto;

    .line 18
    .line 19
    const-string v2, "REDUCED"

    .line 20
    .line 21
    invoke-direct {p0, v2, v1, v0, v1}, Lcz/myskoda/api/bff/v1/ChargingCurrentDto;-><init>(Ljava/lang/String;Ljava/lang/Integer;ILkotlin/jvm/internal/g;)V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    new-instance p0, Lcz/myskoda/api/bff/v1/ChargingCurrentDto;

    .line 32
    .line 33
    const-string v2, "MAXIMUM"

    .line 34
    .line 35
    invoke-direct {p0, v2, v1, v0, v1}, Lcz/myskoda/api/bff/v1/ChargingCurrentDto;-><init>(Ljava/lang/String;Ljava/lang/Integer;ILkotlin/jvm/internal/g;)V

    .line 36
    .line 37
    .line 38
    return-object p0
.end method
