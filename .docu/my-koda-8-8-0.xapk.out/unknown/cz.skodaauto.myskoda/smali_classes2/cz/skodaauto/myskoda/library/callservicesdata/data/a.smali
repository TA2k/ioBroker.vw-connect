.class public abstract Lcz/skodaauto/myskoda/library/callservicesdata/data/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;)Ljd0/d;
    .locals 15

    .line 1
    new-instance v0, Ljd0/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;->getRoadsideAssistance()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;->getInfoLine()Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$InfoLineDto;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v2, "<this>"

    .line 12
    .line 13
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$InfoLineDto;->getPhone()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$InfoLineDto;->getEmail()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$InfoLineDto;->isNonstop()Z

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$InfoLineDto;->getWorkingHours()Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Ljava/lang/Iterable;

    .line 33
    .line 34
    new-instance v6, Ljava/util/ArrayList;

    .line 35
    .line 36
    const/16 v7, 0xa

    .line 37
    .line 38
    invoke-static {p0, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 39
    .line 40
    .line 41
    move-result v8

    .line 42
    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 43
    .line 44
    .line 45
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v8

    .line 53
    if-eqz v8, :cond_1

    .line 54
    .line 55
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    check-cast v8, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$WorkingHoursDto;

    .line 60
    .line 61
    invoke-static {v8, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v8}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$WorkingHoursDto;->getFrom()Ljava/time/DayOfWeek;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    invoke-virtual {v8}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$WorkingHoursDto;->getTo()Ljava/time/DayOfWeek;

    .line 69
    .line 70
    .line 71
    move-result-object v10

    .line 72
    invoke-virtual {v8}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$WorkingHoursDto;->getTimes()Ljava/util/List;

    .line 73
    .line 74
    .line 75
    move-result-object v8

    .line 76
    check-cast v8, Ljava/lang/Iterable;

    .line 77
    .line 78
    new-instance v11, Ljava/util/ArrayList;

    .line 79
    .line 80
    invoke-static {v8, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 81
    .line 82
    .line 83
    move-result v12

    .line 84
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 85
    .line 86
    .line 87
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    :goto_1
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 92
    .line 93
    .line 94
    move-result v12

    .line 95
    if-eqz v12, :cond_0

    .line 96
    .line 97
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v12

    .line 101
    check-cast v12, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$WorkingHoursDto$TimeDto;

    .line 102
    .line 103
    invoke-static {v12, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    new-instance v13, Ljd0/b;

    .line 107
    .line 108
    invoke-virtual {v12}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$WorkingHoursDto$TimeDto;->getFrom()Ljava/time/LocalTime;

    .line 109
    .line 110
    .line 111
    move-result-object v14

    .line 112
    invoke-virtual {v12}, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto$WorkingHoursDto$TimeDto;->getTo()Ljava/time/LocalTime;

    .line 113
    .line 114
    .line 115
    move-result-object v12

    .line 116
    invoke-direct {v13, v14, v12}, Ljd0/b;-><init>(Ljava/time/LocalTime;Ljava/time/LocalTime;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_0
    new-instance v8, Ljd0/c;

    .line 124
    .line 125
    invoke-direct {v8, v9, v10, v11}, Ljd0/c;-><init>(Ljava/time/DayOfWeek;Ljava/time/DayOfWeek;Ljava/util/ArrayList;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    goto :goto_0

    .line 132
    :cond_1
    new-instance p0, Ljd0/a;

    .line 133
    .line 134
    invoke-direct {p0, v3, v4, v6, v5}, Ljd0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Z)V

    .line 135
    .line 136
    .line 137
    invoke-direct {v0, v1, p0}, Ljd0/d;-><init>(Ljava/lang/String;Ljd0/a;)V

    .line 138
    .line 139
    .line 140
    return-object v0
.end method
