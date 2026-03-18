.class public final Llz/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# direct methods
.method public static a(Llz/m;)Ljava/util/ArrayList;
    .locals 14

    .line 1
    iget-object v0, p0, Llz/m;->a:Ljava/time/ZoneId;

    .line 2
    .line 3
    iget-object v1, p0, Llz/m;->b:Ljava/time/ZoneId;

    .line 4
    .line 5
    iget-object p0, p0, Llz/m;->c:Ljava/util/List;

    .line 6
    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v2, Ljava/util/ArrayList;

    .line 10
    .line 11
    const/16 v3, 0xa

    .line 12
    .line 13
    invoke-static {p0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-eqz v4, :cond_3

    .line 29
    .line 30
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    move-object v5, v4

    .line 35
    check-cast v5, Lao0/c;

    .line 36
    .line 37
    iget-object v4, v5, Lao0/c;->c:Ljava/time/LocalTime;

    .line 38
    .line 39
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    invoke-virtual {v4, v6}, Ljava/time/LocalTime;->atDate(Ljava/time/LocalDate;)Ljava/time/LocalDateTime;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    invoke-virtual {v4, v0}, Ljava/time/LocalDateTime;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    invoke-virtual {v4}, Ljava/time/ZonedDateTime;->toOffsetDateTime()Ljava/time/OffsetDateTime;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    invoke-virtual {v4, v1}, Ljava/time/OffsetDateTime;->atZoneSameInstant(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 56
    .line 57
    .line 58
    move-result-object v6

    .line 59
    invoke-virtual {v6}, Ljava/time/ZonedDateTime;->toLocalTime()Ljava/time/LocalTime;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    const-string v6, "toLocalTime(...)"

    .line 64
    .line 65
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object v6, v5, Lao0/c;->e:Ljava/util/Set;

    .line 69
    .line 70
    check-cast v6, Ljava/lang/Iterable;

    .line 71
    .line 72
    new-instance v8, Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-static {v6, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 75
    .line 76
    .line 77
    move-result v9

    .line 78
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    :goto_1
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 86
    .line 87
    .line 88
    move-result v9

    .line 89
    if-eqz v9, :cond_2

    .line 90
    .line 91
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v9

    .line 95
    check-cast v9, Ljava/time/DayOfWeek;

    .line 96
    .line 97
    invoke-virtual {v4}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 98
    .line 99
    .line 100
    move-result-object v10

    .line 101
    invoke-virtual {v4, v1}, Ljava/time/OffsetDateTime;->atZoneSameInstant(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 102
    .line 103
    .line 104
    move-result-object v11

    .line 105
    invoke-virtual {v11}, Ljava/time/ZonedDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 106
    .line 107
    .line 108
    move-result-object v11

    .line 109
    invoke-virtual {v10, v11}, Ljava/time/LocalDate;->isBefore(Ljava/time/chrono/ChronoLocalDate;)Z

    .line 110
    .line 111
    .line 112
    move-result v10

    .line 113
    invoke-virtual {v4}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 114
    .line 115
    .line 116
    move-result-object v11

    .line 117
    invoke-virtual {v4, v1}, Ljava/time/OffsetDateTime;->atZoneSameInstant(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 118
    .line 119
    .line 120
    move-result-object v12

    .line 121
    invoke-virtual {v12}, Ljava/time/ZonedDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 122
    .line 123
    .line 124
    move-result-object v12

    .line 125
    invoke-virtual {v11, v12}, Ljava/time/LocalDate;->isAfter(Ljava/time/chrono/ChronoLocalDate;)Z

    .line 126
    .line 127
    .line 128
    move-result v11

    .line 129
    const-wide/16 v12, 0x1

    .line 130
    .line 131
    if-eqz v11, :cond_0

    .line 132
    .line 133
    invoke-virtual {v9, v12, v13}, Ljava/time/DayOfWeek;->minus(J)Ljava/time/DayOfWeek;

    .line 134
    .line 135
    .line 136
    move-result-object v9

    .line 137
    const-string v10, "minus(...)"

    .line 138
    .line 139
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_0
    if-eqz v10, :cond_1

    .line 144
    .line 145
    invoke-virtual {v9, v12, v13}, Ljava/time/DayOfWeek;->plus(J)Ljava/time/DayOfWeek;

    .line 146
    .line 147
    .line 148
    move-result-object v9

    .line 149
    const-string v10, "plus(...)"

    .line 150
    .line 151
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    :cond_1
    :goto_2
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    goto :goto_1

    .line 158
    :cond_2
    invoke-static {v8}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 159
    .line 160
    .line 161
    move-result-object v9

    .line 162
    const/4 v10, 0x0

    .line 163
    const/16 v11, 0x2b

    .line 164
    .line 165
    const/4 v6, 0x0

    .line 166
    const/4 v8, 0x0

    .line 167
    invoke-static/range {v5 .. v11}, Lao0/c;->a(Lao0/c;ZLjava/time/LocalTime;Lao0/f;Ljava/util/Set;ZI)Lao0/c;

    .line 168
    .line 169
    .line 170
    move-result-object v4

    .line 171
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    goto/16 :goto_0

    .line 175
    .line 176
    :cond_3
    return-object v2
.end method


# virtual methods
.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast p0, Llz/m;

    .line 4
    .line 5
    invoke-static {p0}, Llz/n;->a(Llz/m;)Ljava/util/ArrayList;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
