.class public abstract Lu7/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Landroid/media/AudioManager;


# direct methods
.method public static declared-synchronized a(Landroid/content/Context;)Landroid/media/AudioManager;
    .locals 5

    .line 1
    const-class v0, Lu7/b;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    sput-object v1, Lu7/b;->a:Landroid/media/AudioManager;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_2

    .line 16
    :cond_0
    :goto_0
    sget-object v1, Lu7/b;->a:Landroid/media/AudioManager;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-object v1

    .line 22
    :cond_1
    :try_start_1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    if-eqz v1, :cond_3

    .line 27
    .line 28
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    if-ne v1, v2, :cond_2

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_2
    new-instance v1, Lw7/e;

    .line 36
    .line 37
    invoke-direct {v1}, Lw7/e;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-static {}, Lw7/a;->q()Ljava/util/concurrent/Executor;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    new-instance v3, Lno/nordicsemi/android/ble/o0;

    .line 45
    .line 46
    const/16 v4, 0x14

    .line 47
    .line 48
    invoke-direct {v3, v4, p0, v1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1}, Lw7/e;->a()V

    .line 55
    .line 56
    .line 57
    sget-object p0, Lu7/b;->a:Landroid/media/AudioManager;

    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 60
    .line 61
    .line 62
    monitor-exit v0

    .line 63
    return-object p0

    .line 64
    :cond_3
    :goto_1
    :try_start_2
    const-string v1, "audio"

    .line 65
    .line 66
    invoke-virtual {p0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    check-cast p0, Landroid/media/AudioManager;

    .line 71
    .line 72
    sput-object p0, Lu7/b;->a:Landroid/media/AudioManager;

    .line 73
    .line 74
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 75
    .line 76
    .line 77
    monitor-exit v0

    .line 78
    return-object p0

    .line 79
    :goto_2
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 80
    throw p0
.end method

.method public static final b(Ljava/time/LocalDate;)J
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {p0}, Ljava/time/LocalDate;->getMonthValue()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-virtual {p0}, Ljava/time/LocalDate;->getDayOfMonth()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/4 v7, 0x0

    .line 19
    sget-object v8, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    invoke-static/range {v1 .. v8}, Ljava/time/OffsetDateTime;->of(IIIIIIILjava/time/ZoneOffset;)Ljava/time/OffsetDateTime;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {p0}, Ljava/time/Instant;->toEpochMilli()J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    return-wide v0
.end method

.method public static final c(Ljava/time/LocalDate;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/time/format/FormatStyle;->MEDIUM:Ljava/time/format/FormatStyle;

    .line 7
    .line 8
    invoke-static {v0}, Ljava/time/format/DateTimeFormatter;->ofLocalizedDate(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {p0, v0}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v0, "format(...)"

    .line 17
    .line 18
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public static final d(Ljava/time/LocalDate;)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    sget-object v2, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    sget-object v4, Ljava/time/chrono/IsoChronology;->INSTANCE:Ljava/time/chrono/IsoChronology;

    .line 18
    .line 19
    invoke-static {v2, v3, v4, v1}, Ljava/time/format/DateTimeFormatterBuilder;->getLocalizedDateTimePattern(Ljava/time/format/FormatStyle;Ljava/time/format/FormatStyle;Ljava/time/chrono/Chronology;Ljava/util/Locale;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v2, "getLocalizedDateTimePattern(...)"

    .line 24
    .line 25
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v2, "yyyy"

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    const-string v4, "yy"

    .line 32
    .line 33
    invoke-static {v3, v1, v4, v2}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    new-instance v2, Ljava/time/format/DateTimeFormatterBuilder;

    .line 38
    .line 39
    invoke-direct {v2}, Ljava/time/format/DateTimeFormatterBuilder;-><init>()V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2, v1}, Ljava/time/format/DateTimeFormatterBuilder;->appendPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatterBuilder;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-virtual {v1, v0}, Ljava/time/format/DateTimeFormatterBuilder;->toFormatter(Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {v0, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    const-string v0, "format(...)"

    .line 55
    .line 56
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    return-object p0
.end method

.method public static final e(Ljava/time/LocalDate;)Ljava/lang/String;
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    sget-object v2, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    sget-object v4, Ljava/time/chrono/IsoChronology;->INSTANCE:Ljava/time/chrono/IsoChronology;

    .line 18
    .line 19
    invoke-static {v2, v3, v4, v1}, Ljava/time/format/DateTimeFormatterBuilder;->getLocalizedDateTimePattern(Ljava/time/format/FormatStyle;Ljava/time/format/FormatStyle;Ljava/time/chrono/Chronology;Ljava/util/Locale;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v2, "getLocalizedDateTimePattern(...)"

    .line 24
    .line 25
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    const-string v3, "y"

    .line 30
    .line 31
    const-string v4, ""

    .line 32
    .line 33
    invoke-static {v2, v1, v3, v4}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    move v5, v2

    .line 42
    :goto_0
    const-string v6, "substring(...)"

    .line 43
    .line 44
    if-ge v5, v3, :cond_1

    .line 45
    .line 46
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    const/16 v8, 0x64

    .line 51
    .line 52
    invoke-static {v8}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 53
    .line 54
    .line 55
    move-result-object v8

    .line 56
    const/16 v9, 0x4d

    .line 57
    .line 58
    invoke-static {v9}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 59
    .line 60
    .line 61
    move-result-object v9

    .line 62
    filled-new-array {v8, v9}, [Ljava/lang/Character;

    .line 63
    .line 64
    .line 65
    move-result-object v8

    .line 66
    invoke-static {v8}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    invoke-static {v7}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    invoke-interface {v8, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    if-eqz v7, :cond_0

    .line 79
    .line 80
    invoke-virtual {v1, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_0
    add-int/lit8 v5, v5, 0x1

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_1
    move-object v1, v4

    .line 92
    :goto_1
    invoke-static {v1}, Lly0/p;->F(Ljava/lang/CharSequence;)I

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    :goto_2
    const/4 v5, -0x1

    .line 97
    if-ge v5, v3, :cond_3

    .line 98
    .line 99
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 100
    .line 101
    .line 102
    move-result v5

    .line 103
    const/16 v7, 0x20

    .line 104
    .line 105
    invoke-static {v7}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 106
    .line 107
    .line 108
    move-result-object v7

    .line 109
    const/16 v8, 0x2f

    .line 110
    .line 111
    invoke-static {v8}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 112
    .line 113
    .line 114
    move-result-object v8

    .line 115
    const/16 v9, 0x2d

    .line 116
    .line 117
    invoke-static {v9}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 118
    .line 119
    .line 120
    move-result-object v9

    .line 121
    filled-new-array {v7, v8, v9}, [Ljava/lang/Character;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    invoke-static {v7}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 126
    .line 127
    .line 128
    move-result-object v7

    .line 129
    invoke-static {v5}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 130
    .line 131
    .line 132
    move-result-object v5

    .line 133
    invoke-interface {v7, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v5

    .line 137
    if-nez v5, :cond_2

    .line 138
    .line 139
    add-int/lit8 v3, v3, 0x1

    .line 140
    .line 141
    invoke-virtual {v1, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_2
    add-int/lit8 v3, v3, -0x1

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_3
    :goto_3
    new-instance v1, Ljava/time/format/DateTimeFormatterBuilder;

    .line 153
    .line 154
    invoke-direct {v1}, Ljava/time/format/DateTimeFormatterBuilder;-><init>()V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v1, v4}, Ljava/time/format/DateTimeFormatterBuilder;->appendPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatterBuilder;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-virtual {v1, v0}, Ljava/time/format/DateTimeFormatterBuilder;->toFormatter(Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-virtual {v0, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    const-string v0, "format(...)"

    .line 170
    .line 171
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    return-object p0
.end method

.method public static final f(Ljava/lang/String;)Llx0/u;
    .locals 8

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    invoke-static {v0}, Lry/a;->a(I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    const/4 v2, 0x0

    .line 14
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/16 v4, 0x30

    .line 19
    .line 20
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->g(II)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-gez v4, :cond_1

    .line 25
    .line 26
    const/4 v4, 0x1

    .line 27
    if-eq v1, v4, :cond_5

    .line 28
    .line 29
    const/16 v5, 0x2b

    .line 30
    .line 31
    if-eq v3, v5, :cond_2

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v4, v2

    .line 35
    :cond_2
    const v3, 0x71c71c7

    .line 36
    .line 37
    .line 38
    move v5, v3

    .line 39
    :goto_0
    if-ge v4, v1, :cond_7

    .line 40
    .line 41
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    invoke-static {v6, v0}, Ljava/lang/Character;->digit(II)I

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    if-gez v6, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    invoke-static {v2, v5}, Ljava/lang/Integer;->compareUnsigned(II)I

    .line 53
    .line 54
    .line 55
    move-result v7

    .line 56
    if-lez v7, :cond_4

    .line 57
    .line 58
    if-ne v5, v3, :cond_5

    .line 59
    .line 60
    const/4 v5, -0x1

    .line 61
    invoke-static {v5, v0}, Ljava/lang/Integer;->divideUnsigned(II)I

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    invoke-static {v2, v5}, Ljava/lang/Integer;->compareUnsigned(II)I

    .line 66
    .line 67
    .line 68
    move-result v7

    .line 69
    if-lez v7, :cond_4

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_4
    mul-int/lit8 v2, v2, 0xa

    .line 73
    .line 74
    add-int/2addr v6, v2

    .line 75
    invoke-static {v6, v2}, Ljava/lang/Integer;->compareUnsigned(II)I

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-gez v2, :cond_6

    .line 80
    .line 81
    :cond_5
    :goto_1
    const/4 p0, 0x0

    .line 82
    return-object p0

    .line 83
    :cond_6
    add-int/lit8 v4, v4, 0x1

    .line 84
    .line 85
    move v2, v6

    .line 86
    goto :goto_0

    .line 87
    :cond_7
    new-instance p0, Llx0/u;

    .line 88
    .line 89
    invoke-direct {p0, v2}, Llx0/u;-><init>(I)V

    .line 90
    .line 91
    .line 92
    return-object p0
.end method

.method public static final g(Ljava/lang/String;)Llx0/w;
    .locals 15

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/16 v0, 0xa

    .line 7
    .line 8
    invoke-static {v0}, Lry/a;->a(I)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_0
    const/4 v2, 0x0

    .line 19
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/16 v4, 0x30

    .line 24
    .line 25
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->g(II)I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    if-gez v4, :cond_1

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eq v1, v2, :cond_4

    .line 33
    .line 34
    const/16 v4, 0x2b

    .line 35
    .line 36
    if-eq v3, v4, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    int-to-long v3, v0

    .line 40
    const-wide v5, 0x71c71c71c71c71cL

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    const-wide/16 v7, 0x0

    .line 46
    .line 47
    move-wide v9, v5

    .line 48
    :goto_0
    if-ge v2, v1, :cond_6

    .line 49
    .line 50
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 51
    .line 52
    .line 53
    move-result v11

    .line 54
    invoke-static {v11, v0}, Ljava/lang/Character;->digit(II)I

    .line 55
    .line 56
    .line 57
    move-result v11

    .line 58
    if-gez v11, :cond_2

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    invoke-static {v7, v8, v9, v10}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 62
    .line 63
    .line 64
    move-result v12

    .line 65
    if-lez v12, :cond_3

    .line 66
    .line 67
    cmp-long v9, v9, v5

    .line 68
    .line 69
    if-nez v9, :cond_4

    .line 70
    .line 71
    const-wide/16 v9, -0x1

    .line 72
    .line 73
    invoke-static {v9, v10, v3, v4}, Ljava/lang/Long;->divideUnsigned(JJ)J

    .line 74
    .line 75
    .line 76
    move-result-wide v9

    .line 77
    invoke-static {v7, v8, v9, v10}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 78
    .line 79
    .line 80
    move-result v12

    .line 81
    if-lez v12, :cond_3

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_3
    mul-long/2addr v7, v3

    .line 85
    int-to-long v11, v11

    .line 86
    const-wide v13, 0xffffffffL

    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    and-long/2addr v11, v13

    .line 92
    add-long/2addr v11, v7

    .line 93
    invoke-static {v11, v12, v7, v8}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 94
    .line 95
    .line 96
    move-result v7

    .line 97
    if-gez v7, :cond_5

    .line 98
    .line 99
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 100
    return-object p0

    .line 101
    :cond_5
    add-int/lit8 v2, v2, 0x1

    .line 102
    .line 103
    move-wide v7, v11

    .line 104
    goto :goto_0

    .line 105
    :cond_6
    new-instance p0, Llx0/w;

    .line 106
    .line 107
    invoke-direct {p0, v7, v8}, Llx0/w;-><init>(J)V

    .line 108
    .line 109
    .line 110
    return-object p0
.end method
