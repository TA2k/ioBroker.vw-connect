.class public final Li2/b0;
.super Li2/z;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Ljava/time/ZoneId;


# instance fields
.field public final c:I

.field public final d:Ljava/util/ArrayList;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "UTC"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/time/ZoneId;->of(Ljava/lang/String;)Ljava/time/ZoneId;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Li2/b0;->e:Ljava/time/ZoneId;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/util/Locale;)V
    .locals 7

    .line 1
    invoke-direct {p0, p1}, Li2/z;-><init>(Ljava/util/Locale;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Ljava/time/temporal/WeekFields;->of(Ljava/util/Locale;)Ljava/time/temporal/WeekFields;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Ljava/time/temporal/WeekFields;->getFirstDayOfWeek()Ljava/time/DayOfWeek;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {v0}, Ljava/time/DayOfWeek;->getValue()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iput v0, p0, Li2/b0;->c:I

    .line 17
    .line 18
    sget-object v0, Li2/a0;->a:Lsx0/b;

    .line 19
    .line 20
    new-instance v1, Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-virtual {v0}, Lsx0/b;->c()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lsx0/b;->c()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    const/4 v3, 0x0

    .line 34
    :goto_0
    if-ge v3, v2, :cond_0

    .line 35
    .line 36
    invoke-virtual {v0, v3}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    check-cast v4, Ljava/time/DayOfWeek;

    .line 41
    .line 42
    sget-object v5, Ljava/time/format/TextStyle;->FULL_STANDALONE:Ljava/time/format/TextStyle;

    .line 43
    .line 44
    invoke-virtual {v4, v5, p1}, Ljava/time/DayOfWeek;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    sget-object v6, Ljava/time/format/TextStyle;->NARROW_STANDALONE:Ljava/time/format/TextStyle;

    .line 49
    .line 50
    invoke-virtual {v4, v6, p1}, Ljava/time/DayOfWeek;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    new-instance v6, Llx0/l;

    .line 55
    .line 56
    invoke-direct {v6, v5, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    add-int/lit8 v3, v3, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    iput-object v1, p0, Li2/b0;->d:Ljava/util/ArrayList;

    .line 66
    .line 67
    return-void
.end method


# virtual methods
.method public final a(J)Li2/y;
    .locals 6

    .line 1
    invoke-static {p1, p2}, Ljava/time/Instant;->ofEpochMilli(J)Ljava/time/Instant;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object p1, Li2/b0;->e:Ljava/time/ZoneId;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/time/Instant;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Ljava/time/ZonedDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    new-instance v0, Li2/y;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    invoke-virtual {p0}, Ljava/time/LocalDate;->getMonthValue()I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    invoke-virtual {p0}, Ljava/time/LocalDate;->getDayOfMonth()I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    invoke-virtual {p0}, Ljava/time/LocalDate;->atStartOfDay()Ljava/time/LocalDateTime;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    sget-object p1, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 34
    .line 35
    invoke-interface {p0, p1}, Ljava/time/chrono/ChronoLocalDateTime;->toEpochSecond(Ljava/time/ZoneOffset;)J

    .line 36
    .line 37
    .line 38
    move-result-wide p0

    .line 39
    const/16 p2, 0x3e8

    .line 40
    .line 41
    int-to-long v1, p2

    .line 42
    mul-long/2addr v1, p0

    .line 43
    invoke-direct/range {v0 .. v5}, Li2/y;-><init>(JIII)V

    .line 44
    .line 45
    .line 46
    return-object v0
.end method

.method public final b(J)Li2/c0;
    .locals 0

    .line 1
    invoke-static {p1, p2}, Ljava/time/Instant;->ofEpochMilli(J)Ljava/time/Instant;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    sget-object p2, Li2/b0;->e:Ljava/time/ZoneId;

    .line 6
    .line 7
    invoke-virtual {p1, p2}, Ljava/time/Instant;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    const/4 p2, 0x1

    .line 12
    invoke-virtual {p1, p2}, Ljava/time/ZonedDateTime;->withDayOfMonth(I)Ljava/time/ZonedDateTime;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p1}, Ljava/time/ZonedDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, p1}, Li2/b0;->e(Ljava/time/LocalDate;)Li2/c0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final c()Li2/y;
    .locals 6

    .line 1
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Li2/y;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    invoke-virtual {p0}, Ljava/time/LocalDate;->getMonthValue()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    invoke-virtual {p0}, Ljava/time/LocalDate;->getDayOfMonth()I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    sget-object v1, Ljava/time/LocalTime;->MIDNIGHT:Ljava/time/LocalTime;

    .line 20
    .line 21
    invoke-virtual {p0, v1}, Ljava/time/LocalDate;->atTime(Ljava/time/LocalTime;)Ljava/time/LocalDateTime;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    sget-object v1, Li2/b0;->e:Ljava/time/ZoneId;

    .line 26
    .line 27
    invoke-virtual {p0, v1}, Ljava/time/LocalDateTime;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-interface {p0}, Ljava/time/chrono/ChronoZonedDateTime;->toInstant()Ljava/time/Instant;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p0}, Ljava/time/Instant;->toEpochMilli()J

    .line 36
    .line 37
    .line 38
    move-result-wide v1

    .line 39
    invoke-direct/range {v0 .. v5}, Li2/y;-><init>(JIII)V

    .line 40
    .line 41
    .line 42
    return-object v0
.end method

.method public final d(Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;)Li2/y;
    .locals 6

    .line 1
    iget-object p0, p0, Li2/z;->b:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-static {p2, p3, p0}, Li2/a1;->i(Ljava/lang/String;Ljava/util/Locale;Ljava/util/Map;)Ljava/time/format/DateTimeFormatter;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :try_start_0
    invoke-static {p1, p0}, Ljava/time/LocalDate;->parse(Ljava/lang/CharSequence;Ljava/time/format/DateTimeFormatter;)Ljava/time/LocalDate;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    new-instance v0, Li2/y;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    invoke-virtual {p0}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p1}, Ljava/time/Month;->getValue()I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    invoke-virtual {p0}, Ljava/time/LocalDate;->getDayOfMonth()I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    sget-object p1, Ljava/time/LocalTime;->MIDNIGHT:Ljava/time/LocalTime;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ljava/time/LocalDate;->atTime(Ljava/time/LocalTime;)Ljava/time/LocalDateTime;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    sget-object p1, Li2/b0;->e:Ljava/time/ZoneId;

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Ljava/time/LocalDateTime;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {p0}, Ljava/time/chrono/ChronoZonedDateTime;->toInstant()Ljava/time/Instant;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0}, Ljava/time/Instant;->toEpochMilli()J

    .line 46
    .line 47
    .line 48
    move-result-wide v1

    .line 49
    invoke-direct/range {v0 .. v5}, Li2/y;-><init>(JIII)V
    :try_end_0
    .catch Ljava/time/format/DateTimeParseException; {:try_start_0 .. :try_end_0} :catch_0

    .line 50
    .line 51
    .line 52
    return-object v0

    .line 53
    :catch_0
    const/4 p0, 0x0

    .line 54
    return-object p0
.end method

.method public final e(Ljava/time/LocalDate;)Li2/c0;
    .locals 8

    .line 1
    invoke-virtual {p1}, Ljava/time/LocalDate;->getDayOfWeek()Ljava/time/DayOfWeek;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/time/DayOfWeek;->getValue()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget p0, p0, Li2/b0;->c:I

    .line 10
    .line 11
    sub-int/2addr v0, p0

    .line 12
    if-gez v0, :cond_0

    .line 13
    .line 14
    add-int/lit8 v0, v0, 0x7

    .line 15
    .line 16
    :cond_0
    move v7, v0

    .line 17
    sget-object p0, Ljava/time/LocalTime;->MIDNIGHT:Ljava/time/LocalTime;

    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ljava/time/LocalDate;->atTime(Ljava/time/LocalTime;)Ljava/time/LocalDateTime;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    sget-object v0, Li2/b0;->e:Ljava/time/ZoneId;

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ljava/time/LocalDateTime;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-interface {p0}, Ljava/time/chrono/ChronoZonedDateTime;->toInstant()Ljava/time/Instant;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p0}, Ljava/time/Instant;->toEpochMilli()J

    .line 34
    .line 35
    .line 36
    move-result-wide v2

    .line 37
    new-instance v1, Li2/c0;

    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/time/LocalDate;->getYear()I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    invoke-virtual {p1}, Ljava/time/LocalDate;->getMonthValue()I

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    invoke-virtual {p1}, Ljava/time/LocalDate;->lengthOfMonth()I

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    invoke-direct/range {v1 .. v7}, Li2/c0;-><init>(JIIII)V

    .line 52
    .line 53
    .line 54
    return-object v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "CalendarModel"

    .line 2
    .line 3
    return-object p0
.end method
