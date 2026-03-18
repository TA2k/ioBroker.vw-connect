.class public final Lw10/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# direct methods
.method public static a(Ljava/time/OffsetDateTime;)Llp/be;
    .locals 6

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 25
    .line 26
    .line 27
    move-result-wide v1

    .line 28
    invoke-virtual {p0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 29
    .line 30
    .line 31
    move-result-wide v3

    .line 32
    cmp-long v1, v1, v3

    .line 33
    .line 34
    if-nez v1, :cond_0

    .line 35
    .line 36
    sget-object p0, Lx10/d;->a:Lx10/d;

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_0
    invoke-virtual {v0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 40
    .line 41
    .line 42
    move-result-wide v1

    .line 43
    invoke-virtual {p0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 44
    .line 45
    .line 46
    move-result-wide v3

    .line 47
    sub-long/2addr v1, v3

    .line 48
    const-wide/16 v3, 0x7

    .line 49
    .line 50
    cmp-long v1, v1, v3

    .line 51
    .line 52
    if-gez v1, :cond_1

    .line 53
    .line 54
    new-instance v1, Lx10/b;

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 57
    .line 58
    .line 59
    move-result-wide v2

    .line 60
    invoke-virtual {p0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 61
    .line 62
    .line 63
    move-result-wide v4

    .line 64
    sub-long/2addr v2, v4

    .line 65
    long-to-int p0, v2

    .line 66
    invoke-direct {v1, p0}, Lx10/b;-><init>(I)V

    .line 67
    .line 68
    .line 69
    return-object v1

    .line 70
    :cond_1
    new-instance v0, Lx10/c;

    .line 71
    .line 72
    invoke-direct {v0, p0}, Lx10/c;-><init>(Ljava/time/LocalDate;)V

    .line 73
    .line 74
    .line 75
    return-object v0
.end method


# virtual methods
.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast p0, Ljava/time/OffsetDateTime;

    .line 4
    .line 5
    invoke-static {p0}, Lw10/a;->a(Ljava/time/OffsetDateTime;)Llp/be;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
