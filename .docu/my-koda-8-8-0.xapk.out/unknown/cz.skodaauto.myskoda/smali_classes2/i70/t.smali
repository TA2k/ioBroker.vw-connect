.class public final Li70/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxl0/f;

.field public final b:Lti0/a;

.field public final c:Lxl0/g;

.field public final d:Lxl0/p;


# direct methods
.method public constructor <init>(Lxl0/f;Lti0/a;Lxl0/g;Lxl0/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li70/t;->a:Lxl0/f;

    .line 5
    .line 6
    iput-object p2, p0, Li70/t;->b:Lti0/a;

    .line 7
    .line 8
    iput-object p3, p0, Li70/t;->c:Lxl0/g;

    .line 9
    .line 10
    iput-object p4, p0, Li70/t;->d:Lxl0/p;

    .line 11
    .line 12
    return-void
.end method

.method public static a(Ll70/k;)Llx0/l;
    .locals 4

    .line 1
    iget-object p0, p0, Ll70/k;->a:Ll70/b;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    iget-object v0, p0, Ll70/b;->a:Ljava/time/LocalDate;

    .line 8
    .line 9
    iget-object p0, p0, Ll70/b;->b:Ljava/time/LocalDate;

    .line 10
    .line 11
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v0, v1}, Ljava/time/LocalDate;->atStartOfDay(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0}, Ljava/time/ZonedDateTime;->toOffsetDateTime()Ljava/time/OffsetDateTime;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sget-object v2, Ljava/time/temporal/ChronoUnit;->SECONDS:Ljava/time/temporal/ChronoUnit;

    .line 24
    .line 25
    invoke-virtual {v0, v2}, Ljava/time/OffsetDateTime;->truncatedTo(Ljava/time/temporal/TemporalUnit;)Ljava/time/OffsetDateTime;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sget-object v3, Ljava/time/LocalTime;->MAX:Ljava/time/LocalTime;

    .line 30
    .line 31
    invoke-virtual {p0, v3}, Ljava/time/LocalDate;->atTime(Ljava/time/LocalTime;)Ljava/time/LocalDateTime;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p0, v1}, Ljava/time/LocalDateTime;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {p0}, Ljava/time/ZonedDateTime;->toOffsetDateTime()Ljava/time/OffsetDateTime;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {p0, v2}, Ljava/time/OffsetDateTime;->truncatedTo(Ljava/time/temporal/TemporalUnit;)Ljava/time/OffsetDateTime;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    new-instance v1, Llx0/l;

    .line 48
    .line 49
    invoke-direct {v1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-object v1
.end method
