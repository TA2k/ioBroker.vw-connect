.class public final Lk31/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lf31/g;


# direct methods
.method public constructor <init>(Lf31/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/v;->a:Lf31/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Lp31/b;
    .locals 6

    .line 1
    new-instance v0, Lp31/b;

    .line 2
    .line 3
    iget-object p0, p0, Lk31/v;->a:Lf31/g;

    .line 4
    .line 5
    iget-object p0, p0, Lf31/g;->a:Ljava/time/Clock;

    .line 6
    .line 7
    invoke-static {p0}, Ljava/time/ZonedDateTime;->now(Ljava/time/Clock;)Ljava/time/ZonedDateTime;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-wide/16 v1, 0x1

    .line 12
    .line 13
    invoke-virtual {p0, v1, v2}, Ljava/time/ZonedDateTime;->plusDays(J)Ljava/time/ZonedDateTime;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-static {p0}, Ljava/util/GregorianCalendar;->from(Ljava/time/ZonedDateTime;)Ljava/util/GregorianCalendar;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const-string v1, "from(...)"

    .line 22
    .line 23
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    const/16 v3, 0x8

    .line 40
    .line 41
    :goto_0
    const/16 v4, 0x12

    .line 42
    .line 43
    if-ge v3, v4, :cond_1

    .line 44
    .line 45
    new-instance v4, Lp31/a;

    .line 46
    .line 47
    const/4 v5, 0x0

    .line 48
    invoke-direct {v4, v3, v5}, Lp31/a;-><init>(II)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v2, v4}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    const/16 v4, 0x11

    .line 55
    .line 56
    if-eq v3, v4, :cond_0

    .line 57
    .line 58
    new-instance v4, Lp31/a;

    .line 59
    .line 60
    const/16 v5, 0x1e

    .line 61
    .line 62
    invoke-direct {v4, v3, v5}, Lp31/a;-><init>(II)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2, v4}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    invoke-static {v2}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    invoke-direct {v0, p0, v1, v2}, Lp31/b;-><init>(Ljava/util/GregorianCalendar;Ljava/util/List;Lnx0/c;)V

    .line 76
    .line 77
    .line 78
    return-object v0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lk31/v;->a()Lp31/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
