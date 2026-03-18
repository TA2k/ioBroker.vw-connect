.class public abstract Lgz0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Llx0/q;

.field public static final b:Llx0/q;

.field public static final c:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lf2/h0;

    .line 2
    .line 3
    const/16 v1, 0x1c

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lf2/h0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lgz0/g0;->a:Llx0/q;

    .line 13
    .line 14
    new-instance v0, Lf2/h0;

    .line 15
    .line 16
    const/16 v1, 0x1d

    .line 17
    .line 18
    invoke-direct {v0, v1}, Lf2/h0;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lgz0/g0;->b:Llx0/q;

    .line 26
    .line 27
    new-instance v0, Lgz0/e0;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 31
    .line 32
    .line 33
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Lgz0/g0;->c:Llx0/q;

    .line 38
    .line 39
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/time/format/DateTimeFormatter;)Lgz0/d0;
    .locals 1

    .line 1
    :try_start_0
    new-instance v0, Lgz0/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, p0, v0}, Ljava/time/format/DateTimeFormatter;->parse(Ljava/lang/CharSequence;Ljava/time/temporal/TemporalQuery;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ljava/time/ZoneOffset;

    .line 11
    .line 12
    new-instance p1, Lgz0/d0;

    .line 13
    .line 14
    invoke-direct {p1, p0}, Lgz0/d0;-><init>(Ljava/time/ZoneOffset;)V
    :try_end_0
    .catch Ljava/time/DateTimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    .line 17
    return-object p1

    .line 18
    :catch_0
    move-exception p0

    .line 19
    new-instance p1, Lgz0/a;

    .line 20
    .line 21
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 22
    .line 23
    .line 24
    throw p1
.end method
