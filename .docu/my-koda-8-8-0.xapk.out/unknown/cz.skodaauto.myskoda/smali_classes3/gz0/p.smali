.class public final Lgz0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/lang/Comparable<",
        "Lgz0/p;",
        ">;"
    }
.end annotation

.annotation runtime Llx0/c;
.end annotation

.annotation runtime Lqz0/g;
    with = Lmz0/f;
.end annotation


# static fields
.field public static final Companion:Lgz0/o;

.field public static final e:Lgz0/p;

.field public static final f:Lgz0/p;


# instance fields
.field public final d:Ljava/time/Instant;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lgz0/o;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/p;->Companion:Lgz0/o;

    .line 7
    .line 8
    const-wide v0, -0x2ed378be301L

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    const-wide/32 v2, 0x3b9ac9ff

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1, v2, v3}, Ljava/time/Instant;->ofEpochSecond(JJ)Ljava/time/Instant;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const-string v1, "ofEpochSecond(...)"

    .line 21
    .line 22
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-wide v2, 0x2d044a2eb00L

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    const-wide/16 v4, 0x0

    .line 31
    .line 32
    invoke-static {v2, v3, v4, v5}, Ljava/time/Instant;->ofEpochSecond(JJ)Ljava/time/Instant;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance v0, Lgz0/p;

    .line 40
    .line 41
    sget-object v1, Ljava/time/Instant;->MIN:Ljava/time/Instant;

    .line 42
    .line 43
    const-string v2, "MIN"

    .line 44
    .line 45
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-direct {v0, v1}, Lgz0/p;-><init>(Ljava/time/Instant;)V

    .line 49
    .line 50
    .line 51
    sput-object v0, Lgz0/p;->e:Lgz0/p;

    .line 52
    .line 53
    new-instance v0, Lgz0/p;

    .line 54
    .line 55
    sget-object v1, Ljava/time/Instant;->MAX:Ljava/time/Instant;

    .line 56
    .line 57
    const-string v2, "MAX"

    .line 58
    .line 59
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-direct {v0, v1}, Lgz0/p;-><init>(Ljava/time/Instant;)V

    .line 63
    .line 64
    .line 65
    sput-object v0, Lgz0/p;->f:Lgz0/p;

    .line 66
    .line 67
    return-void
.end method

.method public constructor <init>(Ljava/time/Instant;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgz0/p;->d:Ljava/time/Instant;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 2

    .line 1
    iget-object p0, p0, Lgz0/p;->d:Ljava/time/Instant;

    .line 2
    .line 3
    :try_start_0
    invoke-virtual {p0}, Ljava/time/Instant;->toEpochMilli()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/ArithmeticException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    return-wide v0

    .line 8
    :catch_0
    sget-object v0, Ljava/time/Instant;->EPOCH:Ljava/time/Instant;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/time/Instant;->isAfter(Ljava/time/Instant;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    const-wide v0, 0x7fffffffffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const-wide/high16 v0, -0x8000000000000000L

    .line 23
    .line 24
    :goto_0
    return-wide v0
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    .line 1
    check-cast p1, Lgz0/p;

    .line 2
    .line 3
    const-string v0, "other"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lgz0/p;->d:Ljava/time/Instant;

    .line 9
    .line 10
    iget-object p1, p1, Lgz0/p;->d:Ljava/time/Instant;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ljava/time/Instant;->compareTo(Ljava/time/Instant;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lgz0/p;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lgz0/p;

    .line 8
    .line 9
    iget-object p1, p1, Lgz0/p;->d:Ljava/time/Instant;

    .line 10
    .line 11
    iget-object p0, p0, Lgz0/p;->d:Ljava/time/Instant;

    .line 12
    .line 13
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lgz0/p;->d:Ljava/time/Instant;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/Instant;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Lgz0/p;->d:Ljava/time/Instant;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/Instant;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "toString(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method
