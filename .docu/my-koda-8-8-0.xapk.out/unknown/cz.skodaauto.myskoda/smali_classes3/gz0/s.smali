.class public final Lgz0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;
.implements Ljava/io/Serializable;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/lang/Comparable<",
        "Lgz0/s;",
        ">;",
        "Ljava/io/Serializable;"
    }
.end annotation

.annotation runtime Lqz0/g;
    with = Lmz0/g;
.end annotation


# static fields
.field public static final Companion:Lgz0/q;


# instance fields
.field public final d:Ljava/time/LocalDate;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lgz0/q;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/s;->Companion:Lgz0/q;

    .line 7
    .line 8
    new-instance v0, Lgz0/s;

    .line 9
    .line 10
    sget-object v1, Ljava/time/LocalDate;->MIN:Ljava/time/LocalDate;

    .line 11
    .line 12
    const-string v2, "MIN"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {v0, v1}, Lgz0/s;-><init>(Ljava/time/LocalDate;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Lgz0/s;

    .line 21
    .line 22
    sget-object v1, Ljava/time/LocalDate;->MAX:Ljava/time/LocalDate;

    .line 23
    .line 24
    const-string v2, "MAX"

    .line 25
    .line 26
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-direct {v0, v1}, Lgz0/s;-><init>(Ljava/time/LocalDate;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public constructor <init>(III)V
    .locals 0

    .line 3
    :try_start_0
    invoke-static {p1, p2, p3}, Ljava/time/LocalDate;->of(III)Ljava/time/LocalDate;

    move-result-object p1
    :try_end_0
    .catch Ljava/time/DateTimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-direct {p0, p1}, Lgz0/s;-><init>(Ljava/time/LocalDate;)V

    return-void

    :catch_0
    move-exception p0

    .line 5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw p1
.end method

.method public constructor <init>(Ljava/time/LocalDate;)V
    .locals 1

    const-string v0, "value"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lgz0/s;->d:Ljava/time/LocalDate;

    return-void
.end method


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    .line 1
    check-cast p1, Lgz0/s;

    .line 2
    .line 3
    const-string v0, "other"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 9
    .line 10
    iget-object p1, p1, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ljava/time/LocalDate;->compareTo(Ljava/time/chrono/ChronoLocalDate;)I

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
    instance-of v0, p1, Lgz0/s;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lgz0/s;

    .line 8
    .line 9
    iget-object p1, p1, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 10
    .line 11
    iget-object p0, p0, Lgz0/s;->d:Ljava/time/LocalDate;

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
    iget-object p0, p0, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/LocalDate;->hashCode()I

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
    iget-object p0, p0, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/LocalDate;->toString()Ljava/lang/String;

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
