.class public final Lgz0/i0;
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
        "Lgz0/i0;",
        ">;",
        "Ljava/io/Serializable;"
    }
.end annotation

.annotation runtime Lqz0/g;
    with = Lmz0/n;
.end annotation


# static fields
.field public static final Companion:Lgz0/h0;


# instance fields
.field public final d:Ljava/time/YearMonth;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lgz0/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/i0;->Companion:Lgz0/h0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/time/YearMonth;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lgz0/i0;->d:Ljava/time/YearMonth;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    .line 1
    check-cast p1, Lgz0/i0;

    .line 2
    .line 3
    const-string v0, "other"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lgz0/i0;->d:Ljava/time/YearMonth;

    .line 9
    .line 10
    iget-object p1, p1, Lgz0/i0;->d:Ljava/time/YearMonth;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ljava/time/YearMonth;->compareTo(Ljava/time/YearMonth;)I

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
    instance-of v0, p1, Lgz0/i0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lgz0/i0;

    .line 8
    .line 9
    iget-object p1, p1, Lgz0/i0;->d:Ljava/time/YearMonth;

    .line 10
    .line 11
    iget-object p0, p0, Lgz0/i0;->d:Ljava/time/YearMonth;

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
    iget-object p0, p0, Lgz0/i0;->d:Ljava/time/YearMonth;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/YearMonth;->hashCode()I

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
    sget-object v0, Lgz0/j0;->a:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/time/format/DateTimeFormatter;

    .line 8
    .line 9
    iget-object p0, p0, Lgz0/i0;->d:Ljava/time/YearMonth;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, "format(...)"

    .line 16
    .line 17
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-object p0
.end method
