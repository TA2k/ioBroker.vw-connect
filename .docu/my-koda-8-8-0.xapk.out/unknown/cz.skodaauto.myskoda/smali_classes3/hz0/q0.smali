.class public final Lhz0/q0;
.super Lhz0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljz0/d;


# direct methods
.method public constructor <init>(Ljz0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhz0/q0;->a:Ljz0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Ljz0/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q0;->a:Ljz0/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Llz0/c;
    .locals 0

    .line 1
    sget-object p0, Lhz0/r0;->b:Lhz0/i0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(Llz0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lhz0/i0;

    .line 2
    .line 3
    const-string p0, "intermediate"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance p0, Lgz0/w;

    .line 9
    .line 10
    iget-object v0, p1, Lhz0/i0;->a:Lhz0/h0;

    .line 11
    .line 12
    invoke-virtual {v0}, Lhz0/h0;->b()Lgz0/s;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget-object p1, p1, Lhz0/i0;->b:Lhz0/j0;

    .line 17
    .line 18
    invoke-virtual {p1}, Lhz0/j0;->b()Lgz0/y;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iget-object v0, v0, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 23
    .line 24
    iget-object p1, p1, Lgz0/y;->d:Ljava/time/LocalTime;

    .line 25
    .line 26
    invoke-static {v0, p1}, Ljava/time/LocalDateTime;->of(Ljava/time/LocalDate;Ljava/time/LocalTime;)Ljava/time/LocalDateTime;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    const-string v0, "of(...)"

    .line 31
    .line 32
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-direct {p0, p1}, Lgz0/w;-><init>(Ljava/time/LocalDateTime;)V

    .line 36
    .line 37
    .line 38
    return-object p0
.end method
