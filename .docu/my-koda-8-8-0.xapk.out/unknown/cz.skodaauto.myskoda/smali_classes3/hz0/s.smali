.class public final Lhz0/s;
.super Lhz0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ljz0/d;


# direct methods
.method public synthetic constructor <init>(Ljz0/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lhz0/s;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/s;->b:Ljz0/d;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Ljz0/d;
    .locals 1

    .line 1
    iget v0, p0, Lhz0/s;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhz0/s;->b:Ljz0/d;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Lhz0/s;->b:Ljz0/d;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Llz0/c;
    .locals 0

    .line 1
    iget p0, p0, Lhz0/s;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lhz0/e2;->a:Lhz0/l0;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    sget-object p0, Lhz0/u;->a:Lhz0/q;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Llz0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lhz0/s;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lhz0/l0;

    .line 7
    .line 8
    const-string p0, "intermediate"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 14
    .line 15
    const-string v0, "year"

    .line 16
    .line 17
    invoke-static {p0, v0}, Lhz0/e2;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    iget-object p1, p1, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 25
    .line 26
    const-string v0, "monthNumber"

    .line 27
    .line 28
    invoke-static {p1, v0}, Lhz0/e2;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    new-instance v0, Lgz0/i0;

    .line 36
    .line 37
    :try_start_0
    invoke-static {p0, p1}, Ljava/time/YearMonth;->of(II)Ljava/time/YearMonth;

    .line 38
    .line 39
    .line 40
    move-result-object p0
    :try_end_0
    .catch Ljava/time/DateTimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-direct {v0, p0}, Lgz0/i0;-><init>(Ljava/time/YearMonth;)V

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    :catch_0
    move-exception p0

    .line 49
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 50
    .line 51
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 52
    .line 53
    .line 54
    throw p1

    .line 55
    :pswitch_0
    check-cast p1, Lhz0/q;

    .line 56
    .line 57
    const-string p0, "intermediate"

    .line 58
    .line 59
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    new-instance p0, Lhz0/p;

    .line 63
    .line 64
    invoke-direct {p0, p1}, Lhz0/p;-><init>(Lhz0/q;)V

    .line 65
    .line 66
    .line 67
    return-object p0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
