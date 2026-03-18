.class public final Lcd/i;
.super Luz0/m0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(Lhy0/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcd/i;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Luz0/m0;-><init>(Lhy0/d;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c(Lvz0/n;)Lqz0/a;
    .locals 0

    .line 1
    iget p0, p0, Lcd/i;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "element"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Lvz0/o;->d(Lvz0/n;)Lvz0/a0;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string p1, "type"

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lvz0/a0;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Lvz0/n;

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    invoke-static {p0}, Lvz0/o;->e(Lvz0/n;)Lvz0/e0;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Lvz0/e0;->c()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p0, 0x0

    .line 35
    :goto_0
    const-string p1, "chargingRecord"

    .line 36
    .line 37
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_1

    .line 42
    .line 43
    sget-object p0, Ldd/f;->Companion:Ldd/e;

    .line 44
    .line 45
    invoke-virtual {p0}, Ldd/e;->serializer()Lqz0/a;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    check-cast p0, Lqz0/a;

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    sget-object p0, Ldd/j;->Companion:Ldd/i;

    .line 53
    .line 54
    invoke-virtual {p0}, Ldd/i;->serializer()Lqz0/a;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    check-cast p0, Lqz0/a;

    .line 59
    .line 60
    :goto_1
    return-object p0

    .line 61
    :pswitch_0
    const-string p0, "element"

    .line 62
    .line 63
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-static {p1}, Lvz0/o;->d(Lvz0/n;)Lvz0/a0;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    const-string p1, "type"

    .line 71
    .line 72
    invoke-virtual {p0, p1}, Lvz0/a0;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    check-cast p0, Lvz0/n;

    .line 77
    .line 78
    if-eqz p0, :cond_2

    .line 79
    .line 80
    invoke-static {p0}, Lvz0/o;->e(Lvz0/n;)Lvz0/e0;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    invoke-virtual {p0}, Lvz0/e0;->c()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    goto :goto_2

    .line 89
    :cond_2
    const/4 p0, 0x0

    .line 90
    :goto_2
    const-string p1, "charging_record"

    .line 91
    .line 92
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-eqz p0, :cond_3

    .line 97
    .line 98
    sget-object p0, Lcd/u;->Companion:Lcd/t;

    .line 99
    .line 100
    invoke-virtual {p0}, Lcd/t;->serializer()Lqz0/a;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    check-cast p0, Lqz0/a;

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_3
    sget-object p0, Lcd/y;->Companion:Lcd/x;

    .line 108
    .line 109
    invoke-virtual {p0}, Lcd/x;->serializer()Lqz0/a;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Lqz0/a;

    .line 114
    .line 115
    :goto_3
    return-object p0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
