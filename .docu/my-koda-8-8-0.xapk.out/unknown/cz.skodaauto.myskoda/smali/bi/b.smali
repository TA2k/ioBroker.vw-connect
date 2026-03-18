.class public final synthetic Lbi/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxh/e;


# direct methods
.method public synthetic constructor <init>(Lxh/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lbi/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbi/b;->e:Lxh/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lbi/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lhi/a;

    .line 7
    .line 8
    const-string v0, "$this$sdkViewModel"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-class v0, Led/e;

    .line 14
    .line 15
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast p1, Lii/a;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    move-object v2, p1

    .line 28
    check-cast v2, Led/e;

    .line 29
    .line 30
    new-instance p1, Lnd/l;

    .line 31
    .line 32
    new-instance v0, Ljd/b;

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    const/16 v7, 0xb

    .line 36
    .line 37
    const/4 v1, 0x2

    .line 38
    const-class v3, Led/e;

    .line 39
    .line 40
    const-string v4, "getPublicChargingHistory"

    .line 41
    .line 42
    const-string v5, "getPublicChargingHistory-gIAlu-s(Lkotlinx/datetime/Instant;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 43
    .line 44
    invoke-direct/range {v0 .. v7}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lbi/b;->e:Lxh/e;

    .line 48
    .line 49
    invoke-direct {p1, v0, p0}, Lnd/l;-><init>(Ljd/b;Lxh/e;)V

    .line 50
    .line 51
    .line 52
    return-object p1

    .line 53
    :pswitch_0
    check-cast p1, Lhi/a;

    .line 54
    .line 55
    const-string v0, "$this$sdkViewModel"

    .line 56
    .line 57
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    const-class v0, Lfe/c;

    .line 61
    .line 62
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 63
    .line 64
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    check-cast p1, Lii/a;

    .line 69
    .line 70
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    move-object v2, p1

    .line 75
    check-cast v2, Lfe/c;

    .line 76
    .line 77
    new-instance p1, Lhe/i;

    .line 78
    .line 79
    new-instance v0, Lei/a;

    .line 80
    .line 81
    const/4 v6, 0x0

    .line 82
    const/16 v7, 0x1c

    .line 83
    .line 84
    const/4 v1, 0x1

    .line 85
    const-class v3, Lfe/c;

    .line 86
    .line 87
    const-string v4, "getInvoices"

    .line 88
    .line 89
    const-string v5, "getInvoices-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 90
    .line 91
    invoke-direct/range {v0 .. v7}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 92
    .line 93
    .line 94
    iget-object p0, p0, Lbi/b;->e:Lxh/e;

    .line 95
    .line 96
    invoke-direct {p1, v0, p0}, Lhe/i;-><init>(Lei/a;Lxh/e;)V

    .line 97
    .line 98
    .line 99
    return-object p1

    .line 100
    :pswitch_1
    check-cast p1, Lzg/h;

    .line 101
    .line 102
    if-eqz p1, :cond_0

    .line 103
    .line 104
    iget-object p0, p0, Lbi/b;->e:Lxh/e;

    .line 105
    .line 106
    invoke-virtual {p0, p1}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    return-object p0

    .line 112
    :pswitch_2
    check-cast p1, Lzg/h;

    .line 113
    .line 114
    if-eqz p1, :cond_1

    .line 115
    .line 116
    iget-object p0, p0, Lbi/b;->e:Lxh/e;

    .line 117
    .line 118
    invoke-virtual {p0, p1}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 122
    .line 123
    return-object p0

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
