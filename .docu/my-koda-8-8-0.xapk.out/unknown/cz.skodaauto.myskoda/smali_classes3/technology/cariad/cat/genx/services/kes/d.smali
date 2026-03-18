.class public final synthetic Ltechnology/cariad/cat/genx/services/kes/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Ltechnology/cariad/cat/genx/services/kes/d;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/services/kes/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/services/kes/d;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

    .line 9
    .line 10
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->a(Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, [B

    .line 22
    .line 23
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 26
    .line 27
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->W([BLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 35
    .line 36
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 39
    .line 40
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->V(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 48
    .line 49
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->f:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->y0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;

    .line 61
    .line 62
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->f:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p0, Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->d(Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_4
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Ltechnology/cariad/cat/genx/Reachability;

    .line 74
    .line 75
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/d;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 78
    .line 79
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->b(Ltechnology/cariad/cat/genx/Reachability;Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
