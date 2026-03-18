.class public final synthetic Ltechnology/cariad/cat/genx/keyexchange/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/InternalVehicle;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/InternalVehicle;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/keyexchange/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/d;->e:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/keyexchange/d;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/d;->e:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->f(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->a(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->N(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_2
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->W(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->b(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->Z(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :pswitch_5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->G(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
