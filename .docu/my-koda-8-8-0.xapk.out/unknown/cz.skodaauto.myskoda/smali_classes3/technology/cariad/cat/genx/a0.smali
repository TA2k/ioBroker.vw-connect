.class public final synthetic Ltechnology/cariad/cat/genx/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/Referencing;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/Referencing;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/a0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/a0;->e:Ltechnology/cariad/cat/genx/Referencing;

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
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/a0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/a0;->e:Ltechnology/cariad/cat/genx/Referencing;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 11
    .line 12
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->a1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Llx0/o;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 18
    .line 19
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 20
    .line 21
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->F0(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;)Llx0/b0;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 27
    .line 28
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 29
    .line 30
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->l0(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;)Llx0/b0;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_2
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 36
    .line 37
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 38
    .line 39
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->H(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;)Llx0/b0;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_3
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 45
    .line 46
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 47
    .line 48
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->j(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;)Llx0/b0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
