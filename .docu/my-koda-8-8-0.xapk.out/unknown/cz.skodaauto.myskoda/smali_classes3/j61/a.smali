.class public final synthetic Lj61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

.field public final synthetic f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lj61/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lj61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    iput-object p1, p0, Lj61/a;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;I)V
    .locals 0

    .line 2
    iput p3, p0, Lj61/a;->d:I

    iput-object p1, p0, Lj61/a;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    iput-object p2, p0, Lj61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lj61/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lj61/a;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 7
    .line 8
    iget-object p0, p0, Lj61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 9
    .line 10
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->f(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object v0, p0, Lj61/a;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 16
    .line 17
    iget-object p0, p0, Lj61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 18
    .line 19
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->a(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_1
    iget-object v0, p0, Lj61/a;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 25
    .line 26
    iget-object p0, p0, Lj61/a;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 27
    .line 28
    invoke-static {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->g(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
