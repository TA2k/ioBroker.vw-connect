.class public final synthetic Ltechnology/cariad/cat/genx/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/VehicleManagerImpl;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/v0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/v0;->e:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

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
    iget v0, p0, Ltechnology/cariad/cat/genx/v0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/v0;->e:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->z0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->X0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/o;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->R0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_2
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->B0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/b0;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->w1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->D0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    goto :goto_0

    .line 42
    :pswitch_5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->o1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    goto :goto_0

    .line 47
    :pswitch_6
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->O0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :pswitch_7
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->y0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/GenXError;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_8
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->j1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    goto :goto_0

    .line 62
    :pswitch_9
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->f(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    goto :goto_0

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
