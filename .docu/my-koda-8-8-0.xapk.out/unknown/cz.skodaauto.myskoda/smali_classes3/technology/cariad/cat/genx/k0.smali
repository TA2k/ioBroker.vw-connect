.class public final synthetic Ltechnology/cariad/cat/genx/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltechnology/cariad/cat/genx/k0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/k0;->e:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 4
    .line 5
    iput-object p2, p0, Ltechnology/cariad/cat/genx/k0;->f:Ljava/lang/String;

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
    iget v0, p0, Ltechnology/cariad/cat/genx/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/k0;->e:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 7
    .line 8
    iget-object p0, p0, Ltechnology/cariad/cat/genx/k0;->f:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->T(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)Llx0/o;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/k0;->e:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 16
    .line 17
    iget-object p0, p0, Ltechnology/cariad/cat/genx/k0;->f:Ljava/lang/String;

    .line 18
    .line 19
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->q0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
