.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/Channel;

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/Channel;ILandroid/bluetooth/BluetoothDevice;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->e:Ltechnology/cariad/cat/genx/Channel;

    iput p2, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->f:I

    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->e:Ltechnology/cariad/cat/genx/Channel;

    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->g:Ljava/lang/Object;

    iput p3, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->f:I

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 9
    .line 10
    iget v1, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->f:I

    .line 11
    .line 12
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->e:Ltechnology/cariad/cat/genx/Channel;

    .line 13
    .line 14
    invoke-static {p0, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->k(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->g:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Landroid/bluetooth/BluetoothDevice;

    .line 22
    .line 23
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->e:Ltechnology/cariad/cat/genx/Channel;

    .line 24
    .line 25
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/e;->f:I

    .line 26
    .line 27
    invoke-static {v1, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->P0(Ltechnology/cariad/cat/genx/Channel;ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
