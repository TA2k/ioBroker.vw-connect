.class public final synthetic Lk61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(III)V
    .locals 0

    .line 1
    iput p3, p0, Lk61/a;->d:I

    .line 2
    .line 3
    iput p1, p0, Lk61/a;->e:I

    .line 4
    .line 5
    iput p2, p0, Lk61/a;->f:I

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
    .locals 3

    .line 1
    iget v0, p0, Lk61/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lk61/a;->e:I

    .line 7
    .line 8
    iget p0, p0, Lk61/a;->f:I

    .line 9
    .line 10
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->a(II)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget v0, p0, Lk61/a;->e:I

    .line 16
    .line 17
    invoke-static {v0}, Llp/cd;->c(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget p0, p0, Lk61/a;->f:I

    .line 22
    .line 23
    invoke-static {p0}, Llp/cd;->c(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const-string v1, "onReceive(): Bluetooth state switched from "

    .line 28
    .line 29
    const-string v2, " to "

    .line 30
    .line 31
    invoke-static {v1, v0, v2, p0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
