.class public final synthetic Ltechnology/cariad/cat/genx/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:[B

.field public final synthetic f:[B


# direct methods
.method public synthetic constructor <init>([BI[B)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/p0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/p0;->e:[B

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/p0;->f:[B

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
    iget v0, p0, Ltechnology/cariad/cat/genx/p0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/p0;->e:[B

    .line 7
    .line 8
    iget-object p0, p0, Ltechnology/cariad/cat/genx/p0;->f:[B

    .line 9
    .line 10
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->k([B[B)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/p0;->e:[B

    .line 16
    .line 17
    iget-object p0, p0, Ltechnology/cariad/cat/genx/p0;->f:[B

    .line 18
    .line 19
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->E0([B[B)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/p0;->e:[B

    .line 25
    .line 26
    iget-object p0, p0, Ltechnology/cariad/cat/genx/p0;->f:[B

    .line 27
    .line 28
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->U([B[B)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/p0;->e:[B

    .line 34
    .line 35
    iget-object p0, p0, Ltechnology/cariad/cat/genx/p0;->f:[B

    .line 36
    .line 37
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->U0([B[B)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
