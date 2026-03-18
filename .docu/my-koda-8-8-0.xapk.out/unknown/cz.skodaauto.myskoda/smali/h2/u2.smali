.class public final synthetic Lh2/u2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLjava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lh2/u2;->d:I

    iput-wide p1, p0, Lh2/u2;->e:J

    iput-object p3, p0, Lh2/u2;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;JI)V
    .locals 0

    .line 2
    iput p4, p0, Lh2/u2;->d:I

    iput-object p1, p0, Lh2/u2;->f:Ljava/lang/Object;

    iput-wide p2, p0, Lh2/u2;->e:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lh2/u2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/u2;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 9
    .line 10
    iget-wide v1, p0, Lh2/u2;->e:J

    .line 11
    .line 12
    invoke-static {v1, v2, v0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->q0(JLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object v0, p0, Lh2/u2;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;

    .line 20
    .line 21
    iget-wide v1, p0, Lh2/u2;->e:J

    .line 22
    .line 23
    invoke-static {v1, v2, v0}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->a(JLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object v0, p0, Lh2/u2;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;

    .line 31
    .line 32
    iget-wide v1, p0, Lh2/u2;->e:J

    .line 33
    .line 34
    invoke-static {v1, v2, v0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->b(JLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_2
    iget-object v0, p0, Lh2/u2;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Le3/p;

    .line 42
    .line 43
    iget-wide v1, p0, Lh2/u2;->e:J

    .line 44
    .line 45
    check-cast v0, Le3/l0;

    .line 46
    .line 47
    invoke-virtual {v0, v1, v2}, Le3/l0;->b(J)Landroid/graphics/Shader;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :pswitch_3
    iget-object v0, p0, Lh2/u2;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Lay0/k;

    .line 55
    .line 56
    iget-wide v1, p0, Lh2/u2;->e:J

    .line 57
    .line 58
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object p0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
