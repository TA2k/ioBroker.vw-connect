.class public final synthetic Le1/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Le1/h1;->d:I

    .line 2
    .line 3
    iput p1, p0, Le1/h1;->e:I

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
    .locals 2

    .line 1
    iget v0, p0, Le1/h1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Le1/h1;->e:I

    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;->a(I)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget p0, p0, Le1/h1;->e:I

    .line 14
    .line 15
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;->b(I)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_1
    iget p0, p0, Le1/h1;->e:I

    .line 21
    .line 22
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiInfoExtensionKt;->b(I)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_2
    iget p0, p0, Le1/h1;->e:I

    .line 28
    .line 29
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->c(I)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_3
    iget p0, p0, Le1/h1;->e:I

    .line 35
    .line 36
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->j(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_4
    iget p0, p0, Le1/h1;->e:I

    .line 42
    .line 43
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->e(I)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_5
    iget p0, p0, Le1/h1;->e:I

    .line 49
    .line 50
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->f(I)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_6
    iget p0, p0, Le1/h1;->e:I

    .line 56
    .line 57
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->k(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_7
    iget p0, p0, Le1/h1;->e:I

    .line 63
    .line 64
    const-string v0, "No night mode defined for flag "

    .line 65
    .line 66
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_8
    iget p0, p0, Le1/h1;->e:I

    .line 72
    .line 73
    invoke-static {p0}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->d(I)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :pswitch_9
    new-instance v0, Ln1/v;

    .line 79
    .line 80
    iget p0, p0, Le1/h1;->e:I

    .line 81
    .line 82
    const/4 v1, 0x0

    .line 83
    invoke-direct {v0, p0, v1}, Ln1/v;-><init>(II)V

    .line 84
    .line 85
    .line 86
    return-object v0

    .line 87
    :pswitch_a
    new-instance v0, Lm1/t;

    .line 88
    .line 89
    iget p0, p0, Le1/h1;->e:I

    .line 90
    .line 91
    const/4 v1, 0x0

    .line 92
    invoke-direct {v0, p0, v1}, Lm1/t;-><init>(II)V

    .line 93
    .line 94
    .line 95
    return-object v0

    .line 96
    :pswitch_b
    iget p0, p0, Le1/h1;->e:I

    .line 97
    .line 98
    const-string v0, "Could not handle pairing result code "

    .line 99
    .line 100
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0

    .line 105
    :pswitch_c
    new-instance v0, Le1/n1;

    .line 106
    .line 107
    iget p0, p0, Le1/h1;->e:I

    .line 108
    .line 109
    invoke-direct {v0, p0}, Le1/n1;-><init>(I)V

    .line 110
    .line 111
    .line 112
    return-object v0

    .line 113
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
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
