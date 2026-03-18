.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManagerKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0000\n\u0002\u0010\u000e\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u001a\u000c\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000\u001a\u000c\u0010\u0003\u001a\u00020\u0001*\u00020\u0002H\u0000\u00a8\u0006\u0004"
    }
    d2 = {
        "readableBluetoothState",
        "",
        "",
        "readableScanError",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final readableBluetoothState(I)Ljava/lang/String;
    .locals 2

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const-string v0, "Unknown("

    .line 5
    .line 6
    const-string v1, ")"

    .line 7
    .line 8
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    const-string p0, "BLE_TURNING_OFF"

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_1
    const-string p0, "BLE_ON"

    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_2
    const-string p0, "BLE_TURNING_ON"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_3
    const-string p0, "TURNING_OFF"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_4
    const-string p0, "ON"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_5
    const-string p0, "TURNING_ON"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_6
    const-string p0, "OFF"

    .line 32
    .line 33
    return-object p0

    .line 34
    nop

    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final readableScanError(I)Ljava/lang/String;
    .locals 2

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const-string v0, "Unknown("

    .line 5
    .line 6
    const-string v1, ")"

    .line 7
    .line 8
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    const-string p0, "SCAN_FAILED_SCANNING_TOO_FREQUENTLY"

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_1
    const-string p0, "SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES"

    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_2
    const-string p0, "FEATURE_UNSUPPORTED"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_3
    const-string p0, "INTERNAL_ERROR"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_4
    const-string p0, "APPLICATION_REGISTRATION_FAILED"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_5
    const-string p0, "ALREADY_STARTED"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
