.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0000\u001a\u000c\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000\u001a\u000e\u0010\u0003\u001a\u0004\u0018\u00010\u0002*\u00020\u0001H\u0000\u001a\u000e\u0010\u000f\u001a\u0004\u0018\u00010\u0002*\u00020\u0010H\u0000\"\u0018\u0010\u0004\u001a\u00020\u0005*\u00020\u00068AX\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0007\u0010\u0008\"\u0018\u0010\t\u001a\u00020\u0005*\u00020\n8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000b\u0010\u000c\"\u0018\u0010\r\u001a\u00020\u0005*\u00020\n8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000e\u0010\u000c\u00a8\u0006\u0011"
    }
    d2 = {
        "toType",
        "Ltechnology/cariad/cat/genx/TypedFrameType;",
        "Ltechnology/cariad/cat/genx/Channel;",
        "toChannel",
        "info",
        "",
        "Landroid/bluetooth/BluetoothDevice;",
        "getInfo",
        "(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;",
        "disconnectionReasonDescription",
        "",
        "getDisconnectionReasonDescription",
        "(I)Ljava/lang/String;",
        "failReasonDescription",
        "getFailReasonDescription",
        "channel",
        "Ljava/util/UUID;",
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
.method public static final channel(Ljava/util/UUID;)Ltechnology/cariad/cat/genx/Channel;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 7
    .line 8
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getDataWriteCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-nez v1, :cond_3

    .line 17
    .line 18
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getDataNotifyCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_0
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getHandshakeWriteCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-nez v1, :cond_2

    .line 38
    .line 39
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getHandshakeNotifyCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    if-eqz p0, :cond_1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    const/4 p0, 0x0

    .line 51
    return-object p0

    .line 52
    :cond_2
    :goto_0
    sget-object p0, Ltechnology/cariad/cat/genx/Channel;->HANDSHAKE:Ltechnology/cariad/cat/genx/Channel;

    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_3
    :goto_1
    sget-object p0, Ltechnology/cariad/cat/genx/Channel;->DATA:Ltechnology/cariad/cat/genx/Channel;

    .line 56
    .line 57
    return-object p0
.end method

.method public static final getDisconnectionReasonDescription(I)Ljava/lang/String;
    .locals 2

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    if-eq p0, v0, :cond_0

    .line 4
    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "UNKNOWN"

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :pswitch_0
    const-string v0, "REASON_CANCELLED"

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :pswitch_1
    const-string v0, "REASON_NOT_SUPPORTED"

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :pswitch_2
    const-string v0, "REASON_LINK_LOSS"

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :pswitch_3
    const-string v0, "REASON_TERMINATE_PEER_USER"

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :pswitch_4
    const-string v0, "REASON_TERMINATE_LOCAL_HOST"

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :pswitch_5
    const-string v0, "REASON_SUCCESS"

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :pswitch_6
    const-string v0, "REASON_UNKNOWN"

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const-string v0, "REASON_TIMEOUT"

    .line 33
    .line 34
    :goto_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v0, "("

    .line 43
    .line 44
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, ")"

    .line 51
    .line 52
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final getFailReasonDescription(I)Ljava/lang/String;
    .locals 2

    .line 1
    const/16 v0, -0x64

    .line 2
    .line 3
    if-eq p0, v0, :cond_0

    .line 4
    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "UNKNOWN"

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :pswitch_0
    const-string v0, "REASON_DEVICE_DISCONNECTED"

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :pswitch_1
    const-string v0, "REASON_DEVICE_NOT_SUPPORTED"

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :pswitch_2
    const-string v0, "REASON_NULL_ATTRIBUTE"

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :pswitch_3
    const-string v0, "REASON_REQUEST_FAILED"

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :pswitch_4
    const-string v0, "REASON_TIMEOUT"

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :pswitch_5
    const-string v0, "REASON_VALIDATION"

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :pswitch_6
    const-string v0, "REASON_CANCELLED"

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const-string v0, "REASON_BLUETOOTH_DISABLED"

    .line 33
    .line 34
    :goto_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v0, "("

    .line 43
    .line 44
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, ")"

    .line 51
    .line 52
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch -0x7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 8
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothDevice;->getName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothDevice;->getUuids()[Landroid/os/ParcelUuid;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v6, 0x0

    .line 21
    const/16 v7, 0x3f

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v4, 0x0

    .line 25
    const/4 v5, 0x0

    .line 26
    invoke-static/range {v2 .. v7}, Lmx0/n;->H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    :goto_0
    const-string v2, ", name = "

    .line 33
    .line 34
    const-string v3, ", uuids = "

    .line 35
    .line 36
    const-string v4, "[address = "

    .line 37
    .line 38
    invoke-static {v4, v0, v2, v1, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    const-string v1, "]"

    .line 43
    .line 44
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public static final toChannel(Ltechnology/cariad/cat/genx/TypedFrameType;)Ltechnology/cariad/cat/genx/Channel;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt$WhenMappings;->$EnumSwitchMapping$1:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    packed-switch p0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :pswitch_0
    const/4 p0, 0x0

    .line 24
    return-object p0

    .line 25
    :pswitch_1
    sget-object p0, Ltechnology/cariad/cat/genx/Channel;->DATA:Ltechnology/cariad/cat/genx/Channel;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_2
    sget-object p0, Ltechnology/cariad/cat/genx/Channel;->HANDSHAKE:Ltechnology/cariad/cat/genx/Channel;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static final toType(Ltechnology/cariad/cat/genx/Channel;)Ltechnology/cariad/cat/genx/TypedFrameType;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    if-eq p0, v0, :cond_1

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-ne p0, v0, :cond_0

    .line 19
    .line 20
    sget-object p0, Ltechnology/cariad/cat/genx/TypedFrameType;->Handshake:Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_0
    new-instance p0, La8/r0;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    sget-object p0, Ltechnology/cariad/cat/genx/TypedFrameType;->Data:Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 30
    .line 31
    return-object p0
.end method
