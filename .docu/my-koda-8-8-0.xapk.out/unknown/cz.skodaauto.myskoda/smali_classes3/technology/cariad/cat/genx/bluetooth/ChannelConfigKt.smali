.class public final Ltechnology/cariad/cat/genx/bluetooth/ChannelConfigKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/bluetooth/ChannelConfigKt$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u001a\u000c\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000\u001a\u000c\u0010\u0003\u001a\u00020\u0001*\u00020\u0002H\u0000\u00a8\u0006\u0004"
    }
    d2 = {
        "writeCharacteristicUUID",
        "Ljava/util/UUID;",
        "Ltechnology/cariad/cat/genx/Channel;",
        "notifyCharacteristicUUID",
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
.method public static final notifyCharacteristicUUID(Ltechnology/cariad/cat/genx/Channel;)Ljava/util/UUID;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfigKt$WhenMappings;->$EnumSwitchMapping$0:[I

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
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 21
    .line 22
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getHandshakeNotifyCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 34
    .line 35
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getDataNotifyCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public static final writeCharacteristicUUID(Ltechnology/cariad/cat/genx/Channel;)Ljava/util/UUID;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfigKt$WhenMappings;->$EnumSwitchMapping$0:[I

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
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 21
    .line 22
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getHandshakeWriteCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 34
    .line 35
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getDataWriteCharacteristicUUID$genx_release()Ljava/util/UUID;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method
