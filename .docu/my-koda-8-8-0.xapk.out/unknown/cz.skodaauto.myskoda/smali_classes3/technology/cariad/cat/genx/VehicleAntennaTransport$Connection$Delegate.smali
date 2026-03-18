.class public interface abstract Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x609
    name = "Delegate"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008f\u0018\u00002\u00020\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u001f\u0010\u000b\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\tH&\u00a2\u0006\u0004\u0008\u000b\u0010\u000c\u00a8\u0006\r\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;",
        "",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "connection",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "error",
        "Llx0/b0;",
        "onConnectionDropped",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/GenXError;)V",
        "Ltechnology/cariad/cat/genx/protocol/Message;",
        "message",
        "onConnectionReceived",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Message;)V",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract onConnectionDropped(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/GenXError;)V
.end method

.method public abstract onConnectionReceived(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Message;)V
.end method
