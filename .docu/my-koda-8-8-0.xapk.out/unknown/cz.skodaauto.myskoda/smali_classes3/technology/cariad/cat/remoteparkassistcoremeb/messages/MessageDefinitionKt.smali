.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinitionKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u001a\u001b\u0010\u0004\u001a\u00020\u0003*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u0001H\u0000\u00a2\u0006\u0004\u0008\u0004\u0010\u0005\u00a8\u0006\u0006"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;",
        "bitPacket",
        "Llx0/s;",
        "getUByte",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B",
        "remoteparkassistcoremeb_release"
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
.method public static final getUByte(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bitPacket"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;->toBytes()[B

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method
