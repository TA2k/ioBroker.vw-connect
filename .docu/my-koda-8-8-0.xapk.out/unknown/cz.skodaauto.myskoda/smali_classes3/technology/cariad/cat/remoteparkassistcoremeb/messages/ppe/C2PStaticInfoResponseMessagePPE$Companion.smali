.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessageDefinition;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0005\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0010\u0010\u001b\u001a\u0004\u0018\u00010\u001c2\u0006\u0010\u001d\u001a\u00020\u001eR\u0014\u0010\u0004\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0014\u0010\u0008\u001a\u00020\tX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0014\u0010\u000c\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u0007R\u0014\u0010\u000e\u001a\u00020\u000fX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u0011R\u0014\u0010\u0012\u001a\u00020\u0013X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015R\u000e\u0010\u0016\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0018\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0019\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001a\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u001f"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessageDefinition;",
        "<init>",
        "()V",
        "messageID",
        "",
        "getMessageID",
        "()B",
        "address",
        "",
        "getAddress",
        "()J",
        "priority",
        "getPriority",
        "requiresQueuing",
        "",
        "getRequiresQueuing",
        "()Z",
        "byteLength",
        "",
        "getByteLength",
        "()I",
        "VERSION_MAJOR",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;",
        "VERSION_MINOR",
        "VERSION_PATCH",
        "FUNCTION_RESPONSE",
        "create",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;",
        "payload",
        "",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;
    .locals 6

    .line 1
    const-string v0, "payload"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p1

    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;->getByteLength()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eq v0, p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toUBytes([B)[B

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;

    .line 20
    .line 21
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getVERSION_MAJOR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getVERSION_MINOR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getVERSION_PATCH$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;->getEntries()Lsx0/a;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getFUNCTION_RESPONSE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    move-object v4, p0

    .line 62
    check-cast v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 63
    .line 64
    const/4 v5, 0x0

    .line 65
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;-><init>(BBBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;Lkotlin/jvm/internal/g;)V

    .line 66
    .line 67
    .line 68
    return-object v0
.end method

.method public getAddress()J
    .locals 2

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getAddress$cp()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public getByteLength()I
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getByteLength$cp()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getMessageID()B
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getMessageID$cp()B

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getPriority()B
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getPriority$cp()B

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getRequiresQueuing()Z
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->access$getRequiresQueuing$cp()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
