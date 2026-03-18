.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u0005\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\n\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0017\n\u0002\u0010\u0012\n\u0002\u0008\u0005\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u001a#\u0010\u000c\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\t\u001a\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\n\u0010\u000b\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\r2\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u000e\u0010\u0007\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u000f2\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u0010\u0010\u0011\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00122\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u000e\u0010\u0011\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00132\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u0014\u0010\u0015\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00162\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u000e\u0010\u0015\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00172\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u000e\u0010\u0018\u001a#\u0010\u0008\u001a\u00020\u0005*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00192\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u000e\u0010\u001a\u001a\u001b\u0010\u001d\u001a\u00020\u0001*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u001b\u0010\u001c\u001a\u001b\u0010\u001f\u001a\u00020\r*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u001e\u0010\u001c\u001a\u001b\u0010\"\u001a\u00020\u0017*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008 \u0010!\u001a\u001b\u0010%\u001a\u00020\u000f*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008#\u0010$\u001a\u001b\u0010\'\u001a\u00020\u0012*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008&\u0010$\u001a\u001b\u0010*\u001a\u00020\u0016*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008(\u0010)\u001a\u001b\u0010-\u001a\u00020\u0019*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008+\u0010,\u001a\u001b\u00100\u001a\u00020\u0000*\u00020\u00002\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008.\u0010/\u001a\u001b\u0010\u001d\u001a\u00020\u0001*\u0002012\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u001d\u0010\u001c\u001a\u001b\u0010\u001f\u001a\u00020\r*\u0002012\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\u001f\u0010\u001c\u001a\u001b\u0010\"\u001a\u00020\u0017*\u0002012\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\"\u0010!\u001a\u001b\u0010%\u001a\u00020\u000f*\u0002012\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008%\u0010$\u001a\u001b\u0010\'\u001a\u00020\u0012*\u0002012\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008\'\u0010$\u001a\u001b\u0010*\u001a\u00020\u0016*\u0002012\u0006\u0010\u0004\u001a\u00020\u0003H\u0000\u00a2\u0006\u0004\u0008*\u0010)\u001a\u0013\u00104\u001a\u000201*\u00020\u0000H\u0000\u00a2\u0006\u0004\u00082\u00103\u001a\u0013\u00105\u001a\u00020\u0000*\u000201H\u0000\u00a2\u0006\u0004\u00085\u00103\u00a8\u00066"
    }
    d2 = {
        "Llx0/t;",
        "Llx0/s;",
        "value",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;",
        "bitPacket",
        "Llx0/b0;",
        "setValue-X9TprxQ",
        "([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V",
        "setValue",
        "values",
        "setValues-wl1WTbA",
        "([B[BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V",
        "setValues",
        "",
        "setValue-mbSTycY",
        "Llx0/z;",
        "setValue-xh1D8Z4",
        "([BSLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V",
        "",
        "Llx0/u;",
        "setValue-fCMF4BQ",
        "([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V",
        "",
        "",
        "([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V",
        "",
        "([BLjava/lang/String;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V",
        "getUByte-rto03Yo",
        "([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B",
        "getUByte",
        "getByte-rto03Yo",
        "getByte",
        "getBool-rto03Yo",
        "([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Z",
        "getBool",
        "getUShort-rto03Yo",
        "([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S",
        "getUShort",
        "getShort-rto03Yo",
        "getShort",
        "getInt-rto03Yo",
        "([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I",
        "getInt",
        "getString-rto03Yo",
        "([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Ljava/lang/String;",
        "getString",
        "getUByteArray-rto03Yo",
        "([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)[B",
        "getUByteArray",
        "",
        "toBytes-GBYM_sE",
        "([B)[B",
        "toBytes",
        "toUBytes",
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
.method public static final getBool([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Z
    .locals 2

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x1

    .line 16
    if-gt v0, v1, :cond_1

    .line 17
    .line 18
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getByte([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    return v1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/Exception;

    .line 28
    .line 29
    new-instance v0, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v1, "getBool() for bitPacket: "

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string p1, " is not valid"

    .line 40
    .line 41
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0
.end method

.method public static final getBool-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Z
    .locals 2

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getBool$0"

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x1

    .line 16
    if-gt v0, v1, :cond_1

    .line 17
    .line 18
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    return v1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/Exception;

    .line 28
    .line 29
    new-instance v0, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v1, "getBool() for bitPacket: "

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string p1, " is not valid"

    .line 40
    .line 41
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0
.end method

.method public static final getByte([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B
    .locals 2

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    if-gt v0, v1, :cond_0

    .line 18
    .line 19
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/Exception;

    .line 25
    .line 26
    new-instance v0, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    const-string v1, "getByte() for bitPacket: "

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string p1, " is not valid"

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0
.end method

.method public static final getByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B
    .locals 2

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getByte$0"

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    if-gt v0, v1, :cond_0

    .line 18
    .line 19
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/Exception;

    .line 25
    .line 26
    new-instance v0, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    const-string v1, "getByte() for bitPacket: "

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string p1, " is not valid"

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0
.end method

.method public static final getInt([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I
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
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getShort([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public static final getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I
    .locals 1

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getInt$0"

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
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getShort-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public static final getShort([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S
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
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUShort([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public static final getShort-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S
    .locals 1

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getShort$0"

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
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUShort-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public static final getString-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getString$0"

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
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByteArray-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)[B

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Lly0/w;->l([B)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public static final getUByte([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B
    .locals 2

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    if-gt v0, v1, :cond_0

    .line 18
    .line 19
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toUBytes([B)[B

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/Exception;

    .line 29
    .line 30
    new-instance v0, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const-string v1, "getUByte() for bitPacket: "

    .line 33
    .line 34
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string p1, " is not valid"

    .line 41
    .line 42
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0
.end method

.method public static final getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B
    .locals 5

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getUByte$0"

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    if-gt v0, v1, :cond_2

    .line 18
    .line 19
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/4 v1, 0x0

    .line 24
    move v2, v1

    .line 25
    move v3, v2

    .line 26
    :goto_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-ge v1, v4, :cond_1

    .line 31
    .line 32
    const/4 v4, 0x7

    .line 33
    if-le v0, v4, :cond_0

    .line 34
    .line 35
    add-int/lit8 v3, v3, 0x1

    .line 36
    .line 37
    add-int/lit8 v0, v0, -0x8

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    aget-byte v4, p0, v3

    .line 41
    .line 42
    and-int/lit16 v4, v4, 0xff

    .line 43
    .line 44
    ushr-int/2addr v4, v0

    .line 45
    and-int/lit8 v4, v4, 0x1

    .line 46
    .line 47
    shl-int/2addr v4, v1

    .line 48
    or-int/2addr v2, v4

    .line 49
    add-int/lit8 v1, v1, 0x1

    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    int-to-byte p0, v2

    .line 55
    return p0

    .line 56
    :cond_2
    new-instance p0, Ljava/lang/Exception;

    .line 57
    .line 58
    new-instance v0, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v1, "getUByte() for bitPacket: "

    .line 61
    .line 62
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string p1, " is not valid"

    .line 69
    .line 70
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0
.end method

.method public static final getUByteArray-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)[B
    .locals 8

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getUByteArray$0"

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    add-int/lit8 v1, v0, 0x7

    .line 16
    .line 17
    div-int/lit8 v1, v1, 0x8

    .line 18
    .line 19
    new-array v2, v1, [B

    .line 20
    .line 21
    const/4 v3, 0x0

    .line 22
    move v4, v3

    .line 23
    :goto_0
    if-ge v4, v1, :cond_0

    .line 24
    .line 25
    aput-byte v3, v2, v4

    .line 26
    .line 27
    add-int/lit8 v4, v4, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    :goto_1
    if-ge v3, v0, :cond_1

    .line 35
    .line 36
    add-int v1, p1, v3

    .line 37
    .line 38
    div-int/lit8 v4, v1, 0x8

    .line 39
    .line 40
    rem-int/lit8 v1, v1, 0x8

    .line 41
    .line 42
    div-int/lit8 v5, v3, 0x8

    .line 43
    .line 44
    rem-int/lit8 v6, v3, 0x8

    .line 45
    .line 46
    aget-byte v4, p0, v4

    .line 47
    .line 48
    and-int/lit16 v4, v4, 0xff

    .line 49
    .line 50
    ushr-int v1, v4, v1

    .line 51
    .line 52
    const/4 v4, 0x1

    .line 53
    and-int/2addr v1, v4

    .line 54
    int-to-byte v1, v1

    .line 55
    aget-byte v7, v2, v5

    .line 56
    .line 57
    shl-int/2addr v4, v6

    .line 58
    not-int v4, v4

    .line 59
    int-to-byte v4, v4

    .line 60
    and-int/2addr v4, v7

    .line 61
    int-to-byte v4, v4

    .line 62
    aput-byte v4, v2, v5

    .line 63
    .line 64
    and-int/lit16 v1, v1, 0xff

    .line 65
    .line 66
    shl-int/2addr v1, v6

    .line 67
    int-to-byte v1, v1

    .line 68
    or-int/2addr v1, v4

    .line 69
    int-to-byte v1, v1

    .line 70
    aput-byte v1, v2, v5

    .line 71
    .line 72
    add-int/lit8 v3, v3, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    return-object v2
.end method

.method public static final getUShort([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S
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
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toUBytes([B)[B

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUShort-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public static final getUShort-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)S
    .locals 5

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$getUShort$0"

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    if-le v0, v1, :cond_0

    .line 18
    .line 19
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    sub-int/2addr v0, v1

    .line 24
    move v2, v0

    .line 25
    move v0, v1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    const/4 v2, 0x0

    .line 32
    :goto_0
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 33
    .line 34
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    invoke-direct {v3, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 39
    .line 40
    .line 41
    invoke-static {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 46
    .line 47
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    add-int/2addr p1, v0

    .line 52
    invoke-direct {v4, p1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 53
    .line 54
    .line 55
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getUByte-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)B

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    and-int/lit16 p0, p0, 0xff

    .line 60
    .line 61
    shl-int/2addr p0, v1

    .line 62
    and-int/lit16 p1, v3, 0xff

    .line 63
    .line 64
    or-int/2addr p0, p1

    .line 65
    int-to-short p0, p0

    .line 66
    return p0
.end method

.method public static final setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 6

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bitPacket"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x0

    .line 16
    move v2, v1

    .line 17
    :goto_0
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-ge v1, v3, :cond_1

    .line 22
    .line 23
    const/4 v3, 0x7

    .line 24
    if-le v0, v3, :cond_0

    .line 25
    .line 26
    add-int/lit8 v2, v2, 0x1

    .line 27
    .line 28
    add-int/lit8 v0, v0, -0x8

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    and-int/lit16 v3, p1, 0xff

    .line 32
    .line 33
    ushr-int/2addr v3, v1

    .line 34
    const/4 v4, 0x1

    .line 35
    and-int/2addr v3, v4

    .line 36
    aget-byte v5, p0, v2

    .line 37
    .line 38
    shl-int/2addr v4, v0

    .line 39
    not-int v4, v4

    .line 40
    int-to-byte v4, v4

    .line 41
    and-int/2addr v4, v5

    .line 42
    int-to-byte v4, v4

    .line 43
    aput-byte v4, p0, v2

    .line 44
    .line 45
    shl-int/2addr v3, v0

    .line 46
    int-to-byte v3, v3

    .line 47
    or-int/2addr v3, v4

    .line 48
    int-to-byte v3, v3

    .line 49
    aput-byte v3, p0, v2

    .line 50
    .line 51
    add-int/lit8 v1, v1, 0x1

    .line 52
    .line 53
    add-int/lit8 v0, v0, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    return-void
.end method

.method public static final setValue-fCMF4BQ([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 6

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bitPacket"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x20

    .line 16
    .line 17
    if-gt v0, v1, :cond_3

    .line 18
    .line 19
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/16 v1, 0x8

    .line 24
    .line 25
    if-gt v0, v1, :cond_0

    .line 26
    .line 27
    int-to-byte p1, p1

    .line 28
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_0
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const/16 v2, 0x10

    .line 37
    .line 38
    if-gt v0, v2, :cond_1

    .line 39
    .line 40
    int-to-short p1, p1

    .line 41
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-xh1D8Z4([BSLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_1
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    int-to-short v3, p1

    .line 50
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 51
    .line 52
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    invoke-direct {v4, v5, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 57
    .line 58
    .line 59
    invoke-static {p0, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-xh1D8Z4([BSLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 60
    .line 61
    .line 62
    add-int/lit8 v0, v0, -0x10

    .line 63
    .line 64
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    const/high16 v3, 0xff0000

    .line 69
    .line 70
    and-int/2addr v3, p1

    .line 71
    ushr-int/2addr v3, v2

    .line 72
    int-to-byte v3, v3

    .line 73
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 74
    .line 75
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    add-int/2addr v5, v2

    .line 80
    invoke-direct {v4, v5, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 81
    .line 82
    .line 83
    invoke-static {p0, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 84
    .line 85
    .line 86
    sub-int/2addr v0, v1

    .line 87
    if-lez v0, :cond_2

    .line 88
    .line 89
    ushr-int/lit8 p1, p1, 0x18

    .line 90
    .line 91
    int-to-byte p1, p1

    .line 92
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 93
    .line 94
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    add-int/lit8 p2, p2, 0x18

    .line 99
    .line 100
    invoke-direct {v1, p2, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 101
    .line 102
    .line 103
    invoke-static {p0, p1, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 104
    .line 105
    .line 106
    :cond_2
    return-void

    .line 107
    :cond_3
    new-instance p0, Ljava/lang/Exception;

    .line 108
    .line 109
    int-to-long v0, p1

    .line 110
    const-wide v2, 0xffffffffL

    .line 111
    .line 112
    .line 113
    .line 114
    .line 115
    and-long/2addr v0, v2

    .line 116
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    new-instance v0, Ljava/lang/StringBuilder;

    .line 121
    .line 122
    const-string v1, "UByteArray.setValue(value: "

    .line 123
    .line 124
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    const-string p1, ",  bitPacket: "

    .line 131
    .line 132
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string p1, ") is not valid! bitPacket.length is > 32"

    .line 139
    .line 140
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0
.end method

.method public static final setValue-mbSTycY([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 1

    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bitPacket"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    return-void
.end method

.method public static final setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 1

    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bitPacket"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-fCMF4BQ([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    return-void
.end method

.method public static final setValue-mbSTycY([BLjava/lang/String;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 1

    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "value"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bitPacket"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-static {p1}, Lly0/w;->n(Ljava/lang/String;)[B

    move-result-object p1

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    move-result-object p1

    const-string v0, "copyOf(...)"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValues-wl1WTbA([B[BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    return-void
.end method

.method public static final setValue-mbSTycY([BSLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 1

    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bitPacket"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-xh1D8Z4([BSLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    return-void
.end method

.method public static final setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 1

    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bitPacket"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    return-void
.end method

.method public static final setValue-xh1D8Z4([BSLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 4

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValue$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bitPacket"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    if-le v0, v1, :cond_0

    .line 18
    .line 19
    const v0, 0xffff

    .line 20
    .line 21
    .line 22
    and-int/2addr v0, p1

    .line 23
    and-int/lit16 p1, p1, 0xff

    .line 24
    .line 25
    int-to-byte p1, p1

    .line 26
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 27
    .line 28
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    invoke-direct {v2, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 33
    .line 34
    .line 35
    invoke-static {p0, p1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 36
    .line 37
    .line 38
    ushr-int/lit8 p1, v0, 0x8

    .line 39
    .line 40
    int-to-byte p1, p1

    .line 41
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 42
    .line 43
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    add-int/2addr v2, v1

    .line 48
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    sub-int/2addr p2, v1

    .line 53
    invoke-direct {v0, v2, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 54
    .line 55
    .line 56
    invoke-static {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :cond_0
    int-to-byte p1, p1

    .line 61
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public static final setValues-wl1WTbA([B[BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V
    .locals 7

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$setValues$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "$v$c$kotlin-UByteArray$-values$0"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "bitPacket"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getLength()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;->getStartBit()I

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    const/4 v1, 0x0

    .line 25
    :goto_0
    if-ge v1, v0, :cond_0

    .line 26
    .line 27
    add-int v2, p2, v1

    .line 28
    .line 29
    div-int/lit8 v3, v1, 0x8

    .line 30
    .line 31
    rem-int/lit8 v4, v1, 0x8

    .line 32
    .line 33
    div-int/lit8 v5, v2, 0x8

    .line 34
    .line 35
    rem-int/lit8 v2, v2, 0x8

    .line 36
    .line 37
    aget-byte v3, p1, v3

    .line 38
    .line 39
    and-int/lit16 v3, v3, 0xff

    .line 40
    .line 41
    ushr-int/2addr v3, v4

    .line 42
    const/4 v4, 0x1

    .line 43
    and-int/2addr v3, v4

    .line 44
    int-to-byte v3, v3

    .line 45
    aget-byte v6, p0, v5

    .line 46
    .line 47
    shl-int/2addr v4, v2

    .line 48
    not-int v4, v4

    .line 49
    int-to-byte v4, v4

    .line 50
    and-int/2addr v4, v6

    .line 51
    int-to-byte v4, v4

    .line 52
    aput-byte v4, p0, v5

    .line 53
    .line 54
    and-int/lit16 v3, v3, 0xff

    .line 55
    .line 56
    shl-int v2, v3, v2

    .line 57
    .line 58
    int-to-byte v2, v2

    .line 59
    or-int/2addr v2, v4

    .line 60
    int-to-byte v2, v2

    .line 61
    aput-byte v2, p0, v5

    .line 62
    .line 63
    add-int/lit8 v1, v1, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    return-void
.end method

.method public static final toBytes-GBYM_sE([B)[B
    .locals 1

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$toBytes$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v0, "copyOf(...)"

    .line 12
    .line 13
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public static final toUBytes([B)[B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v0, "copyOf(...)"

    .line 12
    .line 13
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method
