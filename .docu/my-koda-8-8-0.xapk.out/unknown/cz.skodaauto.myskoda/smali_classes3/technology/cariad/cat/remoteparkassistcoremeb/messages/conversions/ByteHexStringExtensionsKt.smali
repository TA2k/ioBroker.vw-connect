.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0010\u000e\n\u0002\u0010\u0005\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\t\n\u0002\u0008\u0005\n\u0002\u0010\u0019\n\u0002\u0008\u0003\u001a\u0011\u0010\u0002\u001a\u00020\u0001*\u00020\u0000\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u001a\u0011\u0010\u0005\u001a\u00020\u0004*\u00020\u0000\u00a2\u0006\u0004\u0008\u0005\u0010\u0006\u001a\u0011\u0010\u0008\u001a\u00020\u0007*\u00020\u0000\u00a2\u0006\u0004\u0008\u0008\u0010\u0003\u001a\u0011\u0010\n\u001a\u00020\t*\u00020\u0000\u00a2\u0006\u0004\u0008\n\u0010\u0006\u001a\u0011\u0010\u000b\u001a\u00020\u0000*\u00020\u0001\u00a2\u0006\u0004\u0008\u000b\u0010\u000c\u001a\u0011\u0010\u000b\u001a\u00020\u0000*\u00020\u0004\u00a2\u0006\u0004\u0008\u000b\u0010\r\u001a\u0011\u0010\u000b\u001a\u00020\u0000*\u00020\u0007\u00a2\u0006\u0004\u0008\u000e\u0010\u000c\u001a\u0011\u0010\u000b\u001a\u00020\u0000*\u00020\t\u00a2\u0006\u0004\u0008\u000f\u0010\r\u001a\u0011\u0010\u000b\u001a\u00020\u0000*\u00020\u0010\u00a2\u0006\u0004\u0008\u000b\u0010\u0011\u001a\u0011\u0010\u0012\u001a\u00020\u0010*\u00020\u0000\u00a2\u0006\u0004\u0008\u0012\u0010\u0013\"\u0014\u0010\u0014\u001a\u00020\u00008\u0006X\u0086T\u00a2\u0006\u0006\n\u0004\u0008\u0014\u0010\u0015\"\u0014\u0010\u0017\u001a\u00020\u00168\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0017\u0010\u0018\u00a8\u0006\u0019"
    }
    d2 = {
        "",
        "",
        "hexStringToByte",
        "(Ljava/lang/String;)B",
        "",
        "hexStringToBytes",
        "(Ljava/lang/String;)[B",
        "Llx0/s;",
        "hexStringToUByte",
        "Llx0/t;",
        "hexStringToUBytes",
        "toHexString",
        "(B)Ljava/lang/String;",
        "([B)Ljava/lang/String;",
        "toHexString-7apg3OU",
        "toHexString-GBYM_sE",
        "",
        "(J)Ljava/lang/String;",
        "hexStringToLong",
        "(Ljava/lang/String;)J",
        "HEX_PREFIX",
        "Ljava/lang/String;",
        "",
        "HEX_CHARS",
        "[C",
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


# static fields
.field private static final HEX_CHARS:[C

.field public static final HEX_PREFIX:Ljava/lang/String; = "0x"


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "0123456789ABCDEF"

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "toCharArray(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->HEX_CHARS:[C

    .line 13
    .line 14
    return-void
.end method

.method public static final hexStringToByte(Ljava/lang/String;)B
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "0x"

    .line 7
    .line 8
    invoke-static {p0, v0}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-static {v1}, Lry/a;->b(C)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x1

    .line 22
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-static {p0}, Lry/a;->b(C)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    const/4 v2, -0x1

    .line 31
    if-eq v1, v2, :cond_0

    .line 32
    .line 33
    if-eq p0, v2, :cond_0

    .line 34
    .line 35
    shl-int/lit8 v0, v1, 0x4

    .line 36
    .line 37
    add-int/2addr v0, p0

    .line 38
    int-to-byte p0, v0

    .line 39
    return p0

    .line 40
    :cond_0
    return v0
.end method

.method public static final hexStringToBytes(Ljava/lang/String;)[B
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x0

    .line 16
    move v3, v2

    .line 17
    :goto_0
    if-ge v3, v1, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    invoke-static {v4}, Lry/a;->d(C)Z

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    if-nez v5, :cond_0

    .line 28
    .line 29
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 30
    .line 31
    .line 32
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string v0, "0x"

    .line 40
    .line 41
    invoke-static {p0, v0}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    rem-int/lit8 v0, v0, 0x2

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    if-ne v0, v1, :cond_2

    .line 53
    .line 54
    new-array p0, v2, [B

    .line 55
    .line 56
    return-object p0

    .line 57
    :cond_2
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    div-int/lit8 v0, v0, 0x2

    .line 62
    .line 63
    new-array v0, v0, [B

    .line 64
    .line 65
    :goto_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-ge v2, v1, :cond_3

    .line 70
    .line 71
    div-int/lit8 v1, v2, 0x2

    .line 72
    .line 73
    add-int/lit8 v3, v2, 0x2

    .line 74
    .line 75
    invoke-virtual {p0, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    const-string v4, "substring(...)"

    .line 80
    .line 81
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->hexStringToByte(Ljava/lang/String;)B

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    aput-byte v2, v0, v1

    .line 89
    .line 90
    move v2, v3

    .line 91
    goto :goto_1

    .line 92
    :cond_3
    return-object v0
.end method

.method public static final hexStringToLong(Ljava/lang/String;)J
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "0x"

    .line 7
    .line 8
    invoke-static {p0, v0}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/16 v0, 0x10

    .line 13
    .line 14
    invoke-static {v0}, Lry/a;->a(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, v0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;I)J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    return-wide v0
.end method

.method public static final hexStringToUByte(Ljava/lang/String;)B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->hexStringToByte(Ljava/lang/String;)B

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static final hexStringToUBytes(Ljava/lang/String;)[B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->hexStringToBytes(Ljava/lang/String;)[B

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toUBytes([B)[B

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final toHexString(B)Ljava/lang/String;
    .locals 3

    and-int/lit16 p0, p0, 0xff

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->HEX_CHARS:[C

    div-int/lit8 v1, p0, 0x10

    aget-char v1, v0, v1

    .line 2
    rem-int/lit8 p0, p0, 0x10

    aget-char p0, v0, p0

    const/4 v0, 0x2

    new-array v0, v0, [C

    const/4 v2, 0x0

    aput-char v1, v0, v2

    const/4 v1, 0x1

    aput-char p0, v0, v1

    .line 3
    invoke-static {v0}, Lmx0/n;->G([C)Ljava/lang/String;

    move-result-object p0

    const-string v0, "0x"

    .line 4
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final toHexString(J)Ljava/lang/String;
    .locals 1

    const/16 v0, 0x10

    .line 19
    invoke-static {v0}, Lry/a;->a(I)V

    invoke-static {p0, p1, v0}, Ljava/lang/Long;->toString(JI)Ljava/lang/String;

    move-result-object p0

    const-string p1, "toString(...)"

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "0x"

    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final toHexString([B)Ljava/lang/String;
    .locals 8

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    array-length v0, p0

    mul-int/lit8 v0, v0, 0x2

    new-array v0, v0, [C

    .line 10
    array-length v1, p0

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v2, v1, :cond_0

    aget-byte v4, p0, v2

    add-int/lit8 v5, v3, 0x1

    and-int/lit16 v4, v4, 0xff

    mul-int/lit8 v3, v3, 0x2

    .line 11
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->HEX_CHARS:[C

    div-int/lit8 v7, v4, 0x10

    aget-char v7, v6, v7

    aput-char v7, v0, v3

    add-int/lit8 v3, v3, 0x1

    .line 12
    rem-int/lit8 v4, v4, 0x10

    aget-char v4, v6, v4

    aput-char v4, v0, v3

    add-int/lit8 v2, v2, 0x1

    move v3, v5

    goto :goto_0

    .line 13
    :cond_0
    invoke-static {v0}, Lmx0/n;->G([C)Ljava/lang/String;

    move-result-object p0

    const-string v0, "0x"

    .line 14
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final toHexString-7apg3OU(B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->toHexString(B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final toHexString-GBYM_sE([B)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "$v$c$kotlin-UByteArray$-$this$toHexString$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->toHexString([B)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
