.class public final Lht/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:B

.field public static final b:B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "01110000"

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-static {v0, v1}, Ljava/lang/Byte;->parseByte(Ljava/lang/String;I)B

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    sput-byte v0, Lht/h;->a:B

    .line 9
    .line 10
    const-string v0, "00001111"

    .line 11
    .line 12
    invoke-static {v0, v1}, Ljava/lang/Byte;->parseByte(Ljava/lang/String;I)B

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    sput-byte v0, Lht/h;->b:B

    .line 17
    .line 18
    return-void
.end method

.method public static a()Ljava/lang/String;
    .locals 4

    .line 1
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/16 v1, 0x11

    .line 6
    .line 7
    new-array v1, v1, [B

    .line 8
    .line 9
    invoke-static {v1}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0}, Ljava/util/UUID;->getMostSignificantBits()J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    invoke-virtual {v1, v2, v3}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/util/UUID;->getLeastSignificantBits()J

    .line 21
    .line 22
    .line 23
    move-result-wide v2

    .line 24
    invoke-virtual {v1, v2, v3}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/nio/ByteBuffer;->array()[B

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const/4 v1, 0x0

    .line 32
    aget-byte v2, v0, v1

    .line 33
    .line 34
    const/16 v3, 0x10

    .line 35
    .line 36
    aput-byte v2, v0, v3

    .line 37
    .line 38
    sget-byte v3, Lht/h;->b:B

    .line 39
    .line 40
    and-int/2addr v2, v3

    .line 41
    sget-byte v3, Lht/h;->a:B

    .line 42
    .line 43
    or-int/2addr v2, v3

    .line 44
    int-to-byte v2, v2

    .line 45
    aput-byte v2, v0, v1

    .line 46
    .line 47
    new-instance v2, Ljava/lang/String;

    .line 48
    .line 49
    const/16 v3, 0xb

    .line 50
    .line 51
    invoke-static {v0, v3}, Landroid/util/Base64;->encode([BI)[B

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    invoke-direct {v2, v0, v3}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 60
    .line 61
    .line 62
    const/16 v0, 0x16

    .line 63
    .line 64
    invoke-virtual {v2, v1, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    return-object v0
.end method
