.class public final Lio/opentelemetry/api/trace/SpanId;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final BYTES_LENGTH:I = 0x8

.field private static final HEX_LENGTH:I = 0x10

.field private static final INVALID:Ljava/lang/String; = "0000000000000000"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static fromBytes([B)Ljava/lang/String;
    .locals 3

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/16 v1, 0x8

    .line 5
    .line 6
    if-ge v0, v1, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/16 v0, 0x10

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/internal/TemporaryBuffers;->chars(I)[C

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-static {p0, v2, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->bytesToBase16([B[CI)V

    .line 16
    .line 17
    .line 18
    new-instance p0, Ljava/lang/String;

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    invoke-direct {p0, v2, v1, v0}, Ljava/lang/String;-><init>([CII)V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    :goto_0
    const-string p0, "spanIdBytes is null or too short"

    .line 26
    .line 27
    invoke-static {p0}, Lio/opentelemetry/api/internal/ApiUsageLogger;->log(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string p0, "0000000000000000"

    .line 31
    .line 32
    return-object p0
.end method

.method public static fromLong(J)Ljava/lang/String;
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p0, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getInvalid()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/16 v0, 0x10

    .line 13
    .line 14
    invoke-static {v0}, Lio/opentelemetry/api/internal/TemporaryBuffers;->chars(I)[C

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-static {p0, p1, v1, v2}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->longToBase16String(J[CI)V

    .line 20
    .line 21
    .line 22
    new-instance p0, Ljava/lang/String;

    .line 23
    .line 24
    invoke-direct {p0, v1, v2, v0}, Ljava/lang/String;-><init>([CII)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method

.method public static getInvalid()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "0000000000000000"

    .line 2
    .line 3
    return-object v0
.end method

.method public static getLength()I
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    return v0
.end method

.method public static isValid(Ljava/lang/CharSequence;)Z
    .locals 2

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x10

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    const-string v0, "0000000000000000"

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/String;->contentEquals(Ljava/lang/CharSequence;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    invoke-static {p0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->isValidBase16String(Ljava/lang/CharSequence;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    return p0
.end method
