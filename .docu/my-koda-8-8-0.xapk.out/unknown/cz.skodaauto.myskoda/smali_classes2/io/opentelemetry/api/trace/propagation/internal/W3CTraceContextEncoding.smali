.class public final Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final TRACESTATE_ENTRY_DELIMITER:C = ','

.field private static final TRACESTATE_ENTRY_DELIMITER_SPLIT_PATTERN:Ljava/util/regex/Pattern;

.field private static final TRACESTATE_KEY_VALUE_DELIMITER:C = '='

.field private static final TRACESTATE_MAX_MEMBERS:I = 0x20

.field private static final TRACESTATE_MAX_SIZE:I = 0x200


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "[ \t]*,[ \t]*"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;->TRACESTATE_ENTRY_DELIMITER_SPLIT_PATTERN:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;->lambda$encodeTraceState$0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static decodeTraceState(Ljava/lang/String;)Lio/opentelemetry/api/trace/TraceState;
    .locals 8

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/TraceState;->builder()Lio/opentelemetry/api/trace/TraceStateBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;->TRACESTATE_ENTRY_DELIMITER_SPLIT_PATTERN:Ljava/util/regex/Pattern;

    .line 6
    .line 7
    invoke-virtual {v1, p0}, Ljava/util/regex/Pattern;->split(Ljava/lang/CharSequence;)[Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    array-length v1, p0

    .line 12
    const/16 v2, 0x20

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x1

    .line 16
    if-gt v1, v2, :cond_0

    .line 17
    .line 18
    move v1, v4

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v1, v3

    .line 21
    :goto_0
    const-string v2, "TraceState has too many elements."

    .line 22
    .line 23
    invoke-static {v1, v2}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    array-length v1, p0

    .line 27
    sub-int/2addr v1, v4

    .line 28
    :goto_1
    if-ltz v1, :cond_2

    .line 29
    .line 30
    aget-object v2, p0, v1

    .line 31
    .line 32
    const/16 v5, 0x3d

    .line 33
    .line 34
    invoke-virtual {v2, v5}, Ljava/lang/String;->indexOf(I)I

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    const/4 v6, -0x1

    .line 39
    if-eq v5, v6, :cond_1

    .line 40
    .line 41
    move v6, v4

    .line 42
    goto :goto_2

    .line 43
    :cond_1
    move v6, v3

    .line 44
    :goto_2
    const-string v7, "Invalid TraceState list-member format."

    .line 45
    .line 46
    invoke-static {v6, v7}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v2, v3, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    add-int/lit8 v5, v5, 0x1

    .line 54
    .line 55
    invoke-virtual {v2, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-interface {v0, v6, v2}, Lio/opentelemetry/api/trace/TraceStateBuilder;->put(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/TraceStateBuilder;

    .line 60
    .line 61
    .line 62
    add-int/lit8 v1, v1, -0x1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_2
    invoke-interface {v0}, Lio/opentelemetry/api/trace/TraceStateBuilder;->build()Lio/opentelemetry/api/trace/TraceState;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-interface {v0}, Lio/opentelemetry/api/trace/TraceState;->size()I

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    array-length p0, p0

    .line 74
    if-eq v1, p0, :cond_3

    .line 75
    .line 76
    invoke-static {}, Lio/opentelemetry/api/trace/TraceState;->getDefault()Lio/opentelemetry/api/trace/TraceState;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :cond_3
    return-object v0
.end method

.method public static encodeTraceState(Lio/opentelemetry/api/trace/TraceState;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/trace/TraceState;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string p0, ""

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const/16 v1, 0x200

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Lio/opentelemetry/api/baggage/propagation/a;

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-direct {v1, v2, v0}, Lio/opentelemetry/api/baggage/propagation/a;-><init>(ILjava/lang/StringBuilder;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {p0, v1}, Lio/opentelemetry/api/trace/TraceState;->forEach(Ljava/util/function/BiConsumer;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method private static synthetic lambda$encodeTraceState$0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/16 v0, 0x2c

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const/16 p1, 0x3d

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    return-void
.end method
