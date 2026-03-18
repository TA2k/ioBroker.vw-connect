.class public final Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/propagation/TextMapPropagator;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final FIELDS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final INSTANCE:Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;

.field private static final SPAN_ID_HEX_SIZE:I

.field private static final SPAN_ID_OFFSET:I

.field private static final TRACEPARENT_DELIMITER:C = '-'

.field private static final TRACEPARENT_DELIMITER_SIZE:I = 0x1

.field private static final TRACEPARENT_HEADER_SIZE:I

.field private static final TRACE_ID_HEX_SIZE:I

.field private static final TRACE_ID_OFFSET:I = 0x3

.field private static final TRACE_OPTION_HEX_SIZE:I

.field private static final TRACE_OPTION_OFFSET:I

.field static final TRACE_PARENT:Ljava/lang/String; = "traceparent"

.field static final TRACE_STATE:Ljava/lang/String; = "tracestate"

.field private static final VALID_VERSIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final VERSION:Ljava/lang/String; = "00"

.field private static final VERSION_00:Ljava/lang/String; = "00"

.field private static final VERSION_SIZE:I = 0x2

.field private static final logger:Ljava/util/logging/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-class v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "traceparent"

    .line 14
    .line 15
    const-string v1, "tracestate"

    .line 16
    .line 17
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->FIELDS:Ljava/util/List;

    .line 30
    .line 31
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getLength()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    sput v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACE_ID_HEX_SIZE:I

    .line 36
    .line 37
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getLength()I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    sput v1, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->SPAN_ID_HEX_SIZE:I

    .line 42
    .line 43
    invoke-static {}, Lio/opentelemetry/api/trace/TraceFlags;->getLength()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    sput v2, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACE_OPTION_HEX_SIZE:I

    .line 48
    .line 49
    add-int/lit8 v0, v0, 0x4

    .line 50
    .line 51
    sput v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->SPAN_ID_OFFSET:I

    .line 52
    .line 53
    add-int/2addr v0, v1

    .line 54
    add-int/lit8 v0, v0, 0x1

    .line 55
    .line 56
    sput v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACE_OPTION_OFFSET:I

    .line 57
    .line 58
    add-int/2addr v0, v2

    .line 59
    sput v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACEPARENT_HEADER_SIZE:I

    .line 60
    .line 61
    new-instance v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;

    .line 62
    .line 63
    invoke-direct {v0}, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;-><init>()V

    .line 64
    .line 65
    .line 66
    sput-object v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->INSTANCE:Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;

    .line 67
    .line 68
    new-instance v0, Ljava/util/HashSet;

    .line 69
    .line 70
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 71
    .line 72
    .line 73
    sput-object v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->VALID_VERSIONS:Ljava/util/Set;

    .line 74
    .line 75
    const/4 v0, 0x0

    .line 76
    :goto_0
    const/16 v1, 0xff

    .line 77
    .line 78
    if-ge v0, v1, :cond_1

    .line 79
    .line 80
    int-to-long v1, v0

    .line 81
    invoke-static {v1, v2}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    const/4 v3, 0x2

    .line 90
    if-ge v2, v3, :cond_0

    .line 91
    .line 92
    const-string v2, "0"

    .line 93
    .line 94
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    :cond_0
    sget-object v2, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->VALID_VERSIONS:Ljava/util/Set;

    .line 99
    .line 100
    invoke-interface {v2, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    add-int/lit8 v0, v0, 0x1

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_1
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

.method private static extractContextFromTraceParent(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanContext;
    .locals 6

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sget v1, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACEPARENT_HEADER_SIZE:I

    .line 6
    .line 7
    const/16 v2, 0x2d

    .line 8
    .line 9
    if-eq v0, v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-le v0, v1, :cond_5

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-ne v0, v2, :cond_5

    .line 22
    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-ne v3, v2, :cond_5

    .line 29
    .line 30
    sget v3, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->SPAN_ID_OFFSET:I

    .line 31
    .line 32
    add-int/lit8 v4, v3, -0x1

    .line 33
    .line 34
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-ne v4, v2, :cond_5

    .line 39
    .line 40
    sget v4, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACE_OPTION_OFFSET:I

    .line 41
    .line 42
    add-int/lit8 v5, v4, -0x1

    .line 43
    .line 44
    invoke-virtual {p0, v5}, Ljava/lang/String;->charAt(I)C

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    if-ne v5, v2, :cond_5

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    invoke-virtual {p0, v2, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sget-object v2, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->VALID_VERSIONS:Ljava/util/Set;

    .line 56
    .line 57
    invoke-interface {v2, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-nez v2, :cond_1

    .line 62
    .line 63
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :cond_1
    const-string v2, "00"

    .line 69
    .line 70
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-eqz v0, :cond_2

    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-le v0, v1, :cond_2

    .line 81
    .line 82
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0

    .line 87
    :cond_2
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getLength()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    const/4 v1, 0x3

    .line 92
    add-int/2addr v0, v1

    .line 93
    invoke-virtual {p0, v1, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getLength()I

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    add-int/2addr v1, v3

    .line 102
    invoke-virtual {p0, v3, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    add-int/lit8 v4, v4, 0x1

    .line 111
    .line 112
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    invoke-static {v2}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->isValidBase16Character(C)Z

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    if-eqz v3, :cond_4

    .line 121
    .line 122
    invoke-static {p0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->isValidBase16Character(C)Z

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-nez v3, :cond_3

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_3
    invoke-static {v2, p0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    invoke-static {p0}, Lio/opentelemetry/api/trace/TraceFlags;->fromByte(B)Lio/opentelemetry/api/trace/TraceFlags;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    invoke-static {}, Lio/opentelemetry/api/trace/TraceState;->getDefault()Lio/opentelemetry/api/trace/TraceState;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    invoke-static {v0, v1, p0, v2}, Lio/opentelemetry/api/trace/SpanContext;->createFromRemoteParent(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;)Lio/opentelemetry/api/trace/SpanContext;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    return-object p0

    .line 146
    :cond_4
    :goto_0
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    return-object p0

    .line 151
    :cond_5
    sget-object p0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->logger:Ljava/util/logging/Logger;

    .line 152
    .line 153
    const-string v0, "Unparseable traceparent header. Returning INVALID span context."

    .line 154
    .line 155
    invoke-virtual {p0, v0}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    return-object p0
.end method

.method private static extractImpl(Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/api/trace/SpanContext;
    .locals 3
    .param p0    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<C:",
            "Ljava/lang/Object;",
            ">(TC;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TC;>;)",
            "Lio/opentelemetry/api/trace/SpanContext;"
        }
    .end annotation

    .line 1
    const-string v0, "traceparent"

    .line 2
    .line 3
    invoke-interface {p1, p0, v0}, Lio/opentelemetry/context/propagation/TextMapGetter;->get(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-static {v0}, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->extractContextFromTraceParent(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanContext;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const-string v1, "tracestate"

    .line 26
    .line 27
    invoke-interface {p1, p0, v1}, Lio/opentelemetry/context/propagation/TextMapGetter;->get(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    if-eqz p0, :cond_3

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    if-eqz p1, :cond_2

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    :try_start_0
    invoke-static {p0}, Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;->decodeTraceState(Ljava/lang/String;)Lio/opentelemetry/api/trace/TraceState;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    invoke-static {p1, v1, v2, p0}, Lio/opentelemetry/api/trace/SpanContext;->createFromRemoteParent(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;)Lio/opentelemetry/api/trace/SpanContext;

    .line 57
    .line 58
    .line 59
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 60
    return-object p0

    .line 61
    :catch_0
    sget-object p0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->logger:Ljava/util/logging/Logger;

    .line 62
    .line 63
    const-string p1, "Unparseable tracestate header. Returning span context without state."

    .line 64
    .line 65
    invoke-virtual {p0, p1}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    :cond_3
    :goto_0
    return-object v0
.end method

.method public static getInstance()Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->INSTANCE:Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public extract(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/context/Context;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<C:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/context/Context;",
            "TC;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TC;>;)",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/context/Context;->root()Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    if-nez p3, :cond_1

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_1
    invoke-static {p2, p3}, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->extractImpl(Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/api/trace/SpanContext;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    if-nez p2, :cond_2

    .line 20
    .line 21
    :goto_0
    return-object p1

    .line 22
    :cond_2
    invoke-static {p0}, Lio/opentelemetry/api/trace/Span;->wrap(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/Span;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-interface {p1, p0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ImplicitContextKeyed;)Lio/opentelemetry/context/Context;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public fields()Ljava/util/Collection;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->FIELDS:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public inject(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapSetter;)V
    .locals 7
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<C:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/context/Context;",
            "TC;",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TC;>;)V"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    if-nez p3, :cond_0

    .line 4
    .line 5
    goto/16 :goto_0

    .line 6
    .line 7
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {p0}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    sget p1, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACEPARENT_HEADER_SIZE:I

    .line 23
    .line 24
    invoke-static {p1}, Lio/opentelemetry/api/internal/TemporaryBuffers;->chars(I)[C

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    const-string v1, "00"

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-virtual {v1, v2}, Ljava/lang/String;->charAt(I)C

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    aput-char v3, v0, v2

    .line 36
    .line 37
    const/4 v3, 0x1

    .line 38
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    aput-char v1, v0, v3

    .line 43
    .line 44
    const/4 v1, 0x2

    .line 45
    const/16 v4, 0x2d

    .line 46
    .line 47
    aput-char v4, v0, v1

    .line 48
    .line 49
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    const/4 v6, 0x3

    .line 58
    invoke-virtual {v1, v2, v5, v0, v6}, Ljava/lang/String;->getChars(II[CI)V

    .line 59
    .line 60
    .line 61
    sget v1, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->SPAN_ID_OFFSET:I

    .line 62
    .line 63
    add-int/lit8 v5, v1, -0x1

    .line 64
    .line 65
    aput-char v4, v0, v5

    .line 66
    .line 67
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 72
    .line 73
    .line 74
    move-result v6

    .line 75
    invoke-virtual {v5, v2, v6, v0, v1}, Ljava/lang/String;->getChars(II[CI)V

    .line 76
    .line 77
    .line 78
    sget v1, Lio/opentelemetry/api/trace/propagation/W3CTraceContextPropagator;->TRACE_OPTION_OFFSET:I

    .line 79
    .line 80
    add-int/lit8 v5, v1, -0x1

    .line 81
    .line 82
    aput-char v4, v0, v5

    .line 83
    .line 84
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    invoke-interface {v4}, Lio/opentelemetry/api/trace/TraceFlags;->asHex()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    invoke-virtual {v4, v2}, Ljava/lang/String;->charAt(I)C

    .line 93
    .line 94
    .line 95
    move-result v5

    .line 96
    aput-char v5, v0, v1

    .line 97
    .line 98
    add-int/2addr v1, v3

    .line 99
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    aput-char v3, v0, v1

    .line 104
    .line 105
    new-instance v1, Ljava/lang/String;

    .line 106
    .line 107
    invoke-direct {v1, v0, v2, p1}, Ljava/lang/String;-><init>([CII)V

    .line 108
    .line 109
    .line 110
    const-string p1, "traceparent"

    .line 111
    .line 112
    invoke-interface {p3, p2, p1, v1}, Lio/opentelemetry/context/propagation/TextMapSetter;->set(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceState()Lio/opentelemetry/api/trace/TraceState;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-interface {p0}, Lio/opentelemetry/api/trace/TraceState;->isEmpty()Z

    .line 120
    .line 121
    .line 122
    move-result p1

    .line 123
    if-eqz p1, :cond_2

    .line 124
    .line 125
    goto :goto_0

    .line 126
    :cond_2
    const-string p1, "tracestate"

    .line 127
    .line 128
    invoke-static {p0}, Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;->encodeTraceState(Lio/opentelemetry/api/trace/TraceState;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    invoke-interface {p3, p2, p1, p0}, Lio/opentelemetry/context/propagation/TextMapSetter;->set(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    :cond_3
    :goto_0
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "W3CTraceContextPropagator"

    .line 2
    .line 3
    return-object p0
.end method
