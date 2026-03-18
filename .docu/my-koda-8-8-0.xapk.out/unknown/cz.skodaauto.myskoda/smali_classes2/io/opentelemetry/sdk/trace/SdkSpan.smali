.class final Lio/opentelemetry/sdk/trace/SdkSpan;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/ReadWriteSpan;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/trace/SdkSpan$EndState;
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# static fields
.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private attributes:Lio/opentelemetry/sdk/internal/AttributesMap;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

.field private final context:Lio/opentelemetry/api/trace/SpanContext;

.field private endEpochNanos:J

.field private events:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/EventData;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

.field private hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

.field private final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field private final kind:Lio/opentelemetry/api/trace/SpanKind;

.field links:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final lock:Ljava/lang/Object;

.field private name:Ljava/lang/String;

.field private final parentSpanContext:Lio/opentelemetry/api/trace/SpanContext;

.field private final resource:Lio/opentelemetry/sdk/resources/Resource;

.field private spanEndingThread:Ljava/lang/Thread;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

.field private final spanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

.field private final startEpochNanos:J

.field private status:Lio/opentelemetry/sdk/trace/data/StatusData;

.field private totalRecordedEvents:I

.field private totalRecordedLinks:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/trace/SdkSpan;

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
    sput-object v0, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/sdk/trace/SpanLimits;Lio/opentelemetry/sdk/trace/SpanProcessor;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;Lio/opentelemetry/sdk/trace/AnchoredClock;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/util/List;IJ)V
    .locals 1
    .param p11    # Lio/opentelemetry/sdk/internal/AttributesMap;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Ljava/util/List;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Lio/opentelemetry/api/trace/SpanKind;",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Lio/opentelemetry/sdk/trace/SpanLimits;",
            "Lio/opentelemetry/sdk/trace/SpanProcessor;",
            "Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;",
            "Lio/opentelemetry/sdk/trace/AnchoredClock;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/internal/AttributesMap;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;IJ)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedEvents:I

    .line 13
    .line 14
    invoke-static {}, Lio/opentelemetry/sdk/trace/data/StatusData;->unset()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 19
    .line 20
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->context:Lio/opentelemetry/api/trace/SpanContext;

    .line 21
    .line 22
    iput-object p3, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 23
    .line 24
    iput-object p5, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->parentSpanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 25
    .line 26
    iput-object p12, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->links:Ljava/util/List;

    .line 27
    .line 28
    iput p13, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedLinks:I

    .line 29
    .line 30
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->name:Ljava/lang/String;

    .line 31
    .line 32
    iput-object p4, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->kind:Lio/opentelemetry/api/trace/SpanKind;

    .line 33
    .line 34
    iput-object p7, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 35
    .line 36
    iput-object p8, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 37
    .line 38
    iput-object p10, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 39
    .line 40
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->NOT_ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 41
    .line 42
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 43
    .line 44
    iput-object p9, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 45
    .line 46
    move-wide p1, p14

    .line 47
    iput-wide p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->startEpochNanos:J

    .line 48
    .line 49
    iput-object p11, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 50
    .line 51
    iput-object p6, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 52
    .line 53
    return-void
.end method

.method private addTimedEvent(Lio/opentelemetry/sdk/trace/data/EventData;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->isModifiableByCurrentThread()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    sget-object p0, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    .line 11
    .line 12
    sget-object p1, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 13
    .line 14
    const-string v1, "Calling addEvent() on an ended Span."

    .line 15
    .line 16
    invoke-virtual {p0, p1, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    monitor-exit v0

    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->events:Ljava/util/List;

    .line 24
    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    new-instance v1, Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->events:Ljava/util/List;

    .line 33
    .line 34
    :cond_1
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->events:Ljava/util/List;

    .line 35
    .line 36
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 41
    .line 42
    invoke-virtual {v2}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfEvents()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-ge v1, v2, :cond_2

    .line 47
    .line 48
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->events:Ljava/util/List;

    .line 49
    .line 50
    invoke-interface {v1, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    :cond_2
    iget p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedEvents:I

    .line 54
    .line 55
    add-int/lit8 p1, p1, 0x1

    .line 56
    .line 57
    iput p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedEvents:I

    .line 58
    .line 59
    monitor-exit v0

    .line 60
    return-void

    .line 61
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    throw p0
.end method

.method private endInternal(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 5
    .line 6
    sget-object v2, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->NOT_ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    sget-object p0, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    .line 11
    .line 12
    sget-object p1, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 13
    .line 14
    const-string p2, "Calling end() on an ended or ending Span."

    .line 15
    .line 16
    invoke-virtual {p0, p1, p2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    monitor-exit v0

    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iput-wide p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->endEpochNanos:J

    .line 24
    .line 25
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanEndingThread:Ljava/lang/Thread;

    .line 30
    .line 31
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDING:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 32
    .line 33
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 34
    .line 35
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    iget-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 37
    .line 38
    instance-of p2, p1, Lio/opentelemetry/sdk/trace/internal/ExtendedSpanProcessor;

    .line 39
    .line 40
    if-eqz p2, :cond_1

    .line 41
    .line 42
    check-cast p1, Lio/opentelemetry/sdk/trace/internal/ExtendedSpanProcessor;

    .line 43
    .line 44
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/internal/ExtendedSpanProcessor;->isOnEndingRequired()Z

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    if-eqz p2, :cond_1

    .line 49
    .line 50
    invoke-interface {p1, p0}, Lio/opentelemetry/sdk/trace/internal/ExtendedSpanProcessor;->onEnding(Lio/opentelemetry/sdk/trace/ReadWriteSpan;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    iget-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 54
    .line 55
    monitor-enter p1

    .line 56
    :try_start_1
    sget-object p2, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 57
    .line 58
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 59
    .line 60
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 61
    iget-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 62
    .line 63
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/SpanProcessor;->isEndRequired()Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-eqz p1, :cond_2

    .line 68
    .line 69
    iget-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 70
    .line 71
    invoke-interface {p1, p0}, Lio/opentelemetry/sdk/trace/SpanProcessor;->onEnd(Lio/opentelemetry/sdk/trace/ReadableSpan;)V

    .line 72
    .line 73
    .line 74
    :cond_2
    return-void

    .line 75
    :catchall_1
    move-exception p0

    .line 76
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 77
    throw p0

    .line 78
    :goto_0
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 79
    throw p0
.end method

.method private getImmutableAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 13
    .line 14
    sget-object v1, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 15
    .line 16
    if-ne v0, v1, :cond_1

    .line 17
    .line 18
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 22
    .line 23
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/AttributesMap;->immutableCopy()Lio/opentelemetry/api/common/Attributes;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :cond_2
    :goto_0
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method private getImmutableLinks()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->links:Ljava/util/List;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->links:Ljava/util/List;

    .line 13
    .line 14
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_1
    :goto_0
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 20
    .line 21
    return-object p0
.end method

.method private getImmutableTimedEvents()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/EventData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->events:Ljava/util/List;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 9
    .line 10
    sget-object v2, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 11
    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_1
    new-instance v0, Ljava/util/ArrayList;

    .line 20
    .line 21
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->events:Ljava/util/List;

    .line 22
    .line 23
    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method private isModifiableByCurrentThread()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->NOT_ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 4
    .line 5
    if-eq v0, v1, :cond_1

    .line 6
    .line 7
    sget-object v1, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDING:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanEndingThread:Ljava/lang/Thread;

    .line 16
    .line 17
    if-ne v0, p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public static startSpan(Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;Lio/opentelemetry/context/Context;Lio/opentelemetry/sdk/trace/SpanLimits;Lio/opentelemetry/sdk/trace/SpanProcessor;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/util/List;IJ)Lio/opentelemetry/sdk/trace/SdkSpan;
    .locals 19
    .param p11    # Lio/opentelemetry/sdk/internal/AttributesMap;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Ljava/util/List;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Lio/opentelemetry/api/trace/SpanKind;",
            "Lio/opentelemetry/api/trace/Span;",
            "Lio/opentelemetry/context/Context;",
            "Lio/opentelemetry/sdk/trace/SpanLimits;",
            "Lio/opentelemetry/sdk/trace/SpanProcessor;",
            "Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;",
            "Lio/opentelemetry/sdk/common/Clock;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/internal/AttributesMap;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;IJ)",
            "Lio/opentelemetry/sdk/trace/SdkSpan;"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    instance-of v1, v0, Lio/opentelemetry/sdk/trace/SdkSpan;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lio/opentelemetry/sdk/trace/SdkSpan;

    .line 9
    .line 10
    iget-object v1, v1, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    move-object v12, v1

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    invoke-static/range {p9 .. p9}, Lio/opentelemetry/sdk/trace/AnchoredClock;->create(Lio/opentelemetry/sdk/common/Clock;)Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const/4 v2, 0x1

    .line 20
    goto :goto_0

    .line 21
    :goto_1
    const-wide/16 v3, 0x0

    .line 22
    .line 23
    cmp-long v1, p14, v3

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    move-wide/from16 v17, p14

    .line 28
    .line 29
    goto :goto_3

    .line 30
    :cond_1
    if-eqz v2, :cond_2

    .line 31
    .line 32
    invoke-virtual {v12}, Lio/opentelemetry/sdk/trace/AnchoredClock;->startTime()J

    .line 33
    .line 34
    .line 35
    move-result-wide v1

    .line 36
    :goto_2
    move-wide/from16 v17, v1

    .line 37
    .line 38
    goto :goto_3

    .line 39
    :cond_2
    invoke-virtual {v12}, Lio/opentelemetry/sdk/trace/AnchoredClock;->now()J

    .line 40
    .line 41
    .line 42
    move-result-wide v1

    .line 43
    goto :goto_2

    .line 44
    :goto_3
    new-instance v3, Lio/opentelemetry/sdk/trace/SdkSpan;

    .line 45
    .line 46
    invoke-interface {v0}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    move-object/from16 v4, p0

    .line 51
    .line 52
    move-object/from16 v5, p1

    .line 53
    .line 54
    move-object/from16 v6, p2

    .line 55
    .line 56
    move-object/from16 v7, p3

    .line 57
    .line 58
    move-object/from16 v9, p6

    .line 59
    .line 60
    move-object/from16 v10, p7

    .line 61
    .line 62
    move-object/from16 v11, p8

    .line 63
    .line 64
    move-object/from16 v13, p10

    .line 65
    .line 66
    move-object/from16 v14, p11

    .line 67
    .line 68
    move-object/from16 v15, p12

    .line 69
    .line 70
    move/from16 v16, p13

    .line 71
    .line 72
    invoke-direct/range {v3 .. v18}, Lio/opentelemetry/sdk/trace/SdkSpan;-><init>(Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/sdk/trace/SpanLimits;Lio/opentelemetry/sdk/trace/SpanProcessor;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;Lio/opentelemetry/sdk/trace/AnchoredClock;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/util/List;IJ)V

    .line 73
    .line 74
    .line 75
    invoke-interface/range {p7 .. p7}, Lio/opentelemetry/sdk/trace/SpanProcessor;->isStartRequired()Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    if-eqz v0, :cond_3

    .line 80
    .line 81
    move-object/from16 v0, p5

    .line 82
    .line 83
    move-object/from16 v10, p7

    .line 84
    .line 85
    invoke-interface {v10, v0, v3}, Lio/opentelemetry/sdk/trace/SpanProcessor;->onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/sdk/trace/ReadWriteSpan;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    return-object v3
.end method


# virtual methods
.method public bridge synthetic addEvent(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->addEvent(Ljava/lang/String;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic addEvent(Ljava/lang/String;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 2
    invoke-virtual {p0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/trace/SdkSpan;->addEvent(Ljava/lang/String;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpan;->addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 4
    invoke-virtual/range {p0 .. p5}, Lio/opentelemetry/sdk/trace/SdkSpan;->addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public addEvent(Ljava/lang/String;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 4

    if-nez p1, :cond_0

    return-object p0

    .line 5
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/AnchoredClock;->now()J

    move-result-wide v0

    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v2

    const/4 v3, 0x0

    invoke-static {v0, v1, p1, v2, v3}, Lio/opentelemetry/sdk/trace/data/EventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;

    move-result-object p1

    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->addTimedEvent(Lio/opentelemetry/sdk/trace/data/EventData;)V

    return-object p0
.end method

.method public addEvent(Ljava/lang/String;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 1

    if-eqz p1, :cond_1

    if-nez p4, :cond_0

    goto :goto_0

    .line 6
    :cond_0
    invoke-virtual {p4, p2, p3}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p2

    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object p4

    const/4 v0, 0x0

    invoke-static {p2, p3, p1, p4, v0}, Lio/opentelemetry/sdk/trace/data/EventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;

    move-result-object p1

    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->addTimedEvent(Lio/opentelemetry/sdk/trace/data/EventData;)V

    :cond_1
    :goto_0
    return-object p0
.end method

.method public addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 5

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    if-nez p2, :cond_1

    .line 7
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    .line 8
    :cond_1
    invoke-interface {p2}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v0

    .line 9
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 10
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/AnchoredClock;->now()J

    move-result-wide v1

    iget-object v3, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 11
    invoke-virtual {v3}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerEvent()I

    move-result v3

    iget-object v4, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 12
    invoke-virtual {v4}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    move-result v4

    .line 13
    invoke-static {p2, v3, v4}, Lio/opentelemetry/sdk/internal/AttributeUtil;->applyAttributesLimit(Lio/opentelemetry/api/common/Attributes;II)Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    .line 14
    invoke-static {v1, v2, p1, p2, v0}, Lio/opentelemetry/sdk/trace/data/EventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;

    move-result-object p1

    .line 15
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->addTimedEvent(Lio/opentelemetry/sdk/trace/data/EventData;)V

    return-object p0
.end method

.method public addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 2

    if-eqz p1, :cond_2

    if-nez p5, :cond_0

    goto :goto_0

    :cond_0
    if-nez p2, :cond_1

    .line 16
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    .line 17
    :cond_1
    invoke-interface {p2}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v0

    .line 18
    invoke-virtual {p5, p3, p4}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p3

    iget-object p5, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 19
    invoke-virtual {p5}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerEvent()I

    move-result p5

    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 20
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    move-result v1

    .line 21
    invoke-static {p2, p5, v1}, Lio/opentelemetry/sdk/internal/AttributeUtil;->applyAttributesLimit(Lio/opentelemetry/api/common/Attributes;II)Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    .line 22
    invoke-static {p3, p4, p1, p2, v0}, Lio/opentelemetry/sdk/trace/data/EventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;

    move-result-object p1

    .line 23
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->addTimedEvent(Lio/opentelemetry/sdk/trace/data/EventData;)V

    :cond_2
    :goto_0
    return-object p0
.end method

.method public addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 2

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    if-nez p2, :cond_1

    .line 11
    .line 12
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 17
    .line 18
    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerLink()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 23
    .line 24
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {p2, v0, v1}, Lio/opentelemetry/sdk/internal/AttributeUtil;->applyAttributesLimit(Lio/opentelemetry/api/common/Attributes;II)Lio/opentelemetry/api/common/Attributes;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    invoke-static {p1, p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->create(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/data/LinkData;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iget-object p2, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 37
    .line 38
    monitor-enter p2

    .line 39
    :try_start_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->isModifiableByCurrentThread()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    .line 46
    .line 47
    sget-object v0, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 48
    .line 49
    const-string v1, "Calling addLink() on an ended Span."

    .line 50
    .line 51
    invoke-virtual {p1, v0, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    monitor-exit p2

    .line 55
    return-object p0

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto :goto_0

    .line 58
    :cond_2
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->links:Ljava/util/List;

    .line 59
    .line 60
    if-nez v0, :cond_3

    .line 61
    .line 62
    new-instance v0, Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 65
    .line 66
    .line 67
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->links:Ljava/util/List;

    .line 68
    .line 69
    :cond_3
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->links:Ljava/util/List;

    .line 70
    .line 71
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 76
    .line 77
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfLinks()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-ge v0, v1, :cond_4

    .line 82
    .line 83
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->links:Ljava/util/List;

    .line 84
    .line 85
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    :cond_4
    iget p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedLinks:I

    .line 89
    .line 90
    add-int/lit8 p1, p1, 0x1

    .line 91
    .line 92
    iput p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedLinks:I

    .line 93
    .line 94
    monitor-exit p2

    .line 95
    return-object p0

    .line 96
    :goto_0
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 97
    throw p0

    .line 98
    :cond_5
    :goto_1
    return-object p0
.end method

.method public end()V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/AnchoredClock;->now()J

    move-result-wide v0

    invoke-direct {p0, v0, v1}, Lio/opentelemetry/sdk/trace/SdkSpan;->endInternal(J)V

    return-void
.end method

.method public end(JLjava/util/concurrent/TimeUnit;)V
    .locals 2

    if-nez p3, :cond_0

    .line 2
    sget-object p3, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    :cond_0
    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-nez v0, :cond_1

    .line 3
    iget-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/AnchoredClock;->now()J

    move-result-wide p1

    goto :goto_0

    :cond_1
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p1

    :goto_0
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpan;->endInternal(J)V

    return-void
.end method

.method public getAttribute(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/AttributesMap;->get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :goto_0
    monitor-exit v0

    .line 15
    return-object p0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    throw p0
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/AttributesMap;->immutableCopy()Lio/opentelemetry/api/common/Attributes;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    :goto_0
    monitor-exit v0

    .line 20
    return-object p0

    .line 21
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method

.method public getClock()Lio/opentelemetry/sdk/trace/AnchoredClock;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInstrumentationLibraryInfo()Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/InstrumentationScopeUtil;->toInstrumentationLibraryInfo(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public getKind()Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->kind:Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    return-object p0
.end method

.method public getLatencyNanos()J
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 5
    .line 6
    sget-object v2, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->NOT_ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 11
    .line 12
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/AnchoredClock;->now()J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    iget-wide v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->endEpochNanos:J

    .line 20
    .line 21
    :goto_0
    iget-wide v3, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->startEpochNanos:J

    .line 22
    .line 23
    sub-long/2addr v1, v3

    .line 24
    monitor-exit v0

    .line 25
    return-wide v1

    .line 26
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method

.method public getName()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->name:Ljava/lang/String;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-object p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->parentSpanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->context:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStartEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->startEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hasEnded()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 5
    .line 6
    sget-object v1, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 7
    .line 8
    if-ne p0, v1, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    monitor-exit v0

    .line 14
    return p0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0
.end method

.method public isRecording()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 5
    .line 6
    sget-object v1, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 7
    .line 8
    if-eq p0, v1, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    monitor-exit v0

    .line 14
    return p0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0
.end method

.method public bridge synthetic recordException(Ljava/lang/Throwable;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->recordException(Ljava/lang/Throwable;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic recordException(Ljava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 2
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpan;->recordException(Ljava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public recordException(Ljava/lang/Throwable;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 1

    .line 3
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-virtual {p0, p1, v0}, Lio/opentelemetry/sdk/trace/SdkSpan;->recordException(Ljava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    return-object p0
.end method

.method public recordException(Ljava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 4

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    if-nez p2, :cond_1

    .line 4
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    .line 5
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    move-result v0

    .line 6
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 7
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributes()I

    move-result v1

    int-to-long v1, v1

    iget-object v3, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    invoke-virtual {v3}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    move-result v3

    .line 8
    invoke-static {v1, v2, v3}, Lio/opentelemetry/sdk/internal/AttributesMap;->create(JI)Lio/opentelemetry/sdk/internal/AttributesMap;

    move-result-object v1

    .line 9
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 10
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v3, Lio/opentelemetry/sdk/trace/b;

    invoke-direct {v3, v1}, Lio/opentelemetry/sdk/trace/b;-><init>(Ljava/lang/Object;)V

    .line 11
    invoke-interface {v2, v3, p1, v0}, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->setExceptionAttributes(Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;Ljava/lang/Throwable;I)V

    .line 12
    new-instance v0, Lio/opentelemetry/sdk/trace/c;

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Lio/opentelemetry/sdk/trace/c;-><init>(Ljava/lang/Object;I)V

    invoke-interface {p2, v0}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 13
    iget-object p2, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->clock:Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 14
    invoke-virtual {p2}, Lio/opentelemetry/sdk/trace/AnchoredClock;->now()J

    move-result-wide v2

    invoke-virtual {v1}, Lio/opentelemetry/sdk/internal/AttributesMap;->getTotalAddedValues()I

    move-result p2

    .line 15
    invoke-static {v2, v3, p1, v1, p2}, Lio/opentelemetry/sdk/trace/data/ExceptionEventData;->create(JLjava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/ExceptionEventData;

    move-result-object p1

    .line 16
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->addTimedEvent(Lio/opentelemetry/sdk/trace/data/EventData;)V

    return-object p0
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpan;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 4
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/sdk/trace/ReadWriteSpan;"
        }
    .end annotation

    if-eqz p1, :cond_3

    .line 2
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    if-nez p2, :cond_0

    goto :goto_1

    .line 3
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->isModifiableByCurrentThread()Z

    move-result v1

    if-nez v1, :cond_1

    .line 5
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    const-string v1, "Calling setAttribute() on an ended Span."

    invoke-virtual {p1, p2, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 6
    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_0

    .line 7
    :cond_1
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    if-nez v1, :cond_2

    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 9
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributes()I

    move-result v1

    int-to-long v1, v1

    iget-object v3, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    invoke-virtual {v3}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    move-result v3

    .line 10
    invoke-static {v1, v2, v3}, Lio/opentelemetry/sdk/internal/AttributesMap;->create(JI)Lio/opentelemetry/sdk/internal/AttributesMap;

    move-result-object v1

    iput-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 11
    :cond_2
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    invoke-virtual {v1, p1, p2}, Lio/opentelemetry/sdk/internal/AttributesMap;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    monitor-exit v0

    return-object p0

    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    :cond_3
    :goto_1
    return-object p0
.end method

.method public bridge synthetic setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpan;->setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 3
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    if-nez p1, :cond_0

    return-object p0

    .line 2
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    monitor-enter v0

    .line 3
    :try_start_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->isModifiableByCurrentThread()Z

    move-result v1

    if-nez v1, :cond_1

    .line 4
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    const-string v1, "Calling setStatus() on an ended Span."

    invoke-virtual {p1, p2, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 5
    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_0

    .line 6
    :cond_1
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    invoke-interface {v1}, Lio/opentelemetry/sdk/trace/data/StatusData;->getStatusCode()Lio/opentelemetry/api/trace/StatusCode;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/api/trace/StatusCode;->OK:Lio/opentelemetry/api/trace/StatusCode;

    if-ne v1, v2, :cond_2

    .line 7
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    const-string v1, "Calling setStatus() on a Span that is already set to OK."

    invoke-virtual {p1, p2, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 8
    monitor-exit v0

    return-object p0

    .line 9
    :cond_2
    sget-object v1, Lio/opentelemetry/api/trace/StatusCode;->UNSET:Lio/opentelemetry/api/trace/StatusCode;

    if-ne p1, v1, :cond_3

    .line 10
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    const-string v1, "Ignoring call to setStatus() with status UNSET."

    invoke-virtual {p1, p2, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 11
    monitor-exit v0

    return-object p0

    :cond_3
    if-eqz p2, :cond_4

    .line 12
    sget-object v1, Lio/opentelemetry/api/trace/StatusCode;->ERROR:Lio/opentelemetry/api/trace/StatusCode;

    if-eq p1, v1, :cond_4

    .line 13
    sget-object p2, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    sget-object v1, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    const-string v2, "Ignoring setStatus() description since status is not ERROR."

    invoke-virtual {p2, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    const/4 p2, 0x0

    .line 14
    :cond_4
    invoke-static {p1, p2}, Lio/opentelemetry/sdk/trace/data/StatusData;->create(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/sdk/trace/data/StatusData;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 15
    monitor-exit v0

    return-object p0

    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public toSpanData()Lio/opentelemetry/sdk/trace/data/SpanData;
    .locals 14

    .line 1
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v1

    .line 4
    :try_start_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->getImmutableLinks()Ljava/util/List;

    .line 5
    .line 6
    .line 7
    move-result-object v3

    .line 8
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->getImmutableTimedEvents()Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object v4

    .line 12
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->getImmutableAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 13
    .line 14
    .line 15
    move-result-object v5

    .line 16
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    move v6, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/AttributesMap;->getTotalAddedValues()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    move v6, v0

    .line 28
    :goto_0
    iget v7, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedEvents:I

    .line 29
    .line 30
    iget v8, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedLinks:I

    .line 31
    .line 32
    iget-object v9, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 33
    .line 34
    iget-object v10, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->name:Ljava/lang/String;

    .line 35
    .line 36
    iget-wide v11, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->endEpochNanos:J

    .line 37
    .line 38
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->hasEnded:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 39
    .line 40
    sget-object v13, Lio/opentelemetry/sdk/trace/SdkSpan$EndState;->ENDED:Lio/opentelemetry/sdk/trace/SdkSpan$EndState;

    .line 41
    .line 42
    if-ne v0, v13, :cond_1

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    :cond_1
    move v13, v2

    .line 46
    move-object v2, p0

    .line 47
    invoke-static/range {v2 .. v13}, Lio/opentelemetry/sdk/trace/SpanWrapper;->create(Lio/opentelemetry/sdk/trace/SdkSpan;Ljava/util/List;Ljava/util/List;Lio/opentelemetry/api/common/Attributes;IIILio/opentelemetry/sdk/trace/data/StatusData;Ljava/lang/String;JZ)Lio/opentelemetry/sdk/trace/SpanWrapper;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    monitor-exit v1

    .line 52
    return-object p0

    .line 53
    :catchall_0
    move-exception v0

    .line 54
    move-object p0, v0

    .line 55
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 56
    throw p0
.end method

.method public toString()Ljava/lang/String;
    .locals 11

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->name:Ljava/lang/String;

    .line 5
    .line 6
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 7
    .line 8
    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    iget-object v3, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 13
    .line 14
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    iget v4, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedEvents:I

    .line 19
    .line 20
    int-to-long v4, v4

    .line 21
    iget-wide v6, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->endEpochNanos:J

    .line 22
    .line 23
    iget v8, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->totalRecordedLinks:I

    .line 24
    .line 25
    int-to-long v8, v8

    .line 26
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    new-instance v0, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v10, "SdkSpan{traceId="

    .line 30
    .line 31
    invoke-direct {v0, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object v10, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->context:Lio/opentelemetry/api/trace/SpanContext;

    .line 35
    .line 36
    invoke-interface {v10}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v10

    .line 40
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v10, ", spanId="

    .line 44
    .line 45
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v10, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->context:Lio/opentelemetry/api/trace/SpanContext;

    .line 49
    .line 50
    invoke-interface {v10}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v10

    .line 54
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v10, ", parentSpanContext="

    .line 58
    .line 59
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    iget-object v10, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->parentSpanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 63
    .line 64
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string v10, ", name="

    .line 68
    .line 69
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", kind="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->kind:Lio/opentelemetry/api/trace/SpanKind;

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, ", attributes="

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", status="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v1, ", totalRecordedEvents="

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v1, ", totalRecordedLinks="

    .line 110
    .line 111
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, v8, v9}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v1, ", startEpochNanos="

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    iget-wide v1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->startEpochNanos:J

    .line 123
    .line 124
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string p0, ", endEpochNanos="

    .line 128
    .line 129
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const-string p0, "}"

    .line 136
    .line 137
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    return-object p0

    .line 145
    :catchall_0
    move-exception p0

    .line 146
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 147
    throw p0
.end method

.method public bridge synthetic updateName(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpan;->updateName(Ljava/lang/String;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;

    move-result-object p0

    return-object p0
.end method

.method public updateName(Ljava/lang/String;)Lio/opentelemetry/sdk/trace/ReadWriteSpan;
    .locals 3

    if-nez p1, :cond_0

    return-object p0

    .line 2
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->lock:Ljava/lang/Object;

    monitor-enter v0

    .line 3
    :try_start_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpan;->isModifiableByCurrentThread()Z

    move-result v1

    if-nez v1, :cond_1

    .line 4
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkSpan;->logger:Ljava/util/logging/Logger;

    sget-object v1, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    const-string v2, "Calling updateName() on an ended Span."

    invoke-virtual {p1, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 5
    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_0

    .line 6
    :cond_1
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpan;->name:Ljava/lang/String;

    .line 7
    monitor-exit v0

    return-object p0

    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method
