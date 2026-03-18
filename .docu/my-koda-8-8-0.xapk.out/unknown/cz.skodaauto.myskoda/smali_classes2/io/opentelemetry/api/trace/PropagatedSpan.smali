.class final Lio/opentelemetry/api/trace/PropagatedSpan;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/Span;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field static final INVALID:Lio/opentelemetry/api/trace/PropagatedSpan;


# instance fields
.field private final spanContext:Lio/opentelemetry/api/trace/SpanContext;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/trace/PropagatedSpan;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Lio/opentelemetry/api/trace/PropagatedSpan;-><init>(Lio/opentelemetry/api/trace/SpanContext;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lio/opentelemetry/api/trace/PropagatedSpan;->INVALID:Lio/opentelemetry/api/trace/PropagatedSpan;

    .line 11
    .line 12
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/api/trace/SpanContext;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/api/trace/PropagatedSpan;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 5
    .line 6
    return-void
.end method

.method public static create(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/trace/PropagatedSpan;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/api/trace/PropagatedSpan;-><init>(Lio/opentelemetry/api/trace/SpanContext;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public addEvent(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    return-object p0
.end method

.method public addEvent(Ljava/lang/String;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 2
    return-object p0
.end method

.method public addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 3
    return-object p0
.end method

.method public addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 4
    return-object p0
.end method

.method public end()V
    .locals 0

    .line 1
    return-void
.end method

.method public end(JLjava/util/concurrent/TimeUnit;)V
    .locals 0

    .line 2
    return-void
.end method

.method public getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/trace/PropagatedSpan;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    return-object p0
.end method

.method public isRecording()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public recordException(Ljava/lang/Throwable;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    return-object p0
.end method

.method public recordException(Ljava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 2
    return-object p0
.end method

.method public setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;
    .locals 0
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
            "Lio/opentelemetry/api/trace/Span;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 2
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 3
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 4
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 5
    return-object p0
.end method

.method public setStatus(Lio/opentelemetry/api/trace/StatusCode;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 2
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "PropagatedSpan{"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/api/trace/PropagatedSpan;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x7d

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public updateName(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    return-object p0
.end method
