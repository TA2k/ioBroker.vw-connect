.class public abstract Lio/opentelemetry/api/internal/ImmutableSpanContext;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/SpanContext;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field public static final INVALID:Lio/opentelemetry/api/trace/SpanContext;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getInvalid()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getInvalid()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {}, Lio/opentelemetry/api/trace/TraceFlags;->getDefault()Lio/opentelemetry/api/trace/TraceFlags;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-static {}, Lio/opentelemetry/api/trace/TraceState;->getDefault()Lio/opentelemetry/api/trace/TraceState;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    const/4 v4, 0x0

    .line 18
    const/4 v5, 0x0

    .line 19
    invoke-static/range {v0 .. v5}, Lio/opentelemetry/api/internal/ImmutableSpanContext;->createInternal(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/api/internal/ImmutableSpanContext;->INVALID:Lio/opentelemetry/api/trace/SpanContext;

    .line 24
    .line 25
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)Lio/opentelemetry/api/trace/SpanContext;
    .locals 6

    .line 1
    if-nez p5, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Lio/opentelemetry/api/trace/SpanId;->isValid(Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result p5

    .line 7
    if-eqz p5, :cond_1

    .line 8
    .line 9
    invoke-static {p0}, Lio/opentelemetry/api/trace/TraceId;->isValid(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result p5

    .line 13
    if-eqz p5, :cond_1

    .line 14
    .line 15
    :cond_0
    move-object v2, p2

    .line 16
    move-object v3, p3

    .line 17
    move v4, p4

    .line 18
    goto :goto_0

    .line 19
    :cond_1
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getInvalid()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getInvalid()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const/4 v5, 0x0

    .line 28
    move-object v2, p2

    .line 29
    move-object v3, p3

    .line 30
    move v4, p4

    .line 31
    invoke-static/range {v0 .. v5}, Lio/opentelemetry/api/internal/ImmutableSpanContext;->createInternal(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :goto_0
    const/4 v5, 0x1

    .line 37
    move-object v0, p0

    .line 38
    move-object v1, p1

    .line 39
    invoke-static/range {v0 .. v5}, Lio/opentelemetry/api/internal/ImmutableSpanContext;->createInternal(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method private static createInternal(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;
    .locals 7

    .line 1
    new-instance v0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-object v2, p1

    .line 5
    move-object v3, p2

    .line 6
    move-object v4, p3

    .line 7
    move v5, p4

    .line 8
    move v6, p5

    .line 9
    invoke-direct/range {v0 .. v6}, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;-><init>(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public abstract isValid()Z
.end method
