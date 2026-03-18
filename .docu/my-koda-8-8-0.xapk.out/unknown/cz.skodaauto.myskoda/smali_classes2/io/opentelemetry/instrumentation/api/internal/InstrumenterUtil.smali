.class public final Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static instrumenterAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;

.field private static instrumenterBuilderAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;


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

.method public static buildDownstreamInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapSetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->instrumenterBuilderAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;

    .line 2
    .line 3
    invoke-interface {v0, p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;->buildDownstreamInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapSetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static buildUpstreamInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapGetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->instrumenterBuilderAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;

    .line 2
    .line 3
    invoke-interface {v0, p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;->buildUpstreamInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapGetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static propagateOperationListenersToOnEnd(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->instrumenterBuilderAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;

    .line 2
    .line 3
    invoke-interface {v0, p0}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;->propagateOperationListenersToOnEnd(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public static setInstrumenterAccess(Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;)V
    .locals 0
    .annotation build Lio/opentelemetry/instrumentation/api/internal/Initializer;
    .end annotation

    .line 1
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->instrumenterAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;

    .line 2
    .line 3
    return-void
.end method

.method public static setInstrumenterBuilderAccess(Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;)V
    .locals 0
    .annotation build Lio/opentelemetry/instrumentation/api/internal/Initializer;
    .end annotation

    .line 1
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->instrumenterBuilderAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;

    .line 2
    .line 3
    return-void
.end method

.method public static startAndEnd(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;Ljava/time/Instant;)Lio/opentelemetry/context/Context;
    .locals 8
    .param p3    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            "Ljava/time/Instant;",
            "Ljava/time/Instant;",
            ")",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->instrumenterAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;

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
    move-object v5, p4

    .line 8
    move-object v6, p5

    .line 9
    move-object v7, p6

    .line 10
    invoke-interface/range {v0 .. v7}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;->startAndEnd(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;Ljava/time/Instant;)Lio/opentelemetry/context/Context;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static suppressSpan(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->instrumenterAccess:Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;

    .line 2
    .line 3
    invoke-interface {v0, p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;->suppressSpan(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
