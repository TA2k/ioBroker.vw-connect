.class public interface abstract Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# direct methods
.method public static synthetic f(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;->lambda$noop$0(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$noop$0(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static noop()Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lf3/d;

    .line 2
    .line 3
    const/16 v1, 0x1c

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lf3/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method


# virtual methods
.method public extract(Ljava/lang/Object;)Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;

    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;-><init>()V

    .line 2
    invoke-interface {p0, v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;->extract(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V

    return-object v0
.end method

.method public abstract extract(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;",
            "TREQUEST;)V"
        }
    .end annotation
.end method
