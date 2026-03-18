.class final Lio/opentelemetry/context/propagation/DefaultContextPropagators;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/propagation/ContextPropagators;


# static fields
.field private static final NOOP:Lio/opentelemetry/context/propagation/ContextPropagators;


# instance fields
.field private final textMapPropagator:Lio/opentelemetry/context/propagation/TextMapPropagator;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/context/propagation/DefaultContextPropagators;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/context/propagation/NoopTextMapPropagator;->getInstance()Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Lio/opentelemetry/context/propagation/DefaultContextPropagators;-><init>(Lio/opentelemetry/context/propagation/TextMapPropagator;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lio/opentelemetry/context/propagation/DefaultContextPropagators;->NOOP:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/context/propagation/TextMapPropagator;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/context/propagation/DefaultContextPropagators;->textMapPropagator:Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 5
    .line 6
    return-void
.end method

.method public static noop()Lio/opentelemetry/context/propagation/ContextPropagators;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/propagation/DefaultContextPropagators;->NOOP:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public getTextMapPropagator()Lio/opentelemetry/context/propagation/TextMapPropagator;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/context/propagation/DefaultContextPropagators;->textMapPropagator:Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "DefaultContextPropagators{textMapPropagator="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/context/propagation/DefaultContextPropagators;->textMapPropagator:Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, "}"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
