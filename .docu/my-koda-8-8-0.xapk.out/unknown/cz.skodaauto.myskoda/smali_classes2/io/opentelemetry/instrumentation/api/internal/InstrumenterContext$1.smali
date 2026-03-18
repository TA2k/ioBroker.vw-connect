.class Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext$1;
.super Ljava/lang/ThreadLocal;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/ThreadLocal<",
        "Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public initialValue()Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;
    .locals 1

    .line 2
    new-instance p0, Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;

    const/4 v0, 0x0

    invoke-direct {p0, v0}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;-><init>(Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext$1;)V

    return-object p0
.end method

.method public bridge synthetic initialValue()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext$1;->initialValue()Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;

    move-result-object p0

    return-object p0
.end method
