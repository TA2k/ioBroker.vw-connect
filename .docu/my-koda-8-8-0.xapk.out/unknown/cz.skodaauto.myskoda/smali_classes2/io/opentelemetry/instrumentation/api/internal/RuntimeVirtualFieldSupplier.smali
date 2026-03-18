.class public final Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;,
        Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;,
        Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;
    }
.end annotation


# static fields
.field private static final DEFAULT:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

.field private static volatile instance:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

.field private static final logger:Ljava/util/logging/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;

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
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;-><init>(Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$1;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->DEFAULT:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

    .line 20
    .line 21
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->instance:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

    .line 22
    .line 23
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

.method public static get()Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->instance:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

    .line 2
    .line 3
    return-object v0
.end method

.method public static set(Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->instance:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->DEFAULT:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

    .line 4
    .line 5
    if-eq v0, v1, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->logger:Ljava/util/logging/Logger;

    .line 8
    .line 9
    const-string v0, "Runtime VirtualField supplier has already been set up, further set() calls are ignored"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/util/logging/Logger;->warning(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->instance:Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

    .line 16
    .line 17
    return-void
.end method
