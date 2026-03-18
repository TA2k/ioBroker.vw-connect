.class public final synthetic Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# virtual methods
.method public final run()V
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/AbstractWeakConcurrentMap;->runCleanup()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
