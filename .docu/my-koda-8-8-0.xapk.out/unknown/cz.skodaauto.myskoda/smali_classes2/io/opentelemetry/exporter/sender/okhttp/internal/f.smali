.class public final synthetic Lio/opentelemetry/exporter/sender/okhttp/internal/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;


# virtual methods
.method public final sleep(J)V
    .locals 0

    .line 1
    sget-object p0, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ljava/util/concurrent/TimeUnit;->sleep(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
