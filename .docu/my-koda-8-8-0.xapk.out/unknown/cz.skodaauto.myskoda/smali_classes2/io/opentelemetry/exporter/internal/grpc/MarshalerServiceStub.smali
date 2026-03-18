.class public abstract Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub;
.super Lio/grpc/stub/AbstractFutureStub;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
        "U:",
        "Ljava/lang/Object;",
        "S:",
        "Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub<",
        "TT;TU;TS;>;>",
        "Lio/grpc/stub/AbstractFutureStub<",
        "TS;>;"
    }
.end annotation


# direct methods
.method public constructor <init>(Lio/grpc/Channel;Lio/grpc/CallOptions;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/grpc/stub/AbstractFutureStub;-><init>(Lio/grpc/Channel;Lio/grpc/CallOptions;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract export(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)Lcom/google/common/util/concurrent/ListenableFuture;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)",
            "Lcom/google/common/util/concurrent/ListenableFuture;"
        }
    .end annotation
.end method
