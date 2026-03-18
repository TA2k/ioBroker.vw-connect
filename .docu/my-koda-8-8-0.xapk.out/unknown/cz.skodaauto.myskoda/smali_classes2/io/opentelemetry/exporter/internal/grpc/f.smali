.class public final synthetic Lio/opentelemetry/exporter/internal/grpc/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:Lio/grpc/ManagedChannel;

.field public final synthetic e:Lio/opentelemetry/sdk/common/CompletableResultCode;


# direct methods
.method public synthetic constructor <init>(Lio/grpc/ManagedChannel;Lio/opentelemetry/sdk/common/CompletableResultCode;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/grpc/f;->d:Lio/grpc/ManagedChannel;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/f;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/f;->d:Lio/grpc/ManagedChannel;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/f;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 4
    .line 5
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/grpc/ManagedChannelUtil;->a(Lio/grpc/ManagedChannel;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
