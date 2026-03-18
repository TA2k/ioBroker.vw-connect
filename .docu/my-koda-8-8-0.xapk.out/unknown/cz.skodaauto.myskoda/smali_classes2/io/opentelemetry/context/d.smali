.class public final synthetic Lio/opentelemetry/context/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# instance fields
.field public final synthetic d:Lio/opentelemetry/context/Context;

.field public final synthetic e:Ljava/util/concurrent/Executor;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/context/Context;Ljava/util/concurrent/Executor;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/context/d;->d:Lio/opentelemetry/context/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/context/d;->e:Ljava/util/concurrent/Executor;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/context/d;->d:Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/context/d;->e:Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    invoke-static {v0, p0, p1}, Lio/opentelemetry/context/Context;->c(Lio/opentelemetry/context/Context;Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
