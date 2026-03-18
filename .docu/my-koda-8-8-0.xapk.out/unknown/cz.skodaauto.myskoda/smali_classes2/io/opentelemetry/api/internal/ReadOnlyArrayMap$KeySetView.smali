.class final Lio/opentelemetry/api/internal/ReadOnlyArrayMap$KeySetView;
.super Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/internal/ReadOnlyArrayMap;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "KeySetView"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/api/internal/ReadOnlyArrayMap<",
        "TK;TV;>.SetView<TK;>;"
    }
.end annotation


# instance fields
.field final synthetic this$0:Lio/opentelemetry/api/internal/ReadOnlyArrayMap;


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/internal/ReadOnlyArrayMap;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$KeySetView;->this$0:Lio/opentelemetry/api/internal/ReadOnlyArrayMap;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;-><init>(Lio/opentelemetry/api/internal/ReadOnlyArrayMap;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$KeySetView;->this$0:Lio/opentelemetry/api/internal/ReadOnlyArrayMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/internal/ReadOnlyArrayMap;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public elementAtArrayIndex(I)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)TK;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$KeySetView;->this$0:Lio/opentelemetry/api/internal/ReadOnlyArrayMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/internal/ReadOnlyArrayMap;->key(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
