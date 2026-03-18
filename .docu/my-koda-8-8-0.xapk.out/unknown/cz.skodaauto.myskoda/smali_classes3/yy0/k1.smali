.class public final Lyy0/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/n1;
.implements Lyy0/i;
.implements Lzy0/o;


# instance fields
.field public final synthetic d:Lyy0/n1;


# direct methods
.method public constructor <init>(Lyy0/n1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyy0/k1;->d:Lyy0/n1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Lpx0/g;ILxy0/a;)Lyy0/i;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lyy0/u;->y(Lyy0/n1;Lpx0/g;ILxy0/a;)Lyy0/i;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final c()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lyy0/k1;->d:Lyy0/n1;

    .line 2
    .line 3
    invoke-interface {p0}, Lyy0/n1;->c()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lyy0/k1;->d:Lyy0/n1;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
