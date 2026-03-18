.class public final Lqa0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;

.field public final b:Lkf0/b;

.field public final c:Lkf0/b0;


# direct methods
.method public constructor <init>(Lbn0/g;Lkf0/b;Lkf0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqa0/d;->a:Lbn0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lqa0/d;->b:Lkf0/b;

    .line 7
    .line 8
    iput-object p3, p0, Lqa0/d;->c:Lkf0/b0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    new-instance v0, Lbn0/c;

    .line 2
    .line 3
    const-string v1, "predictive-wakeup"

    .line 4
    .line 5
    const-string v2, "activate-deactivate"

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lqa0/d;->a:Lbn0/g;

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Lq10/k;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    const/4 v3, 0x1

    .line 20
    invoke-direct {v1, p0, v2, v3}, Lq10/k;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Lac/l;

    .line 24
    .line 25
    invoke-direct {p0, v0, v1}, Lac/l;-><init>(Lzy0/j;Lay0/k;)V

    .line 26
    .line 27
    .line 28
    return-object p0
.end method
