.class public final Lnn0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lnn0/r;

.field public final b:Lnn0/f;


# direct methods
.method public constructor <init>(Lnn0/r;Lnn0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnn0/t;->a:Lnn0/r;

    .line 5
    .line 6
    iput-object p2, p0, Lnn0/t;->b:Lnn0/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lnn0/t;->a:Lnn0/r;

    .line 2
    .line 3
    check-cast v0, Lln0/f;

    .line 4
    .line 5
    iget-object v1, v0, Lln0/f;->d:Lyy0/c2;

    .line 6
    .line 7
    iget-object v0, v0, Lln0/f;->b:Lez0/c;

    .line 8
    .line 9
    new-instance v2, Lmc/e;

    .line 10
    .line 11
    const/16 v3, 0xe

    .line 12
    .line 13
    invoke-direct {v2, p0, v3}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    new-instance v3, Lbq0/i;

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    const/16 v5, 0x1c

    .line 20
    .line 21
    invoke-direct {v3, p0, v4, v5}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {v1, v0, v2, v3}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method
