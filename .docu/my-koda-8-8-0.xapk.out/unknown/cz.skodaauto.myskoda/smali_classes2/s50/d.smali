.class public final Ls50/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ls50/k;

.field public final b:Ls50/f;


# direct methods
.method public constructor <init>(Ls50/k;Ls50/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls50/d;->a:Ls50/k;

    .line 5
    .line 6
    iput-object p2, p0, Ls50/d;->b:Ls50/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Ls50/d;->b:Ls50/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ls50/f;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Ls10/a0;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x1

    .line 13
    invoke-direct {v1, p0, v2, v3}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lne0/n;

    .line 17
    .line 18
    const/4 v2, 0x5

    .line 19
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method
