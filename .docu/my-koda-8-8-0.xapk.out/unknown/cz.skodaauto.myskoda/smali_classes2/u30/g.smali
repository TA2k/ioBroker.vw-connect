.class public final Lu30/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lu30/l0;


# direct methods
.method public constructor <init>(Lu30/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu30/g;->a:Lu30/l0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object p0, p0, Lu30/g;->a:Lu30/l0;

    .line 2
    .line 3
    check-cast p0, Ls30/h;

    .line 4
    .line 5
    iget-object v0, p0, Ls30/h;->a:Lxl0/f;

    .line 6
    .line 7
    new-instance v1, La90/s;

    .line 8
    .line 9
    const/16 v2, 0x18

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v1, p0, v3, v2}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    new-instance p0, Lr40/e;

    .line 16
    .line 17
    const/16 v2, 0x14

    .line 18
    .line 19
    invoke-direct {p0, v2}, Lr40/e;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v1, p0, v3}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
