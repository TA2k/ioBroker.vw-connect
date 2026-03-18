.class public final Lwr0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lur0/b;

.field public final b:Lwr0/g;


# direct methods
.method public constructor <init>(Lur0/b;Lwr0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwr0/c;->a:Lur0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lwr0/c;->b:Lwr0/g;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lwr0/c;->a:Lur0/b;

    .line 2
    .line 3
    iget-object v1, v0, Lur0/b;->a:Lxl0/f;

    .line 4
    .line 5
    new-instance v2, La90/s;

    .line 6
    .line 7
    const/16 v3, 0x1d

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v2, v0, v4, v3}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lu2/d;

    .line 14
    .line 15
    const/16 v3, 0x13

    .line 16
    .line 17
    invoke-direct {v0, v3}, Lu2/d;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v2, v0, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v1, Llb0/y;

    .line 25
    .line 26
    const/16 v2, 0x12

    .line 27
    .line 28
    invoke-direct {v1, v2, v0, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-object v1
.end method
