.class public final Lpp0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpp0/c0;

.field public final b:Lnp0/c;


# direct methods
.method public constructor <init>(Lpp0/c0;Lnp0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/h;->a:Lpp0/c0;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/h;->b:Lnp0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lpp0/h;->b:Lnp0/c;

    .line 2
    .line 3
    iget-object v1, v0, Lnp0/c;->a:Lxl0/f;

    .line 4
    .line 5
    new-instance v2, La90/s;

    .line 6
    .line 7
    const/16 v3, 0x14

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v2, v0, v4, v3}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lnh/i;

    .line 14
    .line 15
    const/4 v3, 0x5

    .line 16
    invoke-direct {v0, v3}, Lnh/i;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, v2, v0, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    new-instance v1, Lnz/g;

    .line 24
    .line 25
    const/4 v2, 0x7

    .line 26
    invoke-direct {v1, p0, v4, v2}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    new-instance p0, Lne0/n;

    .line 30
    .line 31
    const/4 v2, 0x5

    .line 32
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 33
    .line 34
    .line 35
    return-object p0
.end method
