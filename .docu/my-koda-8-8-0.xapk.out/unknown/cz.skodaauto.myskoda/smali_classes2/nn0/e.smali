.class public final Lnn0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lln0/l;


# direct methods
.method public constructor <init>(Lln0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnn0/e;->a:Lln0/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object p0, p0, Lnn0/e;->a:Lln0/l;

    .line 2
    .line 3
    iget-object v0, p0, Lln0/l;->a:Lxl0/f;

    .line 4
    .line 5
    new-instance v1, Lln0/j;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v1, p0, v3, v2}, Lln0/j;-><init>(Lln0/l;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    new-instance p0, Lkq0/a;

    .line 13
    .line 14
    const/16 v2, 0x13

    .line 15
    .line 16
    invoke-direct {p0, v2}, Lkq0/a;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v1, p0, v3}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
