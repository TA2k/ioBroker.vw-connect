.class public final Lp60/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ln60/c;


# direct methods
.method public constructor <init>(Ln60/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp60/f;->a:Ln60/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lp60/f;->a:Ln60/c;

    .line 4
    .line 5
    iget-object p1, p0, Ln60/c;->a:Lxl0/f;

    .line 6
    .line 7
    new-instance p2, La90/s;

    .line 8
    .line 9
    const/16 v0, 0x12

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-direct {p2, p0, v1, v0}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    new-instance p0, Lmj/g;

    .line 16
    .line 17
    const/16 v0, 0x14

    .line 18
    .line 19
    invoke-direct {p0, v0}, Lmj/g;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, p2, p0, v1}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
