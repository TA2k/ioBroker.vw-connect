.class public final Lu40/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ls40/d;


# direct methods
.method public constructor <init>(Ls40/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu40/c;->a:Ls40/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 4

    .line 1
    iget-object p0, p0, Lu40/c;->a:Ls40/d;

    .line 2
    .line 3
    iget-object v0, p0, Ls40/d;->a:Lxl0/f;

    .line 4
    .line 5
    new-instance v1, Ls40/a;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v1, p0, p1, v3, v2}, Ls40/a;-><init>(Ls40/d;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    new-instance p0, Lr40/e;

    .line 13
    .line 14
    const/16 p1, 0x18

    .line 15
    .line 16
    invoke-direct {p0, p1}, Lr40/e;-><init>(I)V

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

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lu40/c;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
