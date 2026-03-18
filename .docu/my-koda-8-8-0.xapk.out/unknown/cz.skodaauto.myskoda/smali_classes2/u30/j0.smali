.class public final Lu30/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lu30/m;


# direct methods
.method public constructor <init>(Lu30/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu30/j0;->a:Lu30/m;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lv30/b;)Lyy0/m1;
    .locals 4

    .line 1
    iget-object p0, p0, Lu30/j0;->a:Lu30/m;

    .line 2
    .line 3
    check-cast p0, Ls30/g;

    .line 4
    .line 5
    iget-object v0, p0, Ls30/g;->a:Lxl0/f;

    .line 6
    .line 7
    new-instance v1, Llo0/b;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/16 v3, 0x15

    .line 11
    .line 12
    invoke-direct {v1, v3, p0, p1, v2}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lv30/b;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lu30/j0;->a(Lv30/b;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
