.class public final Lp60/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lln0/l;

.field public final b:Lsf0/a;


# direct methods
.method public constructor <init>(Lln0/l;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp60/h0;->a:Lln0/l;

    .line 5
    .line 6
    iput-object p2, p0, Lp60/h0;->b:Lsf0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lon0/b0;)Lam0/i;
    .locals 5

    .line 1
    iget-object v0, p0, Lp60/h0;->a:Lln0/l;

    .line 2
    .line 3
    iget-object v1, v0, Lln0/l;->a:Lxl0/f;

    .line 4
    .line 5
    new-instance v2, La2/c;

    .line 6
    .line 7
    const/16 v3, 0x1d

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v2, v3, v0, p1, v4}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1, v2}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iget-object p0, p0, Lp60/h0;->b:Lsf0/a;

    .line 18
    .line 19
    invoke-static {p1, p0, v4}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

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
    check-cast v0, Lon0/b0;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lp60/h0;->a(Lon0/b0;)Lam0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
