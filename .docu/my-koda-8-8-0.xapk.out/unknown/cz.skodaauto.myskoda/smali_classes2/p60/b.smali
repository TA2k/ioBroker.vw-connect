.class public final Lp60/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lln0/l;

.field public final b:Lnn0/x;

.field public final c:Lsf0/a;


# direct methods
.method public constructor <init>(Lln0/l;Lnn0/x;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp60/b;->a:Lln0/l;

    .line 5
    .line 6
    iput-object p2, p0, Lp60/b;->b:Lnn0/x;

    .line 7
    .line 8
    iput-object p3, p0, Lp60/b;->c:Lsf0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lp60/b;->a:Lln0/l;

    .line 4
    .line 5
    iget-object p2, p1, Lln0/l;->a:Lxl0/f;

    .line 6
    .line 7
    new-instance v0, Lln0/j;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v0, p1, v2, v1}, Lln0/j;-><init>(Lln0/l;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, v0}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    sget-object p2, Lon0/c;->d:Lon0/c;

    .line 19
    .line 20
    iget-object v0, p0, Lp60/b;->b:Lnn0/x;

    .line 21
    .line 22
    iget-object v0, v0, Lnn0/x;->a:Lnn0/c;

    .line 23
    .line 24
    check-cast v0, Lln0/c;

    .line 25
    .line 26
    iput-object p2, v0, Lln0/c;->a:Lon0/c;

    .line 27
    .line 28
    iget-object p0, p0, Lp60/b;->c:Lsf0/a;

    .line 29
    .line 30
    invoke-static {p1, p0, v2}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
