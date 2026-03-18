.class public final Lk70/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Li70/v;

.field public final c:Lk70/y;


# direct methods
.method public constructor <init>(Lkf0/o;Li70/v;Lk70/y;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/m;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/m;->b:Li70/v;

    .line 7
    .line 8
    iput-object p3, p0, Lk70/m;->c:Lk70/y;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lk70/l;)Lzy0/j;
    .locals 4

    .line 1
    iget-boolean v0, p1, Lk70/l;->c:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lk70/m;->c:Lk70/y;

    .line 6
    .line 7
    check-cast v0, Li70/n;

    .line 8
    .line 9
    invoke-virtual {v0}, Li70/n;->b()V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lk70/m;->a:Lkf0/o;

    .line 13
    .line 14
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lac/k;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    const/16 v3, 0x11

    .line 22
    .line 23
    invoke-direct {v1, v3, p0, p1, v2}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lk70/l;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lk70/m;->a(Lk70/l;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
