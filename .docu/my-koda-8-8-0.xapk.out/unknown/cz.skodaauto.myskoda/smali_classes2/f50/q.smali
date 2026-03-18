.class public final Lf50/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwj0/j0;

.field public final b:Lwj0/d0;


# direct methods
.method public constructor <init>(Lwj0/j0;Lwj0/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf50/q;->a:Lwj0/j0;

    .line 5
    .line 6
    iput-object p2, p0, Lf50/q;->b:Lwj0/d0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lqp0/b0;)V
    .locals 2

    .line 1
    const/16 v0, 0x41

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/eg;->l(Lqp0/b0;C)Lxj0/r;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Lxj0/r;->c()Lxj0/f;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ljava/util/Collection;

    .line 18
    .line 19
    iget-object v1, p0, Lf50/q;->a:Lwj0/j0;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Lwj0/j0;->a(Ljava/util/Collection;)V

    .line 22
    .line 23
    .line 24
    new-instance v0, Lxj0/u;

    .line 25
    .line 26
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 31
    .line 32
    invoke-direct {v0, p1, v1}, Lxj0/u;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lf50/q;->b:Lwj0/d0;

    .line 36
    .line 37
    iget-object p0, p0, Lwj0/d0;->a:Lwj0/v;

    .line 38
    .line 39
    check-cast p0, Luj0/j;

    .line 40
    .line 41
    iget-object p0, p0, Luj0/j;->a:Lyy0/c2;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lqp0/b0;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lf50/q;->a(Lqp0/b0;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
