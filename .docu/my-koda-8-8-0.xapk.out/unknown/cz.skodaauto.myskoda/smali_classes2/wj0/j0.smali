.class public final Lwj0/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwj0/a;


# direct methods
.method public constructor <init>(Lwj0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwj0/j0;->a:Lwj0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/Collection;)V
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Llp/pe;->c(Ljava/util/Collection;)Lxj0/v;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxj0/x;

    .line 21
    .line 22
    check-cast p1, Ljava/lang/Iterable;

    .line 23
    .line 24
    invoke-static {p1}, Lmx0/q;->I(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Lxj0/f;

    .line 29
    .line 30
    const/high16 v1, 0x41900000    # 18.0f

    .line 31
    .line 32
    invoke-direct {v0, p1, v1}, Lxj0/x;-><init>(Lxj0/f;F)V

    .line 33
    .line 34
    .line 35
    move-object p1, v0

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    sget-object p1, Lxj0/w;->a:Lxj0/w;

    .line 38
    .line 39
    :goto_0
    iget-object p0, p0, Lwj0/j0;->a:Lwj0/a;

    .line 40
    .line 41
    check-cast p0, Luj0/c;

    .line 42
    .line 43
    iget-object p0, p0, Luj0/c;->a:Lyy0/c2;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
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
    check-cast v1, Ljava/util/Collection;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lwj0/j0;->a(Ljava/util/Collection;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
