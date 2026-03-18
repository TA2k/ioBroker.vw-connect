.class public final Lxh/f;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lay0/k;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>(Lzg/f1;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lxh/f;->d:Lay0/k;

    .line 10
    .line 11
    new-instance p2, Lxh/d;

    .line 12
    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    sget-object p1, Lvh/v;->e:Lzg/f1;

    .line 16
    .line 17
    :cond_0
    sget-object v0, Lzg/f1;->g:Lsx0/b;

    .line 18
    .line 19
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-direct {p2, p1, v0}, Lxh/d;-><init>(Lzg/f1;Ljava/util/List;)V

    .line 24
    .line 25
    .line 26
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lyy0/l1;

    .line 31
    .line 32
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 33
    .line 34
    .line 35
    iput-object p2, p0, Lxh/f;->e:Lyy0/l1;

    .line 36
    .line 37
    return-void
.end method
