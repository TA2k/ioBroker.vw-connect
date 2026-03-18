.class public final Lvn0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lrn0/i;

.field public b:Lvy0/x1;

.field public c:Ljava/lang/ref/WeakReference;

.field public d:Le/c;

.field public final e:Llx0/q;


# direct methods
.method public constructor <init>(Lrn0/i;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvn0/a;->a:Lrn0/i;

    .line 5
    .line 6
    new-instance p1, Lu2/a;

    .line 7
    .line 8
    const/16 v0, 0xc

    .line 9
    .line 10
    invoke-direct {p1, p0, v0}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lvn0/a;->e:Llx0/q;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Lun0/a;Z)V
    .locals 5

    .line 1
    new-instance v0, Lun0/b;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Lun0/b;-><init>(Lun0/a;Z)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvn0/a;->a:Lrn0/i;

    .line 7
    .line 8
    iget-object p1, p0, Lrn0/i;->c:Lyy0/q1;

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lrn0/i;->d:Lyy0/c2;

    .line 14
    .line 15
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    move-object p2, p1

    .line 20
    check-cast p2, Ljava/util/List;

    .line 21
    .line 22
    invoke-interface {p2, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    check-cast p2, Ljava/lang/Iterable;

    .line 30
    .line 31
    new-instance v1, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 34
    .line 35
    .line 36
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    :cond_2
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_3

    .line 45
    .line 46
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    move-object v3, v2

    .line 51
    check-cast v3, Lun0/b;

    .line 52
    .line 53
    iget-object v3, v3, Lun0/b;->a:Lun0/a;

    .line 54
    .line 55
    iget-object v4, v0, Lun0/b;->a:Lun0/a;

    .line 56
    .line 57
    if-eq v3, v4, :cond_2

    .line 58
    .line 59
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    invoke-static {v1, v0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    :goto_1
    invoke-virtual {p0, p1, p2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eqz p1, :cond_0

    .line 72
    .line 73
    return-void
.end method
