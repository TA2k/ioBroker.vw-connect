.class public final Lci/e;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lzg/h;

.field public final e:La90/c;

.field public final f:Lci/a;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>(Ly1/i;Lzg/h;La90/c;Lci/a;)V
    .locals 9

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lci/e;->d:Lzg/h;

    .line 5
    .line 6
    iput-object p3, p0, Lci/e;->e:La90/c;

    .line 7
    .line 8
    iput-object p4, p0, Lci/e;->f:Lci/a;

    .line 9
    .line 10
    new-instance v0, Lci/d;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    iget-object p1, p2, Lzg/h;->t:Lzg/q1;

    .line 15
    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    iget-object p1, p1, Lzg/q1;->e:Ljava/lang/Integer;

    .line 19
    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p1, 0x0

    .line 28
    :goto_0
    invoke-static {p1}, Lci/e;->a(I)I

    .line 29
    .line 30
    .line 31
    move-result v7

    .line 32
    sget-object v2, Lci/c;->d:Lci/c;

    .line 33
    .line 34
    const/4 v6, 0x1

    .line 35
    sget-object v8, Lci/d;->i:Ljava/util/List;

    .line 36
    .line 37
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    move-object v1, p2

    .line 41
    invoke-direct/range {v0 .. v8}, Lci/d;-><init>(Lzg/h;Lci/c;ZZZZILjava/util/List;)V

    .line 42
    .line 43
    .line 44
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iput-object p1, p0, Lci/e;->g:Lyy0/c2;

    .line 49
    .line 50
    iput-object p1, p0, Lci/e;->h:Lyy0/c2;

    .line 51
    .line 52
    if-eqz v1, :cond_1

    .line 53
    .line 54
    iget-object p1, v1, Lzg/h;->i:Ljava/lang/String;

    .line 55
    .line 56
    if-eqz p1, :cond_1

    .line 57
    .line 58
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    new-instance p3, Lc80/l;

    .line 63
    .line 64
    const/16 p4, 0x8

    .line 65
    .line 66
    const/4 v0, 0x0

    .line 67
    invoke-direct {p3, p4, p0, p1, v0}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 68
    .line 69
    .line 70
    const/4 p0, 0x3

    .line 71
    invoke-static {p2, v0, v0, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 72
    .line 73
    .line 74
    :cond_1
    return-void
.end method

.method public static a(I)I
    .locals 5

    .line 1
    sget-object v0, Lci/d;->i:Ljava/util/List;

    .line 2
    .line 3
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    check-cast v0, Ljava/lang/Iterable;

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Ljava/lang/Number;

    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    sub-int v3, v2, p0

    .line 36
    .line 37
    invoke-static {v3}, Ljava/lang/Math;->abs(I)I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    sub-int v4, v1, p0

    .line 42
    .line 43
    invoke-static {v4}, Ljava/lang/Math;->abs(I)I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-ge v3, v4, :cond_0

    .line 48
    .line 49
    move v1, v2

    .line 50
    goto :goto_0

    .line 51
    :cond_1
    return v1
.end method
