.class public final Lz90/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lz90/p;

.field public final b:Lz90/y;


# direct methods
.method public constructor <init>(Lz90/p;Lz90/y;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz90/t;->a:Lz90/p;

    .line 5
    .line 6
    iput-object p2, p0, Lz90/t;->b:Lz90/y;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Laa0/e;)V
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lz90/t;->a:Lz90/p;

    .line 7
    .line 8
    check-cast v0, Lx90/a;

    .line 9
    .line 10
    iget-object v1, v0, Lx90/a;->c:Laa0/j;

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    iget-object v1, v1, Laa0/j;->e:Ljava/util/ArrayList;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 18
    .line 19
    :goto_0
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const/4 v2, 0x0

    .line 24
    if-eqz p1, :cond_4

    .line 25
    .line 26
    const/4 v3, 0x1

    .line 27
    if-ne p1, v3, :cond_3

    .line 28
    .line 29
    check-cast v1, Ljava/lang/Iterable;

    .line 30
    .line 31
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    move-object v3, v1

    .line 46
    check-cast v3, Laa0/d;

    .line 47
    .line 48
    instance-of v3, v3, Laa0/a;

    .line 49
    .line 50
    if-eqz v3, :cond_1

    .line 51
    .line 52
    move-object v2, v1

    .line 53
    :cond_2
    check-cast v2, Laa0/d;

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_3
    new-instance p0, La8/r0;

    .line 57
    .line 58
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_4
    check-cast v1, Ljava/lang/Iterable;

    .line 63
    .line 64
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    :cond_5
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-eqz v1, :cond_6

    .line 73
    .line 74
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    move-object v3, v1

    .line 79
    check-cast v3, Laa0/d;

    .line 80
    .line 81
    instance-of v3, v3, Laa0/g;

    .line 82
    .line 83
    if-eqz v3, :cond_5

    .line 84
    .line 85
    move-object v2, v1

    .line 86
    :cond_6
    check-cast v2, Laa0/d;

    .line 87
    .line 88
    :goto_1
    iput-object v2, v0, Lx90/a;->f:Laa0/d;

    .line 89
    .line 90
    iget-object p0, p0, Lz90/t;->b:Lz90/y;

    .line 91
    .line 92
    check-cast p0, Liy/b;

    .line 93
    .line 94
    sget-object p1, Lly/b;->F3:Lly/b;

    .line 95
    .line 96
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 97
    .line 98
    .line 99
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
    check-cast v1, Laa0/e;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lz90/t;->a(Laa0/e;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
