.class public final Ls30/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu30/k;


# instance fields
.field public final a:Lx30/a;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/l1;


# direct methods
.method public constructor <init>(Lx30/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls30/a;->a:Lx30/a;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iput-object p1, p0, Ls30/a;->b:Lyy0/c2;

    .line 12
    .line 13
    new-instance v0, Lyy0/l1;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ls30/a;->c:Lyy0/l1;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/ArrayList;
    .locals 12

    .line 1
    iget-object p0, p0, Ls30/a;->a:Lx30/a;

    .line 2
    .line 3
    iget-object p0, p0, Lx30/a;->b:Llx0/q;

    .line 4
    .line 5
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljava/util/List;

    .line 10
    .line 11
    check-cast p0, Ljava/lang/Iterable;

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    const/16 v1, 0xa

    .line 16
    .line 17
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Lcw/i;

    .line 39
    .line 40
    iget-object v3, v2, Lcw/i;->a:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v4, v2, Lcw/i;->c:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v5, v2, Lcw/i;->i:Lqy0/c;

    .line 45
    .line 46
    new-instance v9, Lr40/e;

    .line 47
    .line 48
    const/16 v6, 0xe

    .line 49
    .line 50
    invoke-direct {v9, v6}, Lr40/e;-><init>(I)V

    .line 51
    .line 52
    .line 53
    const/16 v10, 0x1f

    .line 54
    .line 55
    const/4 v6, 0x0

    .line 56
    const/4 v7, 0x0

    .line 57
    const/4 v8, 0x0

    .line 58
    invoke-static/range {v5 .. v10}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    iget-object v2, v2, Lcw/i;->i:Lqy0/c;

    .line 63
    .line 64
    new-instance v6, Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-static {v2, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 71
    .line 72
    .line 73
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 78
    .line 79
    .line 80
    move-result v7

    .line 81
    if-eqz v7, :cond_0

    .line 82
    .line 83
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v7

    .line 87
    check-cast v7, Lcw/l;

    .line 88
    .line 89
    iget-object v7, v7, Lcw/l;->e:Ljava/lang/String;

    .line 90
    .line 91
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_0
    const/4 v10, 0x0

    .line 96
    const/16 v11, 0x3f

    .line 97
    .line 98
    const/4 v7, 0x0

    .line 99
    const/4 v8, 0x0

    .line 100
    const/4 v9, 0x0

    .line 101
    invoke-static/range {v6 .. v11}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    new-instance v6, Lv30/f;

    .line 106
    .line 107
    invoke-direct {v6, v3, v4, v5, v2}, Lv30/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_1
    return-object v0
.end method
