.class public final synthetic Landroidx/lifecycle/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/lifecycle/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/lifecycle/m;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 2

    .line 1
    iget p1, p0, Landroidx/lifecycle/m;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/lifecycle/m;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch p1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lxy0/x;

    .line 9
    .line 10
    invoke-virtual {p2}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p0, Lxy0/w;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_0
    check-cast p0, Lg11/c;

    .line 21
    .line 22
    sget-object p1, Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;

    .line 23
    .line 24
    if-ne p2, p1, :cond_0

    .line 25
    .line 26
    const/4 p1, 0x1

    .line 27
    iput-boolean p1, p0, Lg11/c;->c:Z

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    sget-object p1, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 31
    .line 32
    if-ne p2, p1, :cond_1

    .line 33
    .line 34
    const/4 p1, 0x0

    .line 35
    iput-boolean p1, p0, Lg11/c;->c:Z

    .line 36
    .line 37
    :cond_1
    :goto_0
    return-void

    .line 38
    :pswitch_1
    check-cast p0, Lay0/k;

    .line 39
    .line 40
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :pswitch_2
    check-cast p0, Lca/g;

    .line 45
    .line 46
    invoke-virtual {p2}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    iput-object p1, p0, Lca/g;->q:Landroidx/lifecycle/q;

    .line 51
    .line 52
    iget-object p1, p0, Lca/g;->c:Lz9/v;

    .line 53
    .line 54
    if-eqz p1, :cond_2

    .line 55
    .line 56
    iget-object p0, p0, Lca/g;->f:Lmx0/l;

    .line 57
    .line 58
    invoke-static {p0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-eqz p1, :cond_2

    .line 71
    .line 72
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    check-cast p1, Lz9/k;

    .line 77
    .line 78
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    iget-object p1, p1, Lz9/k;->k:Lca/c;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    iget-object v0, p1, Lca/c;->a:Lz9/k;

    .line 87
    .line 88
    invoke-virtual {p2}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    iput-object v1, v0, Lz9/k;->g:Landroidx/lifecycle/q;

    .line 93
    .line 94
    invoke-virtual {p2}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    iput-object v0, p1, Lca/c;->d:Landroidx/lifecycle/q;

    .line 99
    .line 100
    invoke-virtual {p1}, Lca/c;->b()V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_2
    return-void

    .line 105
    :pswitch_3
    check-cast p0, Lyy0/c2;

    .line 106
    .line 107
    invoke-virtual {p2}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    const/4 p2, 0x0

    .line 112
    invoke-virtual {p0, p2, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    return-void

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
