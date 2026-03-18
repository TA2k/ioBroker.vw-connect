.class public final synthetic Lsu/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqp/e;
.implements Lqp/c;
.implements Lqp/d;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lsu/i;


# direct methods
.method public synthetic constructor <init>(Lsu/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lsu/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsu/b;->e:Lsu/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Lsp/k;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lsu/b;->e:Lsu/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public b(Lsp/k;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lsu/b;->e:Lsu/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public f(Lsp/k;)Z
    .locals 2

    .line 1
    iget v0, p0, Lsu/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lsu/b;->e:Lsu/i;

    .line 7
    .line 8
    iget-object v0, p0, Lsu/i;->p:Lnd0/c;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object p0, p0, Lsu/i;->m:Lb81/c;

    .line 13
    .line 14
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lqu/a;

    .line 23
    .line 24
    iget-object p1, v0, Lnd0/c;->e:Lay0/k;

    .line 25
    .line 26
    invoke-interface {p0}, Lqu/a;->b()Ljava/util/Collection;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const-string v0, "getItems(...)"

    .line 31
    .line 32
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    check-cast p0, Ljava/lang/Iterable;

    .line 36
    .line 37
    new-instance v0, Ljava/util/ArrayList;

    .line 38
    .line 39
    const/16 v1, 0xa

    .line 40
    .line 41
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 46
    .line 47
    .line 48
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_0

    .line 57
    .line 58
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Lzj0/c;

    .line 63
    .line 64
    iget-object v1, v1, Lzj0/c;->b:Lxj0/r;

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    const/4 p0, 0x1

    .line 74
    goto :goto_1

    .line 75
    :cond_1
    const/4 p0, 0x0

    .line 76
    :goto_1
    return p0

    .line 77
    :pswitch_0
    iget-object p0, p0, Lsu/b;->e:Lsu/i;

    .line 78
    .line 79
    iget-object v0, p0, Lsu/i;->q:Lnd0/c;

    .line 80
    .line 81
    if-eqz v0, :cond_2

    .line 82
    .line 83
    iget-object p0, p0, Lsu/i;->j:Lb81/c;

    .line 84
    .line 85
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p0, Ljava/util/HashMap;

    .line 88
    .line 89
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    check-cast p0, Lzj0/c;

    .line 94
    .line 95
    iget-object p1, v0, Lnd0/c;->e:Lay0/k;

    .line 96
    .line 97
    iget-object p0, p0, Lzj0/c;->b:Lxj0/r;

    .line 98
    .line 99
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    const/4 p0, 0x1

    .line 103
    goto :goto_2

    .line 104
    :cond_2
    const/4 p0, 0x0

    .line 105
    :goto_2
    return p0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
