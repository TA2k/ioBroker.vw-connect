.class public final Ld6/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/util/Iterator;

.field public final f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/collection/d1;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ld6/b0;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Ld6/b0;->f:Ljava/lang/Object;

    .line 7
    iput-object p1, p0, Ld6/b0;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lky0/s;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ld6/b0;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p1, p0, Ld6/b0;->f:Ljava/lang/Object;

    .line 10
    iget-object p1, p1, Lky0/s;->a:Lky0/j;

    .line 11
    invoke-interface {p1}, Lky0/j;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Ld6/b0;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lvw0/e;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Ld6/b0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ld6/b0;->f:Ljava/lang/Object;

    .line 3
    iget-object p1, p1, Lvw0/e;->d:Ljava/util/Set;

    .line 4
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Ld6/b0;->e:Ljava/util/Iterator;

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Ld6/b0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Ld6/b0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld6/b0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvw0/e;

    .line 9
    .line 10
    iget-object v0, v0, Lvw0/e;->e:Lay0/k;

    .line 11
    .line 12
    iget-object p0, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 13
    .line 14
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object v0, p0, Ld6/b0;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Lky0/s;

    .line 26
    .line 27
    iget-object v0, v0, Lky0/s;->b:Lay0/k;

    .line 28
    .line 29
    iget-object p0, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    iget-object v0, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 41
    .line 42
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    iget-object v1, p0, Ld6/b0;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v1, Ljava/util/ArrayList;

    .line 49
    .line 50
    move-object v2, v0

    .line 51
    check-cast v2, Landroid/view/View;

    .line 52
    .line 53
    instance-of v3, v2, Landroid/view/ViewGroup;

    .line 54
    .line 55
    const/4 v4, 0x0

    .line 56
    if-eqz v3, :cond_0

    .line 57
    .line 58
    check-cast v2, Landroid/view/ViewGroup;

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    move-object v2, v4

    .line 62
    :goto_0
    if-eqz v2, :cond_1

    .line 63
    .line 64
    new-instance v4, Landroidx/collection/d1;

    .line 65
    .line 66
    const/4 v3, 0x1

    .line 67
    invoke-direct {v4, v2, v3}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 68
    .line 69
    .line 70
    :cond_1
    if-eqz v4, :cond_2

    .line 71
    .line 72
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_2

    .line 77
    .line 78
    iget-object v2, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 79
    .line 80
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    iput-object v4, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_2
    :goto_1
    iget-object v2, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 87
    .line 88
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    if-nez v2, :cond_3

    .line 93
    .line 94
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-nez v2, :cond_3

    .line 99
    .line 100
    invoke-static {v1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    check-cast v2, Ljava/util/Iterator;

    .line 105
    .line 106
    iput-object v2, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 107
    .line 108
    invoke-static {v1}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_3
    :goto_2
    return-object v0

    .line 113
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 1

    .line 1
    iget v0, p0, Ld6/b0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ld6/b0;->e:Ljava/util/Iterator;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    const-string v0, "Operation is not supported for read-only collection"

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :pswitch_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 21
    .line 22
    const-string v0, "Operation is not supported for read-only collection"

    .line 23
    .line 24
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
