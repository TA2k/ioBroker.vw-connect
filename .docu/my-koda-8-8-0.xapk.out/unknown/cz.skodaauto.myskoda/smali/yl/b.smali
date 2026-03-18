.class public final synthetic Lyl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyl/d;


# direct methods
.method public synthetic constructor <init>(Lyl/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyl/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyl/b;->e:Lyl/d;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lyl/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lyl/b;->e:Lyl/d;

    .line 7
    .line 8
    iget-object v0, p0, Lyl/d;->e:Ljava/util/List;

    .line 9
    .line 10
    new-instance v1, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    move-object v2, v0

    .line 16
    check-cast v2, Ljava/util/Collection;

    .line 17
    .line 18
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/4 v3, 0x0

    .line 23
    :goto_0
    if-ge v3, v2, :cond_0

    .line 24
    .line 25
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    check-cast v4, Lay0/a;

    .line 30
    .line 31
    invoke-interface {v4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    check-cast v4, Ljava/util/List;

    .line 36
    .line 37
    check-cast v4, Ljava/lang/Iterable;

    .line 38
    .line 39
    invoke-static {v4, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 40
    .line 41
    .line 42
    add-int/lit8 v3, v3, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 46
    .line 47
    iput-object v0, p0, Lyl/d;->e:Ljava/util/List;

    .line 48
    .line 49
    return-object v1

    .line 50
    :pswitch_0
    iget-object p0, p0, Lyl/b;->e:Lyl/d;

    .line 51
    .line 52
    iget-object v0, p0, Lyl/d;->d:Ljava/util/List;

    .line 53
    .line 54
    new-instance v1, Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 57
    .line 58
    .line 59
    move-object v2, v0

    .line 60
    check-cast v2, Ljava/util/Collection;

    .line 61
    .line 62
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    const/4 v3, 0x0

    .line 67
    :goto_1
    if-ge v3, v2, :cond_1

    .line 68
    .line 69
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    check-cast v4, Lay0/a;

    .line 74
    .line 75
    invoke-interface {v4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    check-cast v4, Ljava/util/List;

    .line 80
    .line 81
    check-cast v4, Ljava/lang/Iterable;

    .line 82
    .line 83
    invoke-static {v4, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 84
    .line 85
    .line 86
    add-int/lit8 v3, v3, 0x1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 90
    .line 91
    iput-object v0, p0, Lyl/d;->d:Ljava/util/List;

    .line 92
    .line 93
    return-object v1

    .line 94
    nop

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
