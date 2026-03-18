.class public final synthetic Lh2/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Ljava/util/ArrayList;

.field public final synthetic e:Lt3/s0;

.field public final synthetic f:F

.field public final synthetic g:I

.field public final synthetic h:Ljava/util/ArrayList;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Lt3/s0;FILjava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/g;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/g;->e:Lt3/s0;

    .line 7
    .line 8
    iput p3, p0, Lh2/g;->f:F

    .line 9
    .line 10
    iput p4, p0, Lh2/g;->g:I

    .line 11
    .line 12
    iput-object p5, p0, Lh2/g;->h:Ljava/util/ArrayList;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    iget-object v0, p0, Lh2/g;->d:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    move v3, v2

    .line 11
    :goto_0
    if-ge v3, v1, :cond_3

    .line 12
    .line 13
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    check-cast v4, Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    new-array v9, v5, [I

    .line 24
    .line 25
    move v6, v2

    .line 26
    :goto_1
    iget-object v7, p0, Lh2/g;->e:Lt3/s0;

    .line 27
    .line 28
    if-ge v6, v5, :cond_1

    .line 29
    .line 30
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    check-cast v8, Lt3/e1;

    .line 35
    .line 36
    iget v8, v8, Lt3/e1;->d:I

    .line 37
    .line 38
    invoke-static {v4}, Ljp/k1;->h(Ljava/util/List;)I

    .line 39
    .line 40
    .line 41
    move-result v10

    .line 42
    if-ge v6, v10, :cond_0

    .line 43
    .line 44
    iget v10, p0, Lh2/g;->f:F

    .line 45
    .line 46
    invoke-interface {v7, v10}, Lt4/c;->Q(F)I

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    goto :goto_2

    .line 51
    :cond_0
    move v7, v2

    .line 52
    :goto_2
    add-int/2addr v8, v7

    .line 53
    aput v8, v9, v6

    .line 54
    .line 55
    add-int/lit8 v6, v6, 0x1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    sget-object v6, Lk1/j;->b:Lk1/c;

    .line 59
    .line 60
    new-array v11, v5, [I

    .line 61
    .line 62
    invoke-interface {v7}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    iget v8, p0, Lh2/g;->g:I

    .line 67
    .line 68
    invoke-virtual/range {v6 .. v11}, Lk1/c;->c(Lt4/c;I[ILt4/m;[I)V

    .line 69
    .line 70
    .line 71
    move-object v5, v4

    .line 72
    check-cast v5, Ljava/util/Collection;

    .line 73
    .line 74
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    move v6, v2

    .line 79
    :goto_3
    if-ge v6, v5, :cond_2

    .line 80
    .line 81
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    check-cast v7, Lt3/e1;

    .line 86
    .line 87
    aget v8, v11, v6

    .line 88
    .line 89
    iget-object v9, p0, Lh2/g;->h:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v9

    .line 95
    check-cast v9, Ljava/lang/Number;

    .line 96
    .line 97
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 98
    .line 99
    .line 100
    move-result v9

    .line 101
    invoke-static {p1, v7, v8, v9}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 102
    .line 103
    .line 104
    add-int/lit8 v6, v6, 0x1

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    return-object p0
.end method
