.class public final synthetic Lm1/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Ljava/util/ArrayList;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Z


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Ljava/util/ArrayList;Ljava/util/List;ZI)V
    .locals 0

    .line 1
    iput p5, p0, Lm1/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm1/k;->e:Ll2/b1;

    .line 4
    .line 5
    iput-object p2, p0, Lm1/k;->f:Ljava/util/ArrayList;

    .line 6
    .line 7
    iput-object p3, p0, Lm1/k;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-boolean p4, p0, Lm1/k;->h:Z

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lm1/k;->d:I

    .line 2
    .line 3
    check-cast p1, Lt3/d1;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p1, Lt3/d1;->d:Z

    .line 10
    .line 11
    iget-object v0, p0, Lm1/k;->f:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, 0x0

    .line 18
    move v3, v2

    .line 19
    :goto_0
    iget-boolean v4, p0, Lm1/k;->h:Z

    .line 20
    .line 21
    if-ge v3, v1, :cond_0

    .line 22
    .line 23
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v5

    .line 27
    check-cast v5, Ln1/o;

    .line 28
    .line 29
    invoke-virtual {v5, p1, v4}, Ln1/o;->l(Lt3/d1;Z)V

    .line 30
    .line 31
    .line 32
    add-int/lit8 v3, v3, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    iget-object v0, p0, Lm1/k;->g:Ljava/lang/Object;

    .line 36
    .line 37
    move-object v1, v0

    .line 38
    check-cast v1, Ljava/util/Collection;

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    move v3, v2

    .line 45
    :goto_1
    if-ge v3, v1, :cond_1

    .line 46
    .line 47
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    check-cast v5, Ln1/o;

    .line 52
    .line 53
    invoke-virtual {v5, p1, v4}, Ln1/o;->l(Lt3/d1;Z)V

    .line 54
    .line 55
    .line 56
    add-int/lit8 v3, v3, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    iput-boolean v2, p1, Lt3/d1;->d:Z

    .line 60
    .line 61
    iget-object p0, p0, Lm1/k;->e:Ll2/b1;

    .line 62
    .line 63
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_0
    const/4 v0, 0x1

    .line 70
    iput-boolean v0, p1, Lt3/d1;->d:Z

    .line 71
    .line 72
    iget-object v0, p0, Lm1/k;->f:Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    const/4 v2, 0x0

    .line 79
    move v3, v2

    .line 80
    :goto_3
    iget-boolean v4, p0, Lm1/k;->h:Z

    .line 81
    .line 82
    if-ge v3, v1, :cond_2

    .line 83
    .line 84
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    check-cast v5, Lm1/m;

    .line 89
    .line 90
    invoke-virtual {v5, p1, v4}, Lm1/m;->m(Lt3/d1;Z)V

    .line 91
    .line 92
    .line 93
    add-int/lit8 v3, v3, 0x1

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_2
    iget-object v0, p0, Lm1/k;->g:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v1, v0

    .line 99
    check-cast v1, Ljava/util/Collection;

    .line 100
    .line 101
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    move v3, v2

    .line 106
    :goto_4
    if-ge v3, v1, :cond_3

    .line 107
    .line 108
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    check-cast v5, Lm1/m;

    .line 113
    .line 114
    invoke-virtual {v5, p1, v4}, Lm1/m;->m(Lt3/d1;Z)V

    .line 115
    .line 116
    .line 117
    add-int/lit8 v3, v3, 0x1

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_3
    iput-boolean v2, p1, Lt3/d1;->d:Z

    .line 121
    .line 122
    iget-object p0, p0, Lm1/k;->e:Ll2/b1;

    .line 123
    .line 124
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    nop

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
