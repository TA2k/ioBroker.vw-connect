.class public final synthetic Ln70/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm70/g0;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lm70/g0;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Ln70/w;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln70/w;->e:Lm70/g0;

    .line 4
    .line 5
    iput-object p2, p0, Ln70/w;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Ln70/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object v0, p0, Ln70/w;->e:Lm70/g0;

    .line 13
    .line 14
    iget-object v0, v0, Lm70/g0;->d:Ljava/util/List;

    .line 15
    .line 16
    check-cast v0, Ljava/lang/Iterable;

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    move-object v2, v1

    .line 33
    check-cast v2, Ll70/v;

    .line 34
    .line 35
    iget-object v2, v2, Ll70/v;->a:Ll70/w;

    .line 36
    .line 37
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-ne v2, p1, :cond_0

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    const/4 v1, 0x0

    .line 45
    :goto_0
    check-cast v1, Ll70/v;

    .line 46
    .line 47
    if-eqz v1, :cond_2

    .line 48
    .line 49
    iget-object p0, p0, Ln70/w;->f:Lay0/k;

    .line 50
    .line 51
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_0
    check-cast p1, Lm1/f;

    .line 58
    .line 59
    const-string v0, "$this$LazyRow"

    .line 60
    .line 61
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget-object v0, p0, Ln70/w;->e:Lm70/g0;

    .line 65
    .line 66
    iget-boolean v1, v0, Lm70/g0;->o:Z

    .line 67
    .line 68
    if-eqz v1, :cond_3

    .line 69
    .line 70
    const/4 p0, 0x4

    .line 71
    sget-object v0, Ln70/a;->b:Lt2/b;

    .line 72
    .line 73
    invoke-static {p1, p0, v0}, Lm1/f;->q(Lm1/f;ILt2/b;)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_3
    iget-object v0, v0, Lm70/g0;->h:Lm70/f0;

    .line 78
    .line 79
    iget-object v0, v0, Lm70/f0;->a:Ljava/util/List;

    .line 80
    .line 81
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    new-instance v2, Lak/p;

    .line 86
    .line 87
    const/16 v3, 0x1c

    .line 88
    .line 89
    invoke-direct {v2, v0, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 90
    .line 91
    .line 92
    new-instance v3, Lak/q;

    .line 93
    .line 94
    const/4 v4, 0x7

    .line 95
    iget-object p0, p0, Ln70/w;->f:Lay0/k;

    .line 96
    .line 97
    invoke-direct {v3, v0, p0, v4}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 98
    .line 99
    .line 100
    new-instance p0, Lt2/b;

    .line 101
    .line 102
    const/4 v0, 0x1

    .line 103
    const v4, 0x2fd4df92

    .line 104
    .line 105
    .line 106
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 107
    .line 108
    .line 109
    const/4 v0, 0x0

    .line 110
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 111
    .line 112
    .line 113
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
