.class public final synthetic Lck/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltd/p;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ltd/p;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lck/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lck/f;->e:Ltd/p;

    .line 4
    .line 5
    iput-object p2, p0, Lck/f;->f:Lay0/k;

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
    .locals 9

    .line 1
    iget v0, p0, Lck/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lm1/f;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$LazyRow"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lal/d;

    .line 14
    .line 15
    const/16 v1, 0x9

    .line 16
    .line 17
    iget-object v2, p0, Lck/f;->e:Ltd/p;

    .line 18
    .line 19
    iget-object p0, p0, Lck/f;->f:Lay0/k;

    .line 20
    .line 21
    invoke-direct {v0, v1, v2, p0}, Lal/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lt2/b;

    .line 25
    .line 26
    const/4 v3, 0x1

    .line 27
    const v4, 0x35a2bd63

    .line 28
    .line 29
    .line 30
    invoke-direct {v1, v0, v3, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 31
    .line 32
    .line 33
    const/4 v0, 0x3

    .line 34
    invoke-static {p1, v1, v0}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 35
    .line 36
    .line 37
    iget-object v1, v2, Ltd/p;->f:Ljava/util/List;

    .line 38
    .line 39
    new-instance v4, Lck/a;

    .line 40
    .line 41
    const/4 v5, 0x3

    .line 42
    invoke-direct {v4, v5}, Lck/a;-><init>(I)V

    .line 43
    .line 44
    .line 45
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    new-instance v6, Lc41/g;

    .line 50
    .line 51
    const/4 v7, 0x1

    .line 52
    invoke-direct {v6, v7, v4, v1}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    new-instance v4, Lak/p;

    .line 56
    .line 57
    const/4 v7, 0x7

    .line 58
    invoke-direct {v4, v1, v7}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 59
    .line 60
    .line 61
    new-instance v7, Lal/o;

    .line 62
    .line 63
    const/4 v8, 0x2

    .line 64
    invoke-direct {v7, v1, p0, v2, v8}, Lal/o;-><init>(Ljava/util/List;Lay0/k;Ljava/lang/Object;I)V

    .line 65
    .line 66
    .line 67
    new-instance p0, Lt2/b;

    .line 68
    .line 69
    const v1, 0x799532c4

    .line 70
    .line 71
    .line 72
    invoke-direct {p0, v7, v3, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1, v5, v6, v4, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 76
    .line 77
    .line 78
    sget-object p0, Lck/c;->e:Lt2/b;

    .line 79
    .line 80
    invoke-static {p1, p0, v0}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 81
    .line 82
    .line 83
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object p0

    .line 86
    :pswitch_0
    const-string v0, "$this$LazyColumn"

    .line 87
    .line 88
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    iget-object v0, p0, Lck/f;->e:Ltd/p;

    .line 92
    .line 93
    iget-object v0, v0, Ltd/p;->c:Ljava/util/List;

    .line 94
    .line 95
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    new-instance v2, Lak/p;

    .line 100
    .line 101
    const/4 v3, 0x6

    .line 102
    invoke-direct {v2, v0, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 103
    .line 104
    .line 105
    new-instance v3, Lak/q;

    .line 106
    .line 107
    const/4 v4, 0x2

    .line 108
    iget-object p0, p0, Lck/f;->f:Lay0/k;

    .line 109
    .line 110
    invoke-direct {v3, v0, p0, v4}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 111
    .line 112
    .line 113
    new-instance p0, Lt2/b;

    .line 114
    .line 115
    const/4 v0, 0x1

    .line 116
    const v4, 0x799532c4

    .line 117
    .line 118
    .line 119
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 120
    .line 121
    .line 122
    const/4 v0, 0x0

    .line 123
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
