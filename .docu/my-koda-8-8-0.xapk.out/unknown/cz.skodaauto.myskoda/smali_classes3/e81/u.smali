.class public final synthetic Le81/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;I)V
    .locals 0

    .line 1
    iput p2, p0, Le81/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le81/u;->e:Ljava/util/List;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Le81/u;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "$this$LazyColumn"

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    const v4, 0x2fd4df92

    .line 8
    .line 9
    .line 10
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object p0, p0, Le81/u;->e:Ljava/util/List;

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    check-cast p1, Lm1/f;

    .line 18
    .line 19
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    new-instance v2, Lnu0/c;

    .line 27
    .line 28
    const/4 v6, 0x4

    .line 29
    invoke-direct {v2, p0, v6}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 30
    .line 31
    .line 32
    new-instance v7, Lb60/h;

    .line 33
    .line 34
    invoke-direct {v7, p0, v6}, Lb60/h;-><init>(Ljava/lang/Object;I)V

    .line 35
    .line 36
    .line 37
    new-instance p0, Lt2/b;

    .line 38
    .line 39
    invoke-direct {p0, v7, v3, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, v0, v1, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 43
    .line 44
    .line 45
    return-object v5

    .line 46
    :pswitch_0
    check-cast p1, Lm1/f;

    .line 47
    .line 48
    const-string v0, "$this$LazyRow"

    .line 49
    .line 50
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    new-instance v2, Lnu0/c;

    .line 58
    .line 59
    const/4 v6, 0x3

    .line 60
    invoke-direct {v2, p0, v6}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 61
    .line 62
    .line 63
    new-instance v7, Lb60/h;

    .line 64
    .line 65
    invoke-direct {v7, p0, v6}, Lb60/h;-><init>(Ljava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    new-instance p0, Lt2/b;

    .line 69
    .line 70
    invoke-direct {p0, v7, v3, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, v0, v1, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 74
    .line 75
    .line 76
    return-object v5

    .line 77
    :pswitch_1
    check-cast p1, Lm1/f;

    .line 78
    .line 79
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance v0, Lnh/i;

    .line 83
    .line 84
    const/16 v1, 0x8

    .line 85
    .line 86
    invoke-direct {v0, v1}, Lnh/i;-><init>(I)V

    .line 87
    .line 88
    .line 89
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    new-instance v2, Lc41/g;

    .line 94
    .line 95
    const/16 v6, 0xf

    .line 96
    .line 97
    invoke-direct {v2, v6, v0, p0}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    new-instance v0, Lnu0/c;

    .line 101
    .line 102
    const/4 v6, 0x0

    .line 103
    invoke-direct {v0, p0, v6}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 104
    .line 105
    .line 106
    new-instance v6, Lb60/h;

    .line 107
    .line 108
    const/4 v7, 0x2

    .line 109
    invoke-direct {v6, p0, v7}, Lb60/h;-><init>(Ljava/lang/Object;I)V

    .line 110
    .line 111
    .line 112
    new-instance p0, Lt2/b;

    .line 113
    .line 114
    invoke-direct {p0, v6, v3, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {p1, v1, v2, v0, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 118
    .line 119
    .line 120
    return-object v5

    .line 121
    :pswitch_2
    check-cast p1, Ld4/l;

    .line 122
    .line 123
    sget-object v0, Ld4/x;->a:[Lhy0/z;

    .line 124
    .line 125
    sget-object v0, Ld4/k;->w:Ld4/z;

    .line 126
    .line 127
    sget-object v1, Ld4/x;->a:[Lhy0/z;

    .line 128
    .line 129
    const/16 v2, 0x1c

    .line 130
    .line 131
    aget-object v1, v1, v2

    .line 132
    .line 133
    invoke-virtual {v0, p1, p0}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    return-object v5

    .line 137
    :pswitch_3
    check-cast p1, Lz71/i;

    .line 138
    .line 139
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->c(Ljava/util/List;Lz71/i;)Llx0/b0;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    return-object p0

    .line 144
    nop

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
