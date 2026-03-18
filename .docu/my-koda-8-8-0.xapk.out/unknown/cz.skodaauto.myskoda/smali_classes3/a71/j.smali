.class public final synthetic La71/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lt2/b;ZZLay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, La71/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/j;->e:Lt2/b;

    iput-boolean p2, p0, La71/j;->f:Z

    iput-boolean p3, p0, La71/j;->g:Z

    iput-object p4, p0, La71/j;->h:Lay0/a;

    iput-object p5, p0, La71/j;->i:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(ZLt2/b;ZLay0/a;Lay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, La71/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, La71/j;->f:Z

    iput-object p2, p0, La71/j;->e:Lt2/b;

    iput-boolean p3, p0, La71/j;->g:Z

    iput-object p4, p0, La71/j;->h:Lay0/a;

    iput-object p5, p0, La71/j;->i:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, La71/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lk1/q;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$DriveControlGridRow"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    check-cast p2, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-eqz p1, :cond_1

    .line 39
    .line 40
    new-instance p1, La71/o;

    .line 41
    .line 42
    iget-object p3, p0, La71/j;->h:Lay0/a;

    .line 43
    .line 44
    iget-object v0, p0, La71/j;->i:Lay0/a;

    .line 45
    .line 46
    iget-boolean v1, p0, La71/j;->f:Z

    .line 47
    .line 48
    iget-boolean v2, p0, La71/j;->g:Z

    .line 49
    .line 50
    invoke-direct {p1, p3, v0, v1, v2}, La71/o;-><init>(Lay0/a;Lay0/a;ZZ)V

    .line 51
    .line 52
    .line 53
    const p3, 0x351e6a29

    .line 54
    .line 55
    .line 56
    invoke-static {p3, p2, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    const/16 p3, 0x30

    .line 61
    .line 62
    iget-object p0, p0, La71/j;->e:Lt2/b;

    .line 63
    .line 64
    invoke-static {p0, p1, p2, p3}, La71/b;->r(Lt2/b;Lt2/b;Ll2/o;I)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 69
    .line 70
    .line 71
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object p0

    .line 74
    :pswitch_0
    const-string v0, "$this$DriveControlGridRow"

    .line 75
    .line 76
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    and-int/lit8 p1, p3, 0x11

    .line 80
    .line 81
    const/16 v0, 0x10

    .line 82
    .line 83
    const/4 v1, 0x0

    .line 84
    const/4 v2, 0x1

    .line 85
    if-eq p1, v0, :cond_2

    .line 86
    .line 87
    move p1, v2

    .line 88
    goto :goto_2

    .line 89
    :cond_2
    move p1, v1

    .line 90
    :goto_2
    and-int/2addr p3, v2

    .line 91
    check-cast p2, Ll2/t;

    .line 92
    .line 93
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    if-eqz p1, :cond_4

    .line 98
    .line 99
    iget-boolean p1, p0, La71/j;->f:Z

    .line 100
    .line 101
    if-eqz p1, :cond_3

    .line 102
    .line 103
    const p1, -0xf8631e1

    .line 104
    .line 105
    .line 106
    invoke-virtual {p2, p1}, Ll2/t;->Y(I)V

    .line 107
    .line 108
    .line 109
    new-instance p1, La71/p;

    .line 110
    .line 111
    iget-object p3, p0, La71/j;->h:Lay0/a;

    .line 112
    .line 113
    iget-object v0, p0, La71/j;->i:Lay0/a;

    .line 114
    .line 115
    iget-boolean v2, p0, La71/j;->g:Z

    .line 116
    .line 117
    invoke-direct {p1, p3, v0, v2}, La71/p;-><init>(Lay0/a;Lay0/a;Z)V

    .line 118
    .line 119
    .line 120
    const p3, -0x3268e19b

    .line 121
    .line 122
    .line 123
    invoke-static {p3, p2, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    const/16 p3, 0x30

    .line 128
    .line 129
    iget-object p0, p0, La71/j;->e:Lt2/b;

    .line 130
    .line 131
    invoke-static {p0, p1, p2, p3}, La71/b;->r(Lt2/b;Lt2/b;Ll2/o;I)V

    .line 132
    .line 133
    .line 134
    :goto_3
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    goto :goto_4

    .line 138
    :cond_3
    const p0, -0xfdb92f0

    .line 139
    .line 140
    .line 141
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 142
    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 146
    .line 147
    .line 148
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    return-object p0

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
