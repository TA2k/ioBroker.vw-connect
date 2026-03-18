.class public final synthetic Lew/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lt2/b;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lt2/b;II)V
    .locals 0

    .line 1
    iput p4, p0, Lew/a;->d:I

    iput-object p1, p0, Lew/a;->e:Lx2/s;

    iput-object p2, p0, Lew/a;->f:Lt2/b;

    iput p3, p0, Lew/a;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lt2/b;III)V
    .locals 0

    .line 2
    iput p5, p0, Lew/a;->d:I

    iput-object p1, p0, Lew/a;->e:Lx2/s;

    iput-object p2, p0, Lew/a;->f:Lt2/b;

    iput p4, p0, Lew/a;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lew/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lew/a;->g:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 22
    .line 23
    iget-object p0, p0, Lew/a;->f:Lt2/b;

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Llp/pf;->a(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget p2, p0, Lew/a;->g:I

    .line 32
    .line 33
    or-int/lit8 p2, p2, 0x1

    .line 34
    .line 35
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 40
    .line 41
    iget-object p0, p0, Lew/a;->f:Lt2/b;

    .line 42
    .line 43
    invoke-static {v0, p0, p1, p2}, Llp/pf;->b(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :pswitch_1
    iget p2, p0, Lew/a;->g:I

    .line 48
    .line 49
    or-int/lit8 p2, p2, 0x1

    .line 50
    .line 51
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 56
    .line 57
    iget-object p0, p0, Lew/a;->f:Lt2/b;

    .line 58
    .line 59
    invoke-static {v0, p0, p1, p2}, Ly1/k;->d(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_2
    iget p2, p0, Lew/a;->g:I

    .line 64
    .line 65
    or-int/lit8 p2, p2, 0x1

    .line 66
    .line 67
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 72
    .line 73
    iget-object p0, p0, Lew/a;->f:Lt2/b;

    .line 74
    .line 75
    invoke-static {v0, p0, p1, p2}, Llp/of;->c(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :pswitch_3
    iget p2, p0, Lew/a;->g:I

    .line 80
    .line 81
    or-int/lit8 p2, p2, 0x1

    .line 82
    .line 83
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 88
    .line 89
    iget-object p0, p0, Lew/a;->f:Lt2/b;

    .line 90
    .line 91
    invoke-static {v0, p0, p1, p2}, Llp/of;->b(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :pswitch_4
    const/16 p2, 0x31

    .line 96
    .line 97
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 98
    .line 99
    .line 100
    move-result p2

    .line 101
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 102
    .line 103
    iget-object v1, p0, Lew/a;->f:Lt2/b;

    .line 104
    .line 105
    iget p0, p0, Lew/a;->g:I

    .line 106
    .line 107
    invoke-static {v0, v1, p1, p2, p0}, Luz/y;->f(Lx2/s;Lt2/b;Ll2/o;II)V

    .line 108
    .line 109
    .line 110
    goto :goto_0

    .line 111
    :pswitch_5
    const/16 p2, 0x31

    .line 112
    .line 113
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 114
    .line 115
    .line 116
    move-result p2

    .line 117
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 118
    .line 119
    iget-object v1, p0, Lew/a;->f:Lt2/b;

    .line 120
    .line 121
    iget p0, p0, Lew/a;->g:I

    .line 122
    .line 123
    invoke-static {v0, v1, p1, p2, p0}, Li91/h0;->b(Lx2/s;Lt2/b;Ll2/o;II)V

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :pswitch_6
    iget p2, p0, Lew/a;->g:I

    .line 128
    .line 129
    or-int/lit8 p2, p2, 0x1

    .line 130
    .line 131
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 132
    .line 133
    .line 134
    move-result p2

    .line 135
    iget-object v0, p0, Lew/a;->e:Lx2/s;

    .line 136
    .line 137
    iget-object p0, p0, Lew/a;->f:Lt2/b;

    .line 138
    .line 139
    invoke-static {v0, p0, p1, p2}, Lew/e;->b(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 140
    .line 141
    .line 142
    goto :goto_0

    .line 143
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
